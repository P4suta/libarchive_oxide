// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level, session-bound archive inspection, planning, and application.
//!
//! An [`ArchiveSession`] owns a bounded immutable snapshot of its input. Plans
//! are tied to that snapshot and to one session, so a caller cannot accidentally
//! inspect one byte stream and apply a different one.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::fs::Dir;
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits,
    ProbeResult,
};
use sha2::{Digest, Sha256};

use crate::extraction::{ExtractionReport, Policy, RejectionReason};
use crate::filesystem_driver::{apply_registered_plan, apply_seek_plan};
use crate::path::{DestinationClaims, DestinationKey};
use crate::provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, CodecProvider, CodecProviderNode,
    FormatProvider, FormatProviderNode, ProviderCapability, ProviderSet, StaticCodecProviders,
    StaticFormatProviders,
};
use crate::registry::{Registry, RegistryCodecs, RegistryFormats};
use crate::spool::{DEFAULT_MAX_BYTES, DEFAULT_MEMORY_THRESHOLD};
use crate::stream::ProviderArchiveWriter;
use crate::{
    ArchiveReader, ArchiveWriter, BackendPreference, CapStdFilesystemAdapter, FilesystemAdapter,
    FilesystemFinding, ReaderEvent, SecretBytes, SeekArchiveReader, SeekArchiveWriter, SpoolReader,
    StreamError,
};

const FORMAT_PROBE_BYTES: usize = 17 * 2048 + 6;
const DIGEST_BUFFER_BYTES: usize = 64 * 1024;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// SHA-256 identity of the immutable encoded input snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputDigest([u8; 32]);

impl InputDigest {
    /// Digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InputDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for InputDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit immutable snapshot used by inspect/plan/apply sessions.
#[derive(Debug)]
pub struct PreparedArchive {
    snapshot: SpoolReader,
    digest: InputDigest,
}

impl PreparedArchive {
    /// Spools an input with the safe finite memory and total-size bounds.
    pub fn spool(input: impl Read) -> Result<Self, StreamError> {
        Self::spool_with_limits(input, DEFAULT_MEMORY_THRESHOLD, DEFAULT_MAX_BYTES)
    }

    /// Spools an input with explicit memory and total-size bounds.
    pub fn spool_with_limits(
        input: impl Read,
        memory_threshold: usize,
        maximum: u64,
    ) -> Result<Self, StreamError> {
        let mut snapshot = SpoolReader::from_reader_with_limits(input, memory_threshold, maximum)?;
        let digest = digest_snapshot(&mut snapshot)?;
        Ok(Self { snapshot, digest })
    }

    /// SHA-256 identity of the encoded snapshot.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Encoded snapshot length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.snapshot.len()
    }

    /// Whether the encoded snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.snapshot.is_empty()
    }
}

/// High-level archive engine configuration.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveEngine<F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    limits: Limits,
    spool_memory_threshold: usize,
    spool_maximum: u64,
    backend: BackendPreference,
    providers: ProviderSet<F, C>,
}

impl ArchiveEngine<BuiltinFormatProviders, BuiltinCodecProviders> {
    /// Safe finite defaults with the built-in providers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
            spool_memory_threshold: DEFAULT_MEMORY_THRESHOLD,
            spool_maximum: DEFAULT_MAX_BYTES,
            backend: BackendPreference::Auto,
            providers: ProviderSet::builtins(),
        }
    }

    /// Selects the built-in portable or native codec backend at runtime.
    #[must_use]
    pub const fn with_backend_preference(mut self, backend: BackendPreference) -> Self {
        self.backend = backend;
        self.providers = ProviderSet::builtins_with_backend(backend);
        self
    }

    /// Creates a sequential writer from high-level options.
    pub fn create<W: Write>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<ArchiveWriter<W>, StreamError> {
        let limits = options.limits.unwrap_or(self.limits);
        ArchiveWriter::with_filter_and_backend(
            output,
            options.format,
            options.filter,
            limits,
            self.backend,
        )
        .map_err(StreamError::archive)
    }

    /// Creates a streaming `WinZip` AES-256 AE-2 writer.
    ///
    /// The high-level encrypted profile deliberately uses the same Deflate
    /// method as ordinary high-level ZIP creation. Passwords are accepted only
    /// for ZIP without an outer filter, so a supplied secret is never silently
    /// ignored by another format.
    #[cfg(feature = "aes")]
    pub fn create_with_password<W: Write>(
        self,
        output: W,
        options: CreateOptions,
        password: SecretBytes,
    ) -> Result<ArchiveWriter<W>, StreamError> {
        if options.format != FormatId::Zip {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability).with_context(
                    "password-protected high-level creation is available only for ZIP",
                ),
            ));
        }
        if options.filter.is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("zip")
                    .with_context("password-protected ZIP cannot use an outer filter"),
            ));
        }
        let limits = options.limits.unwrap_or(self.limits);
        Ok(ArchiveWriter::with_zip_password_and_backend(
            output,
            crate::ZipMethod::Deflate,
            password,
            limits,
            self.backend,
        ))
    }

    /// Creates a seek-capable writer from high-level options.
    pub fn create_seek<W: Write + Seek>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<SeekArchiveWriter<W>, StreamError> {
        if options.filter.is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_context("seek-native high-level creation does not support outer filters"),
            ));
        }
        SeekArchiveWriter::with_format(
            output,
            options.format,
            options.limits.unwrap_or(self.limits),
        )
    }
}

impl ArchiveEngine<RegistryFormats, RegistryCodecs> {
    /// Creates an engine backed by an immutable object-safe provider registry.
    #[must_use]
    pub fn from_registry(registry: &Registry) -> Self {
        Self {
            limits: Limits::safe(),
            spool_memory_threshold: DEFAULT_MEMORY_THRESHOLD,
            spool_maximum: DEFAULT_MAX_BYTES,
            backend: BackendPreference::Auto,
            providers: registry.providers(),
        }
    }
}

impl<F, C> ArchiveEngine<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Replaces parser, codec, inspection, and extraction budgets.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the immutable snapshot's memory threshold and total byte cap.
    #[must_use]
    pub const fn with_spool_limits(mut self, memory_threshold: usize, maximum: u64) -> Self {
        self.spool_memory_threshold = memory_threshold;
        self.spool_maximum = maximum;
        self
    }

    /// Prepends one compile-time format provider to this engine.
    #[doc(hidden)]
    #[must_use]
    pub fn with_format_provider<P>(self, provider: P) -> ArchiveEngine<FormatProviderNode<P, F>, C>
    where
        P: FormatProvider,
    {
        ArchiveEngine {
            limits: self.limits,
            spool_memory_threshold: self.spool_memory_threshold,
            spool_maximum: self.spool_maximum,
            backend: self.backend,
            providers: self.providers.with_format_provider(provider),
        }
    }

    /// Prepends one compile-time outer-codec provider to this engine.
    #[doc(hidden)]
    #[must_use]
    pub fn with_codec_provider<P>(self, provider: P) -> ArchiveEngine<F, CodecProviderNode<P, C>>
    where
        P: CodecProvider,
    {
        ArchiveEngine {
            limits: self.limits,
            spool_memory_threshold: self.spool_memory_threshold,
            spool_maximum: self.spool_maximum,
            backend: self.backend,
            providers: self.providers.with_codec_provider(provider),
        }
    }

    /// Resource budgets used for new sessions.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Providers available to new sessions.
    #[doc(hidden)]
    #[must_use]
    pub fn providers(self) -> ProviderSet<F, C> {
        self.providers
    }

    /// Creates a sequential writer through this engine's registered provider chains.
    pub fn create_registered<W: Write>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<ProviderArchiveWriter<W, F, C>, StreamError> {
        let limits = options.limits.unwrap_or(self.limits);
        ProviderArchiveWriter::with_providers(
            output,
            options.format,
            options.filter,
            limits,
            self.providers,
        )
        .map_err(StreamError::archive)
    }

    /// Opens a true streaming reader without implicitly spooling the input.
    #[must_use]
    pub fn open<R: Read>(self, input: R) -> ArchiveReader<R, F, C> {
        ArchiveReader::with_providers(input, self.limits, self.providers)
    }

    /// Opens a true streaming reader with an explicit sequential format.
    ///
    /// This is the safe entry point for signatureless formats such as raw
    /// single-entry streams; automatic detection is never allowed to guess
    /// them.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is not a readable sequential format
    /// in this engine's provider set.
    pub fn open_with_format<R: Read>(
        self,
        input: R,
        format: FormatId,
    ) -> Result<ArchiveReader<R, F, C>, ArchiveError> {
        ArchiveReader::with_providers_and_format(input, format, self.limits, self.providers)
    }

    /// Explicitly spools input and opens an inspect/plan/apply session.
    pub fn prepare(self, input: impl Read) -> Result<ArchiveSession<F, C>, StreamError> {
        let prepared = PreparedArchive::spool_with_limits(
            input,
            self.spool_memory_threshold,
            self.spool_maximum,
        )?;
        self.open_prepared(prepared)
    }

    /// Explicitly spools input and opens a password-capable ZIP/7z session.
    ///
    /// This does not change [`Self::open`]: ordinary readers remain true
    /// streaming readers and never spool implicitly. A supplied password is
    /// rejected for formats other than seek-native ZIP and 7z.
    pub fn prepare_with_password(
        self,
        input: impl Read,
        password: SecretBytes,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let prepared = PreparedArchive::spool_with_limits(
            input,
            self.spool_memory_threshold,
            self.spool_maximum,
        )?;
        self.open_prepared_with_password(prepared, password)
    }

    /// Explicitly spools input and opens a session for one sequential format.
    ///
    /// Signatureless formats such as [`FormatId::Raw`] require this path.
    ///
    /// # Errors
    ///
    /// Returns an error if spooling fails or the requested identifier is not a
    /// readable sequential format in this engine's provider set.
    pub fn prepare_with_format(
        self,
        input: impl Read,
        format: FormatId,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let prepared = PreparedArchive::spool_with_limits(
            input,
            self.spool_memory_threshold,
            self.spool_maximum,
        )?;
        self.open_prepared_with_format(prepared, format)
    }

    /// Opens an inspect/plan/apply session over a previously prepared snapshot.
    pub fn open_prepared(
        self,
        prepared: PreparedArchive,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let reader = SessionReader::open(prepared.snapshot, self.limits, self.providers, None)?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest: prepared.digest,
            limits: self.limits,
            reader: Some(reader),
            format_hint: None,
            password: None,
            applied: false,
        })
    }

    /// Opens a prepared snapshot as a password-capable ZIP/7z session.
    ///
    /// The secret remains in zeroizing storage for the session lifetime so
    /// [`ArchiveSession::rewind`] can reconstruct the authenticated reader.
    /// Other formats reject the password instead of ignoring it.
    pub fn open_prepared_with_password(
        self,
        prepared: PreparedArchive,
        password: SecretBytes,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let reader = SessionReader::open(
            prepared.snapshot,
            self.limits,
            self.providers,
            Some(&password),
        )?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest: prepared.digest,
            limits: self.limits,
            reader: Some(reader),
            format_hint: None,
            password: Some(password),
            applied: false,
        })
    }

    /// Opens a prepared snapshot with an explicit sequential format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested identifier is not a readable
    /// sequential format in this engine's provider set.
    pub fn open_prepared_with_format(
        self,
        prepared: PreparedArchive,
        format: FormatId,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let reader = SessionReader::open_with_format(
            prepared.snapshot,
            self.limits,
            self.providers,
            format,
        )?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest: prepared.digest,
            limits: self.limits,
            reader: Some(reader),
            format_hint: Some(format),
            password: None,
            applied: false,
        })
    }
}

impl Default for ArchiveEngine<BuiltinFormatProviders, BuiltinCodecProviders> {
    fn default() -> Self {
        Self::new()
    }
}
/// High-level archive creation choices.
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    format: FormatId,
    filter: Option<FilterId>,
    limits: Option<Limits>,
}

impl CreateOptions {
    /// Creates uncompressed tar with the engine's limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            format: FormatId::Tar,
            filter: None,
            limits: None,
        }
    }

    /// Selects the archive container.
    #[must_use]
    pub const fn with_format(mut self, format: FormatId) -> Self {
        self.format = format;
        self
    }

    /// Selects an outer compression filter.
    #[must_use]
    pub const fn with_filter(mut self, filter: Option<FilterId>) -> Self {
        self.filter = filter;
        self
    }

    /// Overrides the engine limits for this writer.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Selected format.
    #[must_use]
    pub const fn format(self) -> FormatId {
        self.format
    }

    /// Selected outer filter.
    #[must_use]
    pub const fn filter(self) -> Option<FilterId> {
        self.filter
    }

    /// Explicit writer limits, or `None` to inherit the engine limits.
    #[must_use]
    pub const fn limits(self) -> Option<Limits> {
        self.limits
    }
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned metadata descriptor used by inspections and plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDescriptor {
    metadata: EntryMetadata,
}

impl EntryDescriptor {
    /// Full typed and extension-preserving entry metadata.
    #[must_use]
    pub const fn metadata(&self) -> &EntryMetadata {
        &self.metadata
    }
}

/// Bounded collected inspection of one immutable input.
#[derive(Debug)]
pub struct ArchiveInspection {
    digest: InputDigest,
    format: FormatId,
    archive_metadata: Option<ArchiveMetadata>,
    entries: Vec<EntryDescriptor>,
}

impl ArchiveInspection {
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Archive-level metadata, when present.
    #[must_use]
    pub const fn archive_metadata(&self) -> Option<&ArchiveMetadata> {
        self.archive_metadata.as_ref()
    }

    /// Entries in archive order.
    #[must_use]
    pub fn entries(&self) -> &[EntryDescriptor] {
        &self.entries
    }
}

/// Planned handling for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanDisposition {
    /// Apply through the capability filesystem adapter.
    Materialize,
    /// Do not materialize this structural entry.
    Skip,
    /// Policy or capability rejects this entry.
    Reject(RejectionReason),
}

/// One entry in an extraction plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEntry {
    descriptor: EntryDescriptor,
    disposition: PlanDisposition,
    destination: Option<DestinationKey>,
    link_target: Option<DestinationKey>,
}

impl PlannedEntry {
    /// Entry descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &EntryDescriptor {
        &self.descriptor
    }

    /// Planned handling.
    #[must_use]
    pub const fn disposition(&self) -> PlanDisposition {
        self.disposition
    }

    pub(crate) const fn destination(&self) -> Option<&DestinationKey> {
        self.destination.as_ref()
    }

    pub(crate) const fn link_target(&self) -> Option<&DestinationKey> {
        self.link_target.as_ref()
    }
}

/// Non-serializable plan tied to one open session and encoded input digest.
#[derive(Debug)]
pub struct ExtractionPlan {
    session_id: u64,
    digest: InputDigest,
    format: FormatId,
    policy: Policy,
    entries: Vec<PlannedEntry>,
}

impl ExtractionPlan {
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Planned entries in archive order.
    #[must_use]
    pub fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
}

/// Result of applying a session-bound plan.
#[derive(Debug)]
pub struct ApplyReport {
    digest: InputDigest,
    format: FormatId,
    extraction: ExtractionReport,
    findings: Vec<FilesystemFinding>,
}

impl ApplyReport {
    /// Applied encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Applied archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Per-entry materialization and rejection results.
    #[must_use]
    pub const fn extraction(&self) -> &ExtractionReport {
        &self.extraction
    }

    /// Typed filesystem capability, refusal, partial-application, and OS-error findings.
    #[must_use]
    pub fn filesystem_findings(&self) -> &[FilesystemFinding] {
        &self.findings
    }

    /// Whether any requested filesystem operation was not completely applied.
    #[must_use]
    pub fn has_filesystem_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.kind() != crate::filesystem::FilesystemFindingKind::Applied)
    }

    /// Consumes this report and returns the low-level extraction report.
    ///
    /// Use [`Self::into_parts`] when filesystem fidelity evidence is also needed.
    #[must_use]
    pub fn into_extraction(self) -> ExtractionReport {
        self.extraction
    }

    /// Consumes the report into materialization outcomes and filesystem findings.
    #[must_use]
    pub fn into_parts(self) -> (ExtractionReport, Vec<FilesystemFinding>) {
        (self.extraction, self.findings)
    }
}

enum SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    Sequential(Box<ArchiveReader<SpoolReader, F, C>>),
    Seek {
        reader: Box<SeekArchiveReader<SpoolReader>>,
        providers: ProviderSet<F, C>,
    },
}

impl<F, C> fmt::Debug for SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sequential(_) => "SessionReader::Sequential(..)",
            Self::Seek { .. } => "SessionReader::Seek(..)",
        })
    }
}

impl<F, C> SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn open_with_format(
        snapshot: SpoolReader,
        limits: Limits,
        providers: ProviderSet<F, C>,
        format: FormatId,
    ) -> Result<Self, StreamError> {
        let reader = ArchiveReader::with_providers_and_format(snapshot, format, limits, providers)
            .map_err(StreamError::archive)?;
        Ok(Self::Sequential(Box::new(reader)))
    }

    fn open(
        mut snapshot: SpoolReader,
        limits: Limits,
        providers: ProviderSet<F, C>,
        password: Option<&SecretBytes>,
    ) -> Result<Self, StreamError> {
        let mut prefix = vec![0; FORMAT_PROBE_BYTES];
        let mut read = 0;
        while read < prefix.len() {
            let count = snapshot
                .read(&mut prefix[read..])
                .map_err(StreamError::io)?;
            if count == 0 {
                break;
            }
            read += count;
        }
        snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let probed = FormatId::probe(&prefix[..read]);
        if password.is_some()
            && !matches!(
                probed,
                ProbeResult::Match(FormatId::Zip | FormatId::SevenZip)
            )
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_context("password supplied for an archive that is not ZIP or 7z"),
            ));
        }
        let seek_native = match probed {
            ProbeResult::Match(format) => matches!(
                providers.format_capability(format),
                ProviderCapability::Available(capability)
                    if capability.requires_seek(libarchive_oxide_core::Direction::Read)
            ),
            _ => false,
        };
        if seek_native {
            let reader = match password {
                Some(password) => {
                    SeekArchiveReader::with_limits_and_password(snapshot, limits, password.clone())?
                },
                None => SeekArchiveReader::with_limits(snapshot, limits)?,
            };
            Ok(Self::Seek {
                reader: Box::new(reader),
                providers,
            })
        } else {
            Ok(Self::Sequential(Box::new(ArchiveReader::with_providers(
                snapshot, limits, providers,
            ))))
        }
    }

    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match self {
            Self::Sequential(reader) => reader.next_event(),
            Self::Seek { reader, .. } => reader.next_event(),
        }
    }

    fn format(&self) -> Option<FormatId> {
        match self {
            Self::Sequential(reader) => reader.format(),
            Self::Seek { reader, .. } => Some(reader.format()),
        }
    }

    fn into_parts(self) -> Result<(SpoolReader, ProviderSet<F, C>), StreamError> {
        match self {
            Self::Sequential(reader) => (*reader).into_parts().map_err(StreamError::archive),
            Self::Seek { reader, providers } => (*reader)
                .into_inner()
                .map(|reader| (reader, providers))
                .map_err(StreamError::archive),
        }
    }
}
/// Open session over an immutable encoded input snapshot.
pub struct ArchiveSession<F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    id: u64,
    digest: InputDigest,
    limits: Limits,
    reader: Option<SessionReader<F, C>>,
    format_hint: Option<FormatId>,
    password: Option<SecretBytes>,
    applied: bool,
}

impl<F, C> fmt::Debug for ArchiveSession<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchiveSession")
            .field("id", &self.id)
            .field("digest", &self.digest)
            .field("limits", &self.limits)
            .field("reader", &self.reader)
            .field("format_hint", &self.format_hint)
            .field("password", &self.password)
            .field("applied", &self.applied)
            .finish()
    }
}

impl<F, C> ArchiveSession<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Resource budgets used by this session.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Detected format once enough events have been read.
    #[must_use]
    pub fn format(&self) -> Option<FormatId> {
        self.reader.as_ref().and_then(SessionReader::format)
    }

    /// Rewinds to a fresh event stream over the same immutable snapshot.
    pub fn rewind(&mut self) -> Result<(), StreamError> {
        let reader = self.reader.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session reader is unavailable"),
            )
        })?;
        let (mut snapshot, providers) = reader.into_parts()?;
        snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        self.reader = Some(match self.format_hint {
            Some(format) => {
                SessionReader::open_with_format(snapshot, self.limits, providers, format)?
            },
            None => SessionReader::open(snapshot, self.limits, providers, self.password.as_ref())?,
        });
        Ok(())
    }

    /// Produces one bounded event. Data is valid until the next mutable call.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.reader
            .as_mut()
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("archive session reader is unavailable"),
                )
            })?
            .next_event()
    }

    /// Collects metadata within the configured entry and metadata budgets.
    pub fn inspect(&mut self) -> Result<ArchiveInspection, StreamError> {
        self.rewind()?;
        let mut archive_metadata = None;
        let mut entries = Vec::new();
        let mut metadata_bytes = 0_usize;
        loop {
            match self.next_event()? {
                ReaderEvent::ArchiveMetadata(metadata) => {
                    metadata_bytes = checked_metadata_total(
                        metadata_bytes,
                        archive_metadata_cost(&metadata),
                        self.limits,
                    )?;
                    archive_metadata = Some(metadata);
                },
                ReaderEvent::Entry(metadata) => {
                    metadata_bytes = checked_metadata_total(
                        metadata_bytes,
                        entry_metadata_cost(&metadata),
                        self.limits,
                    )?;
                    entries.push(EntryDescriptor { metadata });
                },
                ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
                ReaderEvent::Done => {
                    let format = self.format().ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_context("archive completed without a detected format"),
                        )
                    })?;
                    return Ok(ArchiveInspection {
                        digest: self.digest,
                        format,
                        archive_metadata,
                        entries,
                    });
                },
            }
        }
    }

    /// Builds a non-serializable extraction plan for this session.
    pub fn plan(&mut self, policy: Policy) -> Result<ExtractionPlan, StreamError> {
        let inspection = self.inspect()?;
        let mut claimed = DestinationClaims::default();
        let mut committed = BTreeSet::new();
        let entries = inspection
            .entries
            .into_iter()
            .map(|descriptor| {
                let (disposition, destination, link_target) =
                    plan_entry(descriptor.metadata(), policy, &mut claimed, &mut committed);
                PlannedEntry {
                    descriptor,
                    disposition,
                    destination,
                    link_target,
                }
            })
            .collect();
        Ok(ExtractionPlan {
            session_id: self.id,
            digest: self.digest,
            format: inspection.format,
            policy,
            entries,
        })
    }

    /// Applies a plan exactly once through the built-in `cap-std` adapter.
    ///
    /// This source-compatible shortcut delegates to [`Self::apply_with_adapter`].
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply(&mut self, plan: ExtractionPlan, root: Dir) -> Result<ApplyReport, StreamError> {
        let mut adapter = CapStdFilesystemAdapter::new(root);
        self.apply_with_adapter(plan, &mut adapter)
    }

    /// Applies a plan exactly once through a capability-reporting adapter.
    ///
    /// Session identity and replay checks run before the adapter is touched.
    /// The shared driver retains path policy, resource limits, hardlink order,
    /// and archive parser state; the adapter only receives normalized relative
    /// operations.
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply_with_adapter<A: FilesystemAdapter>(
        &mut self,
        plan: ExtractionPlan,
        adapter: &mut A,
    ) -> Result<ApplyReport, StreamError> {
        let ExtractionPlan {
            session_id,
            digest,
            format,
            policy,
            entries,
        } = plan;
        if session_id != self.id || digest != self.digest {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("extraction plan belongs to a different archive session"),
            ));
        }
        if self.applied {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session has already applied a plan"),
            ));
        }
        // `ExtractionPlan` has no public constructor or mutable fields. Its
        // session identity is checked above, so these destinations are the
        // authoritative result of the one whole-archive preflight.
        self.applied = true;
        self.rewind()?;
        let applied = match self.reader.as_mut().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session reader is unavailable"),
            )
        })? {
            SessionReader::Sequential(reader) => {
                apply_registered_plan(reader, adapter, policy, self.limits, &entries)?
            },
            SessionReader::Seek { reader, .. } => {
                apply_seek_plan(reader, adapter, policy, self.limits, &entries)?
            },
        };
        Ok(ApplyReport {
            digest: self.digest,
            format,
            extraction: applied.extraction,
            findings: applied.findings,
        })
    }
}

fn digest_snapshot(snapshot: &mut SpoolReader) -> Result<InputDigest, StreamError> {
    snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; DIGEST_BUFFER_BYTES];
    loop {
        let read = snapshot.read(&mut buffer).map_err(StreamError::io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    Ok(InputDigest(hasher.finalize().into()))
}

fn checked_metadata_total(
    current: usize,
    added: usize,
    limits: Limits,
) -> Result<usize, StreamError> {
    let total = current.checked_add(added).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_context("collected inspection metadata size overflowed"),
        )
    })?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| total > maximum)
    {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_context("collected inspection exceeds metadata budget"),
        ));
    }
    Ok(total)
}

fn entry_metadata_cost(metadata: &EntryMetadata) -> usize {
    let mut bytes = size_of::<EntryMetadata>()
        .saturating_add(metadata.path().as_bytes().len())
        .saturating_add(
            metadata
                .link_target()
                .map_or(0, |target| target.as_bytes().len()),
        )
        .saturating_add(metadata.owner().user.as_ref().map_or(0, Vec::len))
        .saturating_add(metadata.owner().group.as_ref().map_or(0, Vec::len))
        .saturating_add(metadata.comment().map_or(0, <[u8]>::len));
    for (name, value) in metadata.xattrs() {
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
    }
    for acl in metadata.acl() {
        bytes = bytes.saturating_add(acl.len());
    }
    bytes = bytes.saturating_add(
        metadata
            .sparse_extents()
            .len()
            .saturating_mul(size_of::<libarchive_oxide_core::SparseExtent>()),
    );
    for extension in metadata.extensions() {
        bytes = bytes
            .saturating_add(extension.namespace().len())
            .saturating_add(extension.key().len())
            .saturating_add(extension.value().len());
    }
    bytes
}

fn archive_metadata_cost(metadata: &ArchiveMetadata) -> usize {
    let mut bytes = size_of::<ArchiveMetadata>()
        .saturating_add(
            metadata
                .volume_name()
                .map_or(0, |name| name.as_bytes().len()),
        )
        .saturating_add(metadata.comment().map_or(0, <[u8]>::len));
    for extension in metadata.extensions() {
        bytes = bytes
            .saturating_add(extension.namespace().len())
            .saturating_add(extension.key().len())
            .saturating_add(extension.value().len());
    }
    bytes
}

fn plan_entry(
    metadata: &EntryMetadata,
    policy: Policy,
    claimed: &mut DestinationClaims,
    committed: &mut BTreeSet<DestinationKey>,
) -> (
    PlanDisposition,
    Option<DestinationKey>,
    Option<DestinationKey>,
) {
    if metadata.extensions().iter().any(|extension| {
        extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
    }) {
        return (
            PlanDisposition::Reject(RejectionReason::ExternalReference),
            None,
            None,
        );
    }
    if metadata.kind() == EntryKind::Dir && matches!(metadata.path().as_bytes(), b"." | b"./") {
        return (PlanDisposition::Skip, None, None);
    }
    let Some(destination) = DestinationKey::from_archive_path(metadata.path()) else {
        return (
            PlanDisposition::Reject(RejectionReason::UnsafePath),
            None,
            None,
        );
    };
    if !claimed.claim(&destination, metadata.kind()) {
        return (
            PlanDisposition::Reject(RejectionReason::DestinationCollision),
            Some(destination),
            None,
        );
    }
    let (disposition, link_target) = match metadata.kind() {
        EntryKind::File => {
            committed.insert(destination.clone());
            (PlanDisposition::Materialize, None)
        },
        EntryKind::Dir => (PlanDisposition::Materialize, None),
        EntryKind::Symlink if policy.symlinks() => {
            if let Some(target) = metadata
                .link_target()
                .and_then(DestinationKey::from_archive_path)
            {
                (PlanDisposition::Materialize, Some(target))
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    None,
                )
            }
        },
        EntryKind::Hardlink if policy.hardlinks() => {
            let Some(target) = metadata
                .link_target()
                .and_then(DestinationKey::from_archive_path)
            else {
                return (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    Some(destination),
                    None,
                );
            };
            if let Some(committed_target) = committed.get(&target).cloned() {
                committed.insert(destination.clone());
                (PlanDisposition::Materialize, Some(committed_target))
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    None,
                )
            }
        },
        EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
            if policy.special_files() =>
        {
            if cfg!(any(target_os = "linux", target_os = "android")) {
                (PlanDisposition::Materialize, None)
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsupportedRestore),
                    None,
                )
            }
        },
        _ => (PlanDisposition::Reject(RejectionReason::EntryKind), None),
    };
    (disposition, Some(destination), link_target)
}
