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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::fs::Dir;
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits,
    ProbeResult,
};
use sha2::{Digest, Sha256};

use crate::extractor::{ExtractionPolicy, ExtractionReport, RejectionReason};
use crate::path::sanitize_archive_path;
use crate::spool::{DEFAULT_MAX_BYTES, DEFAULT_MEMORY_THRESHOLD};
use crate::{
    ArchiveReader, ArchiveWriter, Extractor, ReaderEvent, SeekArchiveReader, SeekArchiveWriter,
    SpoolReader, StreamError,
};

const FORMAT_PROBE_BYTES: usize = 16 * 2048 + 6;
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

/// Built-in provider availability for the engine's current feature set.
///
/// External provider registration is intentionally separate from this first
/// high-level engine slice. This type gives callers one capability query
/// surface without exposing the private built-in dispatch enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSet {
    builtins: bool,
}

impl ProviderSet {
    /// Built-in providers compiled into this crate.
    #[must_use]
    pub const fn builtins() -> Self {
        Self { builtins: true }
    }

    /// Whether a built-in format provider is compiled in.
    #[must_use]
    pub const fn supports_format(self, format: FormatId) -> bool {
        if !self.builtins {
            return false;
        }
        if matches!(
            format,
            FormatId::Tar | FormatId::Cpio | FormatId::Ar | FormatId::Zip | FormatId::Iso9660
        ) {
            return true;
        }
        matches!(format, FormatId::SevenZip) && cfg!(feature = "sevenz")
    }

    /// Whether a built-in outer-filter provider is compiled in.
    #[must_use]
    pub const fn supports_filter(self, filter: FilterId) -> bool {
        if !self.builtins {
            return false;
        }
        if matches!(filter, FilterId::Gzip) {
            return true;
        }
        if matches!(filter, FilterId::Bzip2) {
            return cfg!(feature = "bzip2");
        }
        if matches!(filter, FilterId::Zstd) {
            return cfg!(feature = "zstd");
        }
        if matches!(filter, FilterId::Xz) {
            return cfg!(feature = "xz");
        }
        matches!(filter, FilterId::Lz4) && cfg!(feature = "lz4")
    }
}

impl Default for ProviderSet {
    fn default() -> Self {
        Self::builtins()
    }
}

/// High-level archive engine configuration.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveEngine {
    limits: Limits,
    spool_memory_threshold: usize,
    spool_maximum: u64,
    providers: ProviderSet,
}

impl ArchiveEngine {
    /// Safe finite defaults with the built-in providers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
            spool_memory_threshold: DEFAULT_MEMORY_THRESHOLD,
            spool_maximum: DEFAULT_MAX_BYTES,
            providers: ProviderSet::builtins(),
        }
    }

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

    /// Resource budgets used for new sessions.
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Providers available to new sessions.
    #[must_use]
    pub const fn providers(self) -> ProviderSet {
        self.providers
    }

    /// Opens an immutable, bounded snapshot session.
    ///
    /// The snapshot remains in memory through the configured threshold and
    /// then moves to an automatically deleted temporary file.
    pub fn open(self, input: impl Read) -> Result<ArchiveSession, StreamError> {
        let mut snapshot = SpoolReader::from_reader_with_limits(
            input,
            self.spool_memory_threshold,
            self.spool_maximum,
        )?;
        let digest = digest_snapshot(&mut snapshot)?;
        let reader = SessionReader::open(snapshot, self.limits)?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest,
            limits: self.limits,
            reader: Some(reader),
            applied: false,
        })
    }

    /// Creates a sequential writer from high-level options.
    pub fn create<W: Write>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<ArchiveWriter<W>, StreamError> {
        let limits = options.limits.unwrap_or(self.limits);
        ArchiveWriter::with_filter(output, options.format, options.filter, limits)
            .map_err(StreamError::archive)
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

impl Default for ArchiveEngine {
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
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level extraction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Policy {
    overwrite: bool,
    symlinks: bool,
    hardlinks: bool,
    special_files: bool,
}

impl Policy {
    /// Conservative policy.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            overwrite: false,
            symlinks: false,
            hardlinks: false,
            special_files: false,
        }
    }

    /// Enables replacing existing regular files.
    #[must_use]
    pub const fn allow_overwrite(mut self, allow: bool) -> Self {
        self.overwrite = allow;
        self
    }

    /// Enables symbolic-link restoration.
    #[must_use]
    pub const fn allow_symlinks(mut self, allow: bool) -> Self {
        self.symlinks = allow;
        self
    }

    /// Enables links to files created earlier in the same session.
    #[must_use]
    pub const fn allow_hardlinks(mut self, allow: bool) -> Self {
        self.hardlinks = allow;
        self
    }

    /// Enables platform-supported special-file restoration.
    #[must_use]
    pub const fn allow_special_files(mut self, allow: bool) -> Self {
        self.special_files = allow;
        self
    }

    const fn extraction_policy(self) -> ExtractionPolicy {
        ExtractionPolicy::safe()
            .allow_overwrite(self.overwrite)
            .allow_symlinks(self.symlinks)
            .allow_hardlinks(self.hardlinks)
            .allow_special_files(self.special_files)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::safe()
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

    /// Consumes this report and returns the low-level extraction report.
    #[must_use]
    pub fn into_extraction(self) -> ExtractionReport {
        self.extraction
    }
}

#[derive(Debug)]
enum SessionReader {
    Sequential(Box<ArchiveReader<SpoolReader>>),
    Seek(Box<SeekArchiveReader<SpoolReader>>),
}

impl SessionReader {
    fn open(mut snapshot: SpoolReader, limits: Limits) -> Result<Self, StreamError> {
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
        let seek_native = matches!(
            FormatId::probe(&prefix[..read]),
            ProbeResult::Match(FormatId::Zip | FormatId::SevenZip | FormatId::Iso9660)
        );
        if seek_native {
            Ok(Self::Seek(Box::new(SeekArchiveReader::with_limits(
                snapshot, limits,
            )?)))
        } else {
            Ok(Self::Sequential(Box::new(ArchiveReader::with_limits(
                snapshot, limits,
            ))))
        }
    }

    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match self {
            Self::Sequential(reader) => reader.next_event(),
            Self::Seek(reader) => reader.next_event(),
        }
    }

    fn format(&self) -> Option<FormatId> {
        match self {
            Self::Sequential(reader) => reader.format(),
            Self::Seek(reader) => Some(reader.format()),
        }
    }

    fn into_inner(self) -> SpoolReader {
        match self {
            Self::Sequential(reader) => (*reader).into_inner(),
            Self::Seek(reader) => (*reader).into_inner(),
        }
    }
}

/// Open session over an immutable encoded input snapshot.
#[derive(Debug)]
pub struct ArchiveSession {
    id: u64,
    digest: InputDigest,
    limits: Limits,
    reader: Option<SessionReader>,
    applied: bool,
}

impl ArchiveSession {
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
        let mut snapshot = reader.into_inner();
        snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        self.reader = Some(SessionReader::open(snapshot, self.limits)?);
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
        let mut committed = BTreeSet::new();
        let entries = inspection
            .entries
            .into_iter()
            .map(|descriptor| {
                let disposition = plan_entry(descriptor.metadata(), policy, &mut committed);
                PlannedEntry {
                    descriptor,
                    disposition,
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

    /// Applies a plan exactly once through a directory capability.
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply(&mut self, plan: ExtractionPlan, root: Dir) -> Result<ApplyReport, StreamError> {
        let ExtractionPlan {
            session_id,
            digest,
            format,
            policy,
            entries: _,
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
        self.applied = true;
        self.rewind()?;
        let mut extractor =
            Extractor::with_policy_and_limits(root, policy.extraction_policy(), self.limits);
        let extraction = match self.reader.as_mut().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session reader is unavailable"),
            )
        })? {
            SessionReader::Sequential(reader) => extractor.extract(reader)?,
            SessionReader::Seek(reader) => extractor.extract_seek_matching(reader, |_| true)?,
        };
        Ok(ApplyReport {
            digest: self.digest,
            format,
            extraction,
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
    committed: &mut BTreeSet<PathBuf>,
) -> PlanDisposition {
    if metadata.extensions().iter().any(|extension| {
        extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
    }) {
        return PlanDisposition::Reject(RejectionReason::ExternalReference);
    }
    if metadata.kind() == EntryKind::Dir && matches!(metadata.path().as_bytes(), b"." | b"./") {
        return PlanDisposition::Skip;
    }
    let Some(path) = sanitize_archive_path(metadata.path()) else {
        return PlanDisposition::Reject(RejectionReason::UnsafePath);
    };
    match metadata.kind() {
        EntryKind::File => {
            committed.insert(path);
            PlanDisposition::Materialize
        },
        EntryKind::Dir => PlanDisposition::Materialize,
        EntryKind::Symlink if policy.symlinks => {
            if metadata
                .link_target()
                .and_then(sanitize_archive_path)
                .is_some()
            {
                PlanDisposition::Materialize
            } else {
                PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget)
            }
        },
        EntryKind::Hardlink if policy.hardlinks => {
            let Some(target) = metadata.link_target().and_then(sanitize_archive_path) else {
                return PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget);
            };
            if committed.contains(&target) {
                committed.insert(path);
                PlanDisposition::Materialize
            } else {
                PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget)
            }
        },
        EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
            if policy.special_files =>
        {
            if cfg!(any(target_os = "linux", target_os = "android")) {
                PlanDisposition::Materialize
            } else {
                PlanDisposition::Reject(RejectionReason::UnsupportedRestore)
            }
        },
        _ => PlanDisposition::Reject(RejectionReason::EntryKind),
    }
}
