// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RPM package validator.
//!
//! An RPM (`.rpm`) is not an `ar`, `tar`, or `zip` container: it is a bespoke
//! binary stream. It begins with a fixed 96-byte *lead*, followed by a
//! *signature header* and a *main header* (both using the same RPM header
//! structure), and finally a *payload* that is a cpio archive wrapped in one
//! outer compression filter named by the `PAYLOADCOMPRESSOR` tag.
//!
//! [`RpmValidator`] inspects an untrusted package without ever extracting it or
//! buffering the whole payload. The lead and both headers are parsed by a
//! bounded, hand-written parser: header index and data-store sizes are checked
//! against [`Limits::metadata_bytes`] *before* any bytes are read, so a header
//! bomb is refused rather than allocated. The payload is then streamed, chunk by
//! chunk, through a single bounded [`Pipeline`] that decodes only enough to
//! classify the outer filter and validate the nested cpio structure.
//! Decompression is bounded by the configured [`Limits`], so a decompression
//! bomb is refused rather than expanded.
//!
//! The result separates two questions: could the RPM container be parsed at all
//! ([`SupportStatus::container_readable`]) and did the package satisfy the RPM
//! profile ([`SupportStatus::profile_valid`]). Every deviation is reported as a
//! typed [`PackageFinding`].

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, EntryMetadata, ErrorKind, Limits, ProbeResult};

use super::finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
use crate::path::sanitize_archive_path;
use crate::provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, ProviderCapability, ProviderSet,
    StaticCodecProviders,
};
use crate::stream::{Pipeline, PipelineEvent};

/// Profile name reported on every RPM finding.
const PROFILE: &str = "rpm";

/// Fixed length of the RPM lead.
const LEAD_LEN: usize = 96;

/// Lead magic (`ED AB EE DB`).
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];

/// RPM header magic (`8E AD E8`).
const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];

/// Only RPM header structure version this validator accepts.
const HEADER_VERSION: u8 = 0x01;

/// Bytes of the fixed header intro: magic(3) + version(1) + reserved(4) +
/// nindex(4) + hsize(4).
const HEADER_INTRO_LEN: usize = 16;

/// Bytes of one 16-byte header index entry: tag + type + offset + count.
const INDEX_ENTRY_LEN: usize = 16;

/// RPM header data type code for a NUL-terminated string.
const TYPE_STRING: u32 = 6;

/// Main-header tag `PAYLOADFORMAT` (expected value `cpio`).
const TAG_PAYLOADFORMAT: u32 = 1124;

/// Main-header tag `PAYLOADCOMPRESSOR` (for example `gzip` or `xz`).
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;

/// Bytes buffered from the payload head before its outer filter is classified.
///
/// Six bytes cover the longest supported filter signature (xz).
const PROBE_LEN: usize = 6;

/// Chunk size used to stream the payload into the bounded pipeline.
const PAYLOAD_CHUNK: usize = 64 * 1024;

/// Reads a `u32` in big-endian order from the first four bytes of `bytes`.
///
/// The caller guarantees `bytes` is at least four bytes long.
fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Extracts a NUL-terminated string starting at `offset` within a data store.
///
/// Returns `None` when the offset is out of range or the string is unterminated.
fn extract_string(store: &[u8], offset: u32) -> Option<Vec<u8>> {
    let start = usize::try_from(offset).ok()?;
    let rest = store.get(start..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    Some(rest[..end].to_vec())
}

/// The filter a `PAYLOADCOMPRESSOR` tag declares, if it is one this build names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclaredCompressor {
    /// The tag named a known compressor; `None` is the explicit `none` case.
    Known(Option<FilterId>),
    /// The tag was absent or named a compressor with no registered filter.
    Unknown,
}

/// Maps a `PAYLOADCOMPRESSOR` tag value to the filter it declares.
fn declared_filter(tag: Option<&[u8]>) -> DeclaredCompressor {
    let Some(tag) = tag else {
        return DeclaredCompressor::Unknown;
    };
    match tag {
        b"gzip" => DeclaredCompressor::Known(Some(FilterId::Gzip)),
        b"xz" => DeclaredCompressor::Known(Some(FilterId::Xz)),
        b"zstd" => DeclaredCompressor::Known(Some(FilterId::Zstd)),
        b"bzip2" => DeclaredCompressor::Known(Some(FilterId::Bzip2)),
        b"lz4" => DeclaredCompressor::Known(Some(FilterId::Lz4)),
        b"none" => DeclaredCompressor::Known(None),
        _ => DeclaredCompressor::Unknown,
    }
}

/// Reads exactly `len` bytes, returning `Ok(None)` when the source ends early.
fn read_exact_bounded<R: Read>(reader: &mut R, len: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(None),
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
    Ok(Some(buffer))
}

/// The two payload tags this validator extracts from the main header.
#[derive(Debug, Default, Clone)]
struct MainTags {
    payload_format: Option<Vec<u8>>,
    payload_compressor: Option<Vec<u8>>,
}

/// A bounded, per-package validator for the RPM profile.
///
/// The type parameter selects the outer-codec provider chain used to decode the
/// payload; the default is the crate's built-in codecs. Replacing it with
/// [`RpmValidator::with_codec_providers`] lets a caller detect a payload
/// compressed with a method that a given build cannot decode, which is reported
/// as a [`PackageFindingCode::UnsupportedCompression`] finding.
#[derive(Debug, Clone, Copy)]
pub struct RpmValidator<C = BuiltinCodecProviders>
where
    C: StaticCodecProviders,
{
    limits: Limits,
    providers: ProviderSet<BuiltinFormatProviders, C>,
}

impl RpmValidator<BuiltinCodecProviders> {
    /// Creates a validator with the safe finite limits and built-in codecs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
            providers: ProviderSet::builtins(),
        }
    }
}

impl Default for RpmValidator<BuiltinCodecProviders> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> RpmValidator<C>
where
    C: StaticCodecProviders + Copy,
{
    /// Replaces the resource budgets bounding header sizes and the payload decode.
    ///
    /// [`Limits::metadata_bytes`] bounds each header's declared index and data
    /// store (the header-bomb budget); [`Limits::with_decoded_total`] bounds the
    /// decompressed payload (the decompression-bomb budget).
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the outer-codec provider chain used for the payload.
    #[must_use]
    pub fn with_codec_providers<D>(
        self,
        providers: ProviderSet<BuiltinFormatProviders, D>,
    ) -> RpmValidator<D>
    where
        D: StaticCodecProviders,
    {
        RpmValidator {
            limits: self.limits,
            providers,
        }
    }

    /// Resource budgets bounding header sizes and the payload decode.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Validates an untrusted `.rpm` byte stream without extracting it.
    ///
    /// The package is never materialized and the payload is never whole-buffered.
    /// The returned [`RpmValidation`] separates container readability from
    /// profile conformance and lists every typed finding.
    pub fn validate<R: Read>(&self, mut reader: R) -> RpmValidation {
        let mut state = RpmState::new();
        let Ok(tags) = self.parse_containers(&mut reader, &mut state) else {
            return state.finalize();
        };

        let format_ok = tags.payload_format.as_deref() == Some(b"cpio");
        if !format_ok {
            state.findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::PayloadFormatMismatch,
                match &tags.payload_format {
                    Some(other) => format!(
                        "PAYLOADFORMAT is {:?}, expected cpio",
                        String::from_utf8_lossy(other)
                    ),
                    None => "main header has no PAYLOADFORMAT tag".to_string(),
                },
            ));
        }
        state.format_ok = format_ok;
        state
            .payload_compressor
            .clone_from(&tags.payload_compressor);

        self.validate_payload(&mut reader, &tags, &mut state);
        state.finalize()
    }

    /// Parses the lead, signature header, and main header. On success the reader
    /// is positioned at the first payload byte; on failure findings are pushed
    /// and `container_readable` is cleared.
    fn parse_containers<R: Read>(
        &self,
        reader: &mut R,
        state: &mut RpmState,
    ) -> Result<MainTags, ()> {
        Self::read_lead(reader, state)?;
        // Signature header: consumed only for structure; padded to 8 bytes.
        self.read_header(reader, true, state)?;
        let main = self.read_header(reader, false, state)?;
        Ok(extract_main_tags(&main))
    }

    /// Reads and validates the fixed 96-byte lead.
    fn read_lead<R: Read>(reader: &mut R, state: &mut RpmState) -> Result<(), ()> {
        match read_exact_bounded(reader, LEAD_LEN) {
            Ok(Some(lead)) if lead[..4] == LEAD_MAGIC => Ok(()),
            Ok(Some(_)) => {
                state.fail(
                    PackageFindingCode::InvalidLead,
                    "RPM lead magic does not match ED AB EE DB",
                );
                Err(())
            },
            Ok(None) => {
                state.fail(
                    PackageFindingCode::InvalidLead,
                    "input ended before the 96-byte RPM lead",
                );
                Err(())
            },
            Err(error) => {
                state.fail(
                    PackageFindingCode::InvalidLead,
                    format!("cannot read RPM lead: {error}"),
                );
                Err(())
            },
        }
    }

    /// Reads one RPM header structure, returning its raw index and data store.
    ///
    /// When `is_signature` is set the trailing data store is padded to the next
    /// eight-byte boundary, matching the signature-header layout.
    fn read_header<R: Read>(
        &self,
        reader: &mut R,
        is_signature: bool,
        state: &mut RpmState,
    ) -> Result<HeaderSection, ()> {
        let intro = match read_exact_bounded(reader, HEADER_INTRO_LEN) {
            Ok(Some(intro)) => intro,
            Ok(None) => {
                state.fail(
                    PackageFindingCode::InvalidHeader,
                    "input ended before an RPM header intro",
                );
                return Err(());
            },
            Err(error) => {
                state.fail(
                    PackageFindingCode::InvalidHeader,
                    format!("cannot read RPM header intro: {error}"),
                );
                return Err(());
            },
        };
        if intro[..3] != HEADER_MAGIC || intro[3] != HEADER_VERSION {
            state.fail(
                PackageFindingCode::InvalidHeader,
                "RPM header magic or version is invalid",
            );
            return Err(());
        }

        let nindex = be_u32(&intro[8..12]);
        let hsize = be_u32(&intro[12..16]);
        let index_bytes = usize::try_from(nindex)
            .ok()
            .and_then(|count| count.checked_mul(INDEX_ENTRY_LEN));
        let store_bytes = usize::try_from(hsize).ok();
        let total = match (index_bytes, store_bytes) {
            (Some(index), Some(store)) => index.checked_add(store),
            _ => None,
        };
        let over_budget = match (total, self.limits.metadata_bytes()) {
            (None, _) => true,
            (Some(bytes), Some(cap)) => bytes > cap,
            (Some(_), None) => false,
        };
        if over_budget {
            state.fail(
                PackageFindingCode::HeaderTooLarge,
                "RPM header index and store exceed the metadata budget",
            );
            return Err(());
        }
        // Both sizes fit; the `unwrap`s below are proven safe by `over_budget`.
        let index_len = index_bytes.unwrap_or(0);
        let store_len = store_bytes.unwrap_or(0);

        let index = Self::read_header_bytes(reader, index_len, state)?;
        let store = Self::read_header_bytes(reader, store_len, state)?;
        if is_signature {
            let padding = (8 - (store_len % 8)) % 8;
            if padding > 0 {
                Self::read_header_bytes(reader, padding, state)?;
            }
        }
        Ok(HeaderSection { index, store })
    }

    /// Reads exactly `len` header bytes, reporting truncation as a finding.
    fn read_header_bytes<R: Read>(
        reader: &mut R,
        len: usize,
        state: &mut RpmState,
    ) -> Result<Vec<u8>, ()> {
        match read_exact_bounded(reader, len) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => {
                state.fail(
                    PackageFindingCode::InvalidHeader,
                    "input ended inside an RPM header section",
                );
                Err(())
            },
            Err(error) => {
                state.fail(
                    PackageFindingCode::InvalidHeader,
                    format!("cannot read RPM header section: {error}"),
                );
                Err(())
            },
        }
    }

    /// Streams the remaining payload bytes through one bounded pipeline.
    fn validate_payload<R: Read>(&self, reader: &mut R, tags: &MainTags, state: &mut RpmState) {
        let mut payload = Payload::new(self.limits, self.providers);
        let mut buffer = vec![0u8; PAYLOAD_CHUNK];
        loop {
            if payload.is_terminal() {
                break;
            }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => payload.feed(&buffer[..count], &mut state.findings),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                Err(error) => {
                    state.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::TruncatedMember,
                        format!("cannot read RPM payload: {error}"),
                    ));
                    break;
                },
            }
        }
        payload.finish(&mut state.findings);
        state.payload_filter = payload.filter;
        state.payload_ok = payload.done;

        // Cross-check the detected filter against the declared compressor tag.
        if let DeclaredCompressor::Known(expected) =
            declared_filter(tags.payload_compressor.as_deref())
        {
            if payload.decided && payload.filter != expected {
                state.findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::CompressorMismatch,
                    "detected payload filter disagrees with PAYLOADCOMPRESSOR",
                ));
            }
        }
    }
}

/// Parses the main-header index for the two payload tags.
fn extract_main_tags(section: &HeaderSection) -> MainTags {
    let mut tags = MainTags::default();
    let count = section.index.len() / INDEX_ENTRY_LEN;
    for entry in 0..count {
        let base = entry * INDEX_ENTRY_LEN;
        let record = &section.index[base..base + INDEX_ENTRY_LEN];
        let tag = be_u32(&record[0..4]);
        let kind = be_u32(&record[4..8]);
        let offset = be_u32(&record[8..12]);
        if kind != TYPE_STRING {
            continue;
        }
        if tag == TAG_PAYLOADFORMAT {
            tags.payload_format = extract_string(&section.store, offset);
        } else if tag == TAG_PAYLOADCOMPRESSOR {
            tags.payload_compressor = extract_string(&section.store, offset);
        }
    }
    tags
}

/// One parsed RPM header structure's raw index and data store.
struct HeaderSection {
    index: Vec<u8>,
    store: Vec<u8>,
}

/// Mutable accumulator threaded through a single validation.
struct RpmState {
    findings: Vec<PackageFinding>,
    container_readable: bool,
    format_ok: bool,
    payload_ok: bool,
    payload_filter: Option<FilterId>,
    payload_compressor: Option<Vec<u8>>,
}

impl RpmState {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            container_readable: true,
            format_ok: false,
            payload_ok: false,
            payload_filter: None,
            payload_compressor: None,
        }
    }

    /// Records a container-structure failure, clearing `container_readable`.
    fn fail(&mut self, code: PackageFindingCode, detail: impl Into<String>) {
        self.container_readable = false;
        self.findings
            .push(PackageFinding::new(PROFILE, None, code, detail));
    }

    fn finalize(self) -> RpmValidation {
        let blocking = self
            .findings
            .iter()
            .any(|finding| finding.severity() >= Severity::Warning);
        let profile_valid =
            self.container_readable && !blocking && self.format_ok && self.payload_ok;
        RpmValidation {
            status: SupportStatus::new(self.container_readable, profile_valid),
            findings: self.findings,
            payload_filter: self.payload_filter,
            payload_compressor: self.payload_compressor,
        }
    }
}

/// Streams the RPM payload (compressed cpio) through a bounded pipeline.
#[allow(clippy::struct_excessive_bools)]
struct Payload<C: StaticCodecProviders> {
    limits: Limits,
    providers: ProviderSet<BuiltinFormatProviders, C>,
    prefix: Vec<u8>,
    decided: bool,
    skip: bool,
    failed: bool,
    done: bool,
    finished: bool,
    filter: Option<FilterId>,
    pipeline: Option<Pipeline<BuiltinFormatProviders, C>>,
    seen_paths: BTreeSet<PathBuf>,
}

impl<C: StaticCodecProviders + Copy> Payload<C> {
    fn new(limits: Limits, providers: ProviderSet<BuiltinFormatProviders, C>) -> Self {
        Self {
            limits,
            providers,
            prefix: Vec::with_capacity(PROBE_LEN),
            decided: false,
            skip: false,
            failed: false,
            done: false,
            finished: false,
            filter: None,
            pipeline: None,
            seen_paths: BTreeSet::new(),
        }
    }

    fn is_terminal(&self) -> bool {
        self.skip || self.failed || self.done
    }

    fn feed(&mut self, mut chunk: &[u8], findings: &mut Vec<PackageFinding>) {
        if self.is_terminal() {
            return;
        }
        if !self.decided {
            let take = (PROBE_LEN - self.prefix.len()).min(chunk.len());
            self.prefix.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
            if self.prefix.len() < PROBE_LEN {
                return;
            }
            self.decide(findings);
            if self.is_terminal() {
                return;
            }
        }
        self.feed_pipeline(chunk, findings);
    }

    /// Classifies the outer filter, checks capability, and starts the pipeline.
    fn decide(&mut self, findings: &mut Vec<PackageFinding>) {
        self.decided = true;
        if let ProbeResult::Match(filter) = FilterId::probe(&self.prefix) {
            self.filter = Some(filter);
            if !matches!(
                self.providers.codec_capability(filter),
                ProviderCapability::Available(_)
            ) {
                findings.push(PackageFinding::unsupported_method(
                    PROFILE,
                    None,
                    "RPM payload uses a compression method this build cannot decode",
                ));
                self.skip = true;
                return;
            }
        }
        self.pipeline = Some(Pipeline::with_providers(self.limits, self.providers));
        let prefix = std::mem::take(&mut self.prefix);
        self.feed_pipeline(&prefix, findings);
    }

    fn feed_pipeline(&mut self, bytes: &[u8], findings: &mut Vec<PackageFinding>) {
        if self.is_terminal() {
            return;
        }
        let Some(mut pipeline) = self.pipeline.take() else {
            return;
        };
        let mut cursor = bytes;
        while !cursor.is_empty() && !self.failed && !self.done {
            match pipeline.feed(cursor) {
                Ok(0) => break,
                Ok(count) => {
                    cursor = &cursor[count..];
                    self.drive(&mut pipeline, findings);
                },
                Err(error) => {
                    self.record_error(&error, false, findings);
                    break;
                },
            }
        }
        if !self.failed && !self.done {
            self.pipeline = Some(pipeline);
        }
    }

    fn drive(
        &mut self,
        pipeline: &mut Pipeline<BuiltinFormatProviders, C>,
        findings: &mut Vec<PackageFinding>,
    ) {
        loop {
            match pipeline.poll_event() {
                Ok(PipelineEvent::NeedInput) => return,
                Ok(PipelineEvent::Entry(metadata)) => self.check_entry(&metadata, findings),
                Ok(PipelineEvent::Done) => {
                    self.done = true;
                    return;
                },
                Ok(
                    PipelineEvent::ArchiveMetadata(_)
                    | PipelineEvent::Data(_)
                    | PipelineEvent::EndEntry,
                ) => {},
                Err(error) => {
                    self.record_error(&error, self.finished, findings);
                    return;
                },
            }
        }
    }

    fn check_entry(&mut self, metadata: &EntryMetadata, findings: &mut Vec<PackageFinding>) {
        let raw = metadata.path().as_bytes();
        if raw.is_empty() || raw == b"." || raw == b"./" {
            return;
        }
        match sanitize_archive_path(metadata.path()) {
            None => findings.push(PackageFinding::new(
                PROFILE,
                Some(raw.to_vec()),
                PackageFindingCode::UnsafeEntryPath,
                "cpio entry escapes the archive root",
            )),
            Some(safe) => {
                if !self.seen_paths.insert(safe) {
                    findings.push(PackageFinding::new(
                        PROFILE,
                        Some(raw.to_vec()),
                        PackageFindingCode::DuplicateEntryPath,
                        "cpio entry path repeats within the payload",
                    ));
                }
            },
        }
    }

    fn record_error(
        &mut self,
        error: &ArchiveError,
        after_finish: bool,
        findings: &mut Vec<PackageFinding>,
    ) {
        if self.failed {
            return;
        }
        self.failed = true;
        let code = match error.kind() {
            ErrorKind::Limit => PackageFindingCode::DecompressionBomb,
            ErrorKind::Capability => PackageFindingCode::UnsupportedCompression,
            ErrorKind::Malformed if after_finish => PackageFindingCode::TruncatedMember,
            _ => PackageFindingCode::MalformedNesting,
        };
        findings.push(PackageFinding::new(
            PROFILE,
            None,
            code,
            format!("RPM payload cpio stream: {error}"),
        ));
    }

    fn finish(&mut self, findings: &mut Vec<PackageFinding>) {
        if self.skip || self.failed {
            return;
        }
        if !self.decided {
            self.decide(findings);
            if self.is_terminal() {
                return;
            }
        }
        if self.done {
            return;
        }
        let Some(mut pipeline) = self.pipeline.take() else {
            return;
        };
        self.finished = true;
        if let Err(error) = pipeline.finish_input() {
            self.record_error(&error, true, findings);
            return;
        }
        self.drive(&mut pipeline, findings);
        if !self.done && !self.failed {
            self.failed = true;
            findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::TruncatedMember,
                "RPM payload cpio stream did not terminate",
            ));
        }
    }
}

/// Result of validating one RPM package.
#[derive(Debug, Clone)]
pub struct RpmValidation {
    status: SupportStatus,
    findings: Vec<PackageFinding>,
    payload_filter: Option<FilterId>,
    payload_compressor: Option<Vec<u8>>,
}

impl RpmValidation {
    /// Separated container-readability and profile-conformance verdict.
    #[must_use]
    pub const fn status(&self) -> SupportStatus {
        self.status
    }

    /// Whether the RPM lead and both headers could be parsed.
    #[must_use]
    pub const fn container_readable(&self) -> bool {
        self.status.container_readable()
    }

    /// Whether the package satisfied the RPM profile with no blocking findings.
    #[must_use]
    pub const fn profile_valid(&self) -> bool {
        self.status.profile_valid()
    }

    /// Every typed finding, in discovery order.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Detected outer filter of the payload, when one was present.
    ///
    /// `None` means the payload was a plain cpio, was absent, or could not be
    /// classified.
    #[must_use]
    pub const fn payload_filter(&self) -> Option<FilterId> {
        self.payload_filter
    }

    /// Raw `PAYLOADCOMPRESSOR` tag value from the main header, when present.
    #[must_use]
    pub fn payload_compressor(&self) -> Option<&[u8]> {
        self.payload_compressor.as_deref()
    }

    /// Whether any finding carries the given code.
    #[must_use]
    pub fn has_code(&self, code: PackageFindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code() == code)
    }
}
