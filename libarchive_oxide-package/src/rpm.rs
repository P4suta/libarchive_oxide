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
//! Header-declared compressed-payload SHA-256, SHA-512, and SHA3-256 digests are
//! updated during the same forward read and compared at EOF. The corresponding
//! uncompressed `ALT` digests are also verified when the compressor is declared
//! and detected as `none`, where the observed raw and decoded byte streams are
//! identical. Compressed `ALT` coverage remains explicitly unsupported until a
//! decoded-stream hook can preserve cpio headers and padding. Digest state is
//! constant-sized, and the configured decoded-total budget also bounds payload
//! bytes read after the cpio parser completes solely to finish integrity.
//!
//! The result separates two questions: could the RPM container be parsed at all
//! ([`SupportStatus::container_readable`]) and did the package satisfy the RPM
//! profile ([`SupportStatus::profile_valid`]). [`RpmValidation::integrity`] is a
//! third independent verdict; a digest mismatch does not masquerade as a
//! container parse failure. Every deviation is reported as a typed
//! [`PackageFinding`].

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, EntryMetadata, ErrorKind, Limits, ProbeResult};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

use super::finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
use super::verification::VerificationDimension;
use libarchive_oxide::advanced::ProviderCapability;
use libarchive_oxide::advanced::legacy::{
    BuiltinCodecProviders, BuiltinFormatProviders, ProviderSet, StaticCodecProviders,
};
use libarchive_oxide::advanced::{Pipeline, PipelineEvent};
use libarchive_oxide::sanitize_archive_path;

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

/// RPM header data type code for one or more big-endian 32-bit integers.
const TYPE_INT32: u32 = 4;

/// RPM header data type code for an array of NUL-terminated strings.
const TYPE_STRING_ARRAY: u32 = 8;

/// Main-header tag `PAYLOADFORMAT` (expected value `cpio`).
const TAG_PAYLOADFORMAT: u32 = 1124;

/// Main-header tag `PAYLOADCOMPRESSOR` (for example `gzip` or `xz`).
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;

/// Main-header SHA-256 digest of the compressed payload.
const TAG_PAYLOADSHA256: u32 = 5092;

/// Obsolete algorithm identifier accompanying `PAYLOADSHA256`.
const TAG_PAYLOADSHA256ALGO: u32 = 5093;

/// Main-header SHA-256 digest of the uncompressed payload.
const TAG_PAYLOADSHA256ALT: u32 = 5097;

/// Main-header SHA-512 digest of the compressed payload.
const TAG_PAYLOADSHA512: u32 = 5121;

/// Main-header SHA-512 digest of the uncompressed payload.
const TAG_PAYLOADSHA512ALT: u32 = 5122;

/// Main-header SHA3-256 digest of the compressed payload.
///
/// Unlike the obsolete `PAYLOADSHA256ALGO` pairing, the algorithm is fixed by
/// this tag's RPM semantics and has no separate algorithm-id tag.
const TAG_PAYLOADSHA3_256: u32 = 5123;

/// Main-header SHA3-256 digest of the uncompressed payload.
const TAG_PAYLOADSHA3_256ALT: u32 = 5124;

/// `OpenPGP` hash-algorithm identifier for SHA-256.
const HASH_ALGORITHM_SHA256: u32 = 8;

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

/// Extracts one big-endian `u32` from a scalar RPM `INT32` value.
fn extract_int32(store: &[u8], offset: u32) -> Option<u32> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(4)?;
    let bytes = store.get(start..end)?;
    Some(be_u32(bytes))
}

/// Converts one ASCII hexadecimal nibble.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes an exact-width hexadecimal digest without accepting truncation.
fn decode_hex<const N: usize>(encoded: &[u8]) -> Option<[u8; N]> {
    if encoded.len() != N.checked_mul(2)? {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        decoded[index] = hex_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(hex_nibble(pair[1])?)?;
    }
    Some(decoded)
}

/// Extracts and decodes an RPM string array containing fixed-width hex digests.
///
/// The returned allocation is bounded by the header store: every pushed digest
/// consumes `2 * N + 1` source bytes, and malformed short strings are rejected
/// before they can cause a large allocation.
fn extract_hex_array<const N: usize>(
    store: &[u8],
    offset: u32,
    count: u32,
) -> Option<Vec<[u8; N]>> {
    let mut cursor = usize::try_from(offset).ok()?;
    let count = usize::try_from(count).ok()?;
    if count == 0 || count > store.len().saturating_sub(cursor) {
        return None;
    }
    let mut values = Vec::new();
    for _ in 0..count {
        let rest = store.get(cursor..)?;
        let length = rest.iter().position(|byte| *byte == 0)?;
        values.push(decode_hex(rest.get(..length)?)?);
        cursor = cursor.checked_add(length)?.checked_add(1)?;
    }
    Some(values)
}

/// Extracts and decodes one scalar RPM string containing a fixed-width digest.
fn extract_hex_string<const N: usize>(store: &[u8], offset: u32) -> Option<[u8; N]> {
    let value = extract_string(store, offset)?;
    decode_hex(&value)
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

/// Header-declared payload digests and their parse verdict.
#[derive(Debug, Default, Clone)]
struct PayloadDigestDeclarations {
    present: bool,
    invalid: bool,
    unsupported: bool,
    sha256: Vec<[u8; 32]>,
    sha512: Vec<[u8; 64]>,
    sha3_256: Vec<[u8; 32]>,
    sha256_alt: Vec<[u8; 32]>,
    sha512_alt: Vec<[u8; 64]>,
    sha3_256_alt: Vec<[u8; 32]>,
    sha256_algorithm: Option<u32>,
    findings: Vec<PackageFinding>,
}

impl PayloadDigestDeclarations {
    fn invalid(&mut self, detail: impl Into<String>) {
        self.present = true;
        self.invalid = true;
        if !self
            .findings
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::InvalidIntegrityMetadata)
        {
            self.findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::InvalidIntegrityMetadata,
                detail,
            ));
        }
    }

    fn unsupported(&mut self, code: PackageFindingCode, detail: impl Into<String>) {
        self.present = true;
        self.unsupported = true;
        if !self.findings.iter().any(|finding| finding.code() == code) {
            self.findings
                .push(PackageFinding::new(PROFILE, None, code, detail));
        }
    }

    fn observe(&mut self, tag: u32, kind: u32, offset: u32, count: u32, store: &[u8]) {
        self.present = true;
        match tag {
            TAG_PAYLOADSHA256 => {
                if kind != TYPE_STRING_ARRAY {
                    self.invalid("PAYLOADSHA256 is not an RPM string array");
                } else if let Some(values) = extract_hex_array(store, offset, count) {
                    self.sha256 = values;
                } else {
                    self.invalid(
                        "PAYLOADSHA256 is empty, out of bounds, or not a SHA-256 hex digest",
                    );
                }
            },
            TAG_PAYLOADSHA256ALGO => {
                if kind != TYPE_INT32 || count != 1 {
                    self.invalid("PAYLOADSHA256ALGO is not one scalar RPM INT32");
                } else if let Some(algorithm) = extract_int32(store, offset) {
                    self.sha256_algorithm = Some(algorithm);
                } else {
                    self.invalid("PAYLOADSHA256ALGO points outside the RPM header store");
                }
            },
            TAG_PAYLOADSHA256ALT => {
                if kind != TYPE_STRING_ARRAY {
                    self.invalid("PAYLOADSHA256ALT is not an RPM string array");
                } else if let Some(values) = extract_hex_array(store, offset, count) {
                    self.sha256_alt = values;
                } else {
                    self.invalid(
                        "PAYLOADSHA256ALT is empty, out of bounds, or not SHA-256 hexadecimal",
                    );
                }
            },
            TAG_PAYLOADSHA512 => {
                if kind != TYPE_STRING || count != 1 {
                    self.invalid("PAYLOADSHA512 is not one scalar RPM string");
                } else if let Some(value) = extract_hex_string(store, offset) {
                    self.sha512.push(value);
                } else {
                    self.invalid("PAYLOADSHA512 is out of bounds or not a SHA-512 hex digest");
                }
            },
            TAG_PAYLOADSHA512ALT => {
                if kind != TYPE_STRING || count != 1 {
                    self.invalid("PAYLOADSHA512ALT is not one scalar RPM string");
                } else if let Some(value) = extract_hex_string(store, offset) {
                    self.sha512_alt.push(value);
                } else {
                    self.invalid("PAYLOADSHA512ALT is out of bounds or not a SHA-512 hex digest");
                }
            },
            TAG_PAYLOADSHA3_256 => {
                if kind != TYPE_STRING || count != 1 {
                    self.invalid("PAYLOADSHA3_256 is not one scalar RPM string");
                } else if let Some(value) = extract_hex_string(store, offset) {
                    self.sha3_256.push(value);
                } else {
                    self.invalid("PAYLOADSHA3_256 is out of bounds or not a SHA3-256 hex digest");
                }
            },
            TAG_PAYLOADSHA3_256ALT => {
                if kind != TYPE_STRING || count != 1 {
                    self.invalid("PAYLOADSHA3_256ALT is not one scalar RPM string");
                } else if let Some(value) = extract_hex_string(store, offset) {
                    self.sha3_256_alt.push(value);
                } else {
                    self.invalid(
                        "PAYLOADSHA3_256ALT is out of bounds or not a SHA3-256 hex digest",
                    );
                }
            },
            _ => {},
        }
    }

    fn finish_metadata(&mut self) {
        if let Some(algorithm) = self.sha256_algorithm {
            if self.sha256.is_empty() {
                self.invalid("PAYLOADSHA256ALGO is present without PAYLOADSHA256");
            } else if algorithm != HASH_ALGORITHM_SHA256 {
                self.sha256.clear();
                self.sha256_alt.clear();
                self.unsupported(
                    PackageFindingCode::UnsupportedIntegrityAlgorithm,
                    format!("PAYLOADSHA256ALGO requests unsupported hash algorithm {algorithm}"),
                );
            }
        }
    }

    fn has_supported_digest(&self) -> bool {
        !self.sha256.is_empty() || !self.sha512.is_empty() || !self.sha3_256.is_empty()
    }

    fn has_alt_digest(&self) -> bool {
        !self.sha256_alt.is_empty() || !self.sha512_alt.is_empty() || !self.sha3_256_alt.is_empty()
    }
}

/// Payload tags extracted from the main header.
#[derive(Debug, Default, Clone)]
struct MainTags {
    format: Option<Vec<u8>>,
    compressor: Option<Vec<u8>>,
    digests: PayloadDigestDeclarations,
}

/// Incremental verifier for compressed-payload digests declared by the header.
///
/// Hash state is constant-sized. `decoded_total` is also used as the maximum
/// number of compressed payload bytes read solely for integrity verification,
/// so a reader with an endless suffix cannot keep the verifier running after
/// the nested cpio parser has completed.
struct PayloadIntegrity {
    declarations: PayloadDigestDeclarations,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
    sha3_256: Option<Sha3_256>,
    alt_candidate: bool,
    payload_bytes: u64,
    payload_limit: Option<u64>,
    runtime_failed: bool,
}

impl PayloadIntegrity {
    fn new(
        mut declarations: PayloadDigestDeclarations,
        declared_compressor: Option<&[u8]>,
        limits: Limits,
    ) -> Self {
        let alt_candidate = declarations.has_alt_digest()
            && matches!(
                declared_filter(declared_compressor),
                DeclaredCompressor::Known(None)
            );
        if declarations.has_alt_digest() && !alt_candidate && !declarations.invalid {
            declarations.unsupported(
                PackageFindingCode::UnsupportedIntegrityScope,
                "uncompressed RPM payload digests require a decoded-stream hook for compressed or unknown payloads",
            );
        }
        let can_hash = !declarations.invalid;
        let sha256 = (can_hash
            && (!declarations.sha256.is_empty()
                || (alt_candidate && !declarations.sha256_alt.is_empty())))
        .then(Sha256::new);
        let sha512 = (can_hash
            && (!declarations.sha512.is_empty()
                || (alt_candidate && !declarations.sha512_alt.is_empty())))
        .then(Sha512::new);
        let sha3_256 = (can_hash
            && (!declarations.sha3_256.is_empty()
                || (alt_candidate && !declarations.sha3_256_alt.is_empty())))
        .then(Sha3_256::new);
        Self {
            declarations,
            sha256,
            sha512,
            sha3_256,
            alt_candidate,
            payload_bytes: 0,
            payload_limit: limits.decoded_total(),
            runtime_failed: false,
        }
    }

    fn needs_eof(&self) -> bool {
        !self.runtime_failed
            && !self.declarations.invalid
            && (self.sha256.is_some() || self.sha512.is_some() || self.sha3_256.is_some())
    }

    fn feed(&mut self, bytes: &[u8]) {
        if !self.needs_eof() {
            return;
        }
        let Some(length) = u64::try_from(bytes.len()).ok() else {
            self.fail(
                PackageFindingCode::IntegrityResourceLimit,
                "compressed RPM payload length exceeds the platform address space",
            );
            return;
        };
        let Some(total) = self.payload_bytes.checked_add(length) else {
            self.fail(
                PackageFindingCode::IntegrityResourceLimit,
                "compressed RPM payload byte count overflowed",
            );
            return;
        };
        if self.payload_limit.is_some_and(|limit| total > limit) {
            self.fail(
                PackageFindingCode::IntegrityResourceLimit,
                "compressed RPM payload exceeds the configured integrity byte budget",
            );
            return;
        }
        self.payload_bytes = total;
        if let Some(hasher) = &mut self.sha256 {
            hasher.update(bytes);
        }
        if let Some(hasher) = &mut self.sha512 {
            hasher.update(bytes);
        }
        if let Some(hasher) = &mut self.sha3_256 {
            hasher.update(bytes);
        }
    }

    fn read_error(&mut self, error: &std::io::Error) {
        if self.needs_eof() {
            self.fail(
                PackageFindingCode::IntegrityReadFailure,
                format!("cannot read compressed RPM payload for integrity: {error}"),
            );
        }
    }

    fn fail(&mut self, code: PackageFindingCode, detail: impl Into<String>) {
        self.runtime_failed = true;
        self.sha256 = None;
        self.sha512 = None;
        self.sha3_256 = None;
        self.declarations
            .findings
            .push(PackageFinding::new(PROFILE, None, code, detail));
    }

    fn finish(
        mut self,
        actual_filter: Option<FilterId>,
        filter_decided: bool,
    ) -> (VerificationDimension, Vec<PackageFinding>) {
        let alt_eligible = self.alt_candidate && filter_decided && actual_filter.is_none();
        if self.alt_candidate && !alt_eligible && !self.declarations.invalid {
            self.declarations.unsupported(
                PackageFindingCode::UnsupportedIntegrityScope,
                "PAYLOADCOMPRESSOR declared none, but the payload was not proven uncompressed",
            );
        }
        let dimension = if !self.declarations.present {
            VerificationDimension::NotPresent
        } else if self.declarations.invalid || self.runtime_failed {
            VerificationDimension::Invalid
        } else {
            let mut mismatch = false;
            if let Some(hasher) = self.sha256.take() {
                let actual: [u8; 32] = hasher.finalize().into();
                if self
                    .declarations
                    .sha256
                    .iter()
                    .chain(
                        alt_eligible
                            .then_some(self.declarations.sha256_alt.iter())
                            .into_iter()
                            .flatten(),
                    )
                    .any(|expected| expected != &actual)
                {
                    mismatch = true;
                    self.declarations.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::IntegrityMismatch,
                        "RPM payload does not match a declared SHA-256 digest",
                    ));
                }
            }
            if let Some(hasher) = self.sha512.take() {
                let actual: [u8; 64] = hasher.finalize().into();
                if self
                    .declarations
                    .sha512
                    .iter()
                    .chain(
                        alt_eligible
                            .then_some(self.declarations.sha512_alt.iter())
                            .into_iter()
                            .flatten(),
                    )
                    .any(|expected| expected != &actual)
                {
                    mismatch = true;
                    self.declarations.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::IntegrityMismatch,
                        "RPM payload does not match a declared SHA-512 digest",
                    ));
                }
            }
            if let Some(hasher) = self.sha3_256.take() {
                let actual: [u8; 32] = hasher.finalize().into();
                if self
                    .declarations
                    .sha3_256
                    .iter()
                    .chain(
                        alt_eligible
                            .then_some(self.declarations.sha3_256_alt.iter())
                            .into_iter()
                            .flatten(),
                    )
                    .any(|expected| expected != &actual)
                {
                    mismatch = true;
                    self.declarations.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::IntegrityMismatch,
                        "RPM payload does not match a declared SHA3-256 digest",
                    ));
                }
            }
            if mismatch {
                VerificationDimension::Invalid
            } else if self.declarations.unsupported {
                VerificationDimension::Unsupported
            } else if self.declarations.has_supported_digest()
                || (alt_eligible && self.declarations.has_alt_digest())
            {
                VerificationDimension::Verified
            } else {
                VerificationDimension::NotEvaluated
            }
        };
        (dimension, self.declarations.findings)
    }
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
    /// store (the header-bomb budget); [`Limits::with_decoded_total`] bounds both
    /// the decompressed payload and compressed bytes read solely to finish a
    /// declared payload digest.
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

        let format_ok = tags.format.as_deref() == Some(b"cpio");
        if !format_ok {
            state.findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::PayloadFormatMismatch,
                match &tags.format {
                    Some(other) => format!(
                        "PAYLOADFORMAT is {:?}, expected cpio",
                        String::from_utf8_lossy(other)
                    ),
                    None => "main header has no PAYLOADFORMAT tag".to_string(),
                },
            ));
        }
        state.format_ok = format_ok;
        state.payload_compressor.clone_from(&tags.compressor);

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

    /// Streams the remaining payload bytes through one bounded pipeline and,
    /// when declared, constant-memory SHA-2/SHA-3 digest state.
    fn validate_payload<R: Read>(&self, reader: &mut R, tags: &MainTags, state: &mut RpmState) {
        let mut payload = Payload::new(self.limits, self.providers);
        let mut integrity = PayloadIntegrity::new(
            tags.digests.clone(),
            tags.compressor.as_deref(),
            self.limits,
        );
        let mut buffer = vec![0u8; PAYLOAD_CHUNK];
        loop {
            if payload.is_terminal() && !integrity.needs_eof() {
                break;
            }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    integrity.feed(&buffer[..count]);
                    if !payload.is_terminal() {
                        payload.feed(&buffer[..count], &mut state.findings);
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                Err(error) => {
                    integrity.read_error(&error);
                    if !payload.is_terminal() {
                        state.findings.push(PackageFinding::new(
                            PROFILE,
                            None,
                            PackageFindingCode::TruncatedMember,
                            format!("cannot read RPM payload: {error}"),
                        ));
                    }
                    break;
                },
            }
        }
        payload.finish(&mut state.findings);
        state.payload_filter = payload.filter;
        state.payload_ok = payload.done;
        (state.integrity, state.integrity_findings) =
            integrity.finish(payload.filter, payload.decided);

        // Cross-check the detected filter against the declared compressor tag.
        if let DeclaredCompressor::Known(expected) = declared_filter(tags.compressor.as_deref())
            && payload.decided
            && payload.filter != expected
        {
            state.findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::CompressorMismatch,
                "detected payload filter disagrees with PAYLOADCOMPRESSOR",
            ));
        }
    }
}

/// Parses the main-header index for payload layout and integrity tags.
fn extract_main_tags(section: &HeaderSection) -> MainTags {
    let mut tags = MainTags::default();
    let mut seen_integrity_tags = BTreeSet::new();
    let count = section.index.len() / INDEX_ENTRY_LEN;
    for entry in 0..count {
        let base = entry * INDEX_ENTRY_LEN;
        let record = &section.index[base..base + INDEX_ENTRY_LEN];
        let tag = be_u32(&record[0..4]);
        let kind = be_u32(&record[4..8]);
        let offset = be_u32(&record[8..12]);
        let value_count = be_u32(&record[12..16]);
        if tag == TAG_PAYLOADFORMAT && kind == TYPE_STRING {
            tags.format = extract_string(&section.store, offset);
        } else if tag == TAG_PAYLOADCOMPRESSOR && kind == TYPE_STRING {
            tags.compressor = extract_string(&section.store, offset);
        } else if matches!(
            tag,
            TAG_PAYLOADSHA256
                | TAG_PAYLOADSHA256ALGO
                | TAG_PAYLOADSHA256ALT
                | TAG_PAYLOADSHA512
                | TAG_PAYLOADSHA512ALT
                | TAG_PAYLOADSHA3_256
                | TAG_PAYLOADSHA3_256ALT
        ) {
            if seen_integrity_tags.insert(tag) {
                tags.digests
                    .observe(tag, kind, offset, value_count, &section.store);
            } else {
                tags.digests
                    .invalid(format!("RPM main header repeats integrity tag {tag}"));
            }
        }
    }
    tags.digests.finish_metadata();
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
    integrity_findings: Vec<PackageFinding>,
    container_readable: bool,
    format_ok: bool,
    payload_ok: bool,
    payload_filter: Option<FilterId>,
    payload_compressor: Option<Vec<u8>>,
    integrity: VerificationDimension,
}

impl RpmState {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            integrity_findings: Vec::new(),
            container_readable: true,
            format_ok: false,
            payload_ok: false,
            payload_filter: None,
            payload_compressor: None,
            integrity: VerificationDimension::NotEvaluated,
        }
    }

    /// Records a container-structure failure, clearing `container_readable`.
    fn fail(&mut self, code: PackageFindingCode, detail: impl Into<String>) {
        self.container_readable = false;
        self.findings
            .push(PackageFinding::new(PROFILE, None, code, detail));
    }

    fn finalize(mut self) -> RpmValidation {
        let blocking = self
            .findings
            .iter()
            .any(|finding| finding.severity() >= Severity::Warning);
        let profile_valid =
            self.container_readable && !blocking && self.format_ok && self.payload_ok;
        self.findings.append(&mut self.integrity_findings);
        RpmValidation {
            status: SupportStatus::new(self.container_readable, profile_valid),
            findings: self.findings,
            payload_filter: self.payload_filter,
            payload_compressor: self.payload_compressor,
            integrity: self.integrity,
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
                Ok(_) => {
                    let error = ArchiveError::new(ErrorKind::Protocol)
                        .with_context("nested archive pipeline returned an unknown event");
                    self.record_error(&error, self.finished, findings);
                    return;
                },
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
    integrity: VerificationDimension,
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

    /// Every structural and integrity finding, in discovery order.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Verification verdict for supported header-declared payload digests.
    ///
    /// This is independent of [`Self::status`]. A digest mismatch does not turn
    /// a structurally valid RPM into an unreadable container. Signature
    /// validity is not inferred from this digest.
    #[must_use]
    pub const fn integrity(&self) -> VerificationDimension {
        self.integrity
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
