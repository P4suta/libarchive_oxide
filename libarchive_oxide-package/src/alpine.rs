// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Alpine APK v2 structure inspection.
//!
//! APK v2 is a sequence of gzip members which decode to one logical tar
//! stream: zero or more leading `.SIGN.<algorithm>.<key-id>` entries, a control
//! section containing `.PKGINFO`, and package data. This module validates that
//! structure without extracting it, retaining a whole package, or treating
//! signature presence as cryptographic validity.

use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use libarchive_oxide::{ArchiveReader, ReaderEvent, sanitize_archive_path};
use libarchive_oxide_core::{ArchiveError, EntryKind, ErrorKind, Limits};

use crate::alpine_signature::{GzipEvidence, TrackingGzipReader};
use crate::{PackageFinding, PackageFindingCode, Severity, SupportStatus};

const PROFILE: &str = "alpine-apk";
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const DEFAULT_PKGINFO_LIMIT: usize = 64 * 1024 * 1024;

/// Structure inspector for Alpine APK v2 packages.
#[derive(Debug, Clone, Copy)]
pub struct AlpineApkValidator {
    limits: Limits,
}

impl AlpineApkValidator {
    /// Creates an inspector with finite safe resource limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
        }
    }

    /// Replaces the limits applied to gzip decoding, tar parsing, and
    /// `.PKGINFO` retention.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the configured resource limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Inspects an Alpine APK v2 stream without extracting it.
    pub fn validate<R: Read>(&self, mut input: R) -> AlpineApkValidation {
        let mut prefix = Vec::with_capacity(GZIP_MAGIC.len());
        while prefix.len() < GZIP_MAGIC.len() {
            let mut byte = [0_u8; 1];
            match input.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => prefix.push(byte[0]),
                Err(error) => {
                    return AlpineState::unreadable(format!(
                        "cannot read Alpine APK prefix: {error}"
                    ));
                },
            }
        }
        if prefix != GZIP_MAGIC {
            return AlpineState::format_mismatch();
        }

        let pkginfo_limit = self
            .limits
            .metadata_bytes()
            .unwrap_or(DEFAULT_PKGINFO_LIMIT);
        let source = Cursor::new(prefix).chain(input);
        let filtered = TrackingGzipReader::new(source, self.limits, pkginfo_limit);
        let mut archive = ArchiveReader::with_limits(filtered, self.limits);
        let mut state = AlpineState::new(pkginfo_limit);

        loop {
            match archive.next_event() {
                Ok(ReaderEvent::ArchiveMetadata(_)) => {},
                Ok(ReaderEvent::Entry(metadata)) => state.begin_entry(&metadata),
                Ok(ReaderEvent::Data(bytes)) => state.feed(bytes),
                Ok(ReaderEvent::EndEntry) => state.end_entry(),
                Ok(ReaderEvent::Done) => break,
                Ok(_) => {
                    state.fail_container("archive reader returned an unknown event");
                    break;
                },
                Err(error) => {
                    let metadata_limit = metadata_limit_error(&error);
                    let code = if metadata_limit {
                        PackageFindingCode::MetadataTooLarge
                    } else if error.kind() == ErrorKind::Limit
                        || error.io_error().is_some_and(|inner| {
                            matches!(
                                inner.kind(),
                                std::io::ErrorKind::OutOfMemory | std::io::ErrorKind::Other
                            )
                        })
                    {
                        PackageFindingCode::DecompressionBomb
                    } else {
                        PackageFindingCode::ContainerUnreadable
                    };
                    state.container_readable = false;
                    state.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        code,
                        format!("cannot read Alpine APK gzip/tar stream: {error}"),
                    ));
                    break;
                },
            }
        }
        let evidence = match archive.into_inner() {
            Ok(mut filtered) => {
                let mut discard = [0_u8; 8 * 1024];
                loop {
                    match filtered.read(&mut discard) {
                        Ok(0) => break Some(filtered.into_evidence()),
                        Ok(_) => {},
                        Err(error) => {
                            state.fail_container(&format!(
                                "cannot finish Alpine APK gzip stream: {error}"
                            ));
                            break None;
                        },
                    }
                }
            },
            Err(error) => {
                state.fail_container(&format!(
                    "cannot recover Alpine APK gzip stream after parsing: {error}"
                ));
                None
            },
        };
        state.finish(evidence)
    }
}

fn metadata_limit_error(error: &libarchive_oxide::Error) -> bool {
    let archive_error = error.archive_error().or_else(|| {
        error
            .io_error()
            .and_then(std::io::Error::get_ref)
            .and_then(|source| source.downcast_ref::<ArchiveError>())
    });
    archive_error.is_some_and(|archive_error| {
        archive_error.kind() == ErrorKind::Limit
            && archive_error
                .context()
                .iter()
                .any(|context| context.contains("metadata"))
    })
}

impl Default for AlpineApkValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentEntry {
    PackageInfo,
    Signature(usize),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlpineSignatureAlgorithm {
    RsaSha1,
    RsaSha256,
    RsaSha512,
    Dsa,
}

#[derive(Debug, Clone)]
pub(crate) struct AlpineSignatureRecord {
    pub(crate) name: Vec<u8>,
    pub(crate) algorithm: AlpineSignatureAlgorithm,
    pub(crate) key_id: Vec<u8>,
    pub(crate) body: Vec<u8>,
    pub(crate) too_large: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlpineDataHash {
    Absent,
    Valid([u8; 32]),
    Invalid,
}

#[allow(clippy::struct_excessive_bools)]
struct AlpineState {
    container_readable: bool,
    findings: Vec<PackageFinding>,
    names: BTreeSet<Vec<u8>>,
    current: Option<CurrentEntry>,
    pkginfo: Vec<u8>,
    metadata_limit: usize,
    metadata_used: usize,
    pkginfo_too_large: bool,
    signatures: Vec<AlpineSignatureRecord>,
    seen_pkginfo: bool,
    seen_non_signature: bool,
    seen_data: bool,
    signature_present: bool,
}

impl AlpineState {
    fn new(pkginfo_limit: usize) -> Self {
        Self {
            container_readable: true,
            findings: Vec::new(),
            names: BTreeSet::new(),
            current: None,
            pkginfo: Vec::new(),
            metadata_limit: pkginfo_limit,
            metadata_used: 0,
            pkginfo_too_large: false,
            signatures: Vec::new(),
            seen_pkginfo: false,
            seen_non_signature: false,
            seen_data: false,
            signature_present: false,
        }
    }

    fn unreadable(detail: String) -> AlpineApkValidation {
        AlpineApkValidation {
            status: SupportStatus::new(false, false),
            findings: vec![PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::ContainerUnreadable,
                detail,
            )],
            signature_present: false,
            signatures: Vec::new(),
            datahash: AlpineDataHash::Absent,
            gzip_evidence: None,
        }
    }

    fn format_mismatch() -> AlpineApkValidation {
        AlpineApkValidation {
            status: SupportStatus::new(false, false),
            findings: vec![PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::ContainerFormatMismatch,
                "Alpine APK v2 must begin with a gzip member",
            )],
            signature_present: false,
            signatures: Vec::new(),
            datahash: AlpineDataHash::Absent,
            gzip_evidence: None,
        }
    }

    fn fail_container(&mut self, detail: &str) {
        self.container_readable = false;
        self.findings.push(PackageFinding::new(
            PROFILE,
            None,
            PackageFindingCode::ContainerUnreadable,
            detail,
        ));
    }

    fn begin_entry(&mut self, metadata: &libarchive_oxide_core::EntryMetadata) {
        if self.current.take().is_some() {
            self.fail_container("tar began an entry before ending the previous entry");
        }
        let name = metadata.path().as_bytes().to_vec();
        if sanitize_archive_path(metadata.path()).is_none() {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name),
                PackageFindingCode::UnsafeEntryPath,
                "entry path is absolute, traversing, or unrepresentable",
            ));
            self.current = Some(CurrentEntry::Other);
            return;
        }
        if !self.names.insert(name.clone()) {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.clone()),
                PackageFindingCode::DuplicateEntryPath,
                "entry path appears more than once",
            ));
        }

        if name.starts_with(b".SIGN.") {
            self.begin_signature(name, metadata.kind());
            return;
        }

        self.seen_non_signature = true;
        if name == b".PKGINFO" {
            if self.seen_pkginfo {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(name),
                    PackageFindingCode::DuplicateMember,
                    ".PKGINFO appears more than once",
                ));
                self.current = Some(CurrentEntry::Other);
                return;
            }
            if self.seen_data {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(name.clone()),
                    PackageFindingCode::UnexpectedMemberOrder,
                    ".PKGINFO appears after package data",
                ));
            }
            if metadata.kind() == EntryKind::File {
                self.seen_pkginfo = true;
                self.current = Some(CurrentEntry::PackageInfo);
            } else {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(name),
                    PackageFindingCode::InvalidPackageMetadata,
                    ".PKGINFO is not a regular file",
                ));
                self.current = Some(CurrentEntry::Other);
            }
            return;
        }

        if !name.starts_with(b".") {
            self.seen_data = true;
            if !self.seen_pkginfo {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(name),
                    PackageFindingCode::UnexpectedMemberOrder,
                    "package data appears before .PKGINFO",
                ));
                self.current = Some(CurrentEntry::Other);
                return;
            }
        } else if !self.seen_pkginfo {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name),
                PackageFindingCode::UnexpectedMemberOrder,
                "control entry appears before .PKGINFO",
            ));
            self.current = Some(CurrentEntry::Other);
            return;
        }
        self.current = Some(CurrentEntry::Other);
    }

    fn begin_signature(&mut self, name: Vec<u8>, kind: EntryKind) {
        self.signature_present = true;
        if self.seen_non_signature {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.clone()),
                PackageFindingCode::UnexpectedMemberOrder,
                "signature entry appears after control or package data",
            ));
        }
        let Some((algorithm, key_id)) = parse_signature_name(&name) else {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.clone()),
                PackageFindingCode::InvalidSignatureMember,
                "signature must be a regular .SIGN.<algorithm>.<key-id> entry",
            ));
            self.current = Some(CurrentEntry::Other);
            return;
        };
        if kind != EntryKind::File {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.clone()),
                PackageFindingCode::InvalidSignatureMember,
                "signature must be a regular .SIGN.<algorithm>.<key-id> entry",
            ));
            self.current = Some(CurrentEntry::Other);
            return;
        }
        let key_id = key_id.to_vec();
        let index = self.signatures.len();
        self.signatures.push(AlpineSignatureRecord {
            name,
            algorithm,
            key_id,
            body: Vec::new(),
            too_large: false,
        });
        self.current = Some(CurrentEntry::Signature(index));
    }

    fn feed(&mut self, bytes: &[u8]) {
        match self.current {
            Some(CurrentEntry::PackageInfo) if !self.pkginfo_too_large => {
                if self.reserve_metadata(bytes.len()) {
                    self.pkginfo.extend_from_slice(bytes);
                } else {
                    self.mark_pkginfo_too_large();
                }
            },
            Some(CurrentEntry::Signature(index)) => self.feed_signature(index, bytes),
            Some(CurrentEntry::PackageInfo | CurrentEntry::Other) | None => {},
        }
    }

    fn reserve_metadata(&mut self, additional: usize) -> bool {
        let Some(next) = self.metadata_used.checked_add(additional) else {
            return false;
        };
        if next > self.metadata_limit {
            return false;
        }
        self.metadata_used = next;
        true
    }

    fn feed_signature(&mut self, index: usize, bytes: &[u8]) {
        if self
            .signatures
            .get(index)
            .is_none_or(|signature| signature.too_large)
        {
            return;
        }
        if !self.reserve_metadata(bytes.len()) {
            if let Some(signature) = self.signatures.get_mut(index) {
                signature.too_large = true;
                signature.body.clear();
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(signature.name.clone()),
                    PackageFindingCode::SignatureResourceLimit,
                    format!(
                        "signature bytes exceed the configured {}-byte metadata budget",
                        self.metadata_limit
                    ),
                ));
            }
            return;
        }
        if let Some(signature) = self.signatures.get_mut(index) {
            signature.body.extend_from_slice(bytes);
        }
    }

    fn mark_pkginfo_too_large(&mut self) {
        self.pkginfo_too_large = true;
        self.findings.push(PackageFinding::new(
            PROFILE,
            Some(b".PKGINFO".to_vec()),
            PackageFindingCode::MetadataTooLarge,
            format!(
                ".PKGINFO exceeds the configured {}-byte metadata budget",
                self.metadata_limit
            ),
        ));
    }

    fn end_entry(&mut self) {
        self.current = None;
    }

    fn finish(mut self, gzip_evidence: Option<GzipEvidence>) -> AlpineApkValidation {
        if self.container_readable && !self.seen_pkginfo {
            self.findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::MissingRequiredMember,
                "package has no .PKGINFO control entry",
            ));
        }
        let datahash = if self.seen_pkginfo && !self.pkginfo_too_large {
            validate_pkginfo(&self.pkginfo, &mut self.findings)
        } else {
            AlpineDataHash::Absent
        };
        self.findings.push(PackageFinding::new(
            PROFILE,
            None,
            if self.signature_present {
                PackageFindingCode::SigningSchemeDetected
            } else {
                PackageFindingCode::UnsignedPackage
            },
            if self.signature_present {
                "detected an Alpine APK signature entry; cryptographic validity was not evaluated"
            } else {
                "no Alpine APK signature entry was detected"
            },
        ));

        let blocking = self
            .findings
            .iter()
            .any(|finding| finding.severity() >= Severity::Warning);
        let profile_valid = self.container_readable && self.seen_pkginfo && !blocking;
        AlpineApkValidation {
            status: SupportStatus::new(self.container_readable, profile_valid),
            findings: self.findings,
            signature_present: self.signature_present,
            signatures: self.signatures,
            datahash,
            gzip_evidence,
        }
    }
}

fn parse_signature_name(name: &[u8]) -> Option<(AlpineSignatureAlgorithm, &[u8])> {
    let rest = name.strip_prefix(b".SIGN.")?;
    let separator = rest.iter().position(|byte| *byte == b'.')?;
    let algorithm = match &rest[..separator] {
        b"RSA" => AlpineSignatureAlgorithm::RsaSha1,
        b"RSA256" => AlpineSignatureAlgorithm::RsaSha256,
        b"RSA512" => AlpineSignatureAlgorithm::RsaSha512,
        b"DSA" => AlpineSignatureAlgorithm::Dsa,
        _ => return None,
    };
    let key_id = &rest[separator + 1..];
    if key_id.is_empty()
        || key_id.len() > 255
        || key_id
            .iter()
            .any(|byte| matches!(byte, 0 | b'/' | b'\\' | b'\r' | b'\n' | b':' | b'='))
    {
        return None;
    }
    Some((algorithm, key_id))
}

fn validate_pkginfo(body: &[u8], findings: &mut Vec<PackageFinding>) -> AlpineDataHash {
    let mut keys = BTreeSet::new();
    let mut syntax_valid = true;
    let mut datahash = AlpineDataHash::Absent;
    for (index, raw_line) in body.split(|byte| *byte == b'\n').enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(separator) = line.windows(3).position(|window| window == b" = ") else {
            findings.push(PackageFinding::new(
                PROFILE,
                Some(b".PKGINFO".to_vec()),
                PackageFindingCode::InvalidPackageMetadata,
                format!(
                    ".PKGINFO line {} does not use the required `key = value` syntax",
                    index + 1
                ),
            ));
            syntax_valid = false;
            continue;
        };
        let key = &line[..separator];
        let value = &line[separator + 3..];
        if key.is_empty()
            || value.is_empty()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            findings.push(PackageFinding::new(
                PROFILE,
                Some(b".PKGINFO".to_vec()),
                PackageFindingCode::InvalidPackageMetadata,
                format!(
                    ".PKGINFO line {} has an invalid key or empty value",
                    index + 1
                ),
            ));
            syntax_valid = false;
            continue;
        }
        if !keys.insert(key.to_vec()) {
            findings.push(PackageFinding::new(
                PROFILE,
                Some(b".PKGINFO".to_vec()),
                PackageFindingCode::InvalidPackageMetadata,
                format!(
                    ".PKGINFO line {} repeats the {} field",
                    index + 1,
                    String::from_utf8_lossy(key)
                ),
            ));
            syntax_valid = false;
            if key == b"datahash" {
                datahash = AlpineDataHash::Invalid;
            }
            continue;
        }
        if key == b"datahash" {
            datahash = parse_datahash(value).map_or_else(
                || {
                    findings.push(PackageFinding::new(
                        PROFILE,
                        Some(b".PKGINFO".to_vec()),
                        PackageFindingCode::InvalidIntegrityMetadata,
                        ".PKGINFO datahash must be exactly 64 lowercase hexadecimal digits",
                    ));
                    AlpineDataHash::Invalid
                },
                AlpineDataHash::Valid,
            );
        }
    }

    if syntax_valid {
        for required in [b"pkgname".as_slice(), b"pkgver", b"arch"] {
            if !keys.contains(required) {
                findings.push(PackageFinding::new(
                    PROFILE,
                    Some(b".PKGINFO".to_vec()),
                    PackageFindingCode::MissingRequiredMember,
                    format!(
                        ".PKGINFO has no required {} field",
                        String::from_utf8_lossy(required)
                    ),
                ));
            }
        }
    }
    datahash
}

fn parse_datahash(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0])?;
        let low = decode_lower_hex(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Result of inspecting one Alpine APK v2 package.
#[derive(Debug, Clone)]
pub struct AlpineApkValidation {
    status: SupportStatus,
    findings: Vec<PackageFinding>,
    signature_present: bool,
    pub(crate) signatures: Vec<AlpineSignatureRecord>,
    pub(crate) datahash: AlpineDataHash,
    pub(crate) gzip_evidence: Option<GzipEvidence>,
}

impl AlpineApkValidation {
    /// Separated container-readability and profile-conformance verdict.
    #[must_use]
    pub const fn status(&self) -> SupportStatus {
        self.status
    }

    /// Whether the concatenated gzip/tar container was parseable.
    #[must_use]
    pub const fn container_readable(&self) -> bool {
        self.status.container_readable()
    }

    /// Whether the APK satisfied its structural profile.
    #[must_use]
    pub const fn profile_valid(&self) -> bool {
        self.status.profile_valid()
    }

    /// Whether a leading `.SIGN.*` entry was detected.
    #[must_use]
    pub const fn signature_present(&self) -> bool {
        self.signature_present
    }

    /// Typed findings in discovery order.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Whether any finding carries `code`.
    #[must_use]
    pub fn has_code(&self, code: PackageFindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code() == code)
    }
}
