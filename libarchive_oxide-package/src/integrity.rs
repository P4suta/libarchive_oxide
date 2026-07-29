// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Streaming payload-integrity adapters for ZIP-based package profiles.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::ops::Range;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use libarchive_oxide::{ErrorKind, ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::Limits;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::jar_signature::{
    AndroidApkSchemePresence, is_jar_signature_metadata, is_jar_signature_related,
    verify_jar_signatures,
};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode, ZipPackageProfile};

const JAR_MANIFEST: &[u8] = b"META-INF/MANIFEST.MF";
const MAX_MANIFEST_HEADERS: usize = 262_144;
const MAX_MANIFEST_SECTIONS: usize = 65_536;
const MAX_MANIFEST_VALUE_BYTES: usize = 65_535;
const METADATA_FALLBACK: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct ZipVerification {
    pub(crate) integrity: VerificationDimension,
    pub(crate) signature_validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug)]
pub(crate) struct EntryDigest {
    pub(crate) name: Vec<u8>,
    pub(crate) size: u64,
    pub(crate) sha256: Vec<u8>,
    pub(crate) sha384: Vec<u8>,
    pub(crate) sha512: Vec<u8>,
    pub(crate) metadata_body: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct CollectError {
    pub(crate) detail: String,
    pub(crate) resource_limit: bool,
}

impl CollectError {
    fn read(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            resource_limit: false,
        }
    }

    fn resource_limit(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            resource_limit: true,
        }
    }

    fn archive(error: &libarchive_oxide::Error) -> Self {
        if error.kind() == ErrorKind::Limit {
            Self::resource_limit(error.to_string())
        } else {
            Self::read(error.to_string())
        }
    }
}

struct CurrentDigest {
    name: Vec<u8>,
    size: u64,
    sha256: Sha256,
    sha384: Sha384,
    sha512: Sha512,
    metadata_body: Option<Vec<u8>>,
}

impl CurrentDigest {
    fn new(name: Vec<u8>, retain_body: bool) -> Self {
        Self {
            name,
            size: 0,
            sha256: Sha256::new(),
            sha384: Sha384::new(),
            sha512: Sha512::new(),
            metadata_body: retain_body.then(Vec::new),
        }
    }

    fn feed(
        &mut self,
        bytes: &[u8],
        metadata_used: &mut usize,
        metadata_limit: usize,
    ) -> Result<(), CollectError> {
        self.size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| CollectError::read("entry size overflow while hashing"))?;
        self.sha256.update(bytes);
        self.sha384.update(bytes);
        self.sha512.update(bytes);
        if let Some(body) = &mut self.metadata_body {
            *metadata_used = metadata_used.checked_add(bytes.len()).ok_or_else(|| {
                CollectError::resource_limit("integrity metadata accounting overflow")
            })?;
            if *metadata_used > metadata_limit {
                return Err(CollectError::resource_limit(
                    "integrity/signature metadata exceeds configured budget",
                ));
            }
            body.extend_from_slice(bytes);
        }
        Ok(())
    }

    fn finish(self) -> EntryDigest {
        EntryDigest {
            name: self.name,
            size: self.size,
            sha256: self.sha256.finalize().to_vec(),
            sha384: self.sha384.finalize().to_vec(),
            sha512: self.sha512.finalize().to_vec(),
            metadata_body: self.metadata_body,
        }
    }
}

pub(crate) fn verify_zip<R: Read + Seek>(
    profile: ZipPackageProfile,
    reader: R,
    limits: Limits,
) -> ZipVerification {
    if profile == ZipPackageProfile::NuGet {
        return crate::nuget_signature::verify_nuget(reader, limits);
    }

    let label = profile.label();
    let retained = |name: &[u8]| match profile {
        ZipPackageProfile::Jar => is_jar_signature_metadata(name),
        ZipPackageProfile::Wheel => name.ends_with(b".dist-info/RECORD"),
        ZipPackageProfile::NuGet | ZipPackageProfile::Epub => false,
    };
    let entries = match collect_entries(reader, limits, retained) {
        Ok(entries) => entries,
        Err(error) => {
            let finding_code = if error.resource_limit {
                if profile == ZipPackageProfile::Jar {
                    PackageFindingCode::SignatureResourceLimit
                } else {
                    PackageFindingCode::IntegrityResourceLimit
                }
            } else {
                PackageFindingCode::IntegrityReadFailure
            };
            return ZipVerification {
                integrity: VerificationDimension::Invalid,
                signature_validity: if profile == ZipPackageProfile::Jar {
                    VerificationDimension::Invalid
                } else {
                    VerificationDimension::NotEvaluated
                },
                signer_fingerprints: Vec::new(),
                findings: vec![PackageFinding::new(label, None, finding_code, error.detail)],
            };
        },
    };
    let (integrity, mut findings) = match profile {
        ZipPackageProfile::Jar => verify_jar(&entries, label),
        ZipPackageProfile::Wheel => verify_wheel(&entries),
        ZipPackageProfile::NuGet | ZipPackageProfile::Epub => {
            (VerificationDimension::NotPresent, Vec::new())
        },
    };
    let (signature_validity, signer_fingerprints) = if profile == ZipPackageProfile::Jar {
        let verified = verify_jar_signatures(&entries, integrity, label, limits, None);
        findings.extend(verified.findings);
        (verified.validity, verified.signer_fingerprints)
    } else {
        (signature_state(profile, &entries), Vec::new())
    };
    ZipVerification {
        integrity,
        signature_validity,
        signer_fingerprints,
        findings,
    }
}

pub(crate) fn verify_android_apk_v1<R: Read + Seek>(
    reader: R,
    limits: Limits,
    apk_v2_detected: bool,
    apk_v3_detected: bool,
) -> ZipVerification {
    let label = "android-apk";
    let entries = match collect_entries(reader, limits, is_jar_signature_metadata) {
        Ok(entries) => entries,
        Err(error) => {
            return ZipVerification {
                integrity: VerificationDimension::Invalid,
                signature_validity: VerificationDimension::Invalid,
                signer_fingerprints: Vec::new(),
                findings: vec![PackageFinding::new(
                    label,
                    None,
                    if error.resource_limit {
                        PackageFindingCode::SignatureResourceLimit
                    } else {
                        PackageFindingCode::IntegrityReadFailure
                    },
                    error.detail,
                )],
            };
        },
    };
    let (integrity, mut findings) = verify_jar(&entries, label);
    let signatures = verify_jar_signatures(
        &entries,
        integrity,
        label,
        limits,
        Some(AndroidApkSchemePresence::new(
            apk_v2_detected,
            apk_v3_detected,
        )),
    );
    findings.extend(signatures.findings);
    ZipVerification {
        integrity,
        signature_validity: signatures.validity,
        signer_fingerprints: signatures.signer_fingerprints,
        findings,
    }
}

pub(crate) fn collect_entries<R, F>(
    reader: R,
    limits: Limits,
    retain_body: F,
) -> Result<Vec<EntryDigest>, CollectError>
where
    R: Read + Seek,
    F: Fn(&[u8]) -> bool,
{
    let mut archive = SeekArchiveReader::with_limits(reader, limits)
        .map_err(|error| CollectError::archive(&error))?;
    let metadata_limit = limits.metadata_bytes().unwrap_or(METADATA_FALLBACK);
    let mut metadata_used = 0_usize;
    let mut current: Option<CurrentDigest> = None;
    let mut entries = Vec::new();
    loop {
        match archive
            .next_event()
            .map_err(|error| CollectError::archive(&error))?
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                if current.is_some() {
                    return Err(CollectError::read(
                        "ZIP started an entry before ending the previous entry",
                    ));
                }
                let name = metadata.path().as_bytes().to_vec();
                current = Some(CurrentDigest::new(name.clone(), retain_body(&name)));
            },
            ReaderEvent::Data(bytes) => {
                let Some(entry) = &mut current else {
                    return Err(CollectError::read("ZIP produced data outside an entry"));
                };
                entry.feed(bytes, &mut metadata_used, metadata_limit)?;
            },
            ReaderEvent::EndEntry => {
                let entry = current
                    .take()
                    .ok_or_else(|| CollectError::read("ZIP ended an entry that was not open"))?;
                entries.push(entry.finish());
            },
            ReaderEvent::Done => {
                if current.is_some() {
                    return Err(CollectError::read("ZIP ended before the current entry"));
                }
                return Ok(entries);
            },
            _ => return Err(CollectError::read("ZIP reader returned an unknown event")),
        }
    }
}

fn signature_state(profile: ZipPackageProfile, entries: &[EntryDigest]) -> VerificationDimension {
    let present = match profile {
        ZipPackageProfile::Jar => {
            let has_sf = entries
                .iter()
                .any(|entry| direct_meta_inf(&entry.name) && ascii_ends_with(&entry.name, b".SF"));
            let has_block = entries.iter().any(|entry| {
                direct_meta_inf(&entry.name)
                    && [b".RSA".as_slice(), b".DSA", b".EC"]
                        .iter()
                        .any(|suffix| ascii_ends_with(&entry.name, suffix))
            });
            has_sf && has_block
        },
        ZipPackageProfile::NuGet => entries.iter().any(|entry| entry.name == b".signature.p7s"),
        ZipPackageProfile::Wheel => entries.iter().any(|entry| {
            entry.name.ends_with(b".dist-info/RECORD.jws")
                || entry.name.ends_with(b".dist-info/RECORD.p7s")
        }),
        ZipPackageProfile::Epub => false,
    };
    if present {
        VerificationDimension::NotEvaluated
    } else {
        VerificationDimension::NotPresent
    }
}

fn direct_meta_inf(name: &[u8]) -> bool {
    name.strip_prefix(b"META-INF/")
        .is_some_and(|rest| !rest.is_empty() && !rest.contains(&b'/'))
}

fn ascii_ends_with(name: &[u8], suffix: &[u8]) -> bool {
    name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn verify_jar(
    entries: &[EntryDigest],
    profile: &'static str,
) -> (VerificationDimension, Vec<PackageFinding>) {
    let Some(manifest) = entries.iter().find(|entry| entry.name == JAR_MANIFEST) else {
        return (VerificationDimension::NotEvaluated, Vec::new());
    };
    let Some(body) = manifest.metadata_body.as_deref() else {
        return (
            VerificationDimension::Invalid,
            vec![integrity_finding(
                profile,
                Some(JAR_MANIFEST.to_vec()),
                PackageFindingCode::InvalidIntegrityMetadata,
                "JAR manifest body was not retained",
            )],
        );
    };
    let sections = match manifest_sections(body) {
        Ok(sections) => sections,
        Err(detail) => {
            return (
                VerificationDimension::Invalid,
                vec![integrity_finding(
                    profile,
                    Some(JAR_MANIFEST.to_vec()),
                    PackageFindingCode::InvalidIntegrityMetadata,
                    detail,
                )],
            );
        },
    };
    if let Err(detail) = validate_jar_manifest_layout(&sections) {
        return (
            VerificationDimension::Invalid,
            vec![integrity_finding(
                profile,
                Some(JAR_MANIFEST.to_vec()),
                PackageFindingCode::InvalidIntegrityMetadata,
                detail,
            )],
        );
    }

    let by_name: BTreeMap<&[u8], &EntryDigest> = entries
        .iter()
        .map(|entry| (entry.name.as_slice(), entry))
        .collect();
    let mut findings = Vec::new();
    let mut progress = JarProgress::default();
    for section in sections.into_iter().skip(1) {
        verify_jar_section(profile, &section, &by_name, &mut progress, &mut findings);
    }
    require_jar_coverage(entries, profile, &progress.covered, &mut findings);
    integrity_outcome(progress.checked, progress.unsupported, &findings)
}

#[derive(Debug, Default)]
struct JarProgress {
    checked: usize,
    unsupported: bool,
    covered: BTreeSet<Vec<u8>>,
}

fn validate_jar_manifest_layout(sections: &[ManifestSection]) -> Result<(), String> {
    let main = sections
        .first()
        .ok_or_else(|| "JAR manifest has no main section".to_string())?;
    let Some((version_name, version_value)) = main.first() else {
        return Err("JAR manifest main section is empty".to_string());
    };
    if version_name.as_slice() != b"Manifest-Version" || !valid_manifest_version(version_value) {
        return Err(
            "JAR manifest must begin with an exact `Manifest-Version: number` header".to_string(),
        );
    }
    if main
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"Name"))
    {
        return Err("JAR manifest main section contains a forbidden Name header".to_string());
    }
    for section in &sections[1..] {
        let Some((name, value)) = section.first() else {
            return Err("JAR manifest contains an empty individual section".to_string());
        };
        if name.as_slice() != b"Name" || value.is_empty() {
            return Err(
                "JAR manifest individual section must begin with an exact non-empty Name header"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn valid_manifest_version(value: &[u8]) -> bool {
    let mut need_digit = true;
    for byte in value {
        if byte.is_ascii_digit() {
            need_digit = false;
        } else if *byte == b'.' && !need_digit {
            need_digit = true;
        } else {
            return false;
        }
    }
    !need_digit
}

fn verify_jar_section(
    profile: &'static str,
    section: &ManifestSection,
    by_name: &BTreeMap<&[u8], &EntryDigest>,
    progress: &mut JarProgress,
    findings: &mut Vec<PackageFinding>,
) {
    let Some(name) = header_value(section, b"Name") else {
        return;
    };
    if !progress.covered.insert(name.clone()) {
        findings.push(integrity_finding(
            profile,
            Some(name.clone()),
            PackageFindingCode::InvalidIntegrityMetadata,
            "JAR manifest repeats an entry section",
        ));
    }
    let Some(entry) = by_name.get(name.as_slice()).copied() else {
        findings.push(integrity_finding(
            profile,
            Some(name),
            PackageFindingCode::MissingIntegrityRecord,
            "JAR manifest names an entry absent from the archive",
        ));
        return;
    };
    let mut selected = None;
    let mut unsupported = Vec::new();
    for (key, value) in section {
        if let Some(kind) = JarDigestKind::from_header(key) {
            if selected
                .as_ref()
                .is_none_or(|(selected_kind, _, _)| kind > *selected_kind)
            {
                selected = Some((kind, key.as_slice(), value.as_slice()));
            }
        } else if ascii_ends_with(key, b"-Digest") {
            unsupported.push(key);
        }
    }
    let Some((kind, key, value)) = selected else {
        if unsupported.is_empty() {
            findings.push(integrity_finding(
                profile,
                Some(name),
                PackageFindingCode::MissingIntegrityRecord,
                "JAR manifest entry section contains no digest",
            ));
        } else {
            progress.unsupported = true;
            findings.push(integrity_finding(
                profile,
                Some(name),
                PackageFindingCode::UnsupportedIntegrityAlgorithm,
                format!(
                    "JAR manifest entry section uses only unsupported digest algorithms: {}",
                    unsupported
                        .iter()
                        .map(|header| String::from_utf8_lossy(header))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        return;
    };
    verify_jar_digest(profile, &name, key, value, kind.expected(entry), findings);
    progress.checked = progress.checked.saturating_add(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JarDigestKind {
    Sha256,
    Sha384,
    Sha512,
}

impl JarDigestKind {
    fn from_header(header: &[u8]) -> Option<Self> {
        if header.eq_ignore_ascii_case(b"SHA-256-Digest") {
            Some(Self::Sha256)
        } else if header.eq_ignore_ascii_case(b"SHA-384-Digest") {
            Some(Self::Sha384)
        } else if header.eq_ignore_ascii_case(b"SHA-512-Digest") {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    fn expected(self, entry: &EntryDigest) -> &[u8] {
        match self {
            Self::Sha256 => &entry.sha256,
            Self::Sha384 => &entry.sha384,
            Self::Sha512 => &entry.sha512,
        }
    }
}

fn verify_jar_digest(
    profile: &'static str,
    name: &[u8],
    key: &[u8],
    value: &[u8],
    expected: &[u8],
    findings: &mut Vec<PackageFinding>,
) {
    match STANDARD.decode(value) {
        Ok(actual) if actual == expected => {},
        Ok(_) => findings.push(integrity_finding(
            profile,
            Some(name.to_vec()),
            PackageFindingCode::IntegrityMismatch,
            format!(
                "{} does not match the entry bytes",
                String::from_utf8_lossy(key)
            ),
        )),
        Err(error) => findings.push(integrity_finding(
            profile,
            Some(name.to_vec()),
            PackageFindingCode::InvalidIntegrityMetadata,
            format!(
                "{} is not valid base64: {error}",
                String::from_utf8_lossy(key)
            ),
        )),
    }
}

fn require_jar_coverage(
    entries: &[EntryDigest],
    profile: &'static str,
    covered: &BTreeSet<Vec<u8>>,
    findings: &mut Vec<PackageFinding>,
) {
    for entry in entries {
        if entry.name.ends_with(b"/") || is_jar_signature_related(&entry.name) {
            continue;
        }
        if !covered.contains(&entry.name) {
            findings.push(integrity_finding(
                profile,
                Some(entry.name.clone()),
                PackageFindingCode::MissingIntegrityRecord,
                "JAR entry is not covered by META-INF/MANIFEST.MF",
            ));
        }
    }
}

pub(crate) type ManifestSection = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Debug)]
pub(crate) struct RawManifestSection {
    pub(crate) attributes: ManifestSection,
    pub(crate) raw: Range<usize>,
}

pub(crate) fn manifest_sections(body: &[u8]) -> Result<Vec<ManifestSection>, String> {
    Ok(manifest_sections_with_raw(body)?
        .into_iter()
        .map(|section| section.attributes)
        .collect())
}

pub(crate) fn manifest_sections_with_raw(body: &[u8]) -> Result<Vec<RawManifestSection>, String> {
    let mut sections = Vec::new();
    let mut section = ManifestSection::new();
    let mut attribute_names = BTreeSet::<Vec<u8>>::new();
    let mut section_start = 0_usize;
    let mut cursor = 0_usize;
    let mut header_count = 0_usize;

    while cursor < body.len() {
        let line_start = cursor;
        let Some(relative_end) = body[cursor..]
            .iter()
            .position(|byte| matches!(*byte, b'\r' | b'\n'))
        else {
            return Err("JAR manifest physical line is not newline-terminated".to_string());
        };
        let line_end = cursor.saturating_add(relative_end);
        cursor = if body[line_end] == b'\r' && body.get(line_end + 1) == Some(&b'\n') {
            line_end.saturating_add(2)
        } else {
            line_end.saturating_add(1)
        };
        let line = &body[line_start..line_end];
        if line.is_empty() {
            if section.is_empty() {
                return Err("JAR manifest contains an empty section".to_string());
            }
            if section
                .iter()
                .any(|(_, value)| std::str::from_utf8(value).is_err())
            {
                return Err("JAR manifest unfolded header value is not UTF-8".to_string());
            }
            if sections.len() >= MAX_MANIFEST_SECTIONS {
                return Err(format!(
                    "JAR manifest section count exceeds fixed limit {MAX_MANIFEST_SECTIONS}"
                ));
            }
            sections.push(RawManifestSection {
                attributes: core::mem::take(&mut section),
                raw: section_start..cursor,
            });
            attribute_names.clear();
            section_start = cursor;
            continue;
        }
        if let Some(continuation) = line.strip_prefix(b" ") {
            let value = section
                .last_mut()
                .map(|(_, value)| value)
                .ok_or_else(|| "JAR manifest has an orphan continuation line".to_string())?;
            if value.len().saturating_add(continuation.len()) > MAX_MANIFEST_VALUE_BYTES {
                return Err(format!(
                    "JAR manifest unfolded value exceeds fixed limit \
                     {MAX_MANIFEST_VALUE_BYTES}"
                ));
            }
            if continuation.contains(&0) {
                return Err("JAR manifest continuation contains NUL".to_string());
            }
            value.extend_from_slice(continuation);
            continue;
        }
        let separator = line
            .windows(2)
            .position(|window| window == b": ")
            .ok_or_else(|| "JAR manifest header does not use `Name: value` syntax".to_string())?;
        let key = &line[..separator];
        let value = &line[separator + 2..];
        if !valid_manifest_header_name(key) {
            return Err("JAR manifest contains an invalid header name".to_string());
        }
        if value.len() > MAX_MANIFEST_VALUE_BYTES {
            return Err(format!(
                "JAR manifest value exceeds fixed limit {MAX_MANIFEST_VALUE_BYTES}"
            ));
        }
        if value.contains(&0) {
            return Err("JAR manifest header value contains NUL".to_string());
        }
        let normalized = key.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>();
        if !attribute_names.insert(normalized) {
            return Err(format!(
                "JAR manifest section repeats header {}",
                String::from_utf8_lossy(key)
            ));
        }
        header_count = header_count.saturating_add(1);
        if header_count > MAX_MANIFEST_HEADERS {
            return Err(format!(
                "JAR manifest header count exceeds fixed limit {MAX_MANIFEST_HEADERS}"
            ));
        }
        section.push((key.to_vec(), value.to_vec()));
    }
    if !section.is_empty() {
        return Err("JAR manifest final section is not terminated by an empty line".to_string());
    }
    Ok(sections)
}

fn valid_manifest_header_name(name: &[u8]) -> bool {
    name.first().is_some_and(u8::is_ascii_alphanumeric)
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
}

fn header_value(section: &ManifestSection, wanted: &[u8]) -> Option<Vec<u8>> {
    section
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.clone())
}

#[derive(Debug)]
struct WheelRow {
    hash: Vec<u8>,
    size: Vec<u8>,
}

fn verify_wheel(entries: &[EntryDigest]) -> (VerificationDimension, Vec<PackageFinding>) {
    let Some(record) = entries
        .iter()
        .find(|entry| entry.name.ends_with(b".dist-info/RECORD"))
    else {
        return (VerificationDimension::NotEvaluated, Vec::new());
    };
    let Some(body) = record.metadata_body.as_deref() else {
        return (
            VerificationDimension::Invalid,
            vec![integrity_finding(
                "wheel",
                Some(record.name.clone()),
                PackageFindingCode::InvalidIntegrityMetadata,
                "wheel RECORD body was not retained",
            )],
        );
    };
    let (rows, mut findings) = parse_wheel_rows(body, &record.name);
    let signature_paths: BTreeSet<&[u8]> = entries
        .iter()
        .filter(|entry| {
            entry.name.ends_with(b".dist-info/RECORD.jws")
                || entry.name.ends_with(b".dist-info/RECORD.p7s")
        })
        .map(|entry| entry.name.as_slice())
        .collect();
    let mut progress = WheelProgress::default();

    for entry in entries {
        if entry.name.ends_with(b"/") || signature_paths.contains(entry.name.as_slice()) {
            continue;
        }
        let Some(row) = rows.get(entry.name.as_slice()) else {
            findings.push(integrity_finding(
                "wheel",
                Some(entry.name.clone()),
                PackageFindingCode::MissingIntegrityRecord,
                "wheel entry has no RECORD row",
            ));
            continue;
        };
        verify_wheel_row(entry, row, &record.name, &mut progress, &mut findings);
    }
    integrity_outcome(progress.checked, progress.unsupported, &findings)
}

fn parse_wheel_rows(
    body: &[u8],
    record_name: &[u8],
) -> (BTreeMap<Vec<u8>, WheelRow>, Vec<PackageFinding>) {
    let mut rows = BTreeMap::new();
    let mut findings = Vec::new();
    for (index, raw_line) in body.split(|byte| *byte == b'\n').enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let fields = match csv_fields(line) {
            Ok(fields) if fields.len() == 3 => fields,
            Ok(_) => {
                findings.push(integrity_finding(
                    "wheel",
                    Some(record_name.to_vec()),
                    PackageFindingCode::InvalidIntegrityMetadata,
                    format!("wheel RECORD line {} does not have three fields", index + 1),
                ));
                continue;
            },
            Err(detail) => {
                findings.push(integrity_finding(
                    "wheel",
                    Some(record_name.to_vec()),
                    PackageFindingCode::InvalidIntegrityMetadata,
                    format!("wheel RECORD line {}: {detail}", index + 1),
                ));
                continue;
            },
        };
        let [path, hash, size]: [Vec<u8>; 3] = match fields.try_into() {
            Ok(fields) => fields,
            Err(_) => continue,
        };
        if rows.insert(path.clone(), WheelRow { hash, size }).is_some() {
            findings.push(integrity_finding(
                "wheel",
                Some(path),
                PackageFindingCode::InvalidIntegrityMetadata,
                "wheel RECORD path appears more than once",
            ));
        }
    }
    (rows, findings)
}

#[derive(Debug, Default)]
struct WheelProgress {
    checked: usize,
    unsupported: bool,
}

fn verify_wheel_row(
    entry: &EntryDigest,
    row: &WheelRow,
    record_name: &[u8],
    progress: &mut WheelProgress,
    findings: &mut Vec<PackageFinding>,
) {
    if entry.name == record_name {
        if !row.hash.is_empty() || !row.size.is_empty() {
            findings.push(integrity_finding(
                "wheel",
                Some(entry.name.clone()),
                PackageFindingCode::InvalidIntegrityMetadata,
                "the RECORD row for RECORD must have empty hash and size fields",
            ));
        }
        return;
    }
    if row.hash.is_empty() || row.size.is_empty() {
        findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::MissingIntegrityRecord,
            "wheel entry has an empty hash or size in RECORD",
        ));
        return;
    }
    verify_wheel_size(entry, row, findings);
    let Some(separator) = row.hash.iter().position(|byte| *byte == b'=') else {
        findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::InvalidIntegrityMetadata,
            "RECORD hash does not use algorithm=urlsafe-base64 syntax",
        ));
        return;
    };
    let algorithm = &row.hash[..separator];
    let encoded = &row.hash[separator + 1..];
    let expected = if algorithm.eq_ignore_ascii_case(b"sha256") {
        Some(entry.sha256.as_slice())
    } else if algorithm.eq_ignore_ascii_case(b"sha384") {
        Some(entry.sha384.as_slice())
    } else if algorithm.eq_ignore_ascii_case(b"sha512") {
        Some(entry.sha512.as_slice())
    } else {
        progress.unsupported = true;
        findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::UnsupportedIntegrityAlgorithm,
            format!(
                "wheel RECORD requests unsupported digest {}",
                String::from_utf8_lossy(algorithm)
            ),
        ));
        None
    };
    let Some(expected) = expected else {
        return;
    };
    progress.checked += 1;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded));
    match decoded {
        Ok(actual) if actual == expected => {},
        Ok(_) => findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            "wheel RECORD digest does not match the entry bytes",
        )),
        Err(error) => findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::InvalidIntegrityMetadata,
            format!("wheel RECORD digest is not URL-safe base64: {error}"),
        )),
    }
}

fn verify_wheel_size(entry: &EntryDigest, row: &WheelRow, findings: &mut Vec<PackageFinding>) {
    match core::str::from_utf8(&row.size)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(size) if size == entry.size => {},
        Some(size) => findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            format!("RECORD size {size} does not match {}", entry.size),
        )),
        None => findings.push(integrity_finding(
            "wheel",
            Some(entry.name.clone()),
            PackageFindingCode::InvalidIntegrityMetadata,
            "RECORD size is not an unsigned decimal integer",
        )),
    }
}

fn csv_fields(line: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut index = 0;
    while index < line.len() {
        match line[index] {
            b'"' if quoted && line.get(index + 1) == Some(&b'"') => {
                field.push(b'"');
                index += 2;
            },
            b'"' => {
                quoted = !quoted;
                index += 1;
            },
            b',' if !quoted => {
                fields.push(core::mem::take(&mut field));
                index += 1;
            },
            byte => {
                field.push(byte);
                index += 1;
            },
        }
    }
    if quoted {
        return Err("unterminated quoted field");
    }
    fields.push(field);
    Ok(fields)
}

fn integrity_outcome(
    checked: usize,
    unsupported: bool,
    findings: &[PackageFinding],
) -> (VerificationDimension, Vec<PackageFinding>) {
    let invalid = findings.iter().any(|finding| {
        matches!(
            finding.code(),
            PackageFindingCode::IntegrityMismatch
                | PackageFindingCode::InvalidIntegrityMetadata
                | PackageFindingCode::MissingIntegrityRecord
                | PackageFindingCode::IntegrityReadFailure
        )
    });
    let state = if invalid {
        VerificationDimension::Invalid
    } else if unsupported {
        VerificationDimension::Unsupported
    } else if checked == 0 {
        VerificationDimension::NotPresent
    } else {
        VerificationDimension::Verified
    };
    (state, findings.to_vec())
}

fn integrity_finding(
    profile: &'static str,
    path: Option<Vec<u8>>,
    code: PackageFindingCode,
    detail: impl Into<String>,
) -> PackageFinding {
    PackageFinding::new(profile, path, code, detail)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{EntryDigest, JarProgress, manifest_sections, verify_jar_section};

    #[test]
    fn jar_entry_uses_the_strongest_supported_digest_without_sha1_downgrade() {
        let entry = EntryDigest {
            name: b"payload.bin".to_vec(),
            size: 0,
            sha256: vec![0x25; 32],
            sha384: vec![0x38; 48],
            sha512: vec![0x51; 64],
            metadata_body: None,
        };
        let section = vec![
            (b"Name".to_vec(), entry.name.clone()),
            (
                b"SHA1-Digest".to_vec(),
                STANDARD.encode(b"wrong").into_bytes(),
            ),
            (
                b"SHA-256-Digest".to_vec(),
                STANDARD.encode([0x00; 32]).into_bytes(),
            ),
            (
                b"SHA-512-Digest".to_vec(),
                STANDARD.encode([0x51; 64]).into_bytes(),
            ),
        ];
        let mut by_name = BTreeMap::new();
        by_name.insert(entry.name.as_slice(), &entry);
        let mut progress = JarProgress::default();
        let mut findings = Vec::new();

        verify_jar_section("jar", &section, &by_name, &mut progress, &mut findings);

        assert_eq!(progress.checked, 1);
        assert!(!progress.unsupported);
        assert!(findings.is_empty());
    }

    #[test]
    fn manifest_folding_can_split_a_utf8_code_point_but_unfolded_value_must_be_utf8() {
        let split_utf8 = b"Manifest-Version: 1.0\r\nCreated-By: \xc3\r\n \xa9\r\n\r\n";
        assert!(manifest_sections(split_utf8).is_ok());

        let malformed = b"Manifest-Version: 1.0\r\nCreated-By: \xc3\r\n x\r\n\r\n";
        assert!(manifest_sections(malformed).is_err());
    }
}
