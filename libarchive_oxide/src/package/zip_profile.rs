// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded validator for ZIP-container package formats.
//!
//! JAR, `NuGet` (`.nupkg`), Python wheel (`.whl`), and EPUB are all ordinary ZIP
//! archives distinguished only by which members they must contain and, for
//! EPUB, by a structural constraint on the first member. [`ZipPackageValidator`]
//! checks those invariants *without ever extracting the archive*: it reads the
//! central directory to collect each member's name, order, compression method,
//! and encryption flag, and — for EPUB only — reads the single small `mimetype`
//! member body. No entry payload is decompressed, so a decompression bomb is
//! refused by budget rather than expanded.
//!
//! ZIP stores its index (the central directory) at the end of the file, so the
//! input must be seekable; [`ZipPackageValidator::validate`] therefore requires
//! [`Read`] + [`Seek`]. Central-directory size, entry count, and per-entry path
//! length are all bounded by the configured [`Limits`], matching the seekable
//! ZIP reader.
//!
//! The result separates two questions: could the ZIP container be read at all
//! ([`SupportStatus::container_readable`]) and did the archive satisfy its
//! package profile ([`SupportStatus::profile_valid`]). Every deviation is
//! reported as a typed [`PackageFinding`].

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use libarchive_oxide_core::{ArchivePath, Limits, PathEncoding};

use super::finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
use crate::path::sanitize_archive_path;

/// Store compression method (no compression).
const METHOD_STORE: u16 = 0;

/// Deflate compression method.
const METHOD_DEFLATE: u16 = 8;

/// `WinZip` AES compression method (the payload is encrypted).
const METHOD_AES: u16 = 99;

/// Bit 0 of the ZIP general-purpose flags: the entry is encrypted.
const FLAG_ENCRYPTED: u16 = 0x0001;

/// Bit 11 of the ZIP general-purpose flags: names and comments are UTF-8.
const FLAG_UTF8: u16 = 0x0800;

/// Fixed size of a ZIP local file header, before the variable name and extra.
const LOCAL_HEADER_LEN: usize = 30;

/// Fixed size of a ZIP central-directory file header.
const CENTRAL_HEADER_LEN: usize = 46;

/// Minimum size of an end-of-central-directory record.
const EOCD_MIN: usize = 22;

/// Size of a ZIP64 end-of-central-directory locator.
const ZIP64_LOCATOR_LEN: usize = 20;

/// Largest tail scanned for the end-of-central-directory signature: the maximum
/// 16-bit archive comment plus the fixed record.
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;

/// The exact `mimetype` body an EPUB must carry.
const EPUB_MEDIA_TYPE: &[u8] = b"application/epub+zip";

/// A ZIP-container package profile.
///
/// Each profile shares the ZIP-structure checks (safe paths, no duplicate
/// members, no encryption, no unsupported coder, no decompression bomb) and adds
/// its own required members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZipPackageProfile {
    /// Java archive: requires `META-INF/MANIFEST.MF`.
    Jar,
    /// `NuGet` package (`.nupkg`): requires `[Content_Types].xml` and exactly one
    /// root `*.nuspec` manifest.
    NuGet,
    /// Python wheel (`.whl`): requires `*.dist-info/METADATA`, `*.dist-info/RECORD`,
    /// and `*.dist-info/WHEEL`.
    Wheel,
    /// EPUB: requires a first, stored `mimetype` member whose body is
    /// `application/epub+zip`, plus `META-INF/container.xml`.
    Epub,
}

impl ZipPackageProfile {
    /// Stable lowercase profile label reported on every finding.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Jar => "jar",
            Self::NuGet => "nuget",
            Self::Wheel => "wheel",
            Self::Epub => "epub",
        }
    }
}

/// A bounded, per-package validator for ZIP-container package profiles.
///
/// The validator never extracts the archive: it reads the central directory to
/// collect member names, order, compression methods, and encryption flags, and
/// for EPUB reads only the small `mimetype` body. Resource use is bounded by the
/// configured [`Limits`].
#[derive(Debug, Clone, Copy)]
pub struct ZipPackageValidator {
    limits: Limits,
    profile: ZipPackageProfile,
}

impl ZipPackageValidator {
    /// Creates a validator for `profile` with the safe finite limits.
    #[must_use]
    pub const fn new(profile: ZipPackageProfile) -> Self {
        Self {
            limits: Limits::safe(),
            profile,
        }
    }

    /// Creates a validator for the JAR profile.
    #[must_use]
    pub const fn jar() -> Self {
        Self::new(ZipPackageProfile::Jar)
    }

    /// Creates a validator for the `NuGet` profile.
    #[must_use]
    pub const fn nuget() -> Self {
        Self::new(ZipPackageProfile::NuGet)
    }

    /// Creates a validator for the Python wheel profile.
    #[must_use]
    pub const fn wheel() -> Self {
        Self::new(ZipPackageProfile::Wheel)
    }

    /// Creates a validator for the EPUB profile.
    #[must_use]
    pub const fn epub() -> Self {
        Self::new(ZipPackageProfile::Epub)
    }

    /// Replaces the resource budgets bounding the container scan.
    ///
    /// [`Limits::metadata_bytes`] bounds the central directory, [`Limits::entries`]
    /// bounds the member count, and [`Limits::with_decoded_total`] is the
    /// decompression-bomb budget: the summed declared uncompressed size of every
    /// member is refused when it exceeds this value.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The profile this validator checks.
    #[must_use]
    pub const fn profile(&self) -> ZipPackageProfile {
        self.profile
    }

    /// Resource budgets bounding the container scan.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Validates an untrusted ZIP-container package without extracting it.
    ///
    /// The archive is never materialized and no entry payload is decompressed.
    /// The returned [`ZipPackageValidation`] separates container readability from
    /// profile conformance and lists every typed finding.
    pub fn validate<R: Read + Seek>(&self, mut reader: R) -> ZipPackageValidation {
        let profile = self.profile;
        let label = profile.label();
        let mut findings = Vec::new();

        let entries = match read_central_directory(&mut reader, self.limits) {
            Ok(entries) => entries,
            Err(detail) => {
                findings.push(PackageFinding::new(
                    label,
                    None,
                    PackageFindingCode::ContainerUnreadable,
                    detail,
                ));
                return ZipPackageValidation {
                    status: SupportStatus::new(false, false),
                    findings,
                    profile,
                };
            },
        };

        self.check_common(&entries, &mut findings);
        let profile_satisfied = match profile {
            ZipPackageProfile::Jar => check_jar(label, &entries, &mut findings),
            ZipPackageProfile::NuGet => check_nuget(label, &entries, &mut findings),
            ZipPackageProfile::Wheel => check_wheel(label, &entries, &mut findings),
            ZipPackageProfile::Epub => check_epub(label, &entries, &mut reader, &mut findings),
        };

        let blocking = findings
            .iter()
            .any(|finding| finding.severity() >= Severity::Warning);
        let profile_valid = profile_satisfied && !blocking;
        ZipPackageValidation {
            status: SupportStatus::new(true, profile_valid),
            findings,
            profile,
        }
    }

    /// Applies the ZIP-structure checks shared by every profile.
    fn check_common(&self, entries: &[ZipEntry], findings: &mut Vec<PackageFinding>) {
        let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
        let mut decoded_total: u64 = 0;
        let mut bomb_reported = false;
        for entry in entries {
            let path = ArchivePath::from_encoded(entry.name.clone(), entry.encoding);
            match sanitize_archive_path(&path) {
                None => findings.push(PackageFinding::new(
                    self.profile.label(),
                    Some(entry.name.clone()),
                    PackageFindingCode::UnsafeEntryPath,
                    "member name is absolute, traversing, or unrepresentable",
                )),
                Some(safe) => {
                    if !seen.insert(safe) {
                        findings.push(PackageFinding::new(
                            self.profile.label(),
                            Some(entry.name.clone()),
                            PackageFindingCode::DuplicateEntryPath,
                            "member path repeats within the archive",
                        ));
                    }
                },
            }

            if entry.is_encrypted() {
                findings.push(PackageFinding::new(
                    self.profile.label(),
                    Some(entry.name.clone()),
                    PackageFindingCode::UnexpectedEncryption,
                    "member is encrypted, which this profile forbids",
                ));
            } else if entry.method != METHOD_STORE && entry.method != METHOD_DEFLATE {
                findings.push(PackageFinding::unsupported_method(
                    self.profile.label(),
                    Some(entry.name.clone()),
                    format!(
                        "member uses compression method {} this build cannot decode",
                        entry.method
                    ),
                ));
            }

            decoded_total = decoded_total.saturating_add(entry.uncompressed_size);
            if !bomb_reported
                && self
                    .limits
                    .decoded_total()
                    .is_some_and(|limit| decoded_total > limit)
            {
                bomb_reported = true;
                findings.push(PackageFinding::new(
                    self.profile.label(),
                    None,
                    PackageFindingCode::DecompressionBomb,
                    "declared uncompressed size exceeds the decompression budget",
                ));
            }
        }
    }
}

/// Checks the JAR profile: `META-INF/MANIFEST.MF` must be present.
fn check_jar(
    label: &'static str,
    entries: &[ZipEntry],
    findings: &mut Vec<PackageFinding>,
) -> bool {
    if entries
        .iter()
        .any(|entry| entry.name == b"META-INF/MANIFEST.MF")
    {
        return true;
    }
    findings.push(PackageFinding::new(
        label,
        None,
        PackageFindingCode::MissingRequiredMember,
        "archive has no META-INF/MANIFEST.MF member",
    ));
    false
}

/// Checks the `NuGet` profile: `[Content_Types].xml` and exactly one root
/// `*.nuspec` manifest must be present.
fn check_nuget(
    label: &'static str,
    entries: &[ZipEntry],
    findings: &mut Vec<PackageFinding>,
) -> bool {
    let mut ok = true;
    if !entries
        .iter()
        .any(|entry| entry.name == b"[Content_Types].xml")
    {
        findings.push(PackageFinding::new(
            label,
            None,
            PackageFindingCode::MissingRequiredMember,
            "archive has no [Content_Types].xml member",
        ));
        ok = false;
    }
    let mut nuspecs = entries.iter().filter(|entry| is_root_nuspec(&entry.name));
    match nuspecs.next() {
        None => {
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::MissingRequiredMember,
                "archive has no root *.nuspec manifest",
            ));
            ok = false;
        },
        Some(_) => {
            if let Some(extra) = nuspecs.next() {
                findings.push(PackageFinding::new(
                    label,
                    Some(extra.name.clone()),
                    PackageFindingCode::DuplicateMember,
                    "archive has more than one root *.nuspec manifest",
                ));
                ok = false;
            }
        },
    }
    ok
}

/// Checks the wheel profile: the `*.dist-info/METADATA`, `RECORD`, and `WHEEL`
/// members must be present.
fn check_wheel(
    label: &'static str,
    entries: &[ZipEntry],
    findings: &mut Vec<PackageFinding>,
) -> bool {
    let mut ok = true;
    for suffix in [
        b".dist-info/METADATA".as_slice(),
        b".dist-info/RECORD".as_slice(),
        b".dist-info/WHEEL".as_slice(),
    ] {
        if !entries.iter().any(|entry| ends_with(&entry.name, suffix)) {
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::MissingRequiredMember,
                format!("archive has no *{} member", String::from_utf8_lossy(suffix)),
            ));
            ok = false;
        }
    }
    ok
}

/// Checks the EPUB profile: a first, stored `mimetype` member with the exact
/// media type, plus `META-INF/container.xml`.
fn check_epub<R: Read + Seek>(
    label: &'static str,
    entries: &[ZipEntry],
    reader: &mut R,
    findings: &mut Vec<PackageFinding>,
) -> bool {
    let mut ok = true;
    match entries.iter().find(|entry| entry.name == b"mimetype") {
        None => {
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::MissingRequiredMember,
                "archive has no mimetype member",
            ));
            ok = false;
        },
        Some(mimetype) => {
            let is_first = entries
                .iter()
                .all(|entry| mimetype.local_offset <= entry.local_offset);
            if !is_first {
                findings.push(PackageFinding::new(
                    label,
                    Some(mimetype.name.clone()),
                    PackageFindingCode::MimetypeNotFirst,
                    "mimetype is not the first member in the archive",
                ));
                ok = false;
            }
            if mimetype.method != METHOD_STORE {
                findings.push(PackageFinding::new(
                    label,
                    Some(mimetype.name.clone()),
                    PackageFindingCode::MimetypeNotStored,
                    "mimetype member is compressed rather than stored",
                ));
                ok = false;
            } else if !mimetype_body_matches(reader, mimetype) {
                findings.push(PackageFinding::new(
                    label,
                    Some(mimetype.name.clone()),
                    PackageFindingCode::MimetypeInvalidContent,
                    "mimetype body is not application/epub+zip",
                ));
                ok = false;
            }
        },
    }
    if !entries
        .iter()
        .any(|entry| entry.name == b"META-INF/container.xml")
    {
        findings.push(PackageFinding::new(
            label,
            None,
            PackageFindingCode::MissingRequiredMember,
            "archive has no META-INF/container.xml member",
        ));
        ok = false;
    }
    ok
}

/// Whether `name` is a root-level `*.nuspec` file (no directory separator).
fn is_root_nuspec(name: &[u8]) -> bool {
    !name.contains(&b'/') && ends_with(name, b".nuspec")
}

/// Case-sensitive suffix test on archive-native bytes.
fn ends_with(name: &[u8], suffix: &[u8]) -> bool {
    name.len() >= suffix.len() && &name[name.len() - suffix.len()..] == suffix
}

/// Reads and compares a stored EPUB `mimetype` body against the media type.
///
/// Returns `false` on any read error or mismatch; the caller then reports an
/// invalid-mimetype finding. Only the exact media-type length is ever read, so
/// the check is naturally bounded.
fn mimetype_body_matches<R: Read + Seek>(reader: &mut R, entry: &ZipEntry) -> bool {
    if entry.uncompressed_size != EPUB_MEDIA_TYPE.len() as u64 {
        return false;
    }
    let mut header = [0_u8; LOCAL_HEADER_LEN];
    if read_exact_at(reader, entry.local_offset, &mut header).is_err() {
        return false;
    }
    if &header[..4] != b"PK\x03\x04" {
        return false;
    }
    let name_len = u64::from(le_u16(&header, 26));
    let extra_len = u64::from(le_u16(&header, 28));
    let Some(data_offset) = entry
        .local_offset
        .checked_add(LOCAL_HEADER_LEN as u64)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
    else {
        return false;
    };
    let mut body = [0_u8; EPUB_MEDIA_TYPE.len()];
    if read_exact_at(reader, data_offset, &mut body).is_err() {
        return false;
    }
    body == EPUB_MEDIA_TYPE
}

/// One collected central-directory member.
#[derive(Debug, Clone)]
struct ZipEntry {
    name: Vec<u8>,
    encoding: PathEncoding,
    method: u16,
    flags: u16,
    uncompressed_size: u64,
    local_offset: u64,
}

impl ZipEntry {
    /// Whether the member is encrypted (traditional or `WinZip` AES).
    fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == METHOD_AES
    }
}

/// Reads exactly `buffer.len()` bytes starting at `offset`.
fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> std::io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer)
}

/// Reads a little-endian `u16` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 2` bytes.
fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Reads a little-endian `u32` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 4` bytes.
fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Reads a little-endian `u64` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 8` bytes.
fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Locates and parses the central directory into collected members.
///
/// Errors carry a human-readable detail used for the `ContainerUnreadable`
/// finding. Every allocation is bounded by `limits`.
fn read_central_directory<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<Vec<ZipEntry>, String> {
    let end = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("cannot measure ZIP length: {error}"))?;
    let tail_length = end.min(EOCD_SEARCH);
    let tail_start = end - tail_length;
    let tail_len =
        usize::try_from(tail_length).map_err(|_| "EOCD search range exceeds address space")?;
    let mut tail = vec![0_u8; tail_len];
    read_exact_at(reader, tail_start, &mut tail)
        .map_err(|error| format!("cannot read ZIP tail: {error}"))?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or("end-of-central-directory record not found")?;
    if tail.len() - eocd < EOCD_MIN {
        return Err("truncated end-of-central-directory record".to_string());
    }
    let record = &tail[eocd..];
    let mut count = u64::from(le_u16(record, 10));
    let mut central_offset = u64::from(le_u32(record, 16));
    let eocd_absolute = tail_start + eocd as u64;

    if count == u64::from(u16::MAX) || central_offset == u64::from(u32::MAX) {
        let (zip64_count, zip64_offset) = read_zip64_directory(reader, eocd_absolute)?;
        count = zip64_count;
        central_offset = zip64_offset;
    }

    if limits.entries().is_some_and(|limit| count > limit) {
        return Err("central-directory entry count exceeds limit".to_string());
    }

    reader
        .seek(SeekFrom::Start(central_offset))
        .map_err(|error| format!("cannot seek to central directory: {error}"))?;
    let capacity = usize::try_from(count.min(4096)).unwrap_or(4096);
    let mut entries = Vec::with_capacity(capacity);
    let mut metadata_used: usize = 0;
    for _ in 0..count {
        let mut fixed = [0_u8; CENTRAL_HEADER_LEN];
        reader
            .read_exact(&mut fixed)
            .map_err(|error| format!("cannot read central-directory header: {error}"))?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err("bad central-directory signature".to_string());
        }
        let flags = le_u16(&fixed, 8);
        let method = le_u16(&fixed, 10);
        let uncompressed32 = le_u32(&fixed, 24);
        let compressed32 = le_u32(&fixed, 20);
        let name_length = usize::from(le_u16(&fixed, 28));
        let extra_length = usize::from(le_u16(&fixed, 30));
        let comment_length = usize::from(le_u16(&fixed, 32));
        let local32 = le_u32(&fixed, 42);
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or("central variable fields overflow")?;
        metadata_used = metadata_used
            .checked_add(variable_length)
            .and_then(|value| value.checked_add(core::mem::size_of::<ZipEntry>()))
            .ok_or("metadata accounting overflow")?;
        if limits
            .metadata_bytes()
            .is_some_and(|limit| metadata_used > limit)
        {
            return Err("central-directory metadata exceeds limit".to_string());
        }
        let mut variable = vec![0_u8; variable_length];
        reader
            .read_exact(&mut variable)
            .map_err(|error| format!("cannot read central-directory record: {error}"))?;
        let raw_name = &variable[..name_length];
        let extra = &variable[name_length..name_length + extra_length];
        let (uncompressed_size, local_offset) =
            zip64_sizes(extra, uncompressed32, compressed32, local32)?;
        if limits
            .path_bytes()
            .is_some_and(|limit| raw_name.len() > limit)
        {
            return Err("ZIP pathname exceeds configured limit".to_string());
        }
        let encoding = if flags & FLAG_UTF8 != 0 || core::str::from_utf8(raw_name).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        entries.push(ZipEntry {
            name: raw_name.to_vec(),
            encoding,
            method,
            flags,
            uncompressed_size,
            local_offset,
        });
    }
    Ok(entries)
}

/// Follows the ZIP64 locator and record to recover the true entry count and
/// central-directory offset.
fn read_zip64_directory<R: Read + Seek>(
    reader: &mut R,
    eocd_absolute: u64,
) -> Result<(u64, u64), String> {
    if eocd_absolute < ZIP64_LOCATOR_LEN as u64 {
        return Err("ZIP64 locator is missing".to_string());
    }
    let mut locator = [0_u8; ZIP64_LOCATOR_LEN];
    read_exact_at(
        reader,
        eocd_absolute - ZIP64_LOCATOR_LEN as u64,
        &mut locator,
    )
    .map_err(|error| format!("cannot read ZIP64 locator: {error}"))?;
    if &locator[..4] != b"PK\x06\x07" {
        return Err("bad ZIP64 locator".to_string());
    }
    let record_offset = le_u64(&locator, 8);
    let mut record = [0_u8; 56];
    read_exact_at(reader, record_offset, &mut record)
        .map_err(|error| format!("cannot read ZIP64 end record: {error}"))?;
    if &record[..4] != b"PK\x06\x06" {
        return Err("bad ZIP64 end record".to_string());
    }
    Ok((le_u64(&record, 32), le_u64(&record, 48)))
}

/// Resolves the declared uncompressed size and local-header offset, following a
/// ZIP64 extra field whenever the 32-bit central-directory field is the `0xFFFF...`
/// sentinel.
fn zip64_sizes(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local: u32,
) -> Result<(u64, u64), String> {
    let mut zip64: &[u8] = &[];
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le_u16(extra, cursor);
        let length = usize::from(le_u16(extra, cursor + 2));
        let start = cursor + 4;
        let finish = start
            .checked_add(length)
            .ok_or("ZIP64 extra length overflow")?;
        let value = extra
            .get(start..finish)
            .ok_or("truncated ZIP extra field")?;
        if id == 0x0001 {
            zip64 = value;
            break;
        }
        cursor = finish;
    }
    let mut take = || -> Result<u64, String> {
        if zip64.len() < 8 {
            return Err("truncated ZIP64 value".to_string());
        }
        let value = le_u64(zip64, 0);
        zip64 = &zip64[8..];
        Ok(value)
    };
    let uncompressed_size = if uncompressed == u32::MAX {
        take()?
    } else {
        u64::from(uncompressed)
    };
    // The compressed size follows the uncompressed size in the ZIP64 record, so
    // it must be consumed even though this validator never decompresses.
    if compressed == u32::MAX {
        take()?;
    }
    let local_offset = if local == u32::MAX {
        take()?
    } else {
        u64::from(local)
    };
    Ok((uncompressed_size, local_offset))
}

/// Result of validating one ZIP-container package.
#[derive(Debug, Clone)]
pub struct ZipPackageValidation {
    status: SupportStatus,
    findings: Vec<PackageFinding>,
    profile: ZipPackageProfile,
}

impl ZipPackageValidation {
    /// Separated container-readability and profile-conformance verdict.
    #[must_use]
    pub const fn status(&self) -> SupportStatus {
        self.status
    }

    /// Whether the ZIP central directory could be parsed.
    #[must_use]
    pub const fn container_readable(&self) -> bool {
        self.status.container_readable()
    }

    /// Whether the archive satisfied its profile with no blocking findings.
    #[must_use]
    pub const fn profile_valid(&self) -> bool {
        self.status.profile_valid()
    }

    /// The profile that was checked.
    #[must_use]
    pub const fn profile(&self) -> ZipPackageProfile {
        self.profile
    }

    /// Every typed finding, in discovery order.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Whether any finding carries the given code.
    #[must_use]
    pub fn has_code(&self, code: PackageFindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code() == code)
    }
}
