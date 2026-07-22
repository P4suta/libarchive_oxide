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
//!
//! The shared bounded central-directory reader lives in the crate-internal
//! `zip_reader` module and is reused by the OS/app package profiles in
//! [`super::app_profile`].

use std::io::{Read, Seek};

use libarchive_oxide_core::Limits;

use super::finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
use super::zip_reader::{
    LOCAL_HEADER_LEN, METHOD_STORE, ZipEntry, check_common_structure, le_u16,
    read_central_directory, read_exact_at,
};

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

        check_common_structure(label, &entries, self.limits, &mut findings);
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
