// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded validator for OS/app package formats carried in a ZIP container.
//!
//! Android APK, iOS IPA, and Windows MSIX are all ordinary ZIP archives
//! distinguished by which members they must contain and, for APK, by an optional
//! *APK Signing Block* that sits between the last local entry and the central
//! directory. [`AppPackageValidator`] checks those invariants *without ever
//! extracting the archive*: it reuses the shared bounded central-directory reader
//! (the crate-internal `zip_reader` module) to collect member names, order, compression method,
//! encryption flag, and offsets, then inspects the required members and — for APK
//! — detects the v1/v2/v3 signing schemes. No entry payload is decompressed and
//! the signing block is scanned under a cap, so neither a decompression bomb nor
//! an oversized signing block is expanded.
//!
//! ZIP stores its index at the end of the file, so the input must be seekable;
//! [`AppPackageValidator::validate`] therefore requires [`Read`] + [`Seek`].
//! Central-directory size, entry count, per-entry path length, and the signing
//! block scan are all bounded by the configured [`Limits`].
//!
//! Signature detection is *informational*: a detected scheme or a missing
//! signature is reported as an [`Severity::Info`] finding and never on its own
//! invalidates the profile. The result separates container readability
//! ([`SupportStatus::container_readable`]) from profile conformance
//! ([`SupportStatus::profile_valid`]); every deviation is a typed
//! [`PackageFinding`].

use std::io::{Read, Seek};

use libarchive_oxide_core::Limits;

use super::finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
use super::zip_reader::{
    ZipEntry, check_common_structure, le_u32, le_u64, read_central_directory_with_offset,
    read_exact_at,
};

/// The 16-byte magic that terminates an APK Signing Block.
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Bytes read immediately before the central directory to test for the APK
/// Signing Block: an 8-byte trailing size followed by the 16-byte magic.
const APK_SIG_BLOCK_FOOTER: usize = 24;

/// APK Signature Scheme v2 block id.
const APK_V2_BLOCK_ID: u32 = 0x7109_871a;

/// APK Signature Scheme v3 block id.
const APK_V3_BLOCK_ID: u32 = 0xf053_68c0;

/// Fallback cap on the APK Signing Block id-value region scan when no metadata
/// budget is configured (8 MiB).
const APK_SIG_SCAN_FALLBACK: u64 = 8 * 1024 * 1024;

/// An OS/app package profile carried in a ZIP container.
///
/// Each profile shares the ZIP-structure checks (safe paths, no duplicate
/// members, no encryption, no unsupported coder, no decompression bomb) and adds
/// its own required members; APK additionally detects signing schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppPackageProfile {
    /// Android application package (`.apk`): requires a root `AndroidManifest.xml`
    /// and detects the v1/v2/v3 signing schemes.
    Apk,
    /// iOS application archive (`.ipa`): requires a `Payload/<name>.app/Info.plist`
    /// bundle. Structure only.
    Ipa,
    /// Windows app package (`.msix`/`.appx`): requires `AppxManifest.xml`,
    /// `[Content_Types].xml`, and `AppxBlockMap.xml`, and detects the
    /// `AppxSignature.p7x` signature.
    Msix,
}

impl AppPackageProfile {
    /// Stable lowercase profile label reported on every finding.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Apk => "apk",
            Self::Ipa => "ipa",
            Self::Msix => "msix",
        }
    }
}

/// Signing schemes detected in an OS/app package.
///
/// The fields are populated per profile: the `apk_*` fields apply to the APK
/// profile, and [`AppSignatureReport::embedded_signature`] to MSIX. All are
/// `false` for a profile that carries no ZIP-level signature (for example IPA,
/// whose code signature lives inside the `.app` bundle).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct AppSignatureReport {
    apk_v1: bool,
    apk_v2: bool,
    apk_v3: bool,
    apk_signing_block: bool,
    embedded_signature: bool,
}

impl AppSignatureReport {
    /// Whether an APK v1 (JAR-style `META-INF`) signature pair was present.
    #[must_use]
    pub const fn apk_v1(self) -> bool {
        self.apk_v1
    }

    /// Whether the APK Signature Scheme v2 block id was present.
    #[must_use]
    pub const fn apk_v2(self) -> bool {
        self.apk_v2
    }

    /// Whether the APK Signature Scheme v3 block id was present.
    #[must_use]
    pub const fn apk_v3(self) -> bool {
        self.apk_v3
    }

    /// Whether the APK Signing Block magic was present before the central directory.
    #[must_use]
    pub const fn apk_signing_block(self) -> bool {
        self.apk_signing_block
    }

    /// Whether an embedded package signature was present (MSIX `AppxSignature.p7x`).
    #[must_use]
    pub const fn embedded_signature(self) -> bool {
        self.embedded_signature
    }

    /// Whether any signing scheme was detected.
    #[must_use]
    pub const fn any(self) -> bool {
        self.apk_v1
            || self.apk_v2
            || self.apk_v3
            || self.apk_signing_block
            || self.embedded_signature
    }
}

/// A bounded, per-package validator for OS/app package profiles.
///
/// The validator never extracts the archive: it reads the central directory to
/// collect member names, order, compression methods, and encryption flags, and
/// for APK scans the signing block under a cap. Resource use is bounded by the
/// configured [`Limits`].
#[derive(Debug, Clone, Copy)]
pub struct AppPackageValidator {
    limits: Limits,
    profile: AppPackageProfile,
}

impl AppPackageValidator {
    /// Creates a validator for `profile` with the safe finite limits.
    #[must_use]
    pub const fn new(profile: AppPackageProfile) -> Self {
        Self {
            limits: Limits::safe(),
            profile,
        }
    }

    /// Creates a validator for the Android APK profile.
    #[must_use]
    pub const fn apk() -> Self {
        Self::new(AppPackageProfile::Apk)
    }

    /// Creates a validator for the iOS IPA profile.
    #[must_use]
    pub const fn ipa() -> Self {
        Self::new(AppPackageProfile::Ipa)
    }

    /// Creates a validator for the Windows MSIX profile.
    #[must_use]
    pub const fn msix() -> Self {
        Self::new(AppPackageProfile::Msix)
    }

    /// Replaces the resource budgets bounding the container scan.
    ///
    /// [`Limits::metadata_bytes`] bounds the central directory and the APK
    /// Signing Block id-value scan, [`Limits::entries`] bounds the member count,
    /// and [`Limits::with_decoded_total`] is the decompression-bomb budget: the
    /// summed declared uncompressed size of every member is refused when it
    /// exceeds this value.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The profile this validator checks.
    #[must_use]
    pub const fn profile(&self) -> AppPackageProfile {
        self.profile
    }

    /// Resource budgets bounding the container scan.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Validates an untrusted OS/app package without extracting it.
    ///
    /// The archive is never materialized and no entry payload is decompressed.
    /// The returned [`AppPackageValidation`] separates container readability from
    /// profile conformance, lists every typed finding, and carries the detected
    /// signing schemes.
    pub fn validate<R: Read + Seek>(&self, mut reader: R) -> AppPackageValidation {
        let profile = self.profile;
        let label = profile.label();
        let mut findings = Vec::new();

        let (entries, central_offset) =
            match read_central_directory_with_offset(&mut reader, self.limits) {
                Ok(pair) => pair,
                Err(detail) => {
                    findings.push(PackageFinding::new(
                        label,
                        None,
                        PackageFindingCode::ContainerUnreadable,
                        detail,
                    ));
                    return AppPackageValidation {
                        status: SupportStatus::new(false, false),
                        findings,
                        profile,
                        signatures: AppSignatureReport::default(),
                    };
                },
            };

        check_common_structure(label, &entries, self.limits, &mut findings);
        let (profile_satisfied, signatures) = match profile {
            AppPackageProfile::Apk => {
                self.check_apk(label, &entries, central_offset, &mut reader, &mut findings)
            },
            AppPackageProfile::Ipa => (
                check_ipa(label, &entries, &mut findings),
                AppSignatureReport::default(),
            ),
            AppPackageProfile::Msix => check_msix(label, &entries, &mut findings),
        };

        let blocking = findings
            .iter()
            .any(|finding| finding.severity() >= Severity::Warning);
        let profile_valid = profile_satisfied && !blocking;
        AppPackageValidation {
            status: SupportStatus::new(true, profile_valid),
            findings,
            profile,
            signatures,
        }
    }

    /// Checks the APK profile and detects its signing schemes.
    fn check_apk<R: Read + Seek>(
        &self,
        label: &'static str,
        entries: &[ZipEntry],
        central_offset: u64,
        reader: &mut R,
        findings: &mut Vec<PackageFinding>,
    ) -> (bool, AppSignatureReport) {
        let mut satisfied = true;
        if !entries
            .iter()
            .any(|entry| entry.name == b"AndroidManifest.xml")
        {
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::MissingRequiredMember,
                "archive has no root AndroidManifest.xml member",
            ));
            satisfied = false;
        }

        let mut signatures = AppSignatureReport {
            apk_v1: detect_apk_v1(entries),
            ..AppSignatureReport::default()
        };
        self.detect_apk_signing_block(central_offset, reader, &mut signatures, label, findings);
        report_signatures(label, &describe_apk(signatures), signatures.any(), findings);
        (satisfied, signatures)
    }

    /// Detects and bounded-scans the APK Signing Block sitting immediately before
    /// the central directory, recording the v2/v3 scheme ids it carries.
    fn detect_apk_signing_block<R: Read + Seek>(
        &self,
        central_offset: u64,
        reader: &mut R,
        signatures: &mut AppSignatureReport,
        label: &'static str,
        findings: &mut Vec<PackageFinding>,
    ) {
        if central_offset < APK_SIG_BLOCK_FOOTER as u64 {
            return;
        }
        let mut footer = [0_u8; APK_SIG_BLOCK_FOOTER];
        if read_exact_at(
            reader,
            central_offset - APK_SIG_BLOCK_FOOTER as u64,
            &mut footer,
        )
        .is_err()
        {
            return;
        }
        if &footer[8..24] != APK_SIG_BLOCK_MAGIC {
            return;
        }
        signatures.apk_signing_block = true;
        let block_size = le_u64(&footer, 0);

        // block_start = central_offset - 8 (leading size) - block_size.
        let Some(block_start) = central_offset
            .checked_sub(8)
            .and_then(|value| value.checked_sub(block_size))
        else {
            return;
        };
        // The id-value region runs from block_start + 8 up to the 24-byte footer.
        let Some(region_start) = block_start.checked_add(8) else {
            return;
        };
        let region_end = central_offset - APK_SIG_BLOCK_FOOTER as u64;
        if region_start > region_end {
            return;
        }
        let full_len = region_end - region_start;
        let cap = self
            .limits
            .metadata_bytes()
            .map_or(APK_SIG_SCAN_FALLBACK, |value| value as u64);
        let read_len = full_len.min(cap);
        if full_len > cap {
            findings.push(
                PackageFinding::new(
                    label,
                    None,
                    PackageFindingCode::SigningSchemeDetected,
                    "APK Signing Block exceeds the scan budget; scanned a bounded prefix only",
                )
                .with_severity(Severity::Info),
            );
        }
        let Ok(read_len) = usize::try_from(read_len) else {
            return;
        };
        let mut region = vec![0_u8; read_len];
        if read_exact_at(reader, region_start, &mut region).is_err() {
            return;
        }
        scan_apk_id_value_pairs(&region, signatures);
    }
}

/// Scans an APK Signing Block id-value region for the v2 and v3 scheme ids.
///
/// Each pair is `[u64 length][u32 id][value(length - 4)]`; the scan is naturally
/// bounded by the (already capped) region length and stops on any malformed or
/// straddling record.
fn scan_apk_id_value_pairs(region: &[u8], signatures: &mut AppSignatureReport) {
    let mut cursor = 0_usize;
    while cursor + 12 <= region.len() {
        let pair_len = le_u64(region, cursor);
        if pair_len < 4 {
            break;
        }
        let Ok(pair_len) = usize::try_from(pair_len) else {
            break;
        };
        let Some(next) = cursor
            .checked_add(8)
            .and_then(|value| value.checked_add(pair_len))
        else {
            break;
        };
        if next > region.len() {
            break;
        }
        let id = le_u32(region, cursor + 8);
        match id {
            APK_V2_BLOCK_ID => signatures.apk_v2 = true,
            APK_V3_BLOCK_ID => signatures.apk_v3 = true,
            _ => {},
        }
        cursor = next;
    }
}

/// Detects an APK v1 signature: a `META-INF/*.SF` paired with a
/// `META-INF/*.(RSA|DSA|EC)` signature file.
fn detect_apk_v1(entries: &[ZipEntry]) -> bool {
    let has_sf = entries
        .iter()
        .any(|entry| is_meta_inf(&entry.name) && ends_with(&entry.name, b".SF"));
    let has_sig = entries.iter().any(|entry| {
        is_meta_inf(&entry.name)
            && (ends_with(&entry.name, b".RSA")
                || ends_with(&entry.name, b".DSA")
                || ends_with(&entry.name, b".EC"))
    });
    has_sf && has_sig
}

/// Builds a human-readable list of the detected APK signing schemes.
fn describe_apk(signatures: AppSignatureReport) -> String {
    let mut schemes = Vec::new();
    if signatures.apk_v1 {
        schemes.push("v1");
    }
    if signatures.apk_v2 {
        schemes.push("v2");
    }
    if signatures.apk_v3 {
        schemes.push("v3");
    }
    if schemes.is_empty() && signatures.apk_signing_block {
        return "APK Signing Block present with no recognized v2/v3 id".to_string();
    }
    format!("detected APK signing schemes: {}", schemes.join(", "))
}

/// Checks the IPA profile: a `Payload/<name>.app/Info.plist` bundle must exist.
fn check_ipa(
    label: &'static str,
    entries: &[ZipEntry],
    findings: &mut Vec<PackageFinding>,
) -> bool {
    if entries.iter().any(|entry| is_ipa_info_plist(&entry.name)) {
        return true;
    }
    findings.push(PackageFinding::new(
        label,
        None,
        PackageFindingCode::MissingRequiredMember,
        "archive has no Payload/<name>.app/Info.plist bundle",
    ));
    false
}

/// Checks the MSIX profile and detects its `AppxSignature.p7x` signature.
fn check_msix(
    label: &'static str,
    entries: &[ZipEntry],
    findings: &mut Vec<PackageFinding>,
) -> (bool, AppSignatureReport) {
    let mut satisfied = true;
    for required in [
        b"AppxManifest.xml".as_slice(),
        b"[Content_Types].xml".as_slice(),
        b"AppxBlockMap.xml".as_slice(),
    ] {
        if !entries.iter().any(|entry| entry.name == required) {
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::MissingRequiredMember,
                format!(
                    "archive has no {} member",
                    String::from_utf8_lossy(required)
                ),
            ));
            satisfied = false;
        }
    }
    let signatures = AppSignatureReport {
        embedded_signature: entries
            .iter()
            .any(|entry| entry.name == b"AppxSignature.p7x"),
        ..AppSignatureReport::default()
    };
    report_signatures(
        label,
        "detected MSIX AppxSignature.p7x signature",
        signatures.embedded_signature,
        findings,
    );
    (satisfied, signatures)
}

/// Pushes an informational signature finding: [`PackageFindingCode::SigningSchemeDetected`]
/// when a scheme was found, or [`PackageFindingCode::UnsignedPackage`] otherwise.
fn report_signatures(
    label: &'static str,
    detail: &str,
    signed: bool,
    findings: &mut Vec<PackageFinding>,
) {
    if signed {
        findings.push(PackageFinding::new(
            label,
            None,
            PackageFindingCode::SigningSchemeDetected,
            detail.to_string(),
        ));
    } else {
        findings.push(PackageFinding::new(
            label,
            None,
            PackageFindingCode::UnsignedPackage,
            "no package signature was detected",
        ));
    }
}

/// Whether `name` sits directly under the `META-INF/` directory.
fn is_meta_inf(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(b"META-INF/") else {
        return false;
    };
    !rest.is_empty() && !rest.contains(&b'/')
}

/// Whether `name` is a `Payload/<name>.app/Info.plist` at the bundle root.
///
/// The path must start with `Payload/`, contain exactly one `.app/` segment, and
/// end with `Info.plist` directly inside that `.app` bundle.
fn is_ipa_info_plist(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(b"Payload/") else {
        return false;
    };
    let Some(app_end) = find_subslice(rest, b".app/") else {
        return false;
    };
    let bundle = &rest[..app_end];
    // The bundle name must be a single path segment (no nested directories).
    if bundle.is_empty() || bundle.contains(&b'/') {
        return false;
    }
    let inside = &rest[app_end + b".app/".len()..];
    inside == b"Info.plist"
}

/// Case-sensitive suffix test on archive-native bytes.
fn ends_with(name: &[u8], suffix: &[u8]) -> bool {
    name.len() >= suffix.len() && &name[name.len() - suffix.len()..] == suffix
}

/// Position of the first occurrence of `needle` within `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Result of validating one OS/app package.
#[derive(Debug, Clone)]
pub struct AppPackageValidation {
    status: SupportStatus,
    findings: Vec<PackageFinding>,
    profile: AppPackageProfile,
    signatures: AppSignatureReport,
}

impl AppPackageValidation {
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
    pub const fn profile(&self) -> AppPackageProfile {
        self.profile
    }

    /// The signing schemes detected in the package.
    #[must_use]
    pub const fn signatures(&self) -> AppSignatureReport {
        self.signatures
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
