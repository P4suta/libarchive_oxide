// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-validation subcommands for the unified `oxarchive` binary.
//!
//! These commands drive [`PackageVerifier`] from the dedicated
//! `libarchive_oxide-package` crate and render structure, integrity,
//! signature-validity, and trust as separate machine fields.
//!
//! Every subcommand emits one JSON object regardless of any top-level `--json`
//! flag. Exit codes follow the shared contract: 0 when the package satisfied
//! its profile, 1 when the container was read but the profile was not satisfied
//! (or a runtime error occurred), and 2 for a usage failure.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use libarchive_oxide_package::{
    AlpineRsaPublicKey, AndroidApkV4Revision, AppPackageProfile, PackageFinding, PackageVerifier,
    TrustPolicy, VerificationReport, ZipPackageProfile,
};
use serde_json::{Value, json};

use crate::oxarchive::{JSON_SCHEMA_VERSION, hex, print_json};
use crate::{CliError, CliResult};

const PACKAGE_HELP: &str = "\
oxarchive package - bounded software-package validation

Usage:
  oxarchive package validate PACKAGE --type <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix> [--idsig-file PATH] [TRUST FLAGS]

The validator inspects the package structure without extracting it and emits one
JSON object: schema_version, type=\"package_validation\", profile,
container_readable, profile_valid, and the shared typed findings (severity,
code, path, detail).

PACKAGE may be '-' to read standard input for the deb, rpm, and alpine-apk
profiles. The ZIP-container profiles (jar, nuget, wheel, epub, android-apk, ipa,
msix) require a seekable file and reject '-'.

Android APK v2/v3 Signing Block signatures, chunked/fs-verity content digests,
v3 proof-of-rotation, and v3.1 targeted signer ranges are verified offline when
present; no Android verification key file is required because each signer
carries its certificate. Rotation evidence is reported separately from trust.
This does not claim binary-manifest installability across every Android SDK.
For APK Signature Scheme v4/v4.1, --idsig-file explicitly supplies the detached
sidecar. The command never guesses a sibling path. Missing sidecars are optional
and reported as not-evaluated.
MSIX AppxBlockMap.xml file coverage, sizes, and streamed 64-KiB SHA-256 blocks
are verified. AppxSignature.p7x is detected but not yet cryptographically
verified, so its signature-validity verdict remains not-evaluated.

Trust flags:
  --alpine-rsa-key-file PATH
      Supply one Alpine APK v2 RSA public key. The file basename is the exact
      .SIGN key-id. May be repeated. Supplying a key verifies validity but does
      not trust it.
  --trusted-signer-sha256 HEX
      Trust one exact SHA-256 fingerprint of canonical signer material. May be
      repeated. HEX is exactly 64 hexadecimal digits.
  --allow-unsigned
      Explicitly allow a package proven to be unsigned to satisfy trust policy.

Trust evaluation is offline. The command never fetches certificates, keys,
revocation data, transparency records, or any other network resource.

Exit codes: 0 profile satisfied, 1 profile not satisfied or runtime failure,
2 usage failure.";

const MAX_ALPINE_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Dispatches an `oxarchive package` subcommand.
///
/// `args` are the operands following `package`, the first of which selects the
/// subcommand. The only subcommand is `validate`. All package subcommands emit
/// machine JSON regardless of the top-level `--json` flag.
///
/// # Errors
///
/// Returns a usage error (exit 2) for an unknown or missing subcommand and
/// propagates the runtime and usage errors of `validate` otherwise.
pub fn run_package(args: &[String]) -> CliResult {
    let subcommand = args.first().ok_or_else(|| CliError::usage(PACKAGE_HELP))?;
    let operands = &args[1..];
    match subcommand.as_str() {
        "validate" => run_validate(operands),
        flag if flag.starts_with('-') => Err(CliError::unsupported(flag)),
        other => Err(CliError::usage(format!(
            "unknown package subcommand: {other}\n\n{PACKAGE_HELP}"
        ))),
    }
}

/// A selected package profile, unifying static dispatch across every validator
/// without a trait object.
#[derive(Debug, Clone, Copy)]
enum PackageProfile {
    /// Debian `.deb` (`ar` container).
    Deb,
    /// RPM package.
    Rpm,
    /// Alpine APK v2 (concatenated gzip/tar streams).
    AlpineApk,
    /// A ZIP-container package profile (JAR, `NuGet`, wheel, EPUB).
    Zip(ZipPackageProfile),
    /// An OS/app package profile (APK, IPA, MSIX).
    App(AppPackageProfile),
}

impl PackageProfile {
    /// Parses a `--type` token into a profile.
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "deb" => Ok(Self::Deb),
            "rpm" => Ok(Self::Rpm),
            "alpine-apk" => Ok(Self::AlpineApk),
            "jar" => Ok(Self::Zip(ZipPackageProfile::Jar)),
            "nuget" => Ok(Self::Zip(ZipPackageProfile::NuGet)),
            "wheel" => Ok(Self::Zip(ZipPackageProfile::Wheel)),
            "epub" => Ok(Self::Zip(ZipPackageProfile::Epub)),
            "android-apk" => Ok(Self::App(AppPackageProfile::AndroidApk)),
            "apk" => Err(CliError::usage(
                "ambiguous package type apk; use android-apk or alpine-apk",
            )),
            "ipa" => Ok(Self::App(AppPackageProfile::Ipa)),
            "msix" => Ok(Self::App(AppPackageProfile::Msix)),
            other => Err(CliError::usage(format!(
                "unknown package type: {other} (supported: deb, rpm, jar, nuget, \
                 wheel, epub, alpine-apk, android-apk, ipa, msix)"
            ))),
        }
    }

    /// Stable lowercase profile label, matching the accepted `--type` token.
    const fn label(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::AlpineApk => "alpine-apk",
            Self::Zip(profile) => profile.label(),
            Self::App(profile) => profile.label(),
        }
    }

    /// Whether this profile requires a seekable input (a ZIP central directory)
    /// and therefore cannot read standard input.
    const fn requires_seek(self) -> bool {
        matches!(self, Self::Zip(_) | Self::App(_))
    }
}

/// Validates one package against a `--type`-selected profile.
fn run_validate(args: &[String]) -> CliResult {
    let ValidateSelection {
        profile,
        package,
        trust_policy,
        alpine_rsa_key_files,
        idsig_file,
    } = parse_validate(args)?;
    let mut verifier = PackageVerifier::new(trust_policy);
    let mut key_ids = BTreeSet::new();
    for path in alpine_rsa_key_files {
        let key = read_alpine_rsa_key(path)?;
        if !key_ids.insert(key.key_id().to_vec()) {
            return Err(CliError::usage(format!(
                "duplicate Alpine RSA key id from file basename: {}",
                String::from_utf8_lossy(key.key_id())
            )));
        }
        verifier = verifier.with_alpine_rsa_public_key(key);
    }
    let report = match profile {
        PackageProfile::Deb => {
            let source = open_read_source(package)?;
            verifier.deb(source)
        },
        PackageProfile::Rpm => {
            let source = open_read_source(package)?;
            verifier.rpm(source)
        },
        PackageProfile::AlpineApk => {
            let source = open_read_source(package)?;
            verifier.alpine_apk(source)
        },
        PackageProfile::Zip(zip_profile) => {
            let file = open_seek_file(package, profile)?;
            verifier.zip(zip_profile, file)
        },
        PackageProfile::App(app_profile) => {
            let file = open_seek_file(package, profile)?;
            if let Some(idsig_path) = idsig_file {
                let idsig = File::open(idsig_path).map_err(|error| {
                    CliError::runtime(format!("cannot open APK v4 sidecar {idsig_path}: {error}"))
                })?;
                verifier.android_apk_with_v4_sidecar(file, idsig)
            } else {
                verifier.app(app_profile, file)
            }
        },
    };
    emit(profile.label(), &report)
}

#[derive(Debug)]
struct ValidateSelection<'a> {
    profile: PackageProfile,
    package: &'a str,
    trust_policy: TrustPolicy,
    alpine_rsa_key_files: Vec<&'a str>,
    idsig_file: Option<&'a str>,
}

/// Parses the `validate` operands into a profile and the single package operand.
///
/// A `--` separator forces the remaining arguments to be treated as operands.
fn parse_validate(args: &[String]) -> Result<ValidateSelection<'_>, CliError> {
    let mut type_value: Option<&str> = None;
    let mut operands: Vec<&str> = Vec::new();
    let mut trust_policy = TrustPolicy::offline();
    let mut alpine_rsa_key_files = Vec::new();
    let mut idsig_file = None;
    let mut allow_unsigned = false;
    let mut positional_only = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if positional_only {
            operands.push(argument);
            index += 1;
            continue;
        }
        match argument {
            "--" => positional_only = true,
            "--type" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--type requires a value"))?;
                if type_value.replace(value.as_str()).is_some() {
                    return Err(CliError::usage("--type may be specified only once"));
                }
                index += 1;
            },
            "--trusted-signer-sha256" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--trusted-signer-sha256 requires a value"))?;
                trust_policy = trust_policy.with_trusted_signer_sha256(parse_sha256_pin(value)?);
                index += 1;
            },
            "--alpine-rsa-key-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--alpine-rsa-key-file requires a value"))?;
                alpine_rsa_key_files.push(value.as_str());
                index += 1;
            },
            "--idsig-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--idsig-file requires a value"))?;
                set_idsig_file(&mut idsig_file, value)?;
                index += 1;
            },
            "--allow-unsigned" => {
                if allow_unsigned {
                    return Err(CliError::usage(
                        "--allow-unsigned may be specified only once",
                    ));
                }
                allow_unsigned = true;
                trust_policy = trust_policy.with_allow_unsigned(true);
            },
            _ => {
                if let Some(value) = argument.strip_prefix("--type=") {
                    if type_value.replace(value).is_some() {
                        return Err(CliError::usage("--type may be specified only once"));
                    }
                } else if let Some(value) = argument.strip_prefix("--trusted-signer-sha256=") {
                    trust_policy =
                        trust_policy.with_trusted_signer_sha256(parse_sha256_pin(value)?);
                } else if let Some(value) = argument.strip_prefix("--alpine-rsa-key-file=") {
                    if value.is_empty() {
                        return Err(CliError::usage(
                            "--alpine-rsa-key-file requires a non-empty path",
                        ));
                    }
                    alpine_rsa_key_files.push(value);
                } else if let Some(value) = argument.strip_prefix("--idsig-file=") {
                    set_idsig_file(&mut idsig_file, value)?;
                } else if argument.starts_with('-') && argument != "-" {
                    return Err(CliError::unsupported(argument));
                } else {
                    operands.push(argument);
                }
            },
        }
        index += 1;
    }
    finish_validate(
        type_value,
        &operands,
        trust_policy,
        alpine_rsa_key_files,
        idsig_file,
    )
}

fn finish_validate<'a>(
    type_value: Option<&'a str>,
    operands: &[&'a str],
    trust_policy: TrustPolicy,
    alpine_rsa_key_files: Vec<&'a str>,
    idsig_file: Option<&'a str>,
) -> Result<ValidateSelection<'a>, CliError> {
    let type_value = type_value.ok_or_else(|| {
        CliError::usage(
            "package validate requires --type \
             <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix>",
        )
    })?;
    let profile = PackageProfile::parse(type_value)?;
    if !alpine_rsa_key_files.is_empty() && !matches!(profile, PackageProfile::AlpineApk) {
        return Err(CliError::usage(
            "--alpine-rsa-key-file is valid only with --type alpine-apk",
        ));
    }
    if idsig_file.is_some()
        && !matches!(profile, PackageProfile::App(AppPackageProfile::AndroidApk))
    {
        return Err(CliError::usage(
            "--idsig-file is valid only with --type android-apk",
        ));
    }
    let [package] = operands else {
        return Err(CliError::usage(
            "package validate requires exactly one PACKAGE operand",
        ));
    };
    Ok(ValidateSelection {
        profile,
        package,
        trust_policy,
        alpine_rsa_key_files,
        idsig_file,
    })
}

fn set_idsig_file<'a>(slot: &mut Option<&'a str>, value: &'a str) -> CliResult {
    if value.is_empty() || value == "-" {
        return Err(CliError::usage(
            "--idsig-file requires a non-empty filesystem path, not '-'",
        ));
    }
    if slot.replace(value).is_some() {
        return Err(CliError::usage("--idsig-file may be specified only once"));
    }
    Ok(())
}

fn read_alpine_rsa_key(path: &str) -> Result<AlpineRsaPublicKey, CliError> {
    let key_id = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::usage(format!(
                "Alpine RSA key path has no UTF-8 file basename: {path}"
            ))
        })?;
    let file = File::open(path).map_err(|error| {
        CliError::runtime(format!("cannot open Alpine RSA key file {path}: {error}"))
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_ALPINE_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::runtime(format!("cannot read Alpine RSA key file {path}: {error}"))
        })?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_ALPINE_KEY_FILE_BYTES) {
        return Err(CliError::usage(format!(
            "Alpine RSA key file exceeds the {MAX_ALPINE_KEY_FILE_BYTES}-byte limit: {path}"
        )));
    }
    AlpineRsaPublicKey::from_bytes(key_id.as_bytes().to_vec(), bytes)
        .map_err(|error| CliError::usage(format!("invalid Alpine RSA key file {path}: {error}")))
}

fn parse_sha256_pin(value: &str) -> Result<[u8; 32], CliError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(CliError::usage(
            "--trusted-signer-sha256 requires exactly 64 hexadecimal digits",
        ));
    }
    let mut fingerprint = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            CliError::usage("--trusted-signer-sha256 contains a non-hexadecimal digit")
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            CliError::usage("--trusted-signer-sha256 contains a non-hexadecimal digit")
        })?;
        fingerprint[index] = (high << 4) | low;
    }
    Ok(fingerprint)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A byte source that unifies standard input and a file without a trait object,
/// keeping dispatch static. Used by the deb and rpm profiles, which only need
/// sequential reads.
enum ReadSource {
    /// Standard input, used when the package operand is `-`.
    Stdin(io::Stdin),
    /// A regular file opened for reading.
    File(File),
}

impl Read for ReadSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdin(stdin) => stdin.read(buffer),
            Self::File(file) => file.read(buffer),
        }
    }
}

/// Opens a bounded, read-only source for a sequential profile, honoring `-`.
fn open_read_source(path: &str) -> Result<ReadSource, CliError> {
    if path == "-" {
        Ok(ReadSource::Stdin(io::stdin()))
    } else {
        File::open(path)
            .map(ReadSource::File)
            .map_err(|error| CliError::runtime(error.to_string()))
    }
}

/// Opens a seekable file for a ZIP-container profile, rejecting `-` because a
/// central directory cannot be read from a non-seekable stream.
fn open_seek_file(path: &str, profile: PackageProfile) -> Result<File, CliError> {
    debug_assert!(profile.requires_seek());
    if path == "-" {
        return Err(CliError::usage(format!(
            "package type {} requires a seekable file; '-' is not supported",
            profile.label()
        )));
    }
    File::open(path).map_err(|error| CliError::runtime(error.to_string()))
}

/// Renders a validation verdict as one JSON object and maps the profile outcome
/// to the shared process contract.
///
/// The record is written before any exit-code error so machine consumers always
/// observe the findings even when the profile was not satisfied.
fn emit(profile: &str, report: &VerificationReport) -> CliResult {
    let status = report.structure();
    let findings: Vec<Value> = report.findings().iter().map(finding_json).collect();
    let signer_fingerprints: Vec<String> = report
        .signer_fingerprints()
        .iter()
        .map(|fingerprint| hex(fingerprint))
        .collect();
    let android_apk_rotation = report.android_apk_rotation().map(|rotation| {
        let signers = rotation
            .signers()
            .iter()
            .map(|signer| {
                json!({
                    "scheme": signer.scheme(),
                    "minimum_sdk": signer.minimum_sdk(),
                    "maximum_sdk": signer.maximum_sdk(),
                    "signer_fingerprint_sha256": hex(&signer.fingerprint()),
                    "lineage_levels": signer.lineage_levels(),
                    "targets_dev_release": signer.targets_dev_release(),
                })
            })
            .collect::<Vec<_>>();
        let lineage = rotation
            .lineage()
            .iter()
            .enumerate()
            .map(|(index, level)| {
                json!({
                    "index": index,
                    "certificate_fingerprint_sha256": hex(&level.fingerprint()),
                    "flags": level.flags(),
                    "flags_hex": format!("{:#010x}", level.flags()),
                    "signed_signature_algorithm_id": level.signed_signature_algorithm_id(),
                    "signed_signature_algorithm_id_hex":
                        format!("{:#010x}", level.signed_signature_algorithm_id()),
                    "next_signature_algorithm_id": level.next_signature_algorithm_id(),
                    "next_signature_algorithm_id_hex":
                        format!("{:#010x}", level.next_signature_algorithm_id()),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "v3_1_present": rotation.v31_present(),
            "rotation_min_sdk": rotation.rotation_min_sdk(),
            "targets_dev_release": rotation.targets_dev_release(),
            "signers": signers,
            "lineage": lineage,
        })
    });
    let android_apk_v4 = report.android_apk_v4().map(|v4| {
        let fingerprints: Vec<String> = v4
            .signer_fingerprints()
            .iter()
            .map(|fingerprint| hex(fingerprint))
            .collect();
        let findings: Vec<Value> = v4.findings().iter().map(finding_json).collect();
        json!({
            "revision": v4.revision().map(AndroidApkV4Revision::label),
            "integrity": v4.integrity().label(),
            "signature_validity": v4.signature_validity().label(),
            "trust": v4.trust().label(),
            "signer_fingerprints_sha256": fingerprints,
            "findings": findings,
        })
    });
    print_json(&json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "package_validation",
        "profile": profile,
        "container_readable": status.container_readable(),
        "profile_valid": status.profile_valid(),
        "integrity": report.integrity().label(),
        "signature_validity": report.signature_validity().label(),
        "trust": report.trust().label(),
        "signer_fingerprints_sha256": signer_fingerprints,
        "android_apk_rotation": android_apk_rotation,
        "android_apk_v4": android_apk_v4,
        "findings": findings,
    }))?;
    let cryptographic_failure = [
        report.integrity(),
        report.signature_validity(),
        report.trust(),
    ]
    .into_iter()
    .any(|dimension| dimension == libarchive_oxide_package::VerificationDimension::Invalid);
    if status.profile_valid() && !cryptographic_failure {
        Ok(())
    } else if cryptographic_failure {
        Err(CliError::runtime(
            "package integrity, signature, or trust verification failed; see findings",
        ))
    } else {
        Err(CliError::runtime(
            "package did not satisfy its profile; see findings",
        ))
    }
}

/// Renders one [`PackageFinding`] as a JSON object using only its stable
/// accessors, so the CLI never re-derives severity or classification.
fn finding_json(finding: &PackageFinding) -> Value {
    json!({
        "severity": finding.severity().label(),
        "code": finding.code().as_str(),
        "path": finding.path().map(String::from_utf8_lossy),
        "path_raw_hex": finding.path().map(hex),
        "detail": finding.detail(),
    })
}
