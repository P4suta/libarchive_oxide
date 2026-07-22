// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-validation subcommands for the unified `oxarchive` binary.
//!
//! These commands drive the library's package validators
//! ([`DebValidator`], [`RpmValidator`], [`ZipPackageValidator`], and
//! [`AppPackageValidator`]) and render their shared typed findings as machine
//! JSON. The CLI never re-implements package-structure interpretation or
//! finding classification: the library validators are the single source of
//! truth, and this module only selects a profile, opens a bounded input, and
//! serializes the resulting [`SupportStatus`] and [`PackageFinding`] values.
//!
//! Every subcommand emits one JSON object regardless of any top-level `--json`
//! flag. Exit codes follow the shared contract: 0 when the package satisfied
//! its profile, 1 when the container was read but the profile was not satisfied
//! (or a runtime error occurred), and 2 for a usage failure.

use std::fs::File;
use std::io::{self, Read};

use libarchive_oxide::{
    AppPackageProfile, AppPackageValidator, DebValidator, PackageFinding, RpmValidator,
    SupportStatus, ZipPackageProfile, ZipPackageValidator,
};
use serde_json::{Value, json};

use crate::oxarchive::{JSON_SCHEMA_VERSION, hex, print_json};
use crate::{CliError, CliResult};

const PACKAGE_HELP: &str = "\
oxarchive package - bounded software-package validation

Usage:
  oxarchive package validate PACKAGE --type <deb|rpm|jar|nuget|wheel|epub|apk|ipa|msix>

The validator inspects the package structure without extracting it and emits one
JSON object: schema_version, type=\"package_validation\", profile,
container_readable, profile_valid, and the shared typed findings (severity,
code, path, detail).

PACKAGE may be '-' to read standard input for the deb and rpm profiles. The
ZIP-container profiles (jar, nuget, wheel, epub, apk, ipa, msix) require a
seekable file and reject '-'.

Exit codes: 0 profile satisfied, 1 profile not satisfied or runtime failure,
2 usage failure.";

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
            "jar" => Ok(Self::Zip(ZipPackageProfile::Jar)),
            "nuget" => Ok(Self::Zip(ZipPackageProfile::NuGet)),
            "wheel" => Ok(Self::Zip(ZipPackageProfile::Wheel)),
            "epub" => Ok(Self::Zip(ZipPackageProfile::Epub)),
            "apk" => Ok(Self::App(AppPackageProfile::Apk)),
            "ipa" => Ok(Self::App(AppPackageProfile::Ipa)),
            "msix" => Ok(Self::App(AppPackageProfile::Msix)),
            other => Err(CliError::usage(format!(
                "unknown package type: {other} (supported: deb, rpm, jar, nuget, \
                 wheel, epub, apk, ipa, msix)"
            ))),
        }
    }

    /// Stable lowercase profile label, matching the accepted `--type` token.
    const fn label(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
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
    let (profile, package) = parse_validate(args)?;
    match profile {
        PackageProfile::Deb => {
            let source = open_read_source(package)?;
            let validation = DebValidator::new().validate(source);
            emit(profile.label(), validation.status(), validation.findings())
        },
        PackageProfile::Rpm => {
            let source = open_read_source(package)?;
            let validation = RpmValidator::new().validate(source);
            emit(profile.label(), validation.status(), validation.findings())
        },
        PackageProfile::Zip(zip_profile) => {
            let file = open_seek_file(package, profile)?;
            let validation = ZipPackageValidator::new(zip_profile).validate(file);
            emit(profile.label(), validation.status(), validation.findings())
        },
        PackageProfile::App(app_profile) => {
            let file = open_seek_file(package, profile)?;
            let validation = AppPackageValidator::new(app_profile).validate(file);
            emit(profile.label(), validation.status(), validation.findings())
        },
    }
}

/// Parses the `validate` operands into a profile and the single package operand.
///
/// A `--` separator forces the remaining arguments to be treated as operands.
fn parse_validate(args: &[String]) -> Result<(PackageProfile, &str), CliError> {
    let mut type_value: Option<&str> = None;
    let mut operands: Vec<&str> = Vec::new();
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
            _ => {
                if let Some(value) = argument.strip_prefix("--type=") {
                    if type_value.replace(value).is_some() {
                        return Err(CliError::usage("--type may be specified only once"));
                    }
                } else if argument.starts_with('-') && argument != "-" {
                    return Err(CliError::unsupported(argument));
                } else {
                    operands.push(argument);
                }
            },
        }
        index += 1;
    }
    let type_value = type_value.ok_or_else(|| {
        CliError::usage(
            "package validate requires --type \
             <deb|rpm|jar|nuget|wheel|epub|apk|ipa|msix>",
        )
    })?;
    let profile = PackageProfile::parse(type_value)?;
    let [package] = operands.as_slice() else {
        return Err(CliError::usage(
            "package validate requires exactly one PACKAGE operand",
        ));
    };
    Ok((profile, package))
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
fn emit(profile: &str, status: SupportStatus, findings: &[PackageFinding]) -> CliResult {
    let findings: Vec<Value> = findings.iter().map(finding_json).collect();
    print_json(&json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "package_validation",
        "profile": profile,
        "container_readable": status.container_readable(),
        "profile_valid": status.profile_valid(),
        "findings": findings,
    }))?;
    if status.profile_valid() {
        Ok(())
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
