// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCI image layer subcommands for the unified `oxarchive` binary.
//!
//! These commands share the layer engine, plan, and report types from
//! [`libarchive_oxide::oci`] so the CLI never re-implements OCI whiteout,
//! opaque-directory, digest, or path policy. Every subcommand emits machine
//! JSON: `oci inspect` streams bounded JSON Lines (one record per entry framed
//! by a start and a completion sentinel), while `oci verify` and `oci apply`
//! emit a single JSON object.
//!
//! Exit codes follow the shared contract: 0 success, 1 runtime failure, 2 usage
//! failure. Digest mismatches are runtime failures (exit 1) that leave any
//! destination untouched.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    CapStdFilesystemAdapter, IdentityOwnership, LayerDigests, OciApplyReport, OciLayerApplier,
    OciLayerEngine, OciLayerError, Policy,
};
use libarchive_oxide_core::EntryKind;
use serde_json::{Value, json};

use crate::oxarchive::{JSON_SCHEMA_VERSION, hex, print_json, write_json_record};
use crate::{CliError, CliResult};

const OCI_HELP: &str = "\
oxarchive oci - OCI image layer operations

Usage:
  oxarchive oci inspect LAYER
  oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
  oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...

LAYER may be '-' to read standard input for inspect and verify. `oci apply`
requires a seekable file and rejects '-'.

Policy flags (apply only):
  --overwrite
  --allow-symlinks
  --allow-hardlinks
  --allow-special-files

Exit codes: 0 success, 1 runtime failure, 2 usage failure.";

/// Dispatches an `oxarchive oci` subcommand.
///
/// `args` are the operands following `oci`, the first of which selects the
/// subcommand. All `oci` subcommands emit machine JSON regardless of the
/// top-level `--json` flag.
///
/// # Errors
///
/// Returns a usage error (exit 2) for an unknown or missing subcommand and
/// propagates the per-subcommand runtime and usage errors otherwise.
pub fn run_oci(args: &[String]) -> CliResult {
    let subcommand = args.first().ok_or_else(|| CliError::usage(OCI_HELP))?;
    let operands = &args[1..];
    match subcommand.as_str() {
        "inspect" => run_oci_inspect(operands),
        "verify" => run_oci_verify(operands),
        "apply" => run_oci_apply(operands),
        flag if flag.starts_with('-') => Err(CliError::unsupported(flag)),
        other => Err(CliError::usage(format!(
            "unknown oci subcommand: {other}\n\n{OCI_HELP}"
        ))),
    }
}

/// A layer byte source that unifies standard input and a file without a trait
/// object, keeping dispatch static.
enum LayerSource {
    /// Standard input, used when the layer operand is `-`.
    Stdin(io::Stdin),
    /// A regular file opened for reading.
    File(File),
}

impl Read for LayerSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdin(stdin) => stdin.read(buffer),
            Self::File(file) => file.read(buffer),
        }
    }
}

/// Opens a bounded, read-only source for the layer operand, honoring `-`.
fn open_layer_source(path: &str) -> Result<LayerSource, CliError> {
    if path == "-" {
        Ok(LayerSource::Stdin(io::stdin()))
    } else {
        File::open(path)
            .map(LayerSource::File)
            .map_err(|error| CliError::runtime(error.to_string()))
    }
}

/// Streams one OCI layer as bounded JSON Lines.
fn run_oci_inspect(args: &[String]) -> CliResult {
    let layer = one_layer_operand(args)?;
    let source = open_layer_source(layer)?;
    let mut session = OciLayerEngine::new()
        .open(source)
        .map_err(|error| CliError::runtime(error.to_string()))?;

    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    write_json_record(
        &mut output,
        &json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "oci_inspect_start",
        }),
    )?;

    let mut entries = 0_u64;
    while let Some(entry) = session
        .next_entry()
        .map_err(|error| CliError::runtime(error.to_string()))?
    {
        write_json_record(
            &mut output,
            &json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "oci_inspect_entry",
                "index": entries,
                "path": String::from_utf8_lossy(entry.path()),
                "path_raw_hex": hex(entry.path()),
                "kind": kind_name(entry.kind()),
                "size": entry.size(),
                "link_target": entry.link_target().map(String::from_utf8_lossy),
                "link_target_raw_hex": entry.link_target().map(hex),
                "mode": entry.mode(),
                "uid": entry.uid(),
                "gid": entry.gid(),
            }),
        )?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| CliError::runtime("OCI inspection entry count overflow"))?;
    }

    let digests = session
        .digests()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    write_json_record(
        &mut output,
        &json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "oci_inspect_complete",
            "entry_count": entries,
            "digest": digests.compressed_descriptor(),
            "diff_id": digests.diff_id_descriptor(),
            "complete": true,
        }),
    )
}

/// Verifies a layer against an expected compressed digest and diffID.
fn run_oci_verify(args: &[String]) -> CliResult {
    let (options, operands) = parse_oci_options(args)?;
    let [layer] = operands.as_slice() else {
        return Err(CliError::usage(
            "oci verify requires exactly one LAYER operand",
        ));
    };
    let expected = options.expected_digests()?;
    let source = open_layer_source(layer)?;
    let mut session = OciLayerEngine::new()
        .open(source)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    match session.verify(expected) {
        Ok(()) => {
            let actual = session
                .digests()
                .map_err(|error| CliError::runtime(error.to_string()))?;
            print_json(&json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "oci_verify",
                "verified": true,
                "digest": actual.compressed_descriptor(),
                "diff_id": actual.diff_id_descriptor(),
            }))
        },
        Err(OciLayerError::DigestMismatch(mismatch)) => {
            print_json(&json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "oci_verify",
                "verified": false,
                "mismatch": mismatch_json(mismatch),
            }))?;
            Err(CliError::runtime(format!(
                "OCI layer {} did not match the expected value",
                mismatch.kind().label()
            )))
        },
        Err(error) => Err(CliError::runtime(error.to_string())),
    }
}

/// Applies a digest-verified layer to a destination directory.
fn run_oci_apply(args: &[String]) -> CliResult {
    let (options, operands) = parse_oci_options(args)?;
    let [layer, dest] = operands.as_slice() else {
        return Err(CliError::usage(
            "oci apply requires exactly LAYER and DEST operands",
        ));
    };
    if *layer == "-" {
        return Err(CliError::usage(
            "oci apply requires a seekable LAYER file; '-' is not supported",
        ));
    }
    let expected = options.expected_digests()?;
    let policy = options.policy();

    let file = File::open(layer).map_err(|error| CliError::runtime(error.to_string()))?;
    let mut applier = OciLayerApplier::new(file);
    let plan = applier
        .plan(expected, policy, &IdentityOwnership)
        .map_err(|error| CliError::runtime(error.to_string()))?;

    std::fs::create_dir_all(dest).map_err(|error| CliError::runtime(error.to_string()))?;
    let root = Dir::open_ambient_dir(Path::new(dest), ambient_authority())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let mut adapter = CapStdFilesystemAdapter::new(root);

    match applier.apply(plan, &mut adapter) {
        Ok(report) => {
            print_json(&apply_json(&report))?;
            if report.rejected() > 0 {
                return Err(CliError::runtime(
                    "one or more layer entries were refused by the OCI apply policy",
                ));
            }
            Ok(())
        },
        Err(OciLayerError::DigestMismatch(mismatch)) => {
            print_json(&json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "oci_apply",
                "applied": false,
                "mismatch": mismatch_json(mismatch),
            }))?;
            Err(CliError::runtime(format!(
                "OCI layer {} did not match; destination left unchanged",
                mismatch.kind().label()
            )))
        },
        Err(error) => Err(CliError::runtime(error.to_string())),
    }
}

/// Parsed `oci` options: the expected digest pair and apply policy flags.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // Mirrors four independent policy capabilities.
struct OciOptions {
    compressed: Option<[u8; 32]>,
    diff_id: Option<[u8; 32]>,
    overwrite: bool,
    symlinks: bool,
    hardlinks: bool,
    special_files: bool,
}

impl OciOptions {
    /// Returns the required expected digest pair, or a usage error when either
    /// digest is missing.
    fn expected_digests(&self) -> Result<LayerDigests, CliError> {
        let compressed = self
            .compressed
            .ok_or_else(|| CliError::usage("--digest sha256:<hex> is required"))?;
        let diff_id = self
            .diff_id
            .ok_or_else(|| CliError::usage("--diff-id sha256:<hex> is required"))?;
        Ok(LayerDigests::from_bytes(compressed, diff_id))
    }

    /// Builds the apply policy from the parsed flags.
    fn policy(&self) -> Policy {
        Policy::safe()
            .allow_overwrite(self.overwrite)
            .allow_symlinks(self.symlinks)
            .allow_hardlinks(self.hardlinks)
            .allow_special_files(self.special_files)
    }
}

/// Parses digest and policy flags, collecting the remaining positional
/// operands. A `--` separator forces the rest to be treated as operands.
fn parse_oci_options(args: &[String]) -> Result<(OciOptions, Vec<&str>), CliError> {
    let mut options = OciOptions::default();
    let mut operands = Vec::new();
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
            "--digest" | "--diff-id" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage(format!("{argument} requires a value")))?;
                assign_digest(&mut options, argument, value)?;
                index += 1;
            },
            "--overwrite" => options.overwrite = true,
            "--allow-symlinks" => options.symlinks = true,
            "--allow-hardlinks" => options.hardlinks = true,
            "--allow-special-files" => options.special_files = true,
            _ => {
                if let Some(value) = argument.strip_prefix("--digest=") {
                    assign_digest(&mut options, "--digest", value)?;
                } else if let Some(value) = argument.strip_prefix("--diff-id=") {
                    assign_digest(&mut options, "--diff-id", value)?;
                } else if argument.starts_with('-') && argument != "-" {
                    return Err(CliError::unsupported(argument));
                } else {
                    operands.push(argument);
                }
            },
        }
        index += 1;
    }
    Ok((options, operands))
}

/// Stores a parsed `sha256:<hex>` digest into the matching option slot,
/// rejecting a repeated flag.
fn assign_digest(options: &mut OciOptions, flag: &str, value: &str) -> Result<(), CliError> {
    let digest = parse_sha256(value)?;
    let slot = if flag == "--digest" {
        &mut options.compressed
    } else {
        &mut options.diff_id
    };
    if slot.replace(digest).is_some() {
        return Err(CliError::usage(format!(
            "{flag} may be specified only once"
        )));
    }
    Ok(())
}

/// Parses a `sha256:<64 lowercase hex>` descriptor into 32 raw bytes.
fn parse_sha256(value: &str) -> Result<[u8; 32], CliError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| CliError::usage(format!("expected a sha256:<hex> digest, got {value}")))?;
    if hex.len() != 64 {
        return Err(CliError::usage(format!(
            "sha256 digest must be 64 hex characters, got {}",
            hex.len()
        )));
    }
    let bytes = hex.as_bytes();
    let mut digest = [0u8; 32];
    for (target, pair) in digest.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        *target = (high << 4) | low;
    }
    Ok(digest)
}

/// Decodes one lowercase hexadecimal digit, rejecting other bytes.
fn hex_nibble(byte: u8) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CliError::usage(
            "sha256 digest must be lowercase hexadecimal",
        )),
    }
}

/// Extracts the single LAYER operand for inspect, honoring an explicit `--`
/// separator and allowing `-` for standard input.
fn one_layer_operand(args: &[String]) -> Result<&str, CliError> {
    let explicitly_positional = args.first().is_some_and(|argument| argument == "--");
    let args = if explicitly_positional {
        &args[1..]
    } else {
        args
    };
    if args.len() != 1 {
        return Err(CliError::usage(
            "oci inspect requires exactly one LAYER operand",
        ));
    }
    if !explicitly_positional && args[0].starts_with('-') && args[0] != "-" {
        return Err(CliError::unsupported(&args[0]));
    }
    Ok(&args[0])
}

/// Renders an [`OciApplyReport`] as a JSON object.
fn apply_json(report: &OciApplyReport) -> Value {
    let verified = report.verified();
    let findings: Vec<Value> = report
        .findings()
        .iter()
        .map(|finding| {
            json!({
                "path": finding.path().display_lossy(),
                "path_raw_hex": hex(finding.path().as_bytes()),
                "operation": format!("{:?}", finding.operation()).to_ascii_lowercase(),
                "kind": format!("{:?}", finding.kind()).to_ascii_lowercase(),
                "detail": finding.detail(),
                "io_error_kind": finding
                    .io_error_kind()
                    .map(|kind| format!("{kind:?}").to_ascii_lowercase()),
                "raw_os_error": finding.raw_os_error(),
            })
        })
        .collect();
    json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "oci_apply",
        "applied": true,
        "digest": verified.compressed_descriptor(),
        "diff_id": verified.diff_id_descriptor(),
        "materialized": report.materialized(),
        "removed": report.removed(),
        "cleared": report.cleared(),
        "rejected": report.rejected(),
        "findings": findings,
    })
}

/// Renders a digest mismatch as a JSON object.
fn mismatch_json(mismatch: libarchive_oxide::DigestMismatch) -> Value {
    json!({
        "kind": mismatch.kind().label(),
        "expected": format!("sha256:{}", libarchive_oxide::oci::encode_hex(*mismatch.expected())),
        "computed": format!("sha256:{}", libarchive_oxide::oci::encode_hex(*mismatch.actual())),
    })
}

/// Lowercases the debug name of an entry kind for machine output.
fn kind_name(kind: EntryKind) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}
