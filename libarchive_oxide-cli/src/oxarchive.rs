// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified high-level archive inspection, planning, application, and
//! verification commands.

use std::fs::File;
use std::io;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveEngine, ArchiveInspection, ArchiveSession, EntryOutcomeKind, ExtractionPlan,
    PlanDisposition, Policy, ReaderEvent,
};
use libarchive_oxide_core::{ArchivePath, EntryMetadata, FormatId};
use serde_json::{Value, json};

use crate::{CliError, CliResult};

/// Pre-1.0 machine-output schema. This is versioned separately from the Rust
/// and command-line APIs and may change before its own stability declaration.
pub const JSON_SCHEMA_VERSION: &str = "oxarchive.output.v0alpha1";

const HELP: &str = "\
oxarchive - safe high-level archive operations

Usage:
  oxarchive [--json] inspect ARCHIVE
  oxarchive [--json] plan [POLICY FLAGS] ARCHIVE
  oxarchive [--json] apply [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] verify ARCHIVE

ARCHIVE may be '-' to read standard input.

Policy flags:
  --overwrite
  --allow-symlinks
  --allow-hardlinks
  --allow-special-files

JSON plans are advisory reports, not reusable apply inputs.
Exit codes: 0 success, 1 runtime failure, 2 usage failure.";

/// Runs the unified `oxarchive` command.
pub fn run_oxarchive(mut args: Vec<String>) -> CliResult {
    if args.is_empty() {
        return Err(CliError::usage(HELP));
    }
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("oxarchive {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{HELP}");
        return Ok(());
    }

    let json_output = remove_json_flag(&mut args)?;
    let command = args.first().ok_or_else(|| CliError::usage(HELP))?.clone();
    let operands = &args[1..];
    match command.as_str() {
        "inspect" => run_inspect(operands, json_output),
        "plan" => run_plan(operands, json_output),
        "apply" => run_apply(operands, json_output),
        "verify" => run_verify(operands, json_output),
        flag if flag.starts_with('-') => Err(CliError::unsupported(flag)),
        _ => Err(CliError::usage(format!(
            "unknown command: {command}\n\n{HELP}"
        ))),
    }
}

fn remove_json_flag(args: &mut Vec<String>) -> Result<bool, CliError> {
    let mut found = false;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--json" {
            if found {
                return Err(CliError::usage("--json may be specified only once"));
            }
            found = true;
            args.remove(index);
        } else {
            index += 1;
        }
    }
    Ok(found)
}

fn run_inspect(args: &[String], json_output: bool) -> CliResult {
    let archive = one_archive_operand(args)?;
    let mut session = open_session(archive)?;
    let inspection = session
        .inspect()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    if json_output {
        print_json(&inspection_json(&inspection))
    } else {
        println!("format: {}", format_name(inspection.format()));
        println!("digest: {}", inspection.digest());
        println!("entries: {}", inspection.entries().len());
        for entry in inspection.entries() {
            let metadata = entry.metadata();
            println!(
                "{}\t{}\t{}",
                kind_name(metadata),
                metadata
                    .size()
                    .map_or("-".to_string(), |size| size.to_string()),
                metadata.path().display_lossy()
            );
        }
        Ok(())
    }
}

fn run_plan(args: &[String], json_output: bool) -> CliResult {
    let (selection, operands) = parse_policy(args)?;
    if operands.len() != 1 {
        return Err(CliError::usage("plan requires exactly one ARCHIVE operand"));
    }
    let mut session = open_session(operands[0])?;
    let plan = session
        .plan(selection.policy())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    if json_output {
        print_json(&plan_json(&plan, selection))
    } else {
        println!("format: {}", format_name(plan.format()));
        println!("digest: {}", plan.digest());
        println!("policy: {}", selection.human_name());
        println!("entries: {}", plan.entries().len());
        for entry in plan.entries() {
            println!(
                "{}\t{}",
                disposition_name(entry.disposition()),
                entry.descriptor().metadata().path().display_lossy()
            );
        }
        Ok(())
    }
}

fn run_apply(args: &[String], json_output: bool) -> CliResult {
    let (selection, operands) = parse_policy(args)?;
    if operands.len() != 2 {
        return Err(CliError::usage(
            "apply requires exactly ARCHIVE and DEST operands",
        ));
    }
    let mut session = open_session(operands[0])?;
    let plan = session
        .plan(selection.policy())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    std::fs::create_dir_all(operands[1]).map_err(|error| CliError::runtime(error.to_string()))?;
    let root = Dir::open_ambient_dir(Path::new(operands[1]), ambient_authority())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let report = session
        .apply(plan, root)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    if json_output {
        let outcomes: Vec<Value> = report
            .extraction()
            .outcomes()
            .iter()
            .map(|outcome| {
                json!({
                    "path": outcome.path().display_lossy(),
                    "path_raw_hex": hex(outcome.path().as_bytes()),
                    "outcome": outcome_name(outcome.outcome()),
                })
            })
            .collect();
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "apply",
            "format": format_name(report.format()),
            "digest": report.digest().to_string(),
            "policy": selection.json(),
            "rejected": report.extraction().has_rejections(),
            "outcomes": outcomes,
        }))?;
    } else {
        println!("format: {}", format_name(report.format()));
        println!("digest: {}", report.digest());
        for outcome in report.extraction().outcomes() {
            println!(
                "{}\t{}",
                outcome_name(outcome.outcome()),
                outcome.path().display_lossy()
            );
        }
    }
    if report.extraction().has_rejections() {
        return Err(CliError::runtime(
            "one or more archive entries were refused by the safe extraction policy",
        ));
    }
    Ok(())
}

fn run_verify(args: &[String], json_output: bool) -> CliResult {
    let archive = one_archive_operand(args)?;
    let mut session = open_session(archive)?;
    let mut entries = 0_u64;
    let mut payload_bytes = 0_u64;
    loop {
        match session
            .next_event()
            .map_err(|error| CliError::runtime(error.to_string()))?
        {
            ReaderEvent::Entry(_) => {
                entries = entries
                    .checked_add(1)
                    .ok_or_else(|| CliError::runtime("verified entry count overflow"))?;
            },
            ReaderEvent::Data(bytes) => {
                payload_bytes = payload_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| CliError::runtime("verified payload byte count overflow"))?;
            },
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => {
                return Err(CliError::runtime(
                    "archive produced an event this CLI does not understand",
                ));
            },
        }
    }
    let format = session
        .format()
        .ok_or_else(|| CliError::runtime("archive completed without a detected format"))?;
    if json_output {
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "verify",
            "format": format_name(format),
            "digest": session.digest().to_string(),
            "entries": entries,
            "payload_bytes": payload_bytes,
            "verified": true,
        }))
    } else {
        println!("verified: true");
        println!("format: {}", format_name(format));
        println!("digest: {}", session.digest());
        println!("entries: {entries}");
        println!("payload-bytes: {payload_bytes}");
        Ok(())
    }
}

fn one_archive_operand(args: &[String]) -> Result<&str, CliError> {
    if args.len() != 1 {
        return Err(CliError::usage(
            "command requires exactly one ARCHIVE operand",
        ));
    }
    if args[0].starts_with('-') && args[0] != "-" {
        return Err(CliError::unsupported(&args[0]));
    }
    Ok(&args[0])
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // Mirrors four independent policy capabilities.
struct PolicySelection {
    overwrite: bool,
    symlinks: bool,
    hardlinks: bool,
    special_files: bool,
}

impl PolicySelection {
    fn policy(self) -> Policy {
        Policy::safe()
            .allow_overwrite(self.overwrite)
            .allow_symlinks(self.symlinks)
            .allow_hardlinks(self.hardlinks)
            .allow_special_files(self.special_files)
    }

    fn json(self) -> Value {
        json!({
            "overwrite": self.overwrite,
            "symlinks": self.symlinks,
            "hardlinks": self.hardlinks,
            "special_files": self.special_files,
        })
    }

    fn human_name(self) -> String {
        format!(
            "overwrite={}, symlinks={}, hardlinks={}, special-files={}",
            self.overwrite, self.symlinks, self.hardlinks, self.special_files
        )
    }
}

fn parse_policy(args: &[String]) -> Result<(PolicySelection, Vec<&str>), CliError> {
    let mut selection = PolicySelection::default();
    let mut operands = Vec::new();
    let mut options = true;
    for argument in args {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options {
            match argument.as_str() {
                "--overwrite" => selection.overwrite = true,
                "--allow-symlinks" => selection.symlinks = true,
                "--allow-hardlinks" => selection.hardlinks = true,
                "--allow-special-files" => selection.special_files = true,
                flag if flag.starts_with('-') && flag != "-" => {
                    return Err(CliError::unsupported(flag));
                },
                _ => operands.push(argument.as_str()),
            }
        } else {
            operands.push(argument.as_str());
        }
    }
    Ok((selection, operands))
}

fn open_session(path: &str) -> Result<ArchiveSession, CliError> {
    let engine = ArchiveEngine::new();
    if path == "-" {
        let stdin = io::stdin();
        engine
            .open(stdin.lock())
            .map_err(|error| CliError::runtime(error.to_string()))
    } else {
        let input = File::open(path).map_err(|error| CliError::runtime(error.to_string()))?;
        engine
            .open(input)
            .map_err(|error| CliError::runtime(error.to_string()))
    }
}

fn inspection_json(inspection: &ArchiveInspection) -> Value {
    let entries: Vec<Value> = inspection
        .entries()
        .iter()
        .map(|entry| metadata_json(entry.metadata()))
        .collect();
    json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "inspection",
        "format": format_name(inspection.format()),
        "digest": inspection.digest().to_string(),
        "entry_count": entries.len(),
        "entries": entries,
    })
}

fn plan_json(plan: &ExtractionPlan, selection: PolicySelection) -> Value {
    let entries: Vec<Value> = plan
        .entries()
        .iter()
        .map(|entry| {
            let metadata = entry.descriptor().metadata();
            let mut value = metadata_json(metadata);
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "disposition".to_string(),
                    Value::String(disposition_name(entry.disposition())),
                );
            }
            value
        })
        .collect();
    json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "plan",
        "reusable": false,
        "format": format_name(plan.format()),
        "digest": plan.digest().to_string(),
        "policy": selection.json(),
        "entry_count": entries.len(),
        "entries": entries,
    })
}

fn metadata_json(metadata: &EntryMetadata) -> Value {
    json!({
        "path": metadata.path().display_lossy(),
        "path_raw_hex": hex(metadata.path().as_bytes()),
        "kind": kind_name(metadata),
        "size": metadata.size(),
        "link_target": metadata.link_target().map(ArchivePath::display_lossy),
        "link_target_raw_hex": metadata.link_target().map(|target| hex(target.as_bytes())),
    })
}

fn print_json(value: &Value) -> CliResult {
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    println!("{encoded}");
    Ok(())
}

fn format_name(format: FormatId) -> String {
    format!("{format:?}").to_ascii_lowercase()
}

fn kind_name(metadata: &EntryMetadata) -> String {
    format!("{:?}", metadata.kind()).to_ascii_lowercase()
}

fn disposition_name(disposition: PlanDisposition) -> String {
    match disposition {
        PlanDisposition::Materialize => "materialize".to_string(),
        PlanDisposition::Skip => "skip".to_string(),
        PlanDisposition::Reject(reason) => {
            format!("reject:{}", format!("{reason:?}").to_ascii_lowercase())
        },
        _ => "unknown".to_string(),
    }
}

fn outcome_name(outcome: &EntryOutcomeKind) -> String {
    match outcome {
        EntryOutcomeKind::File => "file".to_string(),
        EntryOutcomeKind::Directory => "directory".to_string(),
        EntryOutcomeKind::Symlink => "symlink".to_string(),
        EntryOutcomeKind::Hardlink => "hardlink".to_string(),
        EntryOutcomeKind::Special => "special".to_string(),
        EntryOutcomeKind::Skipped => "skipped".to_string(),
        EntryOutcomeKind::Rejected(reason) => {
            format!("rejected:{}", format!("{reason:?}").to_ascii_lowercase())
        },
        _ => "unknown".to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
