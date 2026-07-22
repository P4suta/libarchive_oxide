// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified high-level archive inspection, planning, application, creation,
//! and verification commands.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveEngine, ArchiveSession, CreateOptions, EntryOutcomeKind, ExtractionPlan,
    PlanDisposition, Policy, ReaderEvent, StreamingArchiveBuilder,
};
use libarchive_oxide_core::{ArchivePath, EntryMetadata, FilterId, FormatId};
use serde_json::{Value, json};

use crate::{CliError, CliResult};

/// Pre-1.0 machine-output schema. This is versioned separately from the Rust
/// and command-line APIs and may change before its own stability declaration.
pub const JSON_SCHEMA_VERSION: &str = "oxarchive.output.v0alpha1";

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

const HELP: &str = "\
oxarchive - safe high-level archive operations

Usage:
  oxarchive [--json] inspect ARCHIVE
  oxarchive [--json] plan [POLICY FLAGS] ARCHIVE
  oxarchive [--json] apply [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] create --format FORMAT [--filter FILTER] ARCHIVE INPUT...
  oxarchive [--json] verify ARCHIVE
  oxarchive oci inspect LAYER
  oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
  oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...

ARCHIVE may be '-' to read standard input, or for create to write standard output.
Create formats: tar, cpio, ar, zip. Filters: none, gzip, bzip2, xz, zstd, lz4.
`--json create -` is refused so machine records never mix with archive bytes.
The `oci` subcommands read OCI image layers (tar, tar+gzip, tar+zstd) and emit
machine JSON only. `oci apply` requires a seekable LAYER file (not '-').

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
        return print_human(format_args!("{HELP}"));
    }
    if args.len() == 1 && args[0] == "--version" {
        return print_human(format_args!("oxarchive {}", env!("CARGO_PKG_VERSION")));
    }
    if args
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return print_human(format_args!("{HELP}"));
    }

    let json_output = remove_json_flag(&mut args)?;
    let command = args.first().ok_or_else(|| CliError::usage(HELP))?.clone();
    let operands = &args[1..];
    match command.as_str() {
        "inspect" => run_inspect(operands, json_output),
        "plan" => run_plan(operands, json_output),
        "apply" => run_apply(operands, json_output),
        "create" => run_create(operands, json_output),
        "verify" => run_verify(operands, json_output),
        "oci" => crate::oci::run_oci(operands),
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
        if args[index] == "--" {
            break;
        }
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
    let digest = session.digest().to_string();
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    if json_output {
        write_json_record(
            &mut output,
            &json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "inspect_start",
                "digest": digest,
            }),
        )?;
    } else {
        write_human_line(&mut output, format_args!("inspect-start\tdigest={digest}"))?;
    }

    let mut entries = 0_u64;
    loop {
        match session
            .next_event()
            .map_err(|error| CliError::runtime(error.to_string()))?
        {
            ReaderEvent::Entry(metadata) => {
                entries = entries
                    .checked_add(1)
                    .ok_or_else(|| CliError::runtime("inspection entry count overflow"))?;
                if json_output {
                    let mut value = metadata_json(&metadata);
                    if let Some(object) = value.as_object_mut() {
                        object.insert(
                            "schema_version".to_string(),
                            Value::String(JSON_SCHEMA_VERSION.to_string()),
                        );
                        object.insert(
                            "type".to_string(),
                            Value::String("inspect_entry".to_string()),
                        );
                        object.insert("index".to_string(), Value::from(entries - 1));
                    }
                    write_json_record(&mut output, &value)?;
                } else {
                    write_human_line(
                        &mut output,
                        format_args!(
                            "entry\t{}\t{}\t{}",
                            kind_name(&metadata),
                            metadata
                                .size()
                                .map_or("-".to_string(), |size| size.to_string()),
                            metadata.path().display_lossy()
                        ),
                    )?;
                }
            },
            ReaderEvent::Done => {
                let format = session.format().ok_or_else(|| {
                    CliError::runtime("archive completed without a detected format")
                })?;
                if json_output {
                    write_json_record(
                        &mut output,
                        &json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "inspect_complete",
                            "format": format_name(format),
                            "digest": digest,
                            "entry_count": entries,
                            "complete": true,
                        }),
                    )?;
                } else {
                    write_human_line(
                        &mut output,
                        format_args!(
                            "inspect-complete\tformat={}\tdigest={}\tentries={entries}",
                            format_name(format),
                            digest,
                        ),
                    )?;
                }
                return output
                    .flush()
                    .map_err(|error| CliError::runtime(format!("cannot flush stdout: {error}")));
            },
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
            _ => {
                return Err(CliError::runtime(
                    "archive produced an event this CLI does not understand",
                ));
            },
        }
    }
}

#[derive(Debug)]
struct CreateSelection<'a> {
    format: FormatId,
    filter: Option<FilterId>,
    archive: &'a str,
    inputs: Vec<&'a str>,
}

fn run_create(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_create(args)?;
    if selection.archive == "-" {
        if json_output {
            return Err(CliError::usage(
                "--json create - would mix JSON records with archive bytes",
            ));
        }
        let stdout = io::stdout();
        let mut output = stream_create(stdout.lock(), &selection)?;
        return output
            .flush()
            .map_err(|error| CliError::runtime(format!("cannot flush stdout: {error}")));
    }

    let destination = PathBuf::from(selection.archive);
    validate_create_destination(&destination, &selection.inputs)?;
    let (temporary, output) = create_temporary_archive(&destination)?;
    let result = stream_create(output, &selection);
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        },
    };
    if let Err(error) = output.sync_all() {
        drop(output);
        let _ = std::fs::remove_file(&temporary);
        return Err(CliError::runtime(format!(
            "cannot synchronize temporary archive: {error}"
        )));
    }
    drop(output);
    if let Err(error) = std::fs::hard_link(&temporary, &destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(CliError::runtime(format!(
            "cannot atomically publish {}: {error}",
            destination.display()
        )));
    }
    if let Err(error) = std::fs::remove_file(&temporary) {
        return Err(CliError::runtime(format!(
            "archive committed at {} but temporary-link cleanup failed: {error}",
            destination.display()
        )));
    }

    if json_output {
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "create",
            "format": format_name(selection.format),
            "filter": selection.filter.map(filter_name),
            "archive": selection.archive,
            "input_count": selection.inputs.len(),
            "complete": true,
        }))
    } else {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        write_human_line(
            &mut output,
            format_args!(
                "created\tformat={}\tfilter={}\tarchive={}\tinputs={}",
                format_name(selection.format),
                selection.filter.map_or("none", filter_name),
                selection.archive,
                selection.inputs.len(),
            ),
        )
    }
}

fn parse_create(args: &[String]) -> Result<CreateSelection<'_>, CliError> {
    let mut format = None;
    let mut filter = None;
    let mut operands = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            operands.extend(args[index + 1..].iter().map(String::as_str));
            break;
        }
        if argument == "--format" || argument == "--filter" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| CliError::usage(format!("{argument} requires a value")))?;
            if argument == "--format" {
                if format.replace(parse_create_format(value)?).is_some() {
                    return Err(CliError::usage("--format may be specified only once"));
                }
            } else if filter.replace(parse_create_filter(value)?).is_some() {
                return Err(CliError::usage("--filter may be specified only once"));
            }
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--format=") {
            if format.replace(parse_create_format(value)?).is_some() {
                return Err(CliError::usage("--format may be specified only once"));
            }
        } else if let Some(value) = argument.strip_prefix("--filter=") {
            if filter.replace(parse_create_filter(value)?).is_some() {
                return Err(CliError::usage("--filter may be specified only once"));
            }
        } else if argument.starts_with('-') && argument != "-" {
            return Err(CliError::unsupported(argument));
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    let format = format.ok_or_else(|| CliError::usage("create requires --format FORMAT"))?;
    if operands.len() < 2 {
        return Err(CliError::usage(
            "create requires ARCHIVE and at least one INPUT operand",
        ));
    }
    Ok(CreateSelection {
        format,
        filter: filter.unwrap_or(None),
        archive: operands[0],
        inputs: operands[1..].to_vec(),
    })
}

fn parse_create_format(value: &str) -> Result<FormatId, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "tar" | "ustar" | "pax" => Ok(FormatId::Tar),
        "cpio" | "newc" => Ok(FormatId::Cpio),
        "ar" => Ok(FormatId::Ar),
        "zip" => Ok(FormatId::Zip),
        _ => Err(CliError::unsupported(format!(
            "--format {value} (supported: tar, cpio, ar, zip)"
        ))),
    }
}

fn parse_create_filter(value: &str) -> Result<Option<FilterId>, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(None),
        "gzip" | "gz" => Ok(Some(FilterId::Gzip)),
        "bzip2" | "bz2" => Ok(Some(FilterId::Bzip2)),
        "xz" => Ok(Some(FilterId::Xz)),
        "zstd" | "zst" => Ok(Some(FilterId::Zstd)),
        "lz4" => Ok(Some(FilterId::Lz4)),
        _ => Err(CliError::unsupported(format!(
            "--filter {value} (supported: none, gzip, bzip2, xz, zstd, lz4)"
        ))),
    }
}

fn stream_create<W: Write>(output: W, selection: &CreateSelection<'_>) -> Result<W, CliError> {
    let options = CreateOptions::new()
        .with_format(selection.format)
        .with_filter(selection.filter);
    let mut builder = StreamingArchiveBuilder::with_engine(ArchiveEngine::new(), output, options)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    for input in &selection.inputs {
        builder
            .append_path(input)
            .map_err(|error| CliError::runtime(format!("cannot archive {input}: {error}")))?;
    }
    builder
        .finish()
        .map_err(|error| CliError::runtime(error.to_string()))
}

fn validate_create_destination(destination: &Path, inputs: &[&str]) -> CliResult {
    if destination.file_name().is_none() {
        return Err(CliError::runtime("archive destination must name a file"));
    }
    if destination.exists() {
        return Err(CliError::runtime(format!(
            "archive destination already exists: {}",
            destination.display()
        )));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent)
        .map_err(|error| CliError::runtime(format!("cannot resolve archive parent: {error}")))?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| CliError::runtime("archive destination must name a file"))?,
    );
    for input in inputs {
        let metadata = std::fs::symlink_metadata(input)
            .map_err(|error| CliError::runtime(format!("cannot inspect input {input}: {error}")))?;
        let source = std::fs::canonicalize(input)
            .map_err(|error| CliError::runtime(format!("cannot resolve input {input}: {error}")))?;
        if source == destination || (metadata.is_dir() && destination.starts_with(&source)) {
            return Err(CliError::runtime(format!(
                "archive destination {} is inside create input {input}",
                destination.display()
            )));
        }
    }
    Ok(())
}

fn create_temporary_archive(destination: &Path) -> Result<(PathBuf, File), CliError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..128 {
        let counter = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".oxarchive-{}-{counter:016x}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => {
                return Err(CliError::runtime(format!(
                    "cannot create temporary archive beside {}: {error}",
                    destination.display()
                )));
            },
        }
    }
    Err(CliError::runtime(
        "cannot allocate a unique temporary archive sibling",
    ))
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
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        write_human_line(
            &mut output,
            format_args!("format: {}", format_name(plan.format())),
        )?;
        write_human_line(&mut output, format_args!("digest: {}", plan.digest()))?;
        write_human_line(
            &mut output,
            format_args!("policy: {}", selection.human_name()),
        )?;
        write_human_line(
            &mut output,
            format_args!("entries: {}", plan.entries().len()),
        )?;
        for entry in plan.entries() {
            write_human_line(
                &mut output,
                format_args!(
                    "{}\t{}",
                    disposition_name(entry.disposition()),
                    entry.descriptor().metadata().path().display_lossy()
                ),
            )?;
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
        let filesystem_findings: Vec<Value> = report
            .filesystem_findings()
            .iter()
            .map(|finding| {
                json!({
                    "path": finding.path().display_lossy(),
                    "path_raw_hex": hex(finding.path().as_bytes()),
                    "operation": format!("{:?}", finding.operation()).to_ascii_lowercase(),
                    "kind": format!("{:?}", finding.kind()).to_ascii_lowercase(),
                    "detail": finding.detail(),
                    "io_error_kind": finding.io_error_kind().map(|kind| format!("{kind:?}").to_ascii_lowercase()),
                    "raw_os_error": finding.raw_os_error(),
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
            "filesystem_incomplete": report.has_filesystem_findings(),
            "outcomes": outcomes,
            "filesystem_findings": filesystem_findings,
        }))?;
    } else {
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        write_human_line(
            &mut output,
            format_args!("format: {}", format_name(report.format())),
        )?;
        write_human_line(&mut output, format_args!("digest: {}", report.digest()))?;
        for outcome in report.extraction().outcomes() {
            write_human_line(
                &mut output,
                format_args!(
                    "{}\t{}",
                    outcome_name(outcome.outcome()),
                    outcome.path().display_lossy()
                ),
            )?;
        }
        for finding in report.filesystem_findings() {
            write_human_line(
                &mut output,
                format_args!(
                    "filesystem:{:?}\t{:?}\t{}\t{}",
                    finding.kind(),
                    finding.operation(),
                    finding.path().display_lossy(),
                    finding.detail(),
                ),
            )?;
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
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        write_human_line(&mut output, format_args!("verified: true"))?;
        write_human_line(&mut output, format_args!("format: {}", format_name(format)))?;
        write_human_line(&mut output, format_args!("digest: {}", session.digest()))?;
        write_human_line(&mut output, format_args!("entries: {entries}"))?;
        write_human_line(&mut output, format_args!("payload-bytes: {payload_bytes}"))
    }
}

fn one_archive_operand(args: &[String]) -> Result<&str, CliError> {
    let explicitly_positional = args.first().is_some_and(|argument| argument == "--");
    let args = if explicitly_positional {
        &args[1..]
    } else {
        args
    };
    if args.len() != 1 {
        return Err(CliError::usage(
            "command requires exactly one ARCHIVE operand",
        ));
    }
    if !explicitly_positional && args[0].starts_with('-') && args[0] != "-" {
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

pub(crate) fn print_json(value: &Value) -> CliResult {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)
        .map_err(|error| CliError::runtime(format!("cannot write JSON output: {error}")))?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|error| CliError::runtime(format!("cannot flush stdout: {error}")))
}

pub(crate) fn write_json_record<W: Write>(output: &mut W, value: &Value) -> CliResult {
    serde_json::to_writer(&mut *output, value)
        .map_err(|error| CliError::runtime(format!("cannot write JSON record: {error}")))?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|error| CliError::runtime(format!("cannot flush JSON record: {error}")))
}

fn print_human(arguments: std::fmt::Arguments<'_>) -> CliResult {
    let stdout = io::stdout();
    write_human_line(&mut stdout.lock(), arguments)
}
fn write_human_line<W: Write>(output: &mut W, arguments: std::fmt::Arguments<'_>) -> CliResult {
    writeln!(output, "{arguments}")
        .and_then(|()| output.flush())
        .map_err(|error| CliError::runtime(format!("cannot write stdout: {error}")))
}

fn format_name(format: FormatId) -> String {
    format!("{format:?}").to_ascii_lowercase()
}

fn filter_name(filter: FilterId) -> &'static str {
    match filter {
        FilterId::Gzip => "gzip",
        FilterId::Bzip2 => "bzip2",
        FilterId::Xz => "xz",
        FilterId::Zstd => "zstd",
        FilterId::Lz4 => "lz4",
        _ => "unknown",
    }
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
