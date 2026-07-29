// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified high-level archive inspection, planning, application, creation,
//! and verification commands.

use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveEngine, ArchiveSession, Backend, CapabilityState, CreateOptions, EntryOutcomeKind,
    ExtractionPlan, PlanDisposition, Policy, ReaderEvent, SecretBytes, StreamingArchiveBuilder,
};
use libarchive_oxide_core::{
    AccessMode, ArchivePath, CAPABILITY_LEDGER, CapabilityRecord, CapabilitySubject, Direction,
    EntryMetadata, FilterId, FormatId, MethodId,
};
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::{CliError, CliResult};

/// Pre-1.0 machine-output schema. This is versioned separately from the Rust
/// and command-line APIs and may change before its own stability declaration.
pub const JSON_SCHEMA_VERSION: &str = "oxarchive.output.v0alpha1";

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);
const PASSWORD_FILE_MAX_BYTES: u64 = 64 * 1024;

const HELP: &str = "\
oxarchive - safe high-level archive operations

Usage:
  oxarchive [--json] list [--format raw] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] extract [--format raw] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] inspect [--format raw] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] plan [--format raw] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE
  oxarchive [--json] apply [--format raw] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] create [--format FORMAT] [--filter FILTER] [--reproducible] [PASSWORD SOURCE] ARCHIVE INPUT...
  oxarchive [--json] verify [--format raw] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] capabilities
  oxarchive completion <bash|zsh|fish|powershell>
  oxarchive man
  oxarchive oci inspect LAYER
  oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
  oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...
  oxarchive package validate PACKAGE --type <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix> [--idsig-file PATH] [TRUST FLAGS]

ARCHIVE may be '-' to read standard input, or for create to write standard output.
Signatureless raw input must be selected explicitly with `--format raw`.
Create formats: tar, cpio, ar, zip. Filters: none, gzip, bzip2, xz, zstd, lz4.
`--json create -` is refused so machine records never mix with archive bytes.
The `oci` subcommands read OCI image layers (tar, tar+gzip, tar+zstd) and emit
machine JSON only. `oci apply` requires a seekable LAYER file (not '-').
The `package validate` subcommand runs the shared package validators and emits
one machine JSON record; deb/rpm/alpine-apk accept '-', the ZIP-container
profiles do not. APK v4/v4.1 sidecars are accepted only through an explicit
`--idsig-file PATH`; no sibling path is guessed.

Policy flags:
  --overwrite
  --allow-symlinks
  --allow-hardlinks
  --allow-special-files

Password source (choose at most one):
  --password-file FILE
  --password-prompt

Password values in argv (`--password`, `--password=...`, and `-P...`) are
always refused. Password files must be regular, non-empty, at most 64 KiB,
and on Unix accessible only by their owner. A single trailing LF or CRLF is
removed. Prompts require a TTY and cannot be combined with archive input '-'.

JSON plans are advisory reports, not reusable apply inputs.
Exit codes: 0 success, 1 runtime failure, 2 usage failure.";

/// Runs the unified `oxarchive` command.
pub fn run_oxarchive(mut args: Vec<String>) -> CliResult {
    reject_argv_password_values(&args)?;
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
        "inspect" | "list" => run_inspect(operands, json_output),
        "plan" => run_plan(operands, json_output),
        "apply" | "extract" => run_apply(operands, json_output),
        "create" => run_create(operands, json_output),
        "verify" => run_verify(operands, json_output),
        "capabilities" => run_capabilities(operands, json_output),
        "completion" => run_completion(operands, json_output),
        "man" => run_man(operands, json_output),
        "oci" => crate::oci::run_oci(operands),
        "package" => crate::package::run_package(operands),
        flag if flag.starts_with('-') => Err(CliError::unsupported(flag)),
        _ => Err(CliError::usage(format!(
            "unknown command: {command}\n\n{HELP}"
        ))),
    }
}

fn run_completion(args: &[String], json_output: bool) -> CliResult {
    if json_output {
        return Err(CliError::usage(
            "completion emits a shell script and cannot be combined with --json",
        ));
    }
    let [shell] = args else {
        return Err(CliError::usage(
            "completion requires exactly one shell: bash, zsh, fish, or powershell",
        ));
    };
    let commands =
        "list extract create inspect plan apply verify capabilities oci package completion man";
    let options = "--password-file --password-prompt --idsig-file";
    let script = match shell.as_str() {
        "bash" => format!(
            "_oxarchive() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  COMPREPLY=( $(compgen -W '{commands} {options}' -- \"$cur\") )\n}}\ncomplete -F _oxarchive oxarchive"
        ),
        "zsh" => {
            format!(
                "#compdef oxarchive\n_arguments '--password-file[read archive password from a protected file]:password file:_files' '--password-prompt[read archive password without echo from the TTY]' '--idsig-file[supply an explicit APK v4 sidecar]:idsig file:_files' '1:command:({commands})' '*:operand:_files'"
            )
        },
        "fish" => {
            let mut lines = commands
                .split_ascii_whitespace()
                .map(|command| {
                    format!("complete -c oxarchive -n '__fish_use_subcommand' -a {command}")
                })
                .collect::<Vec<_>>();
            lines.push(
                "complete -c oxarchive -l password-file -r -d 'Read archive password from a protected file'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l password-prompt -d 'Read archive password without echo from the TTY'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l idsig-file -r -d 'Supply an explicit APK v4 sidecar'"
                    .to_string(),
            );
            lines.join("\n")
        },
        "powershell" => format!(
            "Register-ArgumentCompleter -Native -CommandName oxarchive -ScriptBlock {{\n  param($wordToComplete)\n  '{commands} {options}'.Split(' ') | Where-Object {{ $_ -like \"$wordToComplete*\" }}\n}}"
        ),
        other => {
            return Err(CliError::usage(format!(
                "unknown completion shell: {other} (supported: bash, zsh, fish, powershell)"
            )));
        },
    };
    print_human(format_args!("{script}"))
}

fn run_man(args: &[String], json_output: bool) -> CliResult {
    if json_output {
        return Err(CliError::usage(
            "man emits roff and cannot be combined with --json",
        ));
    }
    if !args.is_empty() {
        return Err(CliError::usage("man does not accept operands"));
    }
    print_human(format_args!(
        ".TH OXARCHIVE 1\n.SH NAME\noxarchive \\- safe archive and package toolkit\n\
         .SH SYNOPSIS\n.B oxarchive\n[--json] COMMAND [OPTIONS]\n\
         .SH COMMANDS\nlist, extract, create, inspect, plan, apply, verify, capabilities, oci, package\n\
         .SH PASSWORDS\nUse --password-file FILE or --password-prompt with archive read commands and ZIP create. \
         A password file must be regular, non-empty, no larger than 64 KiB, and owner-only on Unix. \
         The prompt requires a TTY, disables echo, and cannot share standard input with archive input '-'.\n\
         .SH PACKAGE AUTHENTICITY\nUse package validate --type android-apk --idsig-file PATH to \
         verify an explicitly supplied APK v4/v4.1 sidecar. No sibling path or network source is inferred.\n\
         .SH SECURITY\nExtraction uses the safe policy by default. Password values supplied through --password, \
         --password=VALUE, or -PVALUE are rejected before archive I/O."
    ))
}

fn run_capabilities(args: &[String], json_output: bool) -> CliResult {
    if !args.is_empty() {
        return Err(CliError::usage(
            "capabilities does not accept positional operands",
        ));
    }
    if json_output {
        let entries = CAPABILITY_LEDGER
            .iter()
            .copied()
            .map(capability_json)
            .collect::<Vec<_>>();
        return print_json(&json!({
            "schema": JSON_SCHEMA_VERSION,
            "type": "capability-ledger",
            "entries": entries,
        }));
    }

    print_human(format_args!(
        "{:<28} {:<11} {:<10} {}",
        "KEY", "PORTABLE", "NATIVE", "NAME"
    ))?;
    for record in CAPABILITY_LEDGER {
        print_human(format_args!(
            "{:<28} {:<11} {:<10} {}",
            record.key(),
            capability_state_name(*record, Backend::Portable),
            capability_state_name(*record, Backend::Native),
            record.name(),
        ))?;
    }
    Ok(())
}

fn capability_json(record: CapabilityRecord) -> Value {
    let (kind, format, filter, method_id) = match record.subject() {
        CapabilitySubject::Format(format) => ("format", Some(format_name(format)), None, None),
        CapabilitySubject::Method { format, id } => (
            "method",
            Some(format_name(format)),
            None,
            Some(method_id_json(id)),
        ),
        CapabilitySubject::Filter(filter) => {
            ("filter", None, Some(filter_name(filter).to_string()), None)
        },
        _ => ("unknown", None, None, None),
    };
    json!({
        "key": record.key(),
        "kind": kind,
        "format": format,
        "filter": filter,
        "method_id": method_id,
        "name": record.name(),
        "access": {
            "read": record.access().read().map(access_name),
            "write": record.access().write().map(access_name),
        },
        "requirements": record.requirements(),
        "portable": capability_state_json(record, Backend::Portable),
        "native": capability_state_json(record, Backend::Native),
        "note": record.note(),
    })
}

fn method_id_json(id: MethodId) -> Value {
    match id {
        MethodId::Numeric(value) => json!({
            "kind": "numeric",
            "value": value,
        }),
        MethodId::Bytes(value) => json!({
            "kind": "bytes",
            "hex": hex(value),
        }),
        MethodId::Name(value) => json!({
            "kind": "name",
            "value": value,
        }),
        _ => json!({
            "kind": "unknown",
        }),
    }
}

fn capability_state_json(record: CapabilityRecord, backend: Backend) -> Value {
    match libarchive_oxide::capability_state(record, backend) {
        CapabilityState::Available(directions) => json!({
            "state": "available",
            "read": directions.contains(Direction::Read),
            "write": directions.contains(Direction::Write),
        }),
        CapabilityState::Disabled => json!({
            "state": "disabled",
            "read": false,
            "write": false,
        }),
        CapabilityState::Unsupported => json!({
            "state": "unsupported",
            "read": false,
            "write": false,
        }),
        _ => json!({
            "state": "unknown",
            "read": false,
            "write": false,
        }),
    }
}

fn capability_state_name(record: CapabilityRecord, backend: Backend) -> &'static str {
    match libarchive_oxide::capability_state(record, backend) {
        CapabilityState::Available(directions)
            if directions.contains(Direction::Read) && directions.contains(Direction::Write) =>
        {
            "read/write"
        },
        CapabilityState::Available(directions) if directions.contains(Direction::Read) => "read",
        CapabilityState::Available(directions) if directions.contains(Direction::Write) => "write",
        CapabilityState::Available(_) => "available",
        CapabilityState::Disabled => "disabled",
        CapabilityState::Unsupported => "unsupported",
        _ => "unknown",
    }
}

const fn access_name(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Sequential => "sequential",
        AccessMode::Seek => "seek",
        AccessMode::Filter => "filter",
        _ => "unknown",
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

fn reject_argv_password_values(args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|argument| {
        argument == "--password"
            || argument.starts_with("--password=")
            || argument == "-P"
            || (argument.starts_with("-P") && argument.len() > 2)
    }) {
        return Err(CliError::usage(
            "password values in command-line arguments are refused; use --password-file or --password-prompt",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PasswordSource<'a> {
    File(&'a str),
    Prompt,
}

impl std::fmt::Debug for PasswordSource<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(_) => formatter.write_str("PasswordSource::File([REDACTED])"),
            Self::Prompt => formatter.write_str("PasswordSource::Prompt"),
        }
    }
}

impl PasswordSource<'_> {
    fn acquire(self, archive_uses_stdin: bool) -> Result<SecretBytes, CliError> {
        match self {
            Self::File("-") => Err(CliError::usage(
                "--password-file - is refused because standard input is reserved for archive data or a TTY prompt",
            )),
            Self::File(path) => read_password_file(Path::new(path)),
            Self::Prompt if archive_uses_stdin => Err(CliError::usage(
                "--password-prompt cannot be combined with archive input '-'",
            )),
            Self::Prompt if !io::stdin().is_terminal() => Err(CliError::usage(
                "--password-prompt requires an interactive TTY",
            )),
            Self::Prompt => {
                let password =
                    rpassword::prompt_password("Archive password: ").map_err(|error| {
                        CliError::runtime(format!("cannot read password from TTY: {error}"))
                    })?;
                let bytes = password.into_bytes();
                validate_password_bytes(bytes, "TTY password")
            },
        }
    }
}

fn acquire_password(
    source: Option<PasswordSource<'_>>,
    archive_uses_stdin: bool,
) -> Result<Option<SecretBytes>, CliError> {
    source
        .map(|source| source.acquire(archive_uses_stdin))
        .transpose()
}

fn parse_password_option<'a>(
    args: &'a [String],
    index: usize,
    source: &mut Option<PasswordSource<'a>>,
) -> Result<Option<usize>, CliError> {
    let argument = args[index].as_str();
    let (candidate, consumed) = if argument == "--password-prompt" {
        (PasswordSource::Prompt, 1)
    } else if argument == "--password-file" {
        let path = args
            .get(index + 1)
            .ok_or_else(|| CliError::usage("--password-file requires a path"))?;
        (PasswordSource::File(path), 2)
    } else if let Some(path) = argument.strip_prefix("--password-file=") {
        if path.is_empty() {
            return Err(CliError::usage("--password-file requires a path"));
        }
        (PasswordSource::File(path), 1)
    } else {
        return Ok(None);
    };
    if source.replace(candidate).is_some() {
        return Err(CliError::usage(
            "choose exactly one password source: --password-file or --password-prompt",
        ));
    }
    Ok(Some(index + consumed))
}

fn read_password_file(path: &Path) -> Result<SecretBytes, CliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        CliError::runtime(format!(
            "cannot inspect password file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::usage(
            "password file must be a regular file, not a directory, symlink, device, or pipe",
        ));
    }
    #[cfg(unix)]
    validate_unix_password_file(&metadata)?;
    if metadata.len() > PASSWORD_FILE_MAX_BYTES {
        return Err(CliError::usage(
            "password file exceeds the 64 KiB safety limit",
        ));
    }

    let file = OpenOptions::new().read(true).open(path).map_err(|error| {
        CliError::runtime(format!(
            "cannot open password file {}: {error}",
            path.display()
        ))
    })?;
    let opened = file.metadata().map_err(|error| {
        CliError::runtime(format!(
            "cannot inspect opened password file {}: {error}",
            path.display()
        ))
    })?;
    if !opened.file_type().is_file() {
        return Err(CliError::usage(
            "password file changed and is no longer a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        validate_unix_password_file(&opened)?;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            return Err(CliError::runtime(
                "password file changed while it was being opened",
            ));
        }
    }

    let capacity = usize::try_from(opened.len().min(PASSWORD_FILE_MAX_BYTES))
        .map_err(|_| CliError::runtime("password file length cannot fit in memory"))?;
    let mut bytes = Vec::with_capacity(capacity);
    if let Err(error) = file
        .take(PASSWORD_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(CliError::runtime(format!(
            "cannot read password file {}: {error}",
            path.display()
        )));
    }
    if bytes.len() as u64 > PASSWORD_FILE_MAX_BYTES {
        bytes.zeroize();
        return Err(CliError::usage(
            "password file exceeds the 64 KiB safety limit",
        ));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    validate_password_bytes(bytes, "password file")
}

#[cfg(unix)]
fn validate_unix_password_file(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::usage(
            "password file permissions must deny all group and other access (use mode 0600 or stricter)",
        ));
    }
    Ok(())
}

fn validate_password_bytes(mut bytes: Vec<u8>, source: &str) -> Result<SecretBytes, CliError> {
    if bytes.is_empty() {
        bytes.zeroize();
        return Err(CliError::usage(format!("{source} must not be empty")));
    }
    if bytes.len() as u64 > PASSWORD_FILE_MAX_BYTES {
        bytes.zeroize();
        return Err(CliError::usage(format!(
            "{source} exceeds the 64 KiB safety limit"
        )));
    }
    Ok(SecretBytes::new(bytes))
}

#[derive(Debug)]
struct ReadSelection<'a> {
    format: Option<FormatId>,
    password: Option<PasswordSource<'a>>,
    operands: Vec<&'a str>,
}

fn parse_read_selection(args: &[String]) -> Result<ReadSelection<'_>, CliError> {
    let mut format = None;
    let mut password = None;
    let mut operands = Vec::new();
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument == "--format" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| CliError::usage("--format requires a value"))?;
            if format.replace(parse_read_format(value)?).is_some() {
                return Err(CliError::usage("--format may be specified only once"));
            }
            index += 2;
            continue;
        }
        if options && let Some(next) = parse_password_option(args, index, &mut password)? {
            index = next;
            continue;
        }
        if options {
            if let Some(value) = argument.strip_prefix("--format=") {
                if format.replace(parse_read_format(value)?).is_some() {
                    return Err(CliError::usage("--format may be specified only once"));
                }
                index += 1;
                continue;
            }
            if argument.starts_with('-') && argument != "-" {
                return Err(CliError::unsupported(argument));
            }
        }
        operands.push(argument);
        index += 1;
    }
    Ok(ReadSelection {
        format,
        password,
        operands,
    })
}

fn parse_read_format(value: &str) -> Result<FormatId, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "raw" => Ok(FormatId::Raw),
        "tar" | "ustar" | "pax" => Ok(FormatId::Tar),
        "cpio" | "newc" => Ok(FormatId::Cpio),
        "ar" => Ok(FormatId::Ar),
        "empty" => Ok(FormatId::Empty),
        _ => Err(CliError::unsupported(format!(
            "--format {value} for reading (supported: raw, tar, cpio, ar, empty)"
        ))),
    }
}

fn run_inspect(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_read_selection(args)?;
    let [archive] = selection.operands.as_slice() else {
        return Err(CliError::usage(
            "inspect requires exactly one ARCHIVE operand",
        ));
    };
    let password = acquire_password(selection.password, *archive == "-")?;
    let mut session = open_session(archive, selection.format, password)?;
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
    reproducible: bool,
    password: Option<PasswordSource<'a>>,
    archive: &'a str,
    inputs: Vec<&'a str>,
}

fn run_create(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_create(args)?;
    if selection.password.is_some() {
        if selection.format != FormatId::Zip {
            return Err(CliError::usage(
                "a password source is accepted for create only when the output format is ZIP",
            ));
        }
        if selection.filter.is_some() {
            return Err(CliError::usage(
                "password-protected ZIP create cannot use an outer filter",
            ));
        }
    }
    if selection.archive == "-" && json_output {
        return Err(CliError::usage(
            "--json create - would mix JSON records with archive bytes",
        ));
    }
    let password = acquire_password(selection.password, false)?;
    if selection.archive == "-" {
        let stdout = io::stdout();
        let mut output = stream_create(stdout.lock(), &selection, password)?;
        return output
            .flush()
            .map_err(|error| CliError::runtime(format!("cannot flush stdout: {error}")));
    }

    let destination = PathBuf::from(selection.archive);
    validate_create_destination(&destination, &selection.inputs)?;
    let (temporary, output) = create_temporary_archive(&destination)?;
    let result = stream_create(output, &selection, password);
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
            "metadata_profile": if selection.reproducible { "reproducible" } else { "filesystem" },
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
                "created\tformat={}\tfilter={}\tmetadata={}\tarchive={}\tinputs={}",
                format_name(selection.format),
                selection.filter.map_or("none", filter_name),
                if selection.reproducible {
                    "reproducible"
                } else {
                    "filesystem"
                },
                selection.archive,
                selection.inputs.len(),
            ),
        )
    }
}

fn parse_create(args: &[String]) -> Result<CreateSelection<'_>, CliError> {
    let mut format = None;
    let mut filter = None;
    let mut reproducible = false;
    let mut password = None;
    let mut operands = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            operands.extend(args[index + 1..].iter().map(String::as_str));
            break;
        }
        if argument == "--reproducible" {
            if reproducible {
                return Err(CliError::usage("--reproducible may be specified only once"));
            }
            reproducible = true;
            index += 1;
            continue;
        }
        if let Some(next) = parse_password_option(args, index, &mut password)? {
            index = next;
            continue;
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
    if operands.len() < 2 {
        return Err(CliError::usage(
            "create requires ARCHIVE and at least one INPUT operand",
        ));
    }
    let inferred = infer_create_selection(operands[0]);
    let format = format
        .or_else(|| inferred.map(|selection| selection.0))
        .ok_or_else(|| {
            CliError::usage(
                "cannot infer create format from ARCHIVE; pass --format tar|cpio|ar|zip",
            )
        })?;
    let filter = filter.unwrap_or_else(|| inferred.and_then(|selection| selection.1));
    Ok(CreateSelection {
        format,
        filter,
        reproducible,
        password,
        archive: operands[0],
        inputs: operands[1..].to_vec(),
    })
}

fn infer_create_selection(archive: &str) -> Option<(FormatId, Option<FilterId>)> {
    if archive == "-" {
        return None;
    }
    let name = archive.to_ascii_lowercase();
    for (suffix, format, filter) in [
        (".tar.gz", FormatId::Tar, Some(FilterId::Gzip)),
        (".tgz", FormatId::Tar, Some(FilterId::Gzip)),
        (".tar.bz2", FormatId::Tar, Some(FilterId::Bzip2)),
        (".tbz2", FormatId::Tar, Some(FilterId::Bzip2)),
        (".tbz", FormatId::Tar, Some(FilterId::Bzip2)),
        (".tar.xz", FormatId::Tar, Some(FilterId::Xz)),
        (".txz", FormatId::Tar, Some(FilterId::Xz)),
        (".tar.zst", FormatId::Tar, Some(FilterId::Zstd)),
        (".tzst", FormatId::Tar, Some(FilterId::Zstd)),
        (".tar.lz4", FormatId::Tar, Some(FilterId::Lz4)),
        (".cpio.gz", FormatId::Cpio, Some(FilterId::Gzip)),
        (".cpio.bz2", FormatId::Cpio, Some(FilterId::Bzip2)),
        (".cpio.xz", FormatId::Cpio, Some(FilterId::Xz)),
        (".cpio.zst", FormatId::Cpio, Some(FilterId::Zstd)),
    ] {
        if name.ends_with(suffix) {
            return Some((format, filter));
        }
    }
    for (suffix, format) in [
        (".tar", FormatId::Tar),
        (".cpio", FormatId::Cpio),
        (".ar", FormatId::Ar),
        (".a", FormatId::Ar),
        (".zip", FormatId::Zip),
    ] {
        if name.ends_with(suffix) {
            return Some((format, None));
        }
    }
    None
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

fn stream_create<W: Write>(
    output: W,
    selection: &CreateSelection<'_>,
    password: Option<SecretBytes>,
) -> Result<W, CliError> {
    let options = CreateOptions::new()
        .with_format(selection.format)
        .with_filter(selection.filter);
    let mut builder = match password {
        Some(password) => StreamingArchiveBuilder::with_engine_and_password(
            ArchiveEngine::new(),
            output,
            options,
            password,
        ),
        None => StreamingArchiveBuilder::with_engine(ArchiveEngine::new(), output, options),
    }
    .map_err(|error| CliError::runtime(error.to_string()))?;
    if selection.reproducible {
        builder =
            builder.with_metadata_profile(libarchive_oxide::CreationMetadataProfile::Reproducible);
    }
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
    let arguments = parse_policy(args)?;
    if arguments.operands.len() != 1 {
        return Err(CliError::usage("plan requires exactly one ARCHIVE operand"));
    }
    let password = acquire_password(arguments.password, arguments.operands[0] == "-")?;
    let mut session = open_session(arguments.operands[0], arguments.format, password)?;
    let plan = session
        .plan(arguments.selection.policy())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    if json_output {
        print_json(&plan_json(&plan, arguments.selection))
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
            format_args!("policy: {}", arguments.selection.human_name()),
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
    let arguments = parse_policy(args)?;
    if arguments.operands.len() != 2 {
        return Err(CliError::usage(
            "apply requires exactly ARCHIVE and DEST operands",
        ));
    }
    let password = acquire_password(arguments.password, arguments.operands[0] == "-")?;
    let mut session = open_session(arguments.operands[0], arguments.format, password)?;
    let plan = session
        .plan(arguments.selection.policy())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    std::fs::create_dir_all(arguments.operands[1])
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let root = Dir::open_ambient_dir(Path::new(arguments.operands[1]), ambient_authority())
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
            "policy": arguments.selection.json(),
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
    let selection = parse_read_selection(args)?;
    let [archive] = selection.operands.as_slice() else {
        return Err(CliError::usage(
            "verify requires exactly one ARCHIVE operand",
        ));
    };
    let password = acquire_password(selection.password, *archive == "-")?;
    let mut session = open_session(archive, selection.format, password)?;
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

#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // Mirrors four independent policy capabilities.
struct PolicySelection {
    overwrite: bool,
    symlinks: bool,
    hardlinks: bool,
    special_files: bool,
}

struct PolicyArguments<'a> {
    selection: PolicySelection,
    format: Option<FormatId>,
    password: Option<PasswordSource<'a>>,
    operands: Vec<&'a str>,
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

fn parse_policy(args: &[String]) -> Result<PolicyArguments<'_>, CliError> {
    let mut selection = PolicySelection::default();
    let mut format = None;
    let mut password = None;
    let mut operands = Vec::new();
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options {
            if let Some(next) = parse_password_option(args, index, &mut password)? {
                index = next;
                continue;
            }
            if argument == "--format" {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--format requires a value"))?;
                if format.replace(parse_read_format(value)?).is_some() {
                    return Err(CliError::usage("--format may be specified only once"));
                }
                index += 2;
                continue;
            }
            if let Some(value) = argument.strip_prefix("--format=") {
                if format.replace(parse_read_format(value)?).is_some() {
                    return Err(CliError::usage("--format may be specified only once"));
                }
                index += 1;
                continue;
            }
            match argument {
                "--overwrite" => selection.overwrite = true,
                "--allow-symlinks" => selection.symlinks = true,
                "--allow-hardlinks" => selection.hardlinks = true,
                "--allow-special-files" => selection.special_files = true,
                flag if flag.starts_with('-') && flag != "-" => {
                    return Err(CliError::unsupported(flag));
                },
                _ => operands.push(argument),
            }
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    Ok(PolicyArguments {
        selection,
        format,
        password,
        operands,
    })
}

fn open_session(
    path: &str,
    format: Option<FormatId>,
    password: Option<SecretBytes>,
) -> Result<ArchiveSession, CliError> {
    let engine = ArchiveEngine::new();
    if password.is_some() && format.is_some() {
        return Err(CliError::usage(
            "a password source cannot be combined with an explicit sequential --format",
        ));
    }
    if path == "-" {
        let stdin = io::stdin();
        match (format, password) {
            (Some(format), None) => engine.prepare_with_format(stdin.lock(), format),
            (None, Some(password)) => engine.prepare_with_password(stdin.lock(), password),
            (None, None) => engine.prepare(stdin.lock()),
            (Some(_), Some(_)) => {
                return Err(CliError::usage(
                    "a password source cannot be combined with an explicit sequential --format",
                ));
            },
        }
        .map_err(|error| CliError::runtime(error.to_string()))
    } else {
        let input = File::open(path).map_err(|error| CliError::runtime(error.to_string()))?;
        match (format, password) {
            (Some(format), None) => engine.prepare_with_format(input, format),
            (None, Some(password)) => engine.prepare_with_password(input, password),
            (None, None) => engine.prepare(input),
            (Some(_), Some(_)) => {
                return Err(CliError::usage(
                    "a password source cannot be combined with an explicit sequential --format",
                ));
            },
        }
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
    libarchive_oxide_core::capability::format_capability(format).map_or_else(
        || format!("{format:?}").to_ascii_lowercase(),
        |record| record.name().to_string(),
    )
}

fn filter_name(filter: FilterId) -> &'static str {
    libarchive_oxide_core::capability::filter_capability(filter)
        .map_or("unknown", |record| record.name())
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
