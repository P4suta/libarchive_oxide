// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified high-level archive inspection, planning, application, creation,
//! and verification commands.

use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::advanced::{
    AccessMode, CAPABILITY_LEDGER, CapabilityRecord, CapabilitySubject, Direction, MethodId,
    filter_capability, format_capability,
};
use libarchive_oxide::{
    AesStrength, ArchiveEditor, ArchiveEngine, ArchivePath, ArchiveSession, ArchiveTranscoder,
    Backend, CapabilityState, CreateOptions, EditOperation, EntryMetadata, EntryOutcomeKind,
    ExtractionPlan, FilterId, FormatId, FormatWriteOptions, MetadataField, MetadataLossPolicy,
    OpenOptions as ArchiveOpenOptions, PasswordCandidates, PlanDisposition, Policy, ReaderEvent,
    SecretBytes, SeekArchiveBuilder, SevenZipCompression, SevenZipEncryption, SevenZipFilter,
    SevenZipWriteOptions, StreamingArchiveBuilder, XarCompression, XarWriteOptions, ZipCompression,
    ZipEncryption, ZipWriteOptions,
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
  oxarchive [--json] list [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] extract [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] inspect [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] plan [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE
  oxarchive [--json] apply [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] [POLICY FLAGS] ARCHIVE DEST
  oxarchive [--json] create [--format FORMAT] [--filter FILTER] [--reproducible] [ZIP PROFILE] [7Z PROFILE] [XAR PROFILE] [PASSWORD SOURCE] ARCHIVE INPUT...
  oxarchive [--json] convert [--from-format FORMAT] [--format FORMAT] [--filter FILTER] [--reject-metadata-loss] [PASSWORD SOURCE] SOURCE DEST
  oxarchive [--json] edit [--from-format FORMAT] [--format FORMAT] [--filter FILTER] [--reject-metadata-loss] [PASSWORD SOURCE] (--remove PATH | --rename FROM=TO)... SOURCE DEST
  oxarchive [--json] verify [--format FORMAT] [--discover-volumes] [PASSWORD SOURCE] ARCHIVE
  oxarchive [--json] capabilities
  oxarchive completion <bash|zsh|fish|powershell>
  oxarchive man
  oxarchive oci inspect LAYER
  oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
  oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...
  oxarchive package validate PACKAGE --type <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix> [--idsig-file PATH] [TRUST FLAGS]

ARCHIVE may be '-' to read standard input, or for create to write standard output.
Signatureless raw input must be selected explicitly with `--format raw`.
Sequential read formats: raw, tar, cpio, ar, mtree, rar-legacy (rar4), rar5, empty.
Create formats: tar, cpio, ar, zip, mtree, 7z, iso9660, xar. Filters: none, gzip, bzip2, xz, zstd, lz4.
Seek-native 7z, ISO 9660, and XAR creation requires a file destination and no outer filter.
Convert uses file operands, atomically publishes DEST, and reports metadata loss.
Edit applies exact-path rename/remove operations through the same atomic rewrite path.
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

Path volume source (read commands only):
  --discover-volumes  Discover bounded adjacent 7z, ZIP, or RAR volumes

ZIP create profile:
  --zip-compression <store|deflate|bzip2|lzma|ppmd8|zstd|xz>
  --zip-encryption <none|zipcrypto|aes128|aes192|aes256>

7z create profile:
  --7z-compression <store|lzma|lzma2|ppmd7|deflate|bzip2|zstd>
  --7z-filter <none|delta:1..256|bcj-x86|bcj-ppc|bcj-ia64|bcj-arm|bcj-arm-thumb|bcj-arm64|bcj-sparc|bcj-riscv>
  --7z-solid | --7z-non-solid
  --7z-encryption <none|aes256>

XAR create profile:
  --xar-compression <store|zlib|bzip2>

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
        "convert" => run_convert(operands, json_output),
        "edit" => run_edit(operands, json_output),
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
    let commands = "list extract create convert edit inspect plan apply verify capabilities oci package completion man";
    let options = "--password-file --password-prompt --discover-volumes --zip-compression --zip-encryption --7z-compression --7z-filter --7z-solid --7z-non-solid --7z-encryption --xar-compression --idsig-file";
    let script = match shell.as_str() {
        "bash" => format!(
            "_oxarchive() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  COMPREPLY=( $(compgen -W '{commands} {options}' -- \"$cur\") )\n}}\ncomplete -F _oxarchive oxarchive"
        ),
        "zsh" => {
            format!(
                "#compdef oxarchive\n_arguments '--password-file[read archive password from a protected file]:password file:_files' '--password-prompt[read archive password without echo from the TTY]' '--discover-volumes[discover bounded adjacent 7z, ZIP, or RAR volumes]' '--zip-compression[select ZIP compression]:method:(store deflate bzip2 lzma ppmd8 zstd xz)' '--zip-encryption[select ZIP encryption]:method:(none zipcrypto aes128 aes192 aes256)' '--7z-compression[select 7z compression]:method:(store lzma lzma2 ppmd7 deflate bzip2 zstd)' '--7z-filter[select 7z preprocessing filter]:filter:(none delta\\:1 bcj-x86 bcj-ppc bcj-ia64 bcj-arm bcj-arm-thumb bcj-arm64 bcj-sparc bcj-riscv)' '--7z-solid[group 7z entries in a solid folder]' '--7z-non-solid[write one 7z folder per non-empty entry]' '--7z-encryption[select 7z encryption]:method:(none aes256)' '--xar-compression[select XAR compression]:method:(store zlib bzip2)' '--idsig-file[supply an explicit APK v4 sidecar]:idsig file:_files' '1:command:({commands})' '*:operand:_files'"
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
                "complete -c oxarchive -l discover-volumes -d 'Discover bounded adjacent 7z, ZIP, or RAR volumes'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l zip-compression -r -a 'store deflate bzip2 lzma ppmd8 zstd xz' -d 'Select ZIP compression'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l zip-encryption -r -a 'none zipcrypto aes128 aes192 aes256' -d 'Select ZIP encryption'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l 7z-compression -r -a 'store lzma lzma2 ppmd7 deflate bzip2 zstd' -d 'Select 7z compression'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l 7z-filter -r -a 'none delta:1 bcj-x86 bcj-ppc bcj-ia64 bcj-arm bcj-arm-thumb bcj-arm64 bcj-sparc bcj-riscv' -d 'Select 7z preprocessing filter'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l 7z-solid -d 'Group 7z entries in a solid folder'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l 7z-non-solid -d 'Write one 7z folder per non-empty entry'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l 7z-encryption -r -a 'none aes256' -d 'Select 7z encryption'"
                    .to_string(),
            );
            lines.push(
                "complete -c oxarchive -l xar-compression -r -a 'store zlib bzip2' -d 'Select XAR compression'"
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
         .SH MULTI-VOLUME INPUT\nUse --discover-volumes with a .001-style 7z, terminal .zip, .part1.rar-style RAR, or legacy .rar path. \
         Discovery is never implicit and cannot be used with standard input.\n\
         .SH RAR INPUT\nUse --format rar-legacy (or rar4) for bounded RAR 3.x/4.x SFX scanning, Store/LZ/PPMd reads, and AES-gated header/data decryption; \
         use --format rar5 for bounded RAR5 Store/LZ reads and AES-gated header/data decryption. RAR writing is unavailable.\n\
         .SH ZIP CREATE PROFILES\nUse --zip-compression METHOD and --zip-encryption METHOD to select \
         typed library ZIP writer options. Encrypted profiles require a password source.\n\
         .SH 7Z CREATE PROFILES\nUse --7z-compression METHOD, --7z-filter FILTER, --7z-solid or \
         --7z-non-solid, and --7z-encryption METHOD to select typed library 7z writer options. \
         Encrypted profiles require a password source.\n\
         .SH XAR CREATE PROFILES\nUse --xar-compression METHOD to select Store, zlib, or BZip2 \
         heap payloads through the typed library XAR writer options.\n\
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
    discover_volumes: bool,
    operands: Vec<&'a str>,
}

fn parse_read_selection(args: &[String]) -> Result<ReadSelection<'_>, CliError> {
    let mut format = None;
    let mut password = None;
    let mut discover_volumes = false;
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
        if options && argument == "--discover-volumes" {
            if std::mem::replace(&mut discover_volumes, true) {
                return Err(CliError::usage(
                    "--discover-volumes may be specified only once",
                ));
            }
            index += 1;
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
        discover_volumes,
        operands,
    })
}

fn parse_read_format(value: &str) -> Result<FormatId, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "raw" => Ok(FormatId::Raw),
        "tar" | "ustar" | "pax" => Ok(FormatId::Tar),
        "cpio" | "newc" => Ok(FormatId::Cpio),
        "ar" => Ok(FormatId::Ar),
        "zip" => Ok(FormatId::Zip),
        "7z" | "sevenz" => Ok(FormatId::SevenZip),
        "iso" | "iso9660" => Ok(FormatId::Iso9660),
        "udf" => Ok(FormatId::Udf),
        "cab" => Ok(FormatId::Cab),
        "xar" => Ok(FormatId::Xar),
        "lha" | "lzh" => Ok(FormatId::Lha),
        "warc" => Ok(FormatId::Warc),
        "mtree" => Ok(FormatId::Mtree),
        "rar-legacy" | "rar4" => Ok(FormatId::RarLegacy),
        "rar5" => Ok(FormatId::Rar5),
        "empty" => Ok(FormatId::Empty),
        _ => Err(CliError::unsupported(format!(
            "--format {value} for reading (supported: raw, tar, cpio, ar, zip, 7z, iso, udf, cab, xar, lha, warc, mtree, rar-legacy, rar5, empty)"
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
    let discover_volumes = selection.discover_volumes;
    let mut session = open_session(archive, selection.format, password, discover_volumes)?;
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
struct ConvertSelection<'a> {
    source_format: FormatId,
    destination_format: FormatId,
    filter: Option<FilterId>,
    reject_metadata_loss: bool,
    password: Option<PasswordSource<'a>>,
    source: &'a str,
    destination: &'a str,
}

fn run_convert(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_convert(args)?;
    let password = acquire_password(selection.password, false)?;
    if password.is_some() && !supports_read_password(selection.source_format) {
        return Err(CliError::usage(
            "convert passwords are accepted only for ZIP, 7z, RAR 3.x/4.x, or RAR5 sources",
        ));
    }
    let source_path = Path::new(selection.source);
    let destination_path = PathBuf::from(selection.destination);
    validate_create_destination(&destination_path, &[selection.source])?;
    let input = File::open(source_path).map_err(|error| {
        CliError::runtime(format!(
            "cannot open conversion source {}: {error}",
            source_path.display()
        ))
    })?;
    let (temporary, output) = create_temporary_archive(&destination_path)?;
    let mut source_options = ArchiveOpenOptions::new().with_format(Some(selection.source_format));
    if let Some(password) = password {
        source_options =
            source_options.with_password_provider(Arc::new(PasswordCandidates::new([password])));
    }
    let destination_options = CreateOptions::new()
        .with_format(selection.destination_format)
        .with_filter(selection.filter);
    let transcoder =
        ArchiveTranscoder::new().with_metadata_loss_policy(if selection.reject_metadata_loss {
            MetadataLossPolicy::Reject
        } else {
            MetadataLossPolicy::Report
        });
    let source_seek = is_seek_read_format(selection.source_format);
    let destination_seek = is_seek_create_format(selection.destination_format);
    let outcome = match (source_seek, destination_seek) {
        (false, false) => transcoder.transcode(input, &source_options, output, destination_options),
        (false, true) => {
            transcoder.transcode_to_seek(input, &source_options, output, destination_options)
        },
        (true, false) => {
            transcoder.transcode_from_seek(input, &source_options, output, destination_options)
        },
        (true, true) => {
            transcoder.transcode_seek(input, &source_options, output, destination_options)
        },
    };
    let (output, report) = match outcome {
        Ok(outcome) => outcome.into_parts(),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(CliError::runtime(error.to_string()));
        },
    };
    publish_temporary_archive(&temporary, &destination_path, output)?;
    report_convert_success(&selection, &report, json_output)
}

fn parse_convert(args: &[String]) -> Result<ConvertSelection<'_>, CliError> {
    let (selection, operations) = parse_rewrite(args, false)?;
    debug_assert_eq!(operations, [] as [libarchive_oxide::EditOperation; 0]);
    Ok(selection)
}

#[derive(Debug)]
struct EditSelection<'a> {
    rewrite: ConvertSelection<'a>,
    operations: Vec<EditOperation>,
}

fn run_edit(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_edit(args)?;
    let password = acquire_password(selection.rewrite.password, false)?;
    if password.is_some() && !supports_read_password(selection.rewrite.source_format) {
        return Err(CliError::usage(
            "edit passwords are accepted only for ZIP, 7z, RAR 3.x/4.x, or RAR5 sources",
        ));
    }
    let source_path = Path::new(selection.rewrite.source);
    let destination_path = PathBuf::from(selection.rewrite.destination);
    validate_create_destination(&destination_path, &[selection.rewrite.source])?;
    let input = File::open(source_path).map_err(|error| {
        CliError::runtime(format!(
            "cannot open edit source {}: {error}",
            source_path.display()
        ))
    })?;
    let (temporary, output) = create_temporary_archive(&destination_path)?;
    let mut source_options =
        ArchiveOpenOptions::new().with_format(Some(selection.rewrite.source_format));
    if let Some(password) = password {
        source_options =
            source_options.with_password_provider(Arc::new(PasswordCandidates::new([password])));
    }
    let destination_options = CreateOptions::new()
        .with_format(selection.rewrite.destination_format)
        .with_filter(selection.rewrite.filter);
    let mut editor =
        ArchiveEditor::new().with_metadata_loss_policy(if selection.rewrite.reject_metadata_loss {
            MetadataLossPolicy::Reject
        } else {
            MetadataLossPolicy::Report
        });
    for operation in selection.operations {
        editor = editor.with_operation(operation);
    }
    let source_seek = is_seek_read_format(selection.rewrite.source_format);
    let destination_seek = is_seek_create_format(selection.rewrite.destination_format);
    let outcome = match (source_seek, destination_seek) {
        (false, false) => editor.rewrite(input, &source_options, output, destination_options),
        (false, true) => {
            editor.rewrite_to_seek(input, &source_options, output, destination_options)
        },
        (true, false) => {
            editor.rewrite_from_seek(input, &source_options, output, destination_options)
        },
        (true, true) => editor.rewrite_seek(input, &source_options, output, destination_options),
    };
    let (output, report) = match outcome {
        Ok(outcome) => outcome.into_parts(),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(CliError::runtime(error.to_string()));
        },
    };
    publish_temporary_archive(&temporary, &destination_path, output)?;
    report_edit_success(&selection.rewrite, &report, json_output)
}

fn parse_edit(args: &[String]) -> Result<EditSelection<'_>, CliError> {
    let (rewrite, operations) = parse_rewrite(args, true)?;
    if operations.is_empty() {
        return Err(CliError::usage(
            "edit requires at least one --remove PATH or --rename FROM=TO operation",
        ));
    }
    Ok(EditSelection {
        rewrite,
        operations,
    })
}

#[derive(Debug, Default)]
struct RewriteParseState<'a> {
    source_format: Option<FormatId>,
    destination_format: Option<FormatId>,
    filter: Option<FilterId>,
    filter_seen: bool,
    reject_metadata_loss: bool,
    password: Option<PasswordSource<'a>>,
    edit_operations: Vec<EditOperation>,
    operands: Vec<&'a str>,
}

fn parse_rewrite(
    args: &[String],
    allow_edit_operations: bool,
) -> Result<(ConvertSelection<'_>, Vec<EditOperation>), CliError> {
    let mut state = RewriteParseState::default();
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument == "--reject-metadata-loss" {
            if state.reject_metadata_loss {
                return Err(CliError::usage(
                    "--reject-metadata-loss may be specified only once",
                ));
            }
            state.reject_metadata_loss = true;
            index += 1;
            continue;
        }
        if options && allow_edit_operations && matches!(argument, "--remove" | "--rename") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| CliError::usage(format!("{argument} requires a value")))?;
            push_edit_operation(argument, value, &mut state.edit_operations)?;
            index += 2;
            continue;
        }
        if options && allow_edit_operations {
            if let Some(value) = argument.strip_prefix("--remove=") {
                push_edit_operation("--remove", value, &mut state.edit_operations)?;
                index += 1;
                continue;
            }
            if let Some(value) = argument.strip_prefix("--rename=") {
                push_edit_operation("--rename", value, &mut state.edit_operations)?;
                index += 1;
                continue;
            }
        }
        if options && let Some(next) = parse_password_option(args, index, &mut state.password)? {
            index = next;
            continue;
        }
        if options && matches!(argument, "--from-format" | "--format" | "--filter") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| CliError::usage(format!("{argument} requires a value")))?;
            set_convert_option(
                argument,
                value,
                &mut state.source_format,
                &mut state.destination_format,
                &mut state.filter,
                &mut state.filter_seen,
            )?;
            index += 2;
            continue;
        }
        if options {
            if let Some((name, value)) = argument.split_once('=')
                && matches!(name, "--from-format" | "--format" | "--filter")
            {
                set_convert_option(
                    name,
                    value,
                    &mut state.source_format,
                    &mut state.destination_format,
                    &mut state.filter,
                    &mut state.filter_seen,
                )?;
                index += 1;
                continue;
            }
            if argument.starts_with('-') {
                return Err(CliError::unsupported(argument));
            }
        }
        state.operands.push(argument);
        index += 1;
    }
    finish_rewrite_selection(
        state,
        if allow_edit_operations {
            "edit"
        } else {
            "convert"
        },
    )
}

fn push_edit_operation(
    option: &str,
    value: &str,
    operations: &mut Vec<EditOperation>,
) -> CliResult {
    match option {
        "--remove" if !value.is_empty() => {
            operations.push(EditOperation::Remove(ArchivePath::from_utf8(value)));
        },
        "--rename" => {
            let (from, to) = value
                .split_once('=')
                .ok_or_else(|| CliError::usage("--rename requires FROM=TO with non-empty paths"))?;
            if from.is_empty() || to.is_empty() {
                return Err(CliError::usage(
                    "--rename requires FROM=TO with non-empty paths",
                ));
            }
            operations.push(EditOperation::Rename {
                from: ArchivePath::from_utf8(from),
                to: ArchivePath::from_utf8(to),
            });
        },
        "--remove" => return Err(CliError::usage("--remove requires a non-empty PATH")),
        _ => return Err(CliError::unsupported(option)),
    }
    Ok(())
}

fn finish_rewrite_selection<'a>(
    state: RewriteParseState<'a>,
    command: &str,
) -> Result<(ConvertSelection<'a>, Vec<EditOperation>), CliError> {
    let [source, destination] = state.operands.as_slice() else {
        return Err(CliError::usage(format!(
            "{command} requires exactly SOURCE and DEST file operands"
        )));
    };
    if *source == "-" || *destination == "-" {
        return Err(CliError::usage(format!(
            "{command} currently requires file SOURCE and DEST operands"
        )));
    }
    let source_format = state
        .source_format
        .or_else(|| infer_read_selection(source))
        .ok_or_else(|| CliError::usage("cannot infer source format; pass --from-format FORMAT"))?;
    let inferred = infer_convert_destination(destination);
    let destination_format = state
        .destination_format
        .or_else(|| inferred.map(|value| value.0))
        .ok_or_else(|| CliError::usage("cannot infer destination format; pass --format FORMAT"))?;
    let filter = if state.filter_seen {
        state.filter
    } else {
        inferred.and_then(|value| value.1)
    };
    if is_seek_create_format(destination_format) && filter.is_some() {
        return Err(CliError::usage(format!(
            "seek-native {command} destinations cannot use an outer filter"
        )));
    }
    Ok((
        ConvertSelection {
            source_format,
            destination_format,
            filter,
            reject_metadata_loss: state.reject_metadata_loss,
            password: state.password,
            source,
            destination,
        },
        state.edit_operations,
    ))
}

fn set_convert_option(
    name: &str,
    value: &str,
    source_format: &mut Option<FormatId>,
    destination_format: &mut Option<FormatId>,
    filter: &mut Option<FilterId>,
    filter_seen: &mut bool,
) -> CliResult {
    match name {
        "--from-format" => {
            if source_format
                .replace(parse_convert_source_format(value)?)
                .is_some()
            {
                return Err(CliError::usage("--from-format may be specified only once"));
            }
        },
        "--format" => {
            if destination_format
                .replace(parse_convert_destination_format(value)?)
                .is_some()
            {
                return Err(CliError::usage("--format may be specified only once"));
            }
        },
        "--filter" => {
            if *filter_seen {
                return Err(CliError::usage("--filter may be specified only once"));
            }
            *filter = parse_create_filter(value)?;
            *filter_seen = true;
        },
        _ => return Err(CliError::unsupported(name)),
    }
    Ok(())
}

fn parse_convert_source_format(value: &str) -> Result<FormatId, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "tar" | "ustar" | "pax" => Ok(FormatId::Tar),
        "cpio" | "newc" => Ok(FormatId::Cpio),
        "ar" => Ok(FormatId::Ar),
        "zip" => Ok(FormatId::Zip),
        "7z" | "sevenz" => Ok(FormatId::SevenZip),
        "iso" | "iso9660" => Ok(FormatId::Iso9660),
        "udf" => Ok(FormatId::Udf),
        "cab" => Ok(FormatId::Cab),
        "xar" => Ok(FormatId::Xar),
        "lha" | "lzh" => Ok(FormatId::Lha),
        "rar-legacy" | "rar4" => Ok(FormatId::RarLegacy),
        "rar5" | "rar" => Ok(FormatId::Rar5),
        "warc" => Ok(FormatId::Warc),
        "mtree" => Ok(FormatId::Mtree),
        _ => Err(CliError::unsupported(format!(
            "--from-format {value} is not a built-in readable archive format"
        ))),
    }
}

fn parse_convert_destination_format(value: &str) -> Result<FormatId, CliError> {
    if value.eq_ignore_ascii_case("warc") {
        Ok(FormatId::Warc)
    } else {
        parse_create_format(value)
    }
}

fn infer_read_selection(path: &str) -> Option<FormatId> {
    if let Some((format, _)) = infer_create_selection(path) {
        return Some(format);
    }
    let lower = path.to_ascii_lowercase();
    for (suffix, format) in [
        (".udf", FormatId::Udf),
        (".cab", FormatId::Cab),
        (".lha", FormatId::Lha),
        (".lzh", FormatId::Lha),
        (".rar", FormatId::Rar5),
        (".warc", FormatId::Warc),
    ] {
        if lower.ends_with(suffix) {
            return Some(format);
        }
    }
    None
}

fn infer_convert_destination(path: &str) -> Option<(FormatId, Option<FilterId>)> {
    infer_create_selection(path).or_else(|| {
        path.to_ascii_lowercase()
            .ends_with(".warc")
            .then_some((FormatId::Warc, None))
    })
}

fn is_seek_read_format(format: FormatId) -> bool {
    matches!(
        format,
        FormatId::Zip
            | FormatId::SevenZip
            | FormatId::Iso9660
            | FormatId::Udf
            | FormatId::Cab
            | FormatId::Xar
            | FormatId::Lha
    )
}

fn supports_read_password(format: FormatId) -> bool {
    matches!(
        format,
        FormatId::Zip | FormatId::SevenZip | FormatId::RarLegacy | FormatId::Rar5
    )
}

fn report_convert_success(
    selection: &ConvertSelection<'_>,
    report: &libarchive_oxide::TranscodeReport,
    json_output: bool,
) -> CliResult {
    if json_output {
        let losses: Vec<Value> = report
            .metadata_losses()
            .iter()
            .map(|loss| {
                json!({
                    "entry_index": loss.entry_index(),
                    "path": loss.path().map(ArchivePath::display_lossy),
                    "path_raw_hex": loss.path().map(|path| hex(path.as_bytes())),
                    "field": metadata_field_name(loss.field()),
                })
            })
            .collect();
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "convert",
            "source_format": format_name(selection.source_format),
            "destination_format": format_name(selection.destination_format),
            "filter": selection.filter.map(filter_name),
            "source": selection.source,
            "destination": selection.destination,
            "entries": report.entries(),
            "payload_bytes": report.payload_bytes(),
            "metadata_losses": losses,
            "complete": true,
        }))
    } else {
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        write_human_line(
            &mut output,
            format_args!(
                "converted\tfrom={}\tto={}\tentries={}\tpayload-bytes={}\tmetadata-losses={}",
                format_name(selection.source_format),
                format_name(selection.destination_format),
                report.entries(),
                report.payload_bytes(),
                report.metadata_losses().len(),
            ),
        )?;
        for loss in report.metadata_losses() {
            write_human_line(
                &mut output,
                format_args!(
                    "metadata-loss\tentry={}\tpath={}\tfield={}",
                    loss.entry_index()
                        .map_or_else(|| "archive".to_owned(), |value| value.to_string()),
                    loss.path()
                        .map_or_else(|| "-".to_owned(), ArchivePath::display_lossy),
                    metadata_field_name(loss.field()),
                ),
            )?;
        }
        Ok(())
    }
}

fn report_edit_success(
    selection: &ConvertSelection<'_>,
    report: &libarchive_oxide::EditReport,
    json_output: bool,
) -> CliResult {
    if json_output {
        let losses: Vec<Value> = report
            .metadata_losses()
            .iter()
            .map(|loss| {
                json!({
                    "entry_index": loss.entry_index(),
                    "path": loss.path().map(ArchivePath::display_lossy),
                    "path_raw_hex": loss.path().map(|path| hex(path.as_bytes())),
                    "field": metadata_field_name(loss.field()),
                })
            })
            .collect();
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "edit",
            "source_format": format_name(selection.source_format),
            "destination_format": format_name(selection.destination_format),
            "filter": selection.filter.map(filter_name),
            "source": selection.source,
            "destination": selection.destination,
            "source_entries": report.source_entries(),
            "entries": report.entries(),
            "removed_entries": report.removed_entries(),
            "renamed_entries": report.renamed_entries(),
            "payload_bytes": report.payload_bytes(),
            "metadata_losses": losses,
            "complete": true,
        }))
    } else {
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        write_human_line(
            &mut output,
            format_args!(
                "edited\tfrom={}\tto={}\tsource-entries={}\tentries={}\tremoved={}\trenamed={}\tpayload-bytes={}\tmetadata-losses={}",
                format_name(selection.source_format),
                format_name(selection.destination_format),
                report.source_entries(),
                report.entries(),
                report.removed_entries(),
                report.renamed_entries(),
                report.payload_bytes(),
                report.metadata_losses().len(),
            ),
        )?;
        for loss in report.metadata_losses() {
            write_human_line(
                &mut output,
                format_args!(
                    "metadata-loss\tentry={}\tpath={}\tfield={}",
                    loss.entry_index()
                        .map_or_else(|| "archive".to_owned(), |value| value.to_string()),
                    loss.path()
                        .map_or_else(|| "-".to_owned(), ArchivePath::display_lossy),
                    metadata_field_name(loss.field()),
                ),
            )?;
        }
        Ok(())
    }
}

fn metadata_field_name(field: MetadataField) -> &'static str {
    match field {
        MetadataField::ArchiveVolumeName => "archive_volume_name",
        MetadataField::ArchiveComment => "archive_comment",
        MetadataField::ArchiveExtensions => "archive_extensions",
        MetadataField::DeclaredSize => "declared_size",
        MetadataField::EntryPath => "entry_path",
        MetadataField::Mode => "mode",
        MetadataField::OwnerIds => "owner_ids",
        MetadataField::OwnerNames => "owner_names",
        MetadataField::ModifiedTime => "modified_time",
        MetadataField::AccessedTime => "accessed_time",
        MetadataField::ChangedTime => "changed_time",
        MetadataField::CreatedTime => "created_time",
        MetadataField::InodeAndLinkCount => "inode_and_link_count",
        MetadataField::Devices => "devices",
        MetadataField::SparseMap => "sparse_map",
        MetadataField::ExtendedAttributes => "extended_attributes",
        MetadataField::Acl => "acl",
        MetadataField::FileFlags => "file_flags",
        MetadataField::Checksum => "checksum",
        MetadataField::Encryption => "encryption",
        MetadataField::EntryComment => "entry_comment",
        MetadataField::EntryExtensions => "entry_extensions",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy)]
enum SevenZipFilterSelection {
    None,
    Filter(SevenZipFilter),
}

impl SevenZipFilterSelection {
    const fn filter(self) -> Option<SevenZipFilter> {
        match self {
            Self::None => None,
            Self::Filter(filter) => Some(filter),
        }
    }
}

#[derive(Debug)]
struct CreateSelection<'a> {
    format: FormatId,
    filter: Option<FilterId>,
    reproducible: bool,
    password: Option<PasswordSource<'a>>,
    zip_compression: Option<ZipCompression>,
    zip_encryption: Option<ZipEncryption>,
    sevenz_compression: Option<SevenZipCompression>,
    sevenz_filter: Option<SevenZipFilterSelection>,
    sevenz_solid: Option<bool>,
    sevenz_encryption: Option<SevenZipEncryption>,
    xar_compression: Option<XarCompression>,
    archive: &'a str,
    inputs: Vec<&'a str>,
}

fn run_create(args: &[String], json_output: bool) -> CliResult {
    let selection = parse_create(args)?;
    validate_create_selection(&selection, json_output)?;
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
    let result = if is_seek_create_format(selection.format) {
        stream_create_seek(output, &selection, password)
    } else {
        stream_create(output, &selection, password)
    };
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        },
    };
    publish_temporary_archive(&temporary, &destination, output)?;
    report_create_success(&selection, json_output)
}

fn validate_create_selection(selection: &CreateSelection<'_>, json_output: bool) -> CliResult {
    if selection.format != FormatId::Zip
        && (selection.zip_compression.is_some() || selection.zip_encryption.is_some())
    {
        return Err(CliError::usage(
            "--zip-compression and --zip-encryption require ZIP output",
        ));
    }
    if selection.format != FormatId::SevenZip
        && (selection.sevenz_compression.is_some()
            || selection.sevenz_filter.is_some()
            || selection.sevenz_solid.is_some()
            || selection.sevenz_encryption.is_some())
    {
        return Err(CliError::usage(
            "--7z-compression, --7z-filter, --7z-solid/--7z-non-solid, and --7z-encryption require 7z output",
        ));
    }
    if selection.format != FormatId::Xar && selection.xar_compression.is_some() {
        return Err(CliError::usage("--xar-compression requires XAR output"));
    }
    if is_seek_create_format(selection.format) {
        if selection.archive == "-" {
            return Err(CliError::usage(
                "seek-native create formats require a file destination",
            ));
        }
        if selection.filter.is_some() {
            return Err(CliError::usage(
                "seek-native create formats cannot use an outer filter",
            ));
        }
    }
    if selection.password.is_some() {
        if !matches!(selection.format, FormatId::Zip | FormatId::SevenZip) {
            return Err(CliError::usage(
                "a password source is accepted for create only when the output format is ZIP or 7z",
            ));
        }
        if selection.filter.is_some() {
            return Err(CliError::usage(
                "password-protected ZIP or 7z create cannot use an outer filter",
            ));
        }
    }
    match (selection.zip_encryption, selection.password) {
        (Some(ZipEncryption::None), Some(_)) => {
            return Err(CliError::usage(
                "--zip-encryption none cannot be combined with a password source",
            ));
        },
        (Some(ZipEncryption::Aes(_) | ZipEncryption::ZipCrypto), None) => {
            return Err(CliError::usage(
                "the selected ZIP encryption requires --password-file or --password-prompt",
            ));
        },
        _ => {},
    }
    match (selection.sevenz_encryption, selection.password) {
        (Some(SevenZipEncryption::None), Some(_)) => {
            return Err(CliError::usage(
                "--7z-encryption none cannot be combined with a password source",
            ));
        },
        (Some(SevenZipEncryption::Aes256), None) => {
            return Err(CliError::usage(
                "the selected 7z encryption requires --password-file or --password-prompt",
            ));
        },
        _ => {},
    }
    if selection.archive == "-" && json_output {
        return Err(CliError::usage(
            "--json create - would mix JSON records with archive bytes",
        ));
    }
    Ok(())
}

fn effective_zip_compression(selection: &CreateSelection<'_>) -> ZipCompression {
    selection.zip_compression.unwrap_or(ZipCompression::Deflate)
}

fn effective_zip_encryption(selection: &CreateSelection<'_>) -> ZipEncryption {
    selection.zip_encryption.unwrap_or_else(|| {
        if selection.password.is_some() {
            ZipEncryption::Aes(AesStrength::Bits256)
        } else {
            ZipEncryption::None
        }
    })
}

fn zip_compression_name(compression: ZipCompression) -> &'static str {
    match compression {
        ZipCompression::Store => "store",
        ZipCompression::Deflate => "deflate",
        ZipCompression::Deflate64 => "deflate64",
        ZipCompression::Bzip2 => "bzip2",
        ZipCompression::Lzma => "lzma",
        ZipCompression::Ppmd8 => "ppmd8",
        ZipCompression::Zstd => "zstd",
        ZipCompression::Xz => "xz",
        _ => "unknown",
    }
}

fn zip_encryption_name(encryption: ZipEncryption) -> &'static str {
    match encryption {
        ZipEncryption::None => "none",
        ZipEncryption::ZipCrypto => "zipcrypto",
        ZipEncryption::Aes(AesStrength::Bits128) => "aes128",
        ZipEncryption::Aes(AesStrength::Bits192) => "aes192",
        ZipEncryption::Aes(AesStrength::Bits256) => "aes256",
        _ => "unknown",
    }
}

fn effective_sevenz_options(selection: &CreateSelection<'_>) -> SevenZipWriteOptions {
    let encryption = selection.sevenz_encryption.unwrap_or_else(|| {
        if selection.password.is_some() {
            SevenZipEncryption::Aes256
        } else {
            SevenZipEncryption::None
        }
    });
    SevenZipWriteOptions::new()
        .with_compression(
            selection
                .sevenz_compression
                .unwrap_or(SevenZipCompression::Lzma2),
        )
        .with_filter(
            selection
                .sevenz_filter
                .and_then(SevenZipFilterSelection::filter),
        )
        .with_solid(selection.sevenz_solid.unwrap_or(true))
        .with_encryption(encryption)
}

fn sevenz_compression_name(compression: SevenZipCompression) -> &'static str {
    match compression {
        SevenZipCompression::Store => "store",
        SevenZipCompression::Lzma => "lzma",
        SevenZipCompression::Lzma2 => "lzma2",
        SevenZipCompression::Ppmd7 => "ppmd7",
        SevenZipCompression::Deflate => "deflate",
        SevenZipCompression::Bzip2 => "bzip2",
        SevenZipCompression::Zstd => "zstd",
        _ => "unknown",
    }
}

fn sevenz_filter_name(filter: Option<SevenZipFilter>) -> String {
    match filter {
        None => "none".to_string(),
        Some(SevenZipFilter::Delta(distance)) => format!("delta:{distance}"),
        Some(SevenZipFilter::BcjX86) => "bcj-x86".to_string(),
        Some(SevenZipFilter::BcjPowerPc) => "bcj-ppc".to_string(),
        Some(SevenZipFilter::BcjIa64) => "bcj-ia64".to_string(),
        Some(SevenZipFilter::BcjArm) => "bcj-arm".to_string(),
        Some(SevenZipFilter::BcjArmThumb) => "bcj-arm-thumb".to_string(),
        Some(SevenZipFilter::BcjArm64) => "bcj-arm64".to_string(),
        Some(SevenZipFilter::BcjSparc) => "bcj-sparc".to_string(),
        Some(SevenZipFilter::BcjRiscV) => "bcj-riscv".to_string(),
        Some(_) => "unknown".to_string(),
    }
}

fn sevenz_encryption_name(encryption: SevenZipEncryption) -> &'static str {
    match encryption {
        SevenZipEncryption::None => "none",
        SevenZipEncryption::Aes256 => "aes256",
        _ => "unknown",
    }
}

fn effective_xar_options(selection: &CreateSelection<'_>) -> XarWriteOptions {
    XarWriteOptions::new()
        .with_compression(selection.xar_compression.unwrap_or(XarCompression::Store))
}

fn xar_compression_name(compression: XarCompression) -> &'static str {
    match compression {
        XarCompression::Store => "store",
        XarCompression::Zlib => "zlib",
        XarCompression::Bzip2 => "bzip2",
        _ => "unknown",
    }
}

fn report_create_success(selection: &CreateSelection<'_>, json_output: bool) -> CliResult {
    if json_output {
        print_json(&json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "create",
            "format": format_name(selection.format),
            "filter": selection.filter.map(filter_name),
            "zip_compression": (selection.format == FormatId::Zip)
                .then(|| zip_compression_name(effective_zip_compression(selection))),
            "zip_encryption": (selection.format == FormatId::Zip)
                .then(|| zip_encryption_name(effective_zip_encryption(selection))),
            "sevenz_compression": (selection.format == FormatId::SevenZip)
                .then(|| sevenz_compression_name(effective_sevenz_options(selection).compression())),
            "sevenz_filter": (selection.format == FormatId::SevenZip)
                .then(|| sevenz_filter_name(effective_sevenz_options(selection).filter())),
            "sevenz_solid": (selection.format == FormatId::SevenZip)
                .then(|| effective_sevenz_options(selection).solid()),
            "sevenz_encryption": (selection.format == FormatId::SevenZip)
                .then(|| sevenz_encryption_name(effective_sevenz_options(selection).encryption())),
            "xar_compression": (selection.format == FormatId::Xar)
                .then(|| xar_compression_name(effective_xar_options(selection).compression())),
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

fn set_create_option<T>(
    slot: &mut Option<T>,
    value: T,
    option: &'static str,
) -> Result<(), CliError> {
    if slot.replace(value).is_some() {
        return Err(CliError::usage(format!(
            "{option} may be specified only once"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One pass preserves argv order and option termination semantics.
fn parse_create(args: &[String]) -> Result<CreateSelection<'_>, CliError> {
    let mut format = None;
    let mut filter = None;
    let mut zip_compression = None;
    let mut zip_encryption = None;
    let mut sevenz_compression = None;
    let mut sevenz_filter = None;
    let mut sevenz_solid = None;
    let mut sevenz_encryption = None;
    let mut xar_compression = None;
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
        if matches!(argument, "--7z-solid" | "--7z-non-solid") {
            set_create_option(
                &mut sevenz_solid,
                argument == "--7z-solid",
                "--7z-solid/--7z-non-solid",
            )?;
            index += 1;
            continue;
        }
        if let Some(next) = parse_password_option(args, index, &mut password)? {
            index = next;
            continue;
        }
        if matches!(
            argument,
            "--format"
                | "--filter"
                | "--zip-compression"
                | "--zip-encryption"
                | "--7z-compression"
                | "--7z-filter"
                | "--7z-encryption"
                | "--xar-compression"
        ) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| CliError::usage(format!("{argument} requires a value")))?;
            match argument {
                "--format" => {
                    set_create_option(&mut format, parse_create_format(value)?, "--format")?;
                },
                "--filter" => {
                    set_create_option(&mut filter, parse_create_filter(value)?, "--filter")?;
                },
                "--zip-compression" => set_create_option(
                    &mut zip_compression,
                    parse_zip_compression(value)?,
                    "--zip-compression",
                )?,
                "--zip-encryption" => set_create_option(
                    &mut zip_encryption,
                    parse_zip_encryption(value)?,
                    "--zip-encryption",
                )?,
                "--7z-compression" => set_create_option(
                    &mut sevenz_compression,
                    parse_sevenz_compression(value)?,
                    "--7z-compression",
                )?,
                "--7z-filter" => set_create_option(
                    &mut sevenz_filter,
                    parse_sevenz_filter(value)?,
                    "--7z-filter",
                )?,
                "--7z-encryption" => set_create_option(
                    &mut sevenz_encryption,
                    parse_sevenz_encryption(value)?,
                    "--7z-encryption",
                )?,
                "--xar-compression" => set_create_option(
                    &mut xar_compression,
                    parse_xar_compression(value)?,
                    "--xar-compression",
                )?,
                _ => {},
            }
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--format=") {
            set_create_option(&mut format, parse_create_format(value)?, "--format")?;
        } else if let Some(value) = argument.strip_prefix("--filter=") {
            set_create_option(&mut filter, parse_create_filter(value)?, "--filter")?;
        } else if let Some(value) = argument.strip_prefix("--zip-compression=") {
            set_create_option(
                &mut zip_compression,
                parse_zip_compression(value)?,
                "--zip-compression",
            )?;
        } else if let Some(value) = argument.strip_prefix("--zip-encryption=") {
            set_create_option(
                &mut zip_encryption,
                parse_zip_encryption(value)?,
                "--zip-encryption",
            )?;
        } else if let Some(value) = argument.strip_prefix("--7z-compression=") {
            set_create_option(
                &mut sevenz_compression,
                parse_sevenz_compression(value)?,
                "--7z-compression",
            )?;
        } else if let Some(value) = argument.strip_prefix("--7z-filter=") {
            set_create_option(
                &mut sevenz_filter,
                parse_sevenz_filter(value)?,
                "--7z-filter",
            )?;
        } else if let Some(value) = argument.strip_prefix("--7z-encryption=") {
            set_create_option(
                &mut sevenz_encryption,
                parse_sevenz_encryption(value)?,
                "--7z-encryption",
            )?;
        } else if let Some(value) = argument.strip_prefix("--xar-compression=") {
            set_create_option(
                &mut xar_compression,
                parse_xar_compression(value)?,
                "--xar-compression",
            )?;
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
                "cannot infer create format from ARCHIVE; pass --format tar|cpio|ar|zip|mtree|7z|iso9660|xar",
            )
        })?;
    let filter = filter.unwrap_or_else(|| inferred.and_then(|selection| selection.1));
    Ok(CreateSelection {
        format,
        filter,
        reproducible,
        password,
        zip_compression,
        zip_encryption,
        sevenz_compression,
        sevenz_filter,
        sevenz_solid,
        sevenz_encryption,
        xar_compression,
        archive: operands[0],
        inputs: operands[1..].to_vec(),
    })
}

fn parse_zip_compression(value: &str) -> Result<ZipCompression, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "store" | "stored" | "none" => Ok(ZipCompression::Store),
        "deflate" => Ok(ZipCompression::Deflate),
        "bzip2" | "bz2" => Ok(ZipCompression::Bzip2),
        "lzma" => Ok(ZipCompression::Lzma),
        "ppmd" | "ppmd8" => Ok(ZipCompression::Ppmd8),
        "zstd" | "zstandard" => Ok(ZipCompression::Zstd),
        "xz" => Ok(ZipCompression::Xz),
        _ => Err(CliError::unsupported(format!(
            "--zip-compression {value} (supported: store, deflate, bzip2, lzma, ppmd8, zstd, xz)"
        ))),
    }
}

fn parse_zip_encryption(value: &str) -> Result<ZipEncryption, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(ZipEncryption::None),
        "zipcrypto" | "traditional" | "legacy" => Ok(ZipEncryption::ZipCrypto),
        "aes128" | "aes-128" => Ok(ZipEncryption::Aes(AesStrength::Bits128)),
        "aes192" | "aes-192" => Ok(ZipEncryption::Aes(AesStrength::Bits192)),
        "aes256" | "aes-256" | "aes" => Ok(ZipEncryption::Aes(AesStrength::Bits256)),
        _ => Err(CliError::unsupported(format!(
            "--zip-encryption {value} (supported: none, zipcrypto, aes128, aes192, aes256)"
        ))),
    }
}

fn parse_sevenz_compression(value: &str) -> Result<SevenZipCompression, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "store" | "stored" | "none" => Ok(SevenZipCompression::Store),
        "lzma" | "lzma1" => Ok(SevenZipCompression::Lzma),
        "lzma2" => Ok(SevenZipCompression::Lzma2),
        "ppmd" | "ppmd7" => Ok(SevenZipCompression::Ppmd7),
        "deflate" => Ok(SevenZipCompression::Deflate),
        "bzip2" | "bz2" => Ok(SevenZipCompression::Bzip2),
        "zstd" | "zstandard" => Ok(SevenZipCompression::Zstd),
        _ => Err(CliError::unsupported(format!(
            "--7z-compression {value} (supported: store, lzma, lzma2, ppmd7, deflate, bzip2, zstd)"
        ))),
    }
}

fn parse_sevenz_filter(value: &str) -> Result<SevenZipFilterSelection, CliError> {
    let lower = value.to_ascii_lowercase();
    if let Some(distance) = lower.strip_prefix("delta:") {
        let distance = distance.parse::<u16>().map_err(|_| {
            CliError::unsupported(format!(
                "--7z-filter {value} (delta distance must be an integer from 1 through 256)"
            ))
        })?;
        if !(1..=256).contains(&distance) {
            return Err(CliError::unsupported(format!(
                "--7z-filter {value} (delta distance must be from 1 through 256)"
            )));
        }
        return Ok(SevenZipFilterSelection::Filter(SevenZipFilter::Delta(
            distance,
        )));
    }
    match lower.as_str() {
        "none" => Ok(SevenZipFilterSelection::None),
        "bcj-x86" | "x86" => Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjX86)),
        "bcj-ppc" | "ppc" | "powerpc" => {
            Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjPowerPc))
        },
        "bcj-ia64" | "ia64" => Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjIa64)),
        "bcj-arm" | "arm" => Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjArm)),
        "bcj-arm-thumb" | "arm-thumb" | "thumb" => {
            Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjArmThumb))
        },
        "bcj-arm64" | "arm64" | "aarch64" => {
            Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjArm64))
        },
        "bcj-sparc" | "sparc" => Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjSparc)),
        "bcj-riscv" | "riscv" => Ok(SevenZipFilterSelection::Filter(SevenZipFilter::BcjRiscV)),
        _ => Err(CliError::unsupported(format!(
            "--7z-filter {value} (supported: none, delta:1..256, bcj-x86, bcj-ppc, bcj-ia64, bcj-arm, bcj-arm-thumb, bcj-arm64, bcj-sparc, bcj-riscv)"
        ))),
    }
}

fn parse_sevenz_encryption(value: &str) -> Result<SevenZipEncryption, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(SevenZipEncryption::None),
        "aes256" | "aes-256" | "aes" => Ok(SevenZipEncryption::Aes256),
        _ => Err(CliError::unsupported(format!(
            "--7z-encryption {value} (supported: none, aes256)"
        ))),
    }
}

fn parse_xar_compression(value: &str) -> Result<XarCompression, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "store" | "stored" | "none" => Ok(XarCompression::Store),
        "zlib" | "deflate" => Ok(XarCompression::Zlib),
        "bzip2" | "bz2" => Ok(XarCompression::Bzip2),
        _ => Err(CliError::unsupported(format!(
            "--xar-compression {value} (supported: store, zlib, bzip2)"
        ))),
    }
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
        (".tar.lzo", FormatId::Tar, Some(FilterId::Lzop)),
        (".tar.lzop", FormatId::Tar, Some(FilterId::Lzop)),
        (".tar.z", FormatId::Tar, Some(FilterId::Compress)),
        (".tar.lz", FormatId::Tar, Some(FilterId::Lzip)),
        (".tar.lzma", FormatId::Tar, Some(FilterId::Lzma)),
        (".tar.b64", FormatId::Tar, Some(FilterId::Base64)),
        (".tar.uu", FormatId::Tar, Some(FilterId::Uuencode)),
        (".tar.uue", FormatId::Tar, Some(FilterId::Uuencode)),
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
        (".mtree", FormatId::Mtree),
        (".7z", FormatId::SevenZip),
        (".iso", FormatId::Iso9660),
        (".xar", FormatId::Xar),
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
        "mtree" => Ok(FormatId::Mtree),
        "7z" | "sevenz" => Ok(FormatId::SevenZip),
        "iso" | "iso9660" => Ok(FormatId::Iso9660),
        "xar" => Ok(FormatId::Xar),
        _ => Err(CliError::unsupported(format!(
            "--format {value} (supported: tar, cpio, ar, zip, mtree, 7z, iso9660, xar)"
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
        "lzop" | "lzo" => Ok(Some(FilterId::Lzop)),
        "compress" | "z" => Ok(Some(FilterId::Compress)),
        "lzip" | "lz" => Ok(Some(FilterId::Lzip)),
        "lzma" | "lzma-alone" => Ok(Some(FilterId::Lzma)),
        "base64" | "b64" => Ok(Some(FilterId::Base64)),
        "uuencode" | "uu" | "uue" => Ok(Some(FilterId::Uuencode)),
        _ => Err(CliError::unsupported(format!(
            "--filter {value} (supported: none, gzip, bzip2, xz, zstd, lz4, lzop, compress, lzip, lzma, base64, uuencode)"
        ))),
    }
}

fn stream_create<W: Write>(
    output: W,
    selection: &CreateSelection<'_>,
    password: Option<SecretBytes>,
) -> Result<W, CliError> {
    let format_options = (selection.format == FormatId::Zip).then(|| {
        FormatWriteOptions::Zip(
            ZipWriteOptions::new()
                .with_compression(effective_zip_compression(selection))
                .with_encryption(effective_zip_encryption(selection)),
        )
    });
    let options = CreateOptions::new()
        .with_format(selection.format)
        .with_filter(selection.filter)
        .with_format_options(format_options);
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

fn is_seek_create_format(format: FormatId) -> bool {
    matches!(
        format,
        FormatId::SevenZip | FormatId::Iso9660 | FormatId::Xar
    )
}

fn stream_create_seek<W: Write + io::Seek>(
    output: W,
    selection: &CreateSelection<'_>,
    password: Option<SecretBytes>,
) -> Result<W, CliError> {
    let format_options = match selection.format {
        FormatId::SevenZip => Some(FormatWriteOptions::SevenZip(effective_sevenz_options(
            selection,
        ))),
        FormatId::Xar => Some(FormatWriteOptions::Xar(effective_xar_options(selection))),
        _ => None,
    };
    let options = CreateOptions::new()
        .with_format(selection.format)
        .with_format_options(format_options);
    let mut builder = match password {
        Some(password) => SeekArchiveBuilder::with_engine_and_password(
            ArchiveEngine::new(),
            output,
            options,
            password,
        ),
        None => SeekArchiveBuilder::with_engine(ArchiveEngine::new(), output, options),
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

fn publish_temporary_archive(temporary: &Path, destination: &Path, output: File) -> CliResult {
    if let Err(error) = output.sync_all() {
        drop(output);
        let _ = std::fs::remove_file(temporary);
        return Err(CliError::runtime(format!(
            "cannot synchronize temporary archive: {error}"
        )));
    }
    drop(output);
    if let Err(error) = std::fs::hard_link(temporary, destination) {
        let _ = std::fs::remove_file(temporary);
        return Err(CliError::runtime(format!(
            "cannot atomically publish {}: {error}",
            destination.display()
        )));
    }
    if let Err(error) = std::fs::remove_file(temporary) {
        return Err(CliError::runtime(format!(
            "archive committed at {} but temporary-link cleanup failed: {error}",
            destination.display()
        )));
    }
    Ok(())
}
fn run_plan(args: &[String], json_output: bool) -> CliResult {
    let arguments = parse_policy(args)?;
    if arguments.operands.len() != 1 {
        return Err(CliError::usage("plan requires exactly one ARCHIVE operand"));
    }
    let password = acquire_password(arguments.password, arguments.operands[0] == "-")?;
    let discover_volumes = arguments.discover_volumes;
    let mut session = open_session(
        arguments.operands[0],
        arguments.format,
        password,
        discover_volumes,
    )?;
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
    let discover_volumes = arguments.discover_volumes;
    let mut session = open_session(
        arguments.operands[0],
        arguments.format,
        password,
        discover_volumes,
    )?;
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
    let discover_volumes = selection.discover_volumes;
    let mut session = open_session(archive, selection.format, password, discover_volumes)?;
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
    discover_volumes: bool,
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
    let mut discover_volumes = false;
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
                "--discover-volumes" => {
                    if std::mem::replace(&mut discover_volumes, true) {
                        return Err(CliError::usage(
                            "--discover-volumes may be specified only once",
                        ));
                    }
                },
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
        discover_volumes,
        operands,
    })
}

fn open_session(
    path: &str,
    format: Option<FormatId>,
    password: Option<SecretBytes>,
    discover_volumes: bool,
) -> Result<ArchiveSession, CliError> {
    let engine = ArchiveEngine::new();
    if password.is_some() && format.is_some_and(|format| !supports_read_password(format)) {
        return Err(CliError::usage(
            "a password source requires ZIP, 7z, RAR 3.x/4.x, or RAR5 when --format is explicit",
        ));
    }
    if discover_volumes {
        if path == "-" {
            return Err(CliError::usage(
                "--discover-volumes requires a filesystem path and cannot be combined with archive input '-'",
            ));
        }
        if format.is_some_and(|format| {
            !matches!(
                format,
                FormatId::SevenZip | FormatId::Zip | FormatId::RarLegacy | FormatId::Rar5
            )
        }) {
            return Err(CliError::usage(
                "--discover-volumes requires 7z, zip, rar-legacy, or rar5 when --format is explicit",
            ));
        }
        let mut options = ArchiveOpenOptions::new()
            .with_format(format)
            .with_adjacent_volume_discovery(true);
        if let Some(password) = password {
            options = options.with_password_provider(Arc::new(PasswordCandidates::new([password])));
        }
        return engine
            .open_path_with_options(path, &options)
            .map_err(|error| CliError::runtime(error.to_string()));
    }
    let mut options = ArchiveOpenOptions::new().with_format(format);
    if let Some(password) = password {
        options = options.with_password_provider(Arc::new(PasswordCandidates::new([password])));
    }
    if path == "-" {
        let stdin = io::stdin();
        engine
            .prepare_with_options(stdin.lock(), &options)
            .map_err(|error| CliError::runtime(error.to_string()))
    } else {
        let input = File::open(path).map_err(|error| CliError::runtime(error.to_string()))?;
        engine
            .prepare_with_options(input, &options)
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
    format_capability(format).map_or_else(
        || format!("{format:?}").to_ascii_lowercase(),
        |record| record.name().to_string(),
    )
}

fn filter_name(filter: FilterId) -> &'static str {
    filter_capability(filter).map_or("unknown", |record| record.name())
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
