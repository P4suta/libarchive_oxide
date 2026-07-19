// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxtar` implementation.
//!
//! Supported:
//! - `-c`, `-x`, `-t`;
//! - `-f FILE`, `-C DIR`;
//! - `-v` verbose.
//! - `-z`, `--gzip`, `-j`, `--bzip2`, `-J`, `--xz`, `--zstd`, `--lz4`;
//! - `--format`, member operands, `--help`, `--version`.
//!
//! `-r` and `-u` are unsupported. Extraction rejects path
//! traversal. Decompression uses the crate-level limit.

use std::io::Write;
use std::path::{Path, PathBuf};

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{FormatId, Limits};

use crate::{CliError, CliResult, extract_stream, list_stream};

/// Selected operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Create,
    Extract,
    List,
}

/// Format selected by `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateFormat {
    /// The ustar writer (`tar`/`ustar`/`gnutar`).
    Tar,
    /// The newc cpio writer (`cpio`).
    Cpio,
}

/// Parsed `oxtar` invocation.
#[derive(Debug, Default)]
struct TarOpts {
    mode: Option<Mode>,
    file: Option<String>,
    chdir: Option<String>,
    verbose: bool,
    filter: Option<FilterId>,
    format: Option<CreateFormat>,
    members: Vec<String>,
}

/// `oxtar` entry point: parse arguments then dispatch to create/extract/list.
///
/// # Errors
///
/// Returns [`CliError`] with code 2 for usage/unsupported-flag errors and code 1 for runtime
/// failures (I/O, corrupt archive, decompression-bomb cap).
pub fn run_tar(args: Vec<String>) -> CliResult {
    match parse(args)? {
        Parsed::Help => {
            print!("{HELP}");
            Ok(())
        },
        Parsed::Version => {
            println!("oxtar {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        },
        Parsed::Run(opts) => dispatch(&opts),
    }
}

/// Outcome of parsing: an actionable option set, or an immediate help/version request.
enum Parsed {
    Run(TarOpts),
    Help,
    Version,
}

#[allow(clippy::too_many_lines)]
fn parse(args: Vec<String>) -> Result<Parsed, CliError> {
    let mut opts = TarOpts::default();
    let mut it = args.into_iter().peekable();
    let mut first = true;
    let mut only_positional = false;

    while let Some(mut arg) = it.next() {
        // Classic tar: a bare first argument (`tar xzf f`) is a bundle of option letters.
        if first {
            first = false;
            if !arg.is_empty() && !arg.starts_with('-') {
                arg.insert(0, '-');
            }
        }

        if only_positional {
            opts.members.push(arg);
            continue;
        }
        if arg == "--" {
            only_positional = true;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            match parse_long(long, &mut opts, &mut it)? {
                Some(Parsed::Help) => return Ok(Parsed::Help),
                Some(Parsed::Version) => return Ok(Parsed::Version),
                _ => {},
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let cluster: Vec<char> = arg.chars().skip(1).collect();
            let mut idx = 0;
            while idx < cluster.len() {
                let c = cluster[idx];
                // `-f`/`-C` take a value: the rest of the cluster, or the next argument.
                if c == 'f' || c == 'C' {
                    let rest: String = cluster[idx + 1..].iter().collect();
                    let value = if rest.is_empty() {
                        it.next()
                            .ok_or_else(|| CliError::usage(format!("-{c} requires a value")))?
                    } else {
                        rest
                    };
                    if c == 'f' {
                        opts.file = Some(value);
                    } else {
                        opts.chdir = Some(value);
                    }
                    break;
                }
                apply_bool_flag(c, &mut opts)?;
                idx += 1;
            }
            continue;
        }
        // Bare operand (archive members on create, member selection on extract/list).
        opts.members.push(arg);
    }

    Ok(Parsed::Run(opts))
}

/// Applies a long option. Returns `Some(Parsed::Help|Version)` to short-circuit the caller.
fn parse_long(
    long: &str,
    opts: &mut TarOpts,
    it: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
) -> Result<Option<Parsed>, CliError> {
    let (name, inline) = match long.split_once('=') {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (long, None),
    };
    match name {
        "help" => return Ok(Some(Parsed::Help)),
        "version" => return Ok(Some(Parsed::Version)),
        "gzip" | "gunzip" => opts.filter = Some(FilterId::Gzip),
        "bzip2" | "bunzip2" => opts.filter = Some(FilterId::Bzip2),
        "xz" => opts.filter = Some(FilterId::Xz),
        "zstd" => opts.filter = Some(FilterId::Zstd),
        "lz4" => opts.filter = Some(FilterId::Lz4),
        "format" => {
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .ok_or_else(|| CliError::usage("--format requires a value"))?,
            };
            opts.format = Some(parse_format(&value)?);
        },
        other => return Err(CliError::usage(format!("unknown flag: --{other}"))),
    }
    Ok(None)
}

/// Maps a `--format` value to a supported writer, rejecting formats the library will not emit.
fn parse_format(value: &str) -> Result<CreateFormat, CliError> {
    match value {
        "tar" | "ustar" | "gnutar" | "pax" => Ok(CreateFormat::Tar),
        "cpio" | "newc" => Ok(CreateFormat::Cpio),
        other => Err(CliError::unsupported(format!(
            "--format {other} (supported: tar, ustar, gnutar, cpio)"
        ))),
    }
}

/// Applies a boolean short flag, or maps a classic-but-unsupported one to a precise error.
fn apply_bool_flag(c: char, opts: &mut TarOpts) -> Result<(), CliError> {
    match c {
        'c' => set_mode(opts, Mode::Create)?,
        'x' => set_mode(opts, Mode::Extract)?,
        't' => set_mode(opts, Mode::List)?,
        'v' => opts.verbose = true,
        'z' => opts.filter = Some(FilterId::Gzip),
        'j' => opts.filter = Some(FilterId::Bzip2),
        'J' => opts.filter = Some(FilterId::Xz),
        'r' => {
            return Err(CliError::unsupported(
                "-r (append): rewriting an existing archive is out of scope; use -c",
            ));
        },
        'u' => {
            return Err(CliError::unsupported(
                "-u (update): rewriting an existing archive is out of scope; use -c",
            ));
        },
        other => return Err(CliError::usage(format!("unknown flag: -{other}"))),
    }
    Ok(())
}

/// Records the mode, rejecting a second, conflicting mode letter.
fn set_mode(opts: &mut TarOpts, mode: Mode) -> Result<(), CliError> {
    match opts.mode {
        Some(existing) if existing != mode => {
            Err(CliError::usage("only one of -c, -x, -t may be given"))
        },
        _ => {
            opts.mode = Some(mode);
            Ok(())
        },
    }
}

/// Dispatches a fully-parsed invocation.
fn dispatch(opts: &TarOpts) -> CliResult {
    let Some(mode) = opts.mode else {
        return Err(CliError::usage(
            "a mode is required: one of -c (create), -x (extract), -t (list). Try --help",
        ));
    };
    match mode {
        Mode::Create => create(opts),
        Mode::Extract => extract(opts),
        Mode::List => list(opts),
    }
}

/// `-c`: build an archive from the member paths, apply create-time compression, write it out.
fn create(opts: &TarOpts) -> CliResult {
    if opts.members.is_empty() {
        return Err(CliError::usage(
            "create (-c) requires at least one input path",
        ));
    }
    // Resolve the output target before any chdir so a relative `-f` still points at the original cwd.
    let target = match opts.file.as_deref() {
        None | Some("-") => OutTarget::Stdout,
        Some(path) => OutTarget::File(absolutize(path)),
    };

    if let Some(dir) = &opts.chdir {
        std::env::set_current_dir(dir)
            .map_err(|e| CliError::runtime(format!("cannot chdir to {dir}: {e}")))?;
    }

    let format = match opts.format.unwrap_or(CreateFormat::Tar) {
        CreateFormat::Tar => FormatId::Tar,
        CreateFormat::Cpio => FormatId::Cpio,
    };
    match target {
        OutTarget::Stdout => {
            let stdout = std::io::stdout();
            stream_create(stdout.lock(), opts, format)
        },
        OutTarget::File(path) => {
            let output = std::fs::File::create(&path)
                .map_err(|e| CliError::runtime(format!("cannot write {}: {e}", path.display())))?;
            stream_create(output, opts, format)
        },
    }
}

fn stream_create<W: Write>(output: W, opts: &TarOpts, format: FormatId) -> CliResult {
    let mut builder = libarchive_oxide::StreamingArchiveBuilder::new(
        output,
        format,
        opts.filter,
        Limits::default(),
    )
    .map_err(|error| CliError::runtime(error.to_string()))?;
    for member in &opts.members {
        builder
            .append_path(member)
            .map_err(|error| CliError::runtime(error.to_string()))?;
        if opts.verbose {
            eprintln!("a {member}");
        }
    }
    builder
        .finish()
        .map(|_| ())
        .map_err(|error| CliError::runtime(error.to_string()))
}

/// `-x`: read the archive (auto-detecting compression + format) and extract under `-C` (or `.`).
fn extract(opts: &TarOpts) -> CliResult {
    let dest = opts
        .chdir
        .as_deref()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    match opts.file.as_deref() {
        None | Some("-") => {
            let stdin = std::io::stdin();
            extract_stream(stdin.lock(), &dest, opts.verbose, &opts.members)
        },
        Some(path) => {
            let input = std::fs::File::open(path)
                .map_err(|error| CliError::runtime(format!("cannot read {path}: {error}")))?;
            extract_stream(input, &dest, opts.verbose, &opts.members)
        },
    }
}

/// `-t`: read the archive and list entries (optionally filtered by member operands). `-v` promotes
/// the bare one-name-per-line output to an `ls -l`-style long listing, mirroring `bsdtar -tv`.
fn list(opts: &TarOpts) -> CliResult {
    match opts.file.as_deref() {
        None | Some("-") => {
            let stdin = std::io::stdin();
            list_stream(stdin.lock(), &opts.members, opts.verbose)
        },
        Some(path) => {
            let input = std::fs::File::open(path)
                .map_err(|error| CliError::runtime(format!("cannot read {path}: {error}")))?;
            list_stream(input, &opts.members, opts.verbose)
        },
    }
}

/// Where a created archive is written.
enum OutTarget {
    Stdout,
    File(PathBuf),
}

/// Makes `path` absolute against the current directory (without touching the filesystem), so it
/// survives a later `chdir`. Falls back to the path as-given if the cwd cannot be read.
fn absolutize(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(p),
        Err(_) => p.to_path_buf(),
    }
}

const HELP: &str = "\
oxtar: bsdtar-compatible archive tool

USAGE:
    oxtar -c [-z|-j|-J|--zstd|--lz4] [--format FMT] [-C DIR] [-v] -f ARCHIVE PATH...
    oxtar -x [-C DIR] [-v] -f ARCHIVE [MEMBER...]
    oxtar -t -f ARCHIVE [MEMBER...]

MODES (exactly one):
    -c            Create an archive from PATH...
    -x            Extract an archive.
    -t            List an archive's entries.

OPTIONS:
    -f ARCHIVE    Archive file ('-' or omitted = stdin/stdout).
    -C DIR        Change to DIR (create: before reading paths; extract: destination).
    -v            Verbose.
    -z, --gzip    Create-time gzip compression.
    -j, --bzip2   Create-time bzip2 compression.
    -J, --xz      Create-time xz compression.
        --zstd    Create-time zstd compression.
        --lz4     Create-time lz4 compression.
        --format FMT   Create format: tar|ustar|gnutar (ustar) or cpio (newc). Default: tar.
        --help, --version

Reads auto-detect compression (gzip/bzip2/zstd/xz/lz4) and format (tar/cpio/ar/zip/7z/iso).

UNSUPPORTED (exit 2):
    -r, -u        append/update; rewriting an existing archive is out of scope (use -c).

SAFE DEFAULTS:
    Path-traversal entries ('../', absolute, drive/UNC) are refused, and transparent
    decompression is capped, because untrusted archives are assumed.

EXIT CODES: 0 success, 1 runtime failure, 2 usage/unsupported-flag error.
";
