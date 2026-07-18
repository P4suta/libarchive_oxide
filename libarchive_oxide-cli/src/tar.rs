//! `oxtar` — the bsdtar-compatible tar interface over the flagship library.
//!
//! Supported (each flag is fully functional — no partial behavior):
//!
//! - Modes: `-c` create, `-x` extract, `-t` list (exactly one required).
//! - `-f FILE` archive file (`-` or omitted = stdin/stdout).
//! - `-C DIR` change directory (create: `chdir` before reading members; extract: destination).
//! - `-v` verbose.
//! - Create-time compression: `-z`/`--gzip`, `-J`/`--xz`, `--zstd`, `--lz4`.
//! - `--format FMT` create format: `tar`/`ustar`/`gnutar` (the ustar writer) or `cpio` (newc).
//! - Trailing operands select members on `-x`/`-t`.
//! - `--help`, `--version`.
//!
//! Intentionally unsupported (clean exit-2 error, never a silent stub):
//!
//! - `-j` / `--bzip2` — bzip2 was removed from the library; recompress with another codec.
//! - `-r` / `-u` — append/update. Rewriting an existing archive's trailer is out of scope for the
//!   0.x line (documented in the README); use `-c` to build afresh.
//! - Any other classic flag (`-p`, `--numeric-owner`, `--strip-components`, …) → `unknown flag`.
//!
//! Safe defaults preserved: path-traversal rejection and the decompression-bomb cap stay on; this is
//! a deliberate, documented divergence from historical tar (see the crate-level docs).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use libarchive_oxide_core::filter::FilterId;

use crate::{extract_bytes, list_bytes, read_file, CliError, CliResult};

/// The mode letter selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Create,
    Extract,
    List,
}

/// The create format selected by `--format` (only the writers the library can produce faithfully).
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
        }
        Parsed::Version => {
            println!("oxtar {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
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
                _ => {}
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
        "xz" => opts.filter = Some(FilterId::Xz),
        "zstd" => opts.filter = Some(FilterId::Zstd),
        "lz4" => opts.filter = Some(FilterId::Lz4),
        "bzip2" | "bunzip2" => {
            return Err(CliError::unsupported(
                "--bzip2: bzip2 was removed from libarchive_oxide; use --gzip/--xz/--zstd/--lz4",
            ))
        }
        "format" => {
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .ok_or_else(|| CliError::usage("--format requires a value"))?,
            };
            opts.format = Some(parse_format(&value)?);
        }
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
        'J' => opts.filter = Some(FilterId::Xz),
        'j' => {
            return Err(CliError::unsupported(
                "-j (bzip2): bzip2 was removed from libarchive_oxide; use -z/-J/--zstd/--lz4",
            ))
        }
        'r' => {
            return Err(CliError::unsupported(
                "-r (append): rewriting an existing archive is out of scope; use -c",
            ))
        }
        'u' => {
            return Err(CliError::unsupported(
                "-u (update): rewriting an existing archive is out of scope; use -c",
            ))
        }
        other => return Err(CliError::usage(format!("unknown flag: -{other}"))),
    }
    Ok(())
}

/// Records the mode, rejecting a second, conflicting mode letter.
fn set_mode(opts: &mut TarOpts, mode: Mode) -> Result<(), CliError> {
    match opts.mode {
        Some(existing) if existing != mode => {
            Err(CliError::usage("only one of -c, -x, -t may be given"))
        }
        _ => {
            opts.mode = Some(mode);
            Ok(())
        }
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
        return Err(CliError::usage("create (-c) requires at least one input path"));
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

    let format = opts.format.unwrap_or(CreateFormat::Tar);
    let raw = match format {
        CreateFormat::Tar => libarchive_oxide::build_tar(&opts.members),
        CreateFormat::Cpio => libarchive_oxide::build_cpio(&opts.members),
    }
    .map_err(|e| CliError::runtime(e.to_string()))?;

    let bytes = match opts.filter {
        Some(id) => libarchive_oxide::compress(&raw, id)
            .map_err(|e| CliError::runtime(e.to_string()))?,
        None => raw,
    };

    if opts.verbose {
        for m in &opts.members {
            eprintln!("a {m}");
        }
    }

    match target {
        OutTarget::Stdout => write_stdout(&bytes),
        OutTarget::File(path) => std::fs::write(&path, &bytes)
            .map_err(|e| CliError::runtime(format!("cannot write {}: {e}", path.display()))),
    }
}

/// `-x`: read the archive (auto-detecting compression + format) and extract under `-C` (or `.`).
fn extract(opts: &TarOpts) -> CliResult {
    let bytes = read_input(opts.file.as_deref())?;
    let dest = opts.chdir.as_deref().map_or_else(|| PathBuf::from("."), PathBuf::from);
    extract_bytes(&bytes, &dest, None, opts.verbose, &opts.members)
}

/// `-t`: read the archive and list entries (optionally filtered by member operands). `-v` promotes
/// the bare one-name-per-line output to an `ls -l`-style long listing, mirroring `bsdtar -tv`.
fn list(opts: &TarOpts) -> CliResult {
    let bytes = read_input(opts.file.as_deref())?;
    list_bytes(&bytes, None, &opts.members, opts.verbose)
}

/// Where a created archive is written.
enum OutTarget {
    Stdout,
    File(PathBuf),
}

/// Reads archive bytes from `file` (or stdin when `None`/`-`).
fn read_input(file: Option<&str>) -> Result<Vec<u8>, CliError> {
    match file {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::runtime(format!("cannot read stdin: {e}")))?;
            Ok(buf)
        }
        Some(path) => read_file(path),
    }
}

/// Writes bytes to stdout as a whole (used for `-c -f -`).
fn write_stdout(bytes: &[u8]) -> CliResult {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(bytes)
        .map_err(|e| CliError::runtime(format!("cannot write stdout: {e}")))
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
oxtar — bsdtar-compatible archive tool (libarchive_oxide)

USAGE:
    oxtar -c [-z|-J|--zstd|--lz4] [--format FMT] [-C DIR] [-v] -f ARCHIVE PATH...
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
    -J, --xz      Create-time xz compression.
        --zstd    Create-time zstd compression.
        --lz4     Create-time lz4 compression.
        --format FMT   Create format: tar|ustar|gnutar (ustar) or cpio (newc). Default: tar.
        --help, --version

Reads auto-detect compression (gzip/zstd/xz/lz4) and format (tar/cpio/ar/zip/7z/iso).

UNSUPPORTED (exit 2, by design — never a silent no-op):
    -j, --bzip2   bzip2 was removed from the library; recompress with -z/-J/--zstd/--lz4.
    -r, -u        append/update; rewriting an existing archive is out of scope (use -c).

SAFE DEFAULTS (a deliberate divergence from historical tar):
    Path-traversal entries ('../', absolute, drive/UNC) are refused, and transparent
    decompression is capped, because untrusted archives are assumed.

EXIT CODES: 0 success, 1 runtime failure, 2 usage/unsupported-flag error.
";
