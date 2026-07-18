//! `oxcpio` — the bsdcpio-compatible cpio interface over the flagship library.
//!
//! Supported (each flag fully functional):
//!
//! - Modes: `-o` create (copy-out), `-i` extract (copy-in), `-t` list. `-t` combined with `-i`
//!   (`-it`) lists without extracting, matching bsdcpio.
//! - `-F FILE` archive file (`-` or omitted = stdin/stdout).
//! - `-v` verbose.
//! - `-d` create leading directories on extract (already unconditional here; accepted for scripts).
//! - Trailing operands select members on `-i`/`-t` (literal name / directory-prefix match).
//!
//! Copy-out (`-o`) reads the list of filenames from stdin, one per line — the bsdcpio interface —
//! and writes a newc cpio archive. Reads auto-detect any compression wrapping the cpio stream.
//!
//! Intentionally unsupported (clean exit-2 error): `-p` (pass-through copy), `-C` (I/O block size),
//! and any other classic flag → `unknown flag`. Safe defaults (traversal rejection, bomb cap) stay
//! on, as documented at the crate root.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use crate::{extract_bytes, list_bytes, read_file, CliError, CliResult};

/// The cpio operation selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `-o` copy-out (create).
    Create,
    /// `-i` copy-in (extract).
    Extract,
    /// `-t` (or `-it`) list.
    List,
}

/// Parsed `oxcpio` invocation.
///
/// The three selector booleans mirror bsdcpio's `-i`/`-o`/`-t` letters, which are set independently
/// during parsing and only then folded into a single [`Mode`] by [`resolve_mode`]; keeping them
/// separate here is what lets `-it` mean "list (copy-in), don't extract".
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct CpioOpts {
    extract: bool,
    create: bool,
    list: bool,
    file: Option<String>,
    verbose: bool,
    members: Vec<String>,
}

/// `oxcpio` entry point.
///
/// # Errors
///
/// Returns [`CliError`] with code 2 for usage/unsupported-flag errors and code 1 for runtime
/// failures.
pub fn run_cpio(args: Vec<String>) -> CliResult {
    match parse(args)? {
        Parsed::Help => {
            print!("{HELP}");
            Ok(())
        }
        Parsed::Version => {
            println!("oxcpio {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Parsed::Run(opts) => dispatch(&opts),
    }
}

enum Parsed {
    Run(CpioOpts),
    Help,
    Version,
}

fn parse(args: Vec<String>) -> Result<Parsed, CliError> {
    let mut opts = CpioOpts::default();
    let mut it = args.into_iter().peekable();
    let mut only_positional = false;

    while let Some(arg) = it.next() {
        if only_positional {
            opts.members.push(arg);
            continue;
        }
        if arg == "--" {
            only_positional = true;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            match long {
                "help" => return Ok(Parsed::Help),
                "version" => return Ok(Parsed::Version),
                "create" => opts.create = true,
                "extract" => opts.extract = true,
                "list" => opts.list = true,
                "verbose" => opts.verbose = true,
                "make-directories" => {}
                "file" => {
                    opts.file = Some(
                        it.next()
                            .ok_or_else(|| CliError::usage("--file requires a value"))?,
                    );
                }
                other => return Err(CliError::usage(format!("unknown flag: --{other}"))),
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let cluster: Vec<char> = arg.chars().skip(1).collect();
            let mut idx = 0;
            while idx < cluster.len() {
                let c = cluster[idx];
                if c == 'F' {
                    let rest: String = cluster[idx + 1..].iter().collect();
                    opts.file = Some(if rest.is_empty() {
                        it.next()
                            .ok_or_else(|| CliError::usage("-F requires a value"))?
                    } else {
                        rest
                    });
                    break;
                }
                apply_bool_flag(c, &mut opts)?;
                idx += 1;
            }
            continue;
        }
        opts.members.push(arg);
    }

    Ok(Parsed::Run(opts))
}

fn apply_bool_flag(c: char, opts: &mut CpioOpts) -> Result<(), CliError> {
    match c {
        'o' => opts.create = true,
        'i' => opts.extract = true,
        't' => opts.list = true,
        'v' => opts.verbose = true,
        'd' => {} // Leading directories are always created on extract; accepted for compatibility.
        'p' => {
            return Err(CliError::unsupported(
                "-p (pass-through copy): out of scope; use -o then -i",
            ))
        }
        'C' => {
            return Err(CliError::unsupported(
                "-C (I/O block size): not configurable",
            ))
        }
        other => return Err(CliError::usage(format!("unknown flag: -{other}"))),
    }
    Ok(())
}

/// Resolves the mode, rejecting conflicting or missing selectors. `-t` (list) takes precedence over
/// `-i` so `-it` lists without extracting, as in bsdcpio.
fn resolve_mode(opts: &CpioOpts) -> Result<Mode, CliError> {
    if opts.create && (opts.extract || opts.list) {
        return Err(CliError::usage("-o cannot be combined with -i or -t"));
    }
    if opts.list {
        return Ok(Mode::List);
    }
    if opts.create {
        return Ok(Mode::Create);
    }
    if opts.extract {
        return Ok(Mode::Extract);
    }
    Err(CliError::usage(
        "a mode is required: one of -i (extract), -o (create), -t (list). Try --help",
    ))
}

fn dispatch(opts: &CpioOpts) -> CliResult {
    match resolve_mode(opts)? {
        Mode::Create => create(opts),
        Mode::Extract => {
            let bytes = read_input(opts.file.as_deref())?;
            extract_bytes(&bytes, Path::new("."), None, opts.verbose, &opts.members)
        }
        Mode::List => {
            let bytes = read_input(opts.file.as_deref())?;
            list_bytes(&bytes, None, &opts.members, opts.verbose)
        }
    }
}

/// `-o`: read the newline-separated list of paths from stdin, build a newc cpio, write it out.
fn create(opts: &CpioOpts) -> CliResult {
    let mut names = Vec::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| CliError::runtime(format!("cannot read stdin: {e}")))?;
        let name = line.trim_end_matches(['\r', '\n']);
        if !name.is_empty() {
            names.push(name.to_string());
        }
    }
    if names.is_empty() {
        return Err(CliError::runtime(
            "copy-out (-o) read no filenames from stdin",
        ));
    }

    let bytes = libarchive_oxide::build_cpio(&names).map_err(|e| CliError::runtime(e.to_string()))?;

    if opts.verbose {
        for n in &names {
            eprintln!("a {n}");
        }
    }

    match out_target(opts.file.as_deref()) {
        OutTarget::Stdout => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            out.write_all(&bytes)
                .map_err(|e| CliError::runtime(format!("cannot write stdout: {e}")))
        }
        OutTarget::File(path) => std::fs::write(&path, &bytes)
            .map_err(|e| CliError::runtime(format!("cannot write {}: {e}", path.display()))),
    }
}

enum OutTarget {
    Stdout,
    File(PathBuf),
}

fn out_target(file: Option<&str>) -> OutTarget {
    match file {
        None | Some("-") => OutTarget::Stdout,
        Some(path) => OutTarget::File(PathBuf::from(path)),
    }
}

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

const HELP: &str = "\
oxcpio — bsdcpio-compatible cpio tool (libarchive_oxide)

USAGE:
    ... | oxcpio -o [-v] [-F ARCHIVE]        Create (reads filenames from stdin).
    oxcpio -i [-d] [-v] [-F ARCHIVE] [PATTERN...]   Extract.
    oxcpio -it [-F ARCHIVE] [PATTERN...]            List.

MODES (exactly one):
    -o            Copy-out: build an archive from filenames read on stdin.
    -i            Copy-in: extract.
    -t            List (combine with -i, i.e. '-it', to list without extracting).

OPTIONS:
    -F ARCHIVE    Archive file ('-' or omitted = stdin/stdout).
    -v            Verbose.
    -d            Create leading directories on extract (always on; accepted for scripts).

Reads auto-detect compression (gzip/zstd/xz/lz4).

UNSUPPORTED (exit 2, by design): -p (pass-through), -C (block size), and other classic flags.

SAFE DEFAULTS: path-traversal entries are refused and decompression is capped (untrusted input).

EXIT CODES: 0 success, 1 runtime failure, 2 usage/unsupported-flag error.
";
