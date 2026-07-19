// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxunzip` implementation.
//!
//! Supports `-l`, `-d`, `-o`, `-P`, member operands, `--help`, and
//! `--version`. `-n` and `-x` are unsupported. Extraction rejects path
//! traversal.

use std::path::PathBuf;

use crate::{extract_bytes, list_bytes, read_file, CliError, CliResult};

/// Parsed `oxunzip` invocation.
#[derive(Debug, Default)]
struct UnzipOpts {
    list: bool,
    dest: Option<String>,
    password: Option<String>,
    archive: Option<String>,
    members: Vec<String>,
}

/// `oxunzip` entry point.
///
/// # Errors
///
/// Returns [`CliError`] with code 2 for usage/unsupported-flag errors and code 1 for runtime
/// failures (I/O, corrupt archive, wrong password, decompression-bomb cap).
pub fn run_unzip(args: Vec<String>) -> CliResult {
    match parse(args)? {
        Parsed::Help => {
            print!("{HELP}");
            Ok(())
        },
        Parsed::Version => {
            println!("oxunzip {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        },
        Parsed::Run(opts) => dispatch(&opts),
    }
}

enum Parsed {
    Run(UnzipOpts),
    Help,
    Version,
}

fn parse(args: Vec<String>) -> Result<Parsed, CliError> {
    let mut opts = UnzipOpts::default();
    let mut it = args.into_iter().peekable();
    let mut only_positional = false;

    while let Some(arg) = it.next() {
        if only_positional {
            push_operand(&mut opts, arg);
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
                other => return Err(CliError::usage(format!("unknown flag: --{other}"))),
            }
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let cluster: Vec<char> = arg.chars().skip(1).collect();
            let mut idx = 0;
            while idx < cluster.len() {
                let c = cluster[idx];
                match c {
                    'l' => opts.list = true,
                    'o' => {}, // Always overwrite (non-interactive); accepted for compatibility.
                    'd' | 'P' => {
                        let rest: String = cluster[idx + 1..].iter().collect();
                        let value = if rest.is_empty() {
                            it.next()
                                .ok_or_else(|| CliError::usage(format!("-{c} requires a value")))?
                        } else {
                            rest
                        };
                        if c == 'd' {
                            opts.dest = Some(value);
                        } else {
                            opts.password = Some(value);
                        }
                        break;
                    },
                    'n' => {
                        return Err(CliError::unsupported(
                            "-n (never overwrite): not supported; extraction always overwrites",
                        ))
                    },
                    'x' => {
                        return Err(CliError::unsupported(
                            "-x (exclude): not supported; select members positionally instead",
                        ))
                    },
                    other => return Err(CliError::usage(format!("unknown flag: -{other}"))),
                }
                idx += 1;
            }
            continue;
        }
        push_operand(&mut opts, arg);
    }

    Ok(Parsed::Run(opts))
}

/// The first bare operand is the archive; the rest select members.
fn push_operand(opts: &mut UnzipOpts, arg: String) {
    if opts.archive.is_none() {
        opts.archive = Some(arg);
    } else {
        opts.members.push(arg);
    }
}

fn dispatch(opts: &UnzipOpts) -> CliResult {
    let archive = opts
        .archive
        .as_deref()
        .ok_or_else(|| CliError::usage("missing zip archive operand. Try --help"))?;
    let bytes = read_file(archive)?;

    // Unlike the auto-detecting tar/cpio tools, a zip extractor must reject non-zip input rather
    // than transparently handle whatever format it happens to be (as bsdunzip/Info-ZIP do:
    // "cannot find zipfile directory"). The reader below would otherwise auto-detect and extract a
    // plain tar/cpio/7z, turning a wrong-tool invocation into a false success.
    if !libarchive_oxide::zip::is_zip(&bytes) {
        return Err(CliError::runtime(format!(
            "{archive}: not a zip file (cannot find zipfile directory)"
        )));
    }
    let password = opts.password.as_deref().map(str::as_bytes);

    if opts.list {
        return list_bytes(&bytes, password, &opts.members, false);
    }
    let dest = opts
        .dest
        .as_deref()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    extract_bytes(&bytes, &dest, password, false, &opts.members)
}

const HELP: &str = "\
oxunzip: bsdunzip-compatible zip extractor

USAGE:
    oxunzip [-o] [-d DIR] [-P PASSWORD] ARCHIVE.zip [MEMBER...]
    oxunzip -l ARCHIVE.zip [MEMBER...]

OPTIONS:
    -l            List entries instead of extracting.
    -d DIR        Extract into DIR (default: current directory).
    -o            Overwrite existing files (always on; accepted for compatibility).
    -P PASSWORD   Decryption password (WinZip AES-256 / zip64 supported).
    --help, --version

UNSUPPORTED (exit 2): -n (never overwrite), -x (exclude), other classic flags.

SAFE DEFAULTS: path-traversal entries are refused and decompression is capped (untrusted input).

EXIT CODES: 0 success, 1 runtime failure, 2 usage/unsupported-flag error.
";
