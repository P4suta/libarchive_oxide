// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxcat` implementation.
//!
//! Detects gzip, zstd, xz, and lz4. Uncompressed input passes through. Supports
//! file operands, standard input, `--help`, and `--version`. Decompression uses
//! the crate-level limit.

use std::io::{Read, Write};

use crate::{CliError, CliResult};

/// `oxcat` entry point.
///
/// # Errors
///
/// Returns [`CliError`] with code 2 for usage errors and code 1 for runtime failures (I/O, corrupt
/// stream, decompression-bomb cap).
pub fn run_cat(args: Vec<String>) -> CliResult {
    let mut files: Vec<String> = Vec::new();
    let mut only_positional = false;
    for arg in args {
        if only_positional {
            files.push(arg);
            continue;
        }
        match arg.as_str() {
            "--" => only_positional = true,
            "--help" => {
                print!("{HELP}");
                return Ok(());
            },
            "--version" => {
                println!("oxcat {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            },
            "-" => files.push(arg),
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(CliError::usage(format!("unknown flag: {other}")));
            },
            _ => files.push(arg),
        }
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if files.is_empty() {
        let stdin = std::io::stdin();
        return cat_stream(stdin.lock(), &mut out);
    }
    for file in &files {
        if file == "-" {
            let stdin = std::io::stdin();
            cat_stream(stdin.lock(), &mut out)?;
        } else {
            let input = std::fs::File::open(file)
                .map_err(|error| CliError::runtime(format!("cannot read {file}: {error}")))?;
            cat_stream(input, &mut out)?;
        }
    }
    Ok(())
}

/// Decompresses (or passes through) a stream and copies it to `out`.
fn cat_stream<R: Read, W: Write>(input: R, out: &mut W) -> CliResult {
    let mut input = libarchive_oxide::FilterReader::new(input)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    std::io::copy(&mut input, out)
        .map(|_| ())
        .map_err(|error| CliError::runtime(format!("cannot copy stream: {error}")))
}

const HELP: &str = "\
oxcat: bsdcat-compatible transparent decompressor

USAGE:
    oxcat [FILE...]        Decompress each FILE to stdout ('-' or none = stdin).

Auto-detects gzip/zstd/xz/lz4; uncompressed input is passed through. Decompression is
capped to defend against bombs (a documented safe default).

    --help, --version

EXIT CODES: 0 success, 1 runtime failure, 2 usage error.
";
