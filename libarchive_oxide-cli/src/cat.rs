// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxcat` implementation.
//!
//! Detects gzip, zstd, xz, and lz4. Uncompressed input passes through. Supports
//! file operands, standard input, `--help`, and `--version`. Decompression uses
//! the crate-level limit.

use std::io::{Read, Write};

use crate::{decompress_cap, CliError, CliResult};

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
        return cat_stream(&read_stdin()?, &mut out);
    }
    for file in &files {
        let bytes = if file == "-" {
            read_stdin()?
        } else {
            std::fs::read(file)
                .map_err(|e| CliError::runtime(format!("cannot read {file}: {e}")))?
        };
        cat_stream(&bytes, &mut out)?;
    }
    Ok(())
}

/// Decompresses (or passes through) `bytes` and writes the result to `out`.
fn cat_stream<W: Write>(bytes: &[u8], out: &mut W) -> CliResult {
    let plain = libarchive_oxide::decompress_capped(bytes, decompress_cap())
        .map_err(|e| CliError::runtime(e.to_string()))?;
    out.write_all(&plain)
        .map_err(|e| CliError::runtime(format!("cannot write stdout: {e}")))
}

/// Reads all of stdin into memory.
fn read_stdin() -> Result<Vec<u8>, CliError> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| CliError::runtime(format!("cannot read stdin: {e}")))?;
    Ok(buf)
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
