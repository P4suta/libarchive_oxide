// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxcat` entry point over
//! [`libarchive_oxide_cli::run_cat`], mapping the [`CliError`] onto the exit-code contract
//! (0 success / 1 runtime / 2 usage). See the library docs for the full flag interface.
//!
//! [`CliError`]: libarchive_oxide_cli::CliError

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    libarchive_oxide_cli::report_exit("oxcat", libarchive_oxide_cli::run_cat(args))
}
