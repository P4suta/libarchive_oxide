// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified `oxarchive` entry point over
//! [`libarchive_oxide_cli::run_oxarchive`].

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    libarchive_oxide_cli::report_exit("oxarchive", libarchive_oxide_cli::run_oxarchive(args))
}
