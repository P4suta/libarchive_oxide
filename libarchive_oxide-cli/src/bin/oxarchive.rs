// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified `oxarchive` entry point over
//! [`libarchive_oxide_cli::run_oxarchive`].

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match libarchive_oxide_cli::run_oxarchive(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oxarchive: {error}");
            ExitCode::from(error.code)
        },
    }
}
