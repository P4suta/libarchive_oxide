// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared implementation of the unified `oxarchive` command.

#![forbid(unsafe_code)]

pub mod oci;
pub mod oxarchive;
pub mod package;

use std::io::Write;

pub use oxarchive::run_oxarchive;

/// A CLI error and process exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// Message written to standard error.
    pub message: String,
    /// Process exit code: 1 for runtime errors, 2 for usage errors.
    pub code: u8,
}

impl CliError {
    /// Creates a usage error with exit code 2.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }

    /// Creates a runtime error with exit code 1.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    /// Creates an unsupported-option error with exit code 2.
    pub fn unsupported(flag: impl std::fmt::Display) -> Self {
        Self::usage(format!("unsupported: {flag}"))
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Convenience alias for CLI entry points.
pub type CliResult = Result<(), CliError>;

/// Maps a command result to the process contract and reports failures without
/// panicking when the diagnostic stream is closed.
#[must_use]
pub fn report_exit(tool: &str, result: CliResult) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let stderr = std::io::stderr();
            let _ = writeln!(stderr.lock(), "{tool}: {error}");
            std::process::ExitCode::from(error.code)
        },
    }
}
