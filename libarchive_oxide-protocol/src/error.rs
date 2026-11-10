// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Context-rich errors shared by formats, codecs, and adapters.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Stable classification of v0.2 archive failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An underlying reader, writer, or filesystem operation failed.
    Io,
    /// Malformed bytes or contradictory headers.
    Malformed,
    /// Valid but unsupported format capability.
    Unsupported,
    /// Configured resource budget was exceeded.
    Limit,
    /// A checksum, authentication tag, or other integrity check failed.
    Integrity,
    /// The current input/output lacks a required capability.
    Capability,
    /// A writer requires a declared entry size.
    SizeRequired,
    /// Caller or implementation violated the state-machine contract.
    Protocol,
    /// Filesystem extraction policy rejected an operation.
    Policy,
}

/// Context-rich, `no_std + alloc` archive failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveError {
    kind: ErrorKind,
    format: Option<&'static str>,
    offset: Option<u64>,
    entry_index: Option<u64>,
    entry_path: Option<Vec<u8>>,
    context: Vec<String>,
}

impl ArchiveError {
    /// Creates an error with a stable kind.
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            format: None,
            offset: None,
            entry_index: None,
            entry_path: None,
            context: Vec::new(),
        }
    }

    /// Adds a diagnostic context frame.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context.push(context.into());
        self
    }

    /// Adds format context.
    #[must_use]
    pub const fn with_format(mut self, format: &'static str) -> Self {
        self.format = Some(format);
        self
    }

    /// Adds byte offset context.
    #[must_use]
    pub const fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Adds entry context.
    #[must_use]
    pub fn with_entry(mut self, index: u64, path: impl Into<Vec<u8>>) -> Self {
        self.entry_index = Some(index);
        self.entry_path = Some(path.into());
        self
    }

    /// Stable classification.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Format context.
    #[must_use]
    pub const fn format(&self) -> Option<&'static str> {
        self.format
    }

    /// Byte offset.
    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Entry index and raw path.
    #[must_use]
    pub fn entry(&self) -> Option<(u64, &[u8])> {
        Some((self.entry_index?, self.entry_path.as_deref()?))
    }

    /// Diagnostic context frames, outermost last.
    #[must_use]
    pub fn context(&self) -> &[String] {
        &self.context
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} archive error", self.kind)?;
        if let Some(format) = self.format {
            write!(f, " in {format}")?;
        }
        if let Some(offset) = self.offset {
            write!(f, " at byte {offset}")?;
        }
        for context in &self.context {
            write!(f, ": {context}")?;
        }
        Ok(())
    }
}

impl core::error::Error for ArchiveError {}

#[cfg(test)]
mod tests {
    use super::{ArchiveError, ErrorKind};

    #[test]
    fn preserves_structured_context() {
        let error = ArchiveError::new(ErrorKind::Integrity)
            .with_format("zip")
            .with_offset(42)
            .with_entry(3, b"payload".to_vec())
            .with_context("authentication failed");
        assert_eq!(error.kind(), ErrorKind::Integrity);
        assert_eq!(error.format(), Some("zip"));
        assert_eq!(error.offset(), Some(42));
        assert_eq!(error.entry(), Some((3, b"payload".as_slice())));
        assert_eq!(error.context(), &["authentication failed"]);
    }
}
