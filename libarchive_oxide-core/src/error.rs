// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `no_std`-friendly error type. Does not depend on `std::io::Error`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Crate-wide result type.
pub(crate) type Result<T> = core::result::Result<T, Error>;

/// `libarchive_oxide-core`'s error. Represents, in the type system, the semantic failures that can occur in the sans-IO layer.
///
/// I/O-originated failures are not expressed in the base layer (since it is sans-IO, the bytes are carried by the caller).
/// The std-side adapters are responsible for interconversion with `std::io::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Error {
    /// The input byte sequence violates the format specification (corrupt header, invalid magic, etc.).
    Malformed(&'static str),
    /// Valid per the specification, but a feature this implementation does not yet handle.
    Unsupported(&'static str),
    /// A header-declared size or similar exceeded the configured safety limit (guards against decompression bombs and huge lengths).
    LimitExceeded(&'static str),
    /// A protocol violation, such as attempting to proceed to the next operation before fully reading an entry's data.
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed archive: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported feature: {m}"),
            Self::LimitExceeded(m) => write!(f, "safety limit exceeded: {m}"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
        }
    }
}

impl core::error::Error for Error {}

/// Stable classification of v0.2 archive failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
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

impl From<Error> for ArchiveError {
    fn from(value: Error) -> Self {
        match value {
            Error::Malformed(message) => Self::new(ErrorKind::Malformed).with_context(message),
            Error::Unsupported(message) => Self::new(ErrorKind::Unsupported).with_context(message),
            Error::LimitExceeded(message) => Self::new(ErrorKind::Limit).with_context(message),
            Error::InvalidState(message) => Self::new(ErrorKind::Protocol).with_context(message),
        }
    }
}
