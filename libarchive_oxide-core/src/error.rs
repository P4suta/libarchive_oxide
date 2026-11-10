// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Format-internal errors plus the shared public error surface.

use core::fmt;

pub use libarchive_oxide_protocol::{ArchiveError, ErrorKind};

/// Crate-wide result type used by compact format parsers.
pub(crate) type Result<T> = core::result::Result<T, Error>;

/// Internal static error used while parsing sans-I/O format state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Error {
    /// The input byte sequence violates the format specification.
    Malformed(&'static str),
    /// Valid per the specification, but unsupported here.
    Unsupported(&'static str),
    /// A declared size exceeded a configured or address-space limit.
    LimitExceeded(&'static str),
    /// Caller or format state violated the protocol ordering.
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "malformed archive: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported feature: {message}"),
            Self::LimitExceeded(message) => write!(f, "safety limit exceeded: {message}"),
            Self::InvalidState(message) => write!(f, "invalid state: {message}"),
        }
    }
}

impl core::error::Error for Error {}

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
