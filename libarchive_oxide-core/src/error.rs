//! `no_std`-friendly error type. Does not depend on `std::io::Error`.

use core::fmt;

/// Crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;

/// `libarchive_oxide-core`'s error. Represents, in the type system, the semantic failures that can occur in the sans-IO layer.
///
/// I/O-originated failures are not expressed in the base layer (since it is sans-IO, the bytes are carried by the caller).
/// The std-side adapters are responsible for interconversion with `std::io::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input byte sequence violates the format specification (corrupt header, invalid magic, etc.).
    Malformed(&'static str),
    /// Valid per the specification, but a feature this implementation does not yet handle.
    Unsupported(&'static str),
    /// A header-declared size or similar exceeded the configured safety limit (guards against decompression bombs and huge lengths).
    LimitExceeded(&'static str),
    /// The caller's output buffer is too small to advance even a single element.
    OutputTooSmall,
    /// A protocol violation, such as attempting to proceed to the next operation before fully reading an entry's data.
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed archive: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported feature: {m}"),
            Self::LimitExceeded(m) => write!(f, "safety limit exceeded: {m}"),
            Self::OutputTooSmall => f.write_str("output buffer too small to make progress"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
        }
    }
}

impl core::error::Error for Error {}
