// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP-specific options shared by the streaming adapters.

/// Compression method used for a streaming ZIP entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZipMethod {
    /// Store bytes without compression.
    Store,
    /// Encode bytes as raw DEFLATE.
    Deflate,
    /// Encode bytes as `bzip2` (method 12).
    #[cfg(feature = "bzip2")]
    Bzip2,
    /// Encode bytes as Zstandard (method 93).
    ///
    /// Both codec profiles support streaming output. The portable backend
    /// emits bounded raw-block frames; the native backend applies compression.
    #[cfg(feature = "zstd")]
    Zstd,
    /// Encode bytes as LZMA (method 14).
    ///
    /// Raw LZMA1 with a ZIP-specific 9-byte header, terminated by an
    /// end-of-stream marker. Read and write are both available whenever the
    /// `xz` feature is enabled (both codec profiles).
    #[cfg(feature = "xz")]
    Lzma,
    /// Encode bytes as a complete XZ stream (method 95).
    #[cfg(feature = "xz")]
    Xz,
    /// Encode bytes with prediction by partial matching variant I revision 1 (method 98).
    ///
    /// The encoder uses an 8 MiB model at order 8 and validates that allocation against the configured codec-memory limit before starting an entry.
    #[cfg(feature = "ppmd")]
    Ppmd8,
}
