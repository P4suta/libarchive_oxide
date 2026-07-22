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
    /// Reading is available on both codec profiles; writing requires the
    /// `native-codecs` profile (the portable `ruzstd` path is decode-only).
    #[cfg(feature = "zstd")]
    Zstd,
    /// Encode bytes as LZMA (method 14).
    ///
    /// Raw LZMA1 with a ZIP-specific 9-byte header, terminated by an
    /// end-of-stream marker. Read and write are both available whenever the
    /// `xz` feature is enabled (both codec profiles).
    #[cfg(feature = "xz")]
    Lzma,
}
