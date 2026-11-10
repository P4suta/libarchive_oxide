// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Format-specific high-level archive writer options.

/// AES key strength requested for an archive writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AesStrength {
    /// AES-128.
    Bits128,
    /// AES-192.
    Bits192,
    /// AES-256.
    Bits256,
}

/// ZIP member compression method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZipCompression {
    /// Store without compression (method 0).
    Store,
    /// DEFLATE (method 8).
    Deflate,
    /// Deflate64 (method 9).
    Deflate64,
    /// `BZip2` (method 12).
    Bzip2,
    /// LZMA (method 14).
    Lzma,
    /// `PPMd8` (method 98).
    Ppmd8,
    /// Zstandard (method 93).
    Zstd,
    /// XZ (method 95).
    Xz,
}

/// ZIP encryption wrapper.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZipEncryption {
    /// No encryption.
    #[default]
    None,
    /// Traditional PKWARE `ZipCrypto` for weak legacy interoperability.
    ZipCrypto,
    /// `WinZip` AES with an explicit key strength.
    Aes(AesStrength),
}

/// ZIP-specific writer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZipWriteOptions {
    compression: ZipCompression,
    encryption: ZipEncryption,
}

impl ZipWriteOptions {
    /// Creates the interoperable DEFLATE, unencrypted profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            compression: ZipCompression::Deflate,
            encryption: ZipEncryption::None,
        }
    }

    /// Selects the member compression method.
    #[must_use]
    pub const fn with_compression(mut self, compression: ZipCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Selects the encryption wrapper.
    #[must_use]
    pub const fn with_encryption(mut self, encryption: ZipEncryption) -> Self {
        self.encryption = encryption;
        self
    }

    /// Selected compression method.
    #[must_use]
    pub const fn compression(self) -> ZipCompression {
        self.compression
    }

    /// Selected encryption wrapper.
    #[must_use]
    pub const fn encryption(self) -> ZipEncryption {
        self.encryption
    }
}

impl Default for ZipWriteOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression coder for a 7z folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SevenZipCompression {
    /// Store without compression.
    Store,
    /// LZMA1.
    Lzma,
    /// LZMA2.
    Lzma2,
    /// `PPMd7`.
    Ppmd7,
    /// Raw DEFLATE.
    Deflate,
    /// `BZip2`.
    Bzip2,
    /// Zstandard.
    Zstd,
}

/// Reversible preprocessing filter before a 7z compression coder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SevenZipFilter {
    /// Delta filter with distance 1 through 256.
    Delta(u16),
    /// x86 BCJ.
    BcjX86,
    /// PowerPC BCJ.
    BcjPowerPc,
    /// IA-64 BCJ.
    BcjIa64,
    /// ARM BCJ.
    BcjArm,
    /// ARM Thumb BCJ.
    BcjArmThumb,
    /// ARM64 BCJ.
    BcjArm64,
    /// SPARC BCJ.
    BcjSparc,
    /// RISC-V BCJ.
    BcjRiscV,
}

/// 7z encryption selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SevenZipEncryption {
    /// No encryption.
    #[default]
    None,
    /// 7z AES-256/SHA-256.
    Aes256,
}

/// 7z-specific writer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SevenZipWriteOptions {
    compression: SevenZipCompression,
    filter: Option<SevenZipFilter>,
    solid: bool,
    encryption: SevenZipEncryption,
}

impl SevenZipWriteOptions {
    /// Creates the currently interoperable solid LZMA2 profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            compression: SevenZipCompression::Lzma2,
            filter: None,
            solid: true,
            encryption: SevenZipEncryption::None,
        }
    }

    /// Selects the folder compression coder.
    #[must_use]
    pub const fn with_compression(mut self, compression: SevenZipCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Selects an optional preprocessing filter.
    #[must_use]
    pub const fn with_filter(mut self, filter: Option<SevenZipFilter>) -> Self {
        self.filter = filter;
        self
    }

    /// Enables or disables solid folder grouping.
    #[must_use]
    pub const fn with_solid(mut self, solid: bool) -> Self {
        self.solid = solid;
        self
    }

    /// Selects 7z encryption.
    #[must_use]
    pub const fn with_encryption(mut self, encryption: SevenZipEncryption) -> Self {
        self.encryption = encryption;
        self
    }

    /// Selected compression coder.
    #[must_use]
    pub const fn compression(self) -> SevenZipCompression {
        self.compression
    }

    /// Selected preprocessing filter.
    #[must_use]
    pub const fn filter(self) -> Option<SevenZipFilter> {
        self.filter
    }

    /// Whether entries share a solid folder.
    #[must_use]
    pub const fn solid(self) -> bool {
        self.solid
    }

    /// Selected encryption.
    #[must_use]
    pub const fn encryption(self) -> SevenZipEncryption {
        self.encryption
    }
}

impl Default for SevenZipWriteOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression method for regular-file payloads in a XAR heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum XarCompression {
    /// Store payload bytes without compression.
    Store,
    /// RFC 1950 zlib stream (`application/x-gzip` in XAR TOCs).
    Zlib,
    /// `BZip2` stream (`application/x-bzip2` in XAR TOCs).
    Bzip2,
}

/// XAR-specific writer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XarWriteOptions {
    compression: XarCompression,
}

impl XarWriteOptions {
    /// Creates the backward-compatible stored-payload profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            compression: XarCompression::Store,
        }
    }

    /// Selects the compression method for every regular-file payload.
    #[must_use]
    pub const fn with_compression(mut self, compression: XarCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Selected regular-file compression method.
    #[must_use]
    pub const fn compression(self) -> XarCompression {
        self.compression
    }
}

impl Default for XarWriteOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Format-scoped options attached to [`crate::CreateOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormatWriteOptions {
    /// ZIP-specific method and encryption choices.
    Zip(ZipWriteOptions),
    /// 7z-specific coder graph, solid, and encryption choices.
    SevenZip(SevenZipWriteOptions),
    /// XAR heap-payload compression choice.
    Xar(XarWriteOptions),
}
