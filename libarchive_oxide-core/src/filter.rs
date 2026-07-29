// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression-filter identifiers and incremental probing.

use crate::ProbeResult;
use core::fmt;

/// Stable, extensible compression-filter identifier.
///
/// Downstream codec providers allocate identifiers with [`FilterId::custom`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FilterId(u32);

#[allow(non_upper_case_globals)]
impl FilterId {
    const CUSTOM_BIT: u32 = 1 << 31;

    /// DEFLATE with gzip framing.
    pub const Gzip: Self = Self(1);
    /// Zstandard.
    pub const Zstd: Self = Self(2);
    /// XZ / LZMA2.
    pub const Xz: Self = Self(3);
    /// LZ4 frame.
    pub const Lz4: Self = Self(4);
    /// Bzip2 stream.
    pub const Bzip2: Self = Self(5);
    /// Raw DEFLATE (RFC 1951) with no framing.
    ///
    /// The 7z Deflate coder stores bare deflate blocks with no gzip header,
    /// trailer, or checksum. It is selected structurally and is never probed.
    pub const Deflate: Self = Self(6);
    /// Unix `compress(1)` LZW stream (`.Z`).
    pub const Compress: Self = Self(7);
    /// lzip member stream.
    pub const Lzip: Self = Self(8);

    /// Creates a downstream identifier from the collision-free custom range.
    ///
    /// Values below `0x8000_0000` are reserved for built-in filters.
    #[must_use]
    pub const fn custom(value: u32) -> Option<Self> {
        if value & Self::CUSTOM_BIT == Self::CUSTOM_BIT {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether this identifier belongs to the downstream custom range.
    #[must_use]
    pub const fn is_custom(self) -> bool {
        self.0 & Self::CUSTOM_BIT == Self::CUSTOM_BIT
    }

    /// Probes a potentially incomplete prefix.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<Self> {
        const BZIP2_PREFIX: &[u8] = b"BZh";
        const SIGNATURES: &[(FilterId, &[u8])] = &[
            (FilterId::Gzip, &[0x1f, 0x8b]),
            (FilterId::Compress, &[0x1f, 0x9d]),
            (FilterId::Zstd, &[0x28, 0xb5, 0x2f, 0xfd]),
            (FilterId::Xz, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
            (FilterId::Lz4, &[0x04, 0x22, 0x4d, 0x18]),
            (FilterId::Lzip, b"LZIP"),
        ];
        let mut minimum = if prefix.len() < BZIP2_PREFIX.len() && BZIP2_PREFIX.starts_with(prefix) {
            4
        } else if prefix.starts_with(BZIP2_PREFIX) {
            if prefix.len() < 4 {
                return ProbeResult::NeedMore { minimum: 4 };
            }
            if matches!(prefix[3], b'1'..=b'9') {
                return ProbeResult::Match(FilterId::Bzip2);
            }
            usize::MAX
        } else {
            usize::MAX
        };
        for (identifier, signature) in SIGNATURES {
            if prefix.len() >= signature.len() && prefix.starts_with(signature) {
                return ProbeResult::Match(*identifier);
            }
            if prefix.len() < signature.len() && signature.starts_with(prefix) {
                minimum = minimum.min(signature.len());
            }
        }
        if minimum == usize::MAX {
            ProbeResult::NoMatch
        } else {
            ProbeResult::NeedMore { minimum }
        }
    }
}

impl fmt::Debug for FilterId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Gzip => "Gzip",
            Self::Zstd => "Zstd",
            Self::Xz => "Xz",
            Self::Lz4 => "Lz4",
            Self::Bzip2 => "Bzip2",
            Self::Deflate => "Deflate",
            Self::Compress => "Compress",
            Self::Lzip => "Lzip",
            _ => return write!(formatter, "FilterId({:#010x})", self.0),
        };
        formatter.write_str(name)
    }
}
