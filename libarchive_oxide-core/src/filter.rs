// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression filter traits and identifiers.
//!
//! Filters implement [`Transform`]. Archive formats consume the resulting
//! uncompressed bytes.

use crate::transform::Transform;

/// Compression filter identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FilterId {
    /// DEFLATE with gzip framing.
    Gzip,
    /// Zstandard.
    Zstd,
    /// XZ / LZMA2.
    Xz,
    /// LZ4 frame.
    Lz4,
}

impl FilterId {
    /// Detects a filter from leading magic bytes.
    ///
    /// Returns `None` when there is not enough prefix to decide, or when nothing matches.
    #[must_use]
    pub fn sniff(prefix: &[u8]) -> Option<Self> {
        match prefix {
            [0x1f, 0x8b, ..] => Some(Self::Gzip),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Self::Zstd),
            [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Some(Self::Xz),
            [0x04, 0x22, 0x4d, 0x18, ..] => Some(Self::Lz4),
            _ => None,
        }
    }
}

/// Compression filter marker.
pub trait Filter: Transform {
    /// The codec this filter belongs to.
    const ID: FilterId;
}

/// Compressed-to-plain transform.
pub trait Decoder: Filter {}

/// Plain-to-compressed transform.
pub trait Encoder: Filter {}
