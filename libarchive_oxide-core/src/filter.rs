// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression-filter identifiers and incremental probing.

use crate::ProbeResult;

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
    /// Probes a potentially incomplete prefix.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<Self> {
        const SIGNATURES: &[(FilterId, &[u8])] = &[
            (FilterId::Gzip, &[0x1f, 0x8b]),
            (FilterId::Zstd, &[0x28, 0xb5, 0x2f, 0xfd]),
            (FilterId::Xz, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
            (FilterId::Lz4, &[0x04, 0x22, 0x4d, 0x18]),
        ];
        let mut minimum = usize::MAX;
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
