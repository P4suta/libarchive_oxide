//! Filter axis: a subdivision of [`Transform`] that represents compression codecs.
//!
//! The filter axis is **orthogonal** to the format axis. The format layer merely reads
//! bytes from a chain of `Box<dyn Decoder>`, knowing nothing about whether or how they are compressed.
//!
//! # Duality (decode ⇄ encode)
//!
//! [`Decoder`] and [`Encoder`] are type-level duals. For any codec, passing bytes
//! through the `Encoder` and then through the `Decoder` yields the identity (`Decoder ∘ Encoder = id`).
//! This invariant is enforced mechanically by property tests once the encoders are implemented.
//!
//! # Origin-opaque
//!
//! Our own `Inflate` (sans-IO, `no_std`), as well as the adapters wrapping `ruzstd`/`lzma-rs`/`lz4_flex`,
//! all ride on the same [`Filter`] isomorphically. The seams are sealed inside each adapter,
//! and the only compromise that surfaces is that "the zstd/xz adapters are `std` feature-gated".

use crate::transform::Transform;

/// Identifier for a compression filter. Used for detection, diagnostics, and automatic layering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FilterId {
    /// DEFLATE + gzip framing (our own inflate, `no_std`).
    Gzip,
    /// Zstandard (`ruzstd` adapter, std).
    Zstd,
    /// XZ / LZMA2 (`lzma-rs` adapter, std, subset).
    Xz,
    /// LZ4 frame (`lz4_flex` adapter, std).
    Lz4,
    /// bzip2 (`bzip2-rs` adapter, std).
    Bzip2,
}

impl FilterId {
    /// Infers the filter from the magic bytes at the start of a byte stream (for auto-detection).
    ///
    /// Returns `None` when there is not enough prefix to decide, or when nothing matches.
    #[must_use]
    pub fn sniff(prefix: &[u8]) -> Option<Self> {
        match prefix {
            [0x1f, 0x8b, ..] => Some(Self::Gzip),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Self::Zstd),
            [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Some(Self::Xz),
            [0x04, 0x22, 0x4d, 0x18, ..] => Some(Self::Lz4),
            [b'B', b'Z', b'h', ..] => Some(Self::Bzip2),
            _ => None,
        }
    }
}

/// Marker indicating that a type is a compression filter. The common supertrait of [`Decoder`]/[`Encoder`].
pub trait Filter: Transform {
    /// The codec this filter belongs to.
    const ID: FilterId;
}

/// Decompressor: compressed byte stream → plaintext byte stream. The dual of [`Encoder`].
pub trait Decoder: Filter {}

/// Compressor: plaintext byte stream → compressed byte stream. The dual of [`Decoder`].
pub trait Encoder: Filter {}
