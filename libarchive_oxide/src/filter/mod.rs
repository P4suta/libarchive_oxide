// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `filter` — concrete implementations of compression filters.
//!
//! They all sit isomorphically as [`libarchive_oxide_core::Filter`]. Whether it is a hand-written
//! sans-IO filter (`gzip`) or an adapter wrapping `ruzstd`/`lzma_rust2`/`lz4_flex`, the caller's
//! type cannot tell them apart (origin-opaque). The seams are sealed inside the adapters.
//!
//! # Implementation status
//!
//! - P2: `gzip` (adapts `miniz_oxide` into a sans-IO `Transform`).
//! - P3: `zstd`/`xz`/`lz4` adapters.

#[cfg(feature = "gzip")]
use alloc::vec::Vec;

// The codec-dispatch enums and registry (`AnyDecoder`/`AnyEncoder`, `decoder`/`encoder`) only exist
// when at least one codec is compiled in; with no codec feature there is nothing to dispatch.
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::filter::FilterId;
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::transform::{Step, Transform};
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::Result;

/// One-shot raw DEFLATE decompression with an output-size cap.
///
/// Used by per-entry container formats (e.g. zip) whose uncompressed size is known up front; the
/// cap defends against a lying size field (decompression bomb).
#[cfg(feature = "gzip")]
pub fn inflate(compressed: &[u8], max_size: usize) -> libarchive_oxide_core::Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(compressed, max_size)
        .map_err(|_| libarchive_oxide_core::Error::Malformed("deflate: decode failed"))
}

/// One-shot raw DEFLATE compression — the dual of [`inflate`].
///
/// Used by per-entry container formats (e.g. the zip writer) that buffer an entry's plaintext and
/// need the compressed bytes plus their final length up front. Level 6 (the `miniz_oxide` default)
/// balances ratio against speed.
#[cfg(feature = "gzip")]
#[must_use]
pub fn deflate(plain: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(plain, 6)
}

#[cfg(feature = "gzip")]
pub mod gzip;

/// Shared CRC-32 primitives (IEEE, polynomial `0xEDB88320`), re-exported at the crate root so the
/// zip and 7z writers reach them without depending on the gzip module path.
#[cfg(feature = "gzip")]
pub use gzip::{crc32, Crc32};

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
mod bridge;
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
mod push;
#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
pub mod reused;

/// A decompressor for any codec compiled in — a sealed enum with **zero type erasure**. Every
/// variant is a concrete [`Transform`]; the `Transform` impl forwards each call by exhaustive
/// `match`, so the origin (hand-written gzip vs. adapter over a reused crate) never leaks into the
/// caller's type. Adding a codec is a compiler-checked exhaustiveness obligation, not a trait-object cast.
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
#[derive(Debug)]
pub enum AnyDecoder {
    /// gzip (hand-written, `no_std`).
    #[cfg(feature = "gzip")]
    Gzip(gzip::GzipDecoder),
    /// Zstandard (`ruzstd` adapter).
    #[cfg(feature = "zstd")]
    Zstd(reused::ZstdDecoder),
    /// XZ (`lzma-rust2` adapter).
    #[cfg(feature = "xz")]
    Xz(reused::XzDecoder),
    /// LZ4 frame (`lz4_flex` adapter).
    #[cfg(feature = "lz4")]
    Lz4(reused::Lz4Decoder),
}

#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
impl Transform for AnyDecoder {
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step> {
        match self {
            #[cfg(feature = "gzip")]
            Self::Gzip(d) => d.step(input, output),
            #[cfg(feature = "zstd")]
            Self::Zstd(d) => d.step(input, output),
            #[cfg(feature = "xz")]
            Self::Xz(d) => d.step(input, output),
            #[cfg(feature = "lz4")]
            Self::Lz4(d) => d.step(input, output),
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
        match self {
            #[cfg(feature = "gzip")]
            Self::Gzip(d) => d.finish(output),
            #[cfg(feature = "zstd")]
            Self::Zstd(d) => d.finish(output),
            #[cfg(feature = "xz")]
            Self::Xz(d) => d.finish(output),
            #[cfg(feature = "lz4")]
            Self::Lz4(d) => d.finish(output),
        }
    }
}

/// A compressor for any codec compiled in — the dual of [`AnyDecoder`]. Same sealed-enum,
/// exhaustive-forwarding shape, no type erasure.
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
#[derive(Debug)]
pub enum AnyEncoder {
    /// gzip (hand-written, `no_std`).
    #[cfg(feature = "gzip")]
    Gzip(gzip::GzipEncoder),
    /// Zstandard (`ruzstd` adapter).
    #[cfg(feature = "zstd")]
    Zstd(reused::ZstdEncoder),
    /// XZ (`lzma-rust2` adapter).
    #[cfg(feature = "xz")]
    Xz(reused::XzEncoder),
    /// LZ4 frame (`lz4_flex` adapter).
    #[cfg(feature = "lz4")]
    Lz4(reused::Lz4Encoder),
}

#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
impl Transform for AnyEncoder {
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step> {
        match self {
            #[cfg(feature = "gzip")]
            Self::Gzip(e) => e.step(input, output),
            #[cfg(feature = "zstd")]
            Self::Zstd(e) => e.step(input, output),
            #[cfg(feature = "xz")]
            Self::Xz(e) => e.step(input, output),
            #[cfg(feature = "lz4")]
            Self::Lz4(e) => e.step(input, output),
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
        match self {
            #[cfg(feature = "gzip")]
            Self::Gzip(e) => e.finish(output),
            #[cfg(feature = "zstd")]
            Self::Zstd(e) => e.finish(output),
            #[cfg(feature = "xz")]
            Self::Xz(e) => e.finish(output),
            #[cfg(feature = "lz4")]
            Self::Lz4(e) => e.finish(output),
        }
    }
}

/// Builds the decoder for the given codec (only for features compiled in).
///
/// The single entry point of the filter layer. The format layer obtains an [`AnyDecoder`] and knows
/// neither the kind of compression nor its origin (hand-written/reused) (orthogonal, origin-opaque).
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
#[must_use]
pub fn decoder(id: FilterId) -> Option<AnyDecoder> {
    match id {
        #[cfg(feature = "gzip")]
        FilterId::Gzip => Some(AnyDecoder::Gzip(gzip::GzipDecoder::new())),
        #[cfg(feature = "zstd")]
        FilterId::Zstd => Some(AnyDecoder::Zstd(reused::ZstdDecoder::new())),
        #[cfg(feature = "xz")]
        FilterId::Xz => Some(AnyDecoder::Xz(reused::XzDecoder::new())),
        #[cfg(feature = "lz4")]
        FilterId::Lz4 => Some(AnyDecoder::Lz4(reused::Lz4Decoder::new())),
        _ => None,
    }
}

/// Builds the encoder for the given codec (only for features compiled in). The dual of [`decoder`].
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
#[must_use]
pub fn encoder(id: FilterId) -> Option<AnyEncoder> {
    match id {
        #[cfg(feature = "gzip")]
        FilterId::Gzip => Some(AnyEncoder::Gzip(gzip::GzipEncoder::new())),
        #[cfg(feature = "zstd")]
        FilterId::Zstd => Some(AnyEncoder::Zstd(reused::ZstdEncoder::new())),
        #[cfg(feature = "xz")]
        FilterId::Xz => Some(AnyEncoder::Xz(reused::XzEncoder::new())),
        #[cfg(feature = "lz4")]
        FilterId::Lz4 => Some(AnyEncoder::Lz4(reused::Lz4Encoder::new())),
        _ => None,
    }
}
