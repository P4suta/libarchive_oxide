// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression filter implementations and runtime dispatch.

#[cfg(feature = "gzip")]
use alloc::vec::Vec;

// Dispatch is omitted when no codec feature is enabled.
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::filter::FilterId;
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::transform::{Step, Transform};
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::Result;

/// Decompresses raw DEFLATE with an output limit.
#[cfg(feature = "gzip")]
pub fn inflate(compressed: &[u8], max_size: usize) -> libarchive_oxide_core::Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(compressed, max_size)
        .map_err(|_| libarchive_oxide_core::Error::Malformed("deflate: decode failed"))
}

/// Compresses raw DEFLATE at level 6.
#[cfg(feature = "gzip")]
#[must_use]
pub fn deflate(plain: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(plain, 6)
}

#[cfg(feature = "gzip")]
pub mod gzip;

/// IEEE CRC-32 primitives.
#[cfg(feature = "gzip")]
pub use gzip::{crc32, Crc32};

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
mod bridge;
#[cfg(any(feature = "gzip", feature = "zstd", feature = "xz", feature = "lz4"))]
mod push;
#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
pub mod reused;

/// Decoder selected from enabled codec features.
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

/// Encoder selected from enabled codec features.
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

/// Returns a decoder when the codec feature is enabled.
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

/// Returns an encoder when the codec feature is enabled.
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
