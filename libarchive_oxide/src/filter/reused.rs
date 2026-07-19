// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adapters for pure-Rust codec crates.
//!
//! zstd and lz4 expose `std::io::Read`. The xz adapter bridges the
//! `lzma-rust2` I/O traits.

use alloc::vec::Vec;
use std::io::{Cursor, Write};

use libarchive_oxide_core::filter::{Decoder, Encoder, Filter, FilterId};
use libarchive_oxide_core::transform::{Step, Transform};
use libarchive_oxide_core::{Error, Result};

use super::bridge::PullBridge;
use super::push::PushBridge;

/// Generates a decoder adapter over a concrete `Read` type.
macro_rules! read_adapter {
    ($(#[$meta:meta])* $name:ident, $id:expr, $doc:literal, $read:ty, $make:expr) => {
        $(#[$meta])*
        #[doc = $doc]
        pub struct $name(PullBridge<$read>);

        $(#[$meta])*
        impl $name {
            /// Creates a fresh decoder.
            #[must_use]
            pub fn new() -> Self {
                Self(PullBridge::new())
            }
        }

        $(#[$meta])*
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        $(#[$meta])*
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        $(#[$meta])*
        impl Transform for $name {
            fn step(&mut self, input: &[u8], _output: &mut [u8]) -> Result<Step> {
                Ok(self.0.push(input))
            }

            fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
                self.0.drain(output, $make)
            }
        }

        $(#[$meta])*
        impl Filter for $name {
            const ID: FilterId = $id;
        }

        $(#[$meta])*
        impl Decoder for $name {}
    };
}

read_adapter!(
    #[cfg(feature = "zstd")]
    ZstdDecoder,
    FilterId::Zstd,
    "Streaming Zstandard decompressor (adapter over `ruzstd`), conformed to the sans-IO `Transform`.",
    ruzstd::decoding::StreamingDecoder<Cursor<Vec<u8>>, ruzstd::decoding::FrameDecoder>,
    |cur: Cursor<Vec<u8>>| {
        ruzstd::decoding::StreamingDecoder::new(cur)
            .map_err(|_| Error::Malformed("zstd: init failed"))
    }
);

read_adapter!(
    #[cfg(feature = "lz4")]
    Lz4Decoder,
    FilterId::Lz4,
    "Streaming LZ4 frame decompressor (adapter over `lz4_flex`), conformed to the sans-IO `Transform`.",
    lz4_flex::frame::FrameDecoder<Cursor<Vec<u8>>>,
    |cur: Cursor<Vec<u8>>| Ok(lz4_flex::frame::FrameDecoder::new(cur))
);

read_adapter!(
    #[cfg(feature = "xz")]
    XzDecoder,
    FilterId::Xz,
    "Streaming XZ (LZMA2) decompressor (adapter over `lzma-rust2`), conformed to the sans-IO `Transform`.",
    lzma_rust2::XzReader<Cursor<Vec<u8>>>,
    // Under the `std` feature, lzma-rust2's `Read` is `std::io::Read`, so the cursor and the
    // resulting reader both speak std `Read` — no shim needed. `true` allows multiple streams.
    |cur: Cursor<Vec<u8>>| Ok(lzma_rust2::XzReader::new(cur, true))
);

/// Generates a compressor adapter that buffers plaintext in a [`PushBridge`] and compresses it
/// with `$compress` on `finish`. `$compress: FnOnce(&[u8]) -> Result<Vec<u8>>`.
macro_rules! write_adapter {
    ($(#[$meta:meta])* $name:ident, $id:expr, $doc:literal, $compress:expr) => {
        $(#[$meta])*
        #[doc = $doc]
        pub struct $name(PushBridge);

        $(#[$meta])*
        impl $name {
            /// Creates a fresh compressor.
            #[must_use]
            pub fn new() -> Self {
                Self(PushBridge::new())
            }
        }

        $(#[$meta])*
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        $(#[$meta])*
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        $(#[$meta])*
        impl Transform for $name {
            fn step(&mut self, input: &[u8], _output: &mut [u8]) -> Result<Step> {
                Ok(self.0.push(input))
            }

            fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
                self.0.drain(output, $compress)
            }
        }

        $(#[$meta])*
        impl Filter for $name {
            const ID: FilterId = $id;
        }

        $(#[$meta])*
        impl Encoder for $name {}
    };
}

write_adapter!(
    #[cfg(feature = "zstd")]
    ZstdEncoder,
    FilterId::Zstd,
    "Zstandard compressor using `ruzstd`.",
    |plain: &[u8]| {
        use ruzstd::encoding::{compress_to_vec, CompressionLevel};
        Ok(compress_to_vec(plain, CompressionLevel::Fastest))
    }
);

write_adapter!(
    #[cfg(feature = "lz4")]
    Lz4Encoder,
    FilterId::Lz4,
    "LZ4 frame compressor using `lz4_flex`.",
    |plain: &[u8]| {
        let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
        enc.write_all(plain)
            .map_err(|_| Error::Malformed("lz4: encode failed"))?;
        enc.finish()
            .map_err(|_| Error::Malformed("lz4: finish failed"))
    }
);

write_adapter!(
    #[cfg(feature = "xz")]
    XzEncoder,
    FilterId::Xz,
    "XZ (LZMA2) compressor using `lzma-rust2`.",
    |plain: &[u8]| {
        let mut w = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
            .map_err(|_| Error::Malformed("xz: init failed"))?;
        w.write_all(plain)
            .map_err(|_| Error::Malformed("xz: encode failed"))?;
        w.finish()
            .map_err(|_| Error::Malformed("xz: finish failed"))
    }
);
