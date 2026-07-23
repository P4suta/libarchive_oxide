// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression filter implementations and runtime dispatch.

#[cfg(all(feature = "sevenz", feature = "aes"))]
pub(crate) mod aes7z;
#[cfg(feature = "sevenz")]
pub(crate) mod bcj;
#[cfg(feature = "sevenz")]
pub(crate) mod delta;
pub mod gzip;
#[cfg(all(feature = "lz4", not(feature = "native-codecs")))]
pub(crate) mod lz4;
#[cfg(all(feature = "xz", not(feature = "native-codecs")))]
pub(crate) mod xz;
#[cfg(all(feature = "zstd", not(feature = "native-codecs")))]
pub(crate) mod zstd;

/// IEEE CRC-32 primitives.
pub use gzip::{Crc32, crc32};
