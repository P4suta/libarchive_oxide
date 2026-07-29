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
#[cfg(feature = "lz4")]
pub(crate) mod lz4;
#[cfg(feature = "lzip")]
pub(crate) mod lzip;
#[cfg(feature = "xz")]
pub(crate) mod xz;
#[cfg(feature = "zstd")]
pub(crate) mod zstd;

/// IEEE CRC-32 primitives.
pub use gzip::{Crc32, crc32};
