// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression filter implementations and runtime dispatch.

pub mod gzip;
#[cfg(feature = "lz4")]
pub(crate) mod lz4;
#[cfg(feature = "zstd")]
pub(crate) mod zstd;

/// IEEE CRC-32 primitives.
pub use gzip::{Crc32, crc32};
