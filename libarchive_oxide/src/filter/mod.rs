// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compression filter implementations and runtime dispatch.

pub mod gzip;

/// IEEE CRC-32 primitives.
pub use gzip::{Crc32, crc32};
