// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive detection, compression, extraction, and creation.
//!
//! This crate adds codecs, zip/7z, filesystem operations, path sanitization, and
//! output limits to [`libarchive_oxide_core`].

#![forbid(unsafe_code)]

// Filter modules use `alloc` paths and also compile under std.
extern crate alloc;

use std::borrow::Cow;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{decode_to_vec, decode_to_vec_capped, Error, Result};

pub mod create;
pub mod extract;
pub mod filter;
pub mod path;
#[cfg(feature = "sevenz")]
pub mod sevenz;
pub mod zip;

pub use create::{build_archive, build_archive_with, build_cpio, build_tar, CreateOptions};
pub use extract::{reader, reader_with_password, Stats};
pub use libarchive_oxide_core;
pub use path::sanitize;
pub use zip::{SaltSource, ZipMethod, ZipOptions};

/// Detects compression and returns decompressed bytes.
///
/// Returns borrowed input when no compression is detected. Returns
/// [`Error::Unsupported`] when the required filter feature is disabled. This
/// function has no output limit; use [`decompress_capped`] for untrusted input.
pub fn decompress(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    decompress_capped(bytes, usize::MAX)
}

/// Detects compression and enforces `max_output`.
///
/// Returns [`Error::LimitExceeded`] when output exceeds the limit.
pub fn decompress_capped(bytes: &[u8], max_output: usize) -> Result<Cow<'_, [u8]>> {
    match FilterId::sniff(bytes) {
        Some(id) => {
            let mut decoder =
                crate::filter::decoder(id).ok_or(Error::Unsupported("filter not built in"))?;
            let plain = decode_to_vec_capped(&mut decoder, bytes, max_output)?;
            Ok(Cow::Owned(plain))
        },
        None => Ok(Cow::Borrowed(bytes)),
    }
}

/// Compresses `plain` with `id`.
pub fn compress(plain: &[u8], id: FilterId) -> Result<Vec<u8>> {
    let mut encoder =
        crate::filter::encoder(id).ok_or(Error::Unsupported("filter not built in"))?;
    decode_to_vec(&mut encoder, plain)
}

/// Returns the compression codec implied by a filename.
#[must_use]
pub fn filter_for_name(name: &str) -> Option<FilterId> {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("gz" | "tgz") => Some(FilterId::Gzip),
        Some("zst") => Some(FilterId::Zstd),
        Some("xz") => Some(FilterId::Xz),
        Some("lz4") => Some(FilterId::Lz4),
        _ => None,
    }
}
