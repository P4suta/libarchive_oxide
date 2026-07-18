//! `arca` — the std high-level API of the unified streaming archive library.
//!
//! On top of [`arca_core`]'s frozen trait algebra, this layers a practical std layer:
//! automatic compression/format detection, filesystem extraction, safe path sanitization, allocation caps.
//!
//! # Implementation status
//!
//! - P2: automatic compression detection + gzip decompression ([`decompress`]).
//! - P3: zstd/xz/lz4 decompression via the same entry point.
//! - P4: tar/cpio/ar readers (in `arca_core`), composed for `.deb`.
//! - P5: format detection ([`reader`]), safe FS extraction ([`extract`]), path sanitization, CLI.

#![forbid(unsafe_code)]

use std::borrow::Cow;

use arca_core::filter::FilterId;
use arca_core::{decode_to_vec_capped, Error, Result};

pub mod create;
pub mod extract;
pub mod path;

pub use arca_core;
pub use arca_filter;
pub use create::build_tar;
pub use extract::{reader, Stats};
pub use path::sanitize;

/// Auto-detects compression from the leading magic bytes and returns the decompressed archive byte stream.
///
/// If no compression is detected, the input is borrowed and returned as-is (plain tar, etc., with no copy).
/// If the detected filter is not built in (feature off), returns [`Error::Unsupported`].
///
/// The returned byte stream can be passed directly to an [`arca_core::EntryReader`] such as `TarReader`.
///
/// This form is uncapped. Prefer [`decompress_capped`] when handling untrusted input.
pub fn decompress(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    decompress_capped(bytes, usize::MAX)
}

/// Like [`decompress`], but fails with [`Error::LimitExceeded`] if the decompressed size would
/// exceed `max_output` bytes. Use this on untrusted archives to defend against decompression bombs.
pub fn decompress_capped(bytes: &[u8], max_output: usize) -> Result<Cow<'_, [u8]>> {
    match FilterId::sniff(bytes) {
        Some(id) => {
            let mut decoder =
                arca_filter::decoder(id).ok_or(Error::Unsupported("filter not built in"))?;
            let plain = decode_to_vec_capped(decoder.as_mut(), bytes, max_output)?;
            Ok(Cow::Owned(plain))
        }
        None => Ok(Cow::Borrowed(bytes)),
    }
}
