//! `arca` — the std high-level API of the unified streaming archive library.
//!
//! On top of [`arca_core`]'s frozen trait algebra, this layers a practical std layer:
//! automatic compression/format detection, filesystem extraction, safe path sanitization, allocation caps.
//!
//! # Implementation status
//!
//! - P2: automatic compression detection + gzip decompression ([`decompress`]).
//! - P5: FS extraction, path sanitization, CLI.

#![forbid(unsafe_code)]

use std::borrow::Cow;

use arca_core::filter::FilterId;
use arca_core::{decode_to_vec, Error, Result};

pub use arca_core;
pub use arca_filter;

/// Auto-detects compression from the leading magic bytes and returns the decompressed archive byte stream.
///
/// If no compression is detected, the input is borrowed and returned as-is (plain tar, etc., with no copy).
/// If the detected filter is not built in (feature off), returns [`Error::Unsupported`].
///
/// The returned byte stream can be passed directly to an [`arca_core::EntryReader`] such as `TarReader`.
pub fn decompress(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    match FilterId::sniff(bytes) {
        Some(id) => {
            let mut decoder =
                arca_filter::decoder(id).ok_or(Error::Unsupported("filter not built in"))?;
            let plain = decode_to_vec(decoder.as_mut(), bytes)?;
            Ok(Cow::Owned(plain))
        }
        None => Ok(Cow::Borrowed(bytes)),
    }
}
