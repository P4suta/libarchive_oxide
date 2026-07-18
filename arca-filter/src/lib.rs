//! `arca-filter` — concrete implementations of compression filters.
//!
//! They all sit isomorphically as [`arca_core::Filter`]. Whether it is a hand-written sans-IO filter (`gzip`, `no_std`)
//! or an adapter (`std`) wrapping `ruzstd`/`lzma_rust2`/`lz4_flex`, the caller's type cannot
//! tell them apart (origin-opaque). The seams are sealed inside the adapters, and the only
//! compromise visible on the surface is that "the zstd/xz/lz4 adapters are a `std` feature".
//!
//! # Implementation status
//!
//! - P2: `gzip` (adapts `miniz_oxide` into a sans-IO `Transform`, `no_std`).
//! - P3: `zstd`/`xz`/`lz4` adapters (`std`).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;

use arca_core::filter::FilterId;
use arca_core::Transform;

#[cfg(feature = "gzip")]
pub mod gzip;

/// Builds the decoder for the given codec (only for features compiled in).
///
/// The single entry point of the filter layer. The format layer merely obtains a
/// `Box<dyn Transform>` from here and knows neither the kind of compression nor its origin
/// (hand-written/reused) (orthogonal, origin-opaque).
#[must_use]
pub fn decoder(id: FilterId) -> Option<Box<dyn Transform>> {
    match id {
        #[cfg(feature = "gzip")]
        FilterId::Gzip => Some(Box::new(gzip::GzipDecoder::new())),
        _ => None,
    }
}
