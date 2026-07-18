//! Adapters over reused pure-Rust decoder crates, all conformed to the sans-IO `Transform`
//! via the shared [`PullBridge`](crate::bridge::PullBridge).
//!
//! Every reused decoder is the *same* adapter modulo two things: its [`FilterId`] and the
//! constructor that turns the buffered input into a `Read` decoder. The `read_adapter!` macro
//! makes that uniformity explicit — the origin (hand-written vs reused) never leaks into the
//! caller's types.
//!
//! `zstd` (`ruzstd`) and `lz4` (`lz4_flex`) expose `std::io::Read` directly. `xz` (`lzma-rust2`) uses
//! its own `Read` trait, so two thin shims (`xz_shim`) bridge std `Read` in and lzma `Read` out;
//! that seam stays sealed inside this module.

use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{Cursor, Read};

use arca_core::filter::{Decoder, Filter, FilterId};
use arca_core::transform::{Step, Transform};
use arca_core::{Error, Result};

use crate::bridge::PullBridge;

/// Generates a decoder adapter that stores a [`PullBridge`] and constructs its `Read` decoder
/// with `$make` on `finish`. `$make: FnOnce(Cursor<Vec<u8>>) -> Result<Box<dyn Read>>`.
macro_rules! read_adapter {
    ($(#[$meta:meta])* $name:ident, $id:expr, $make:expr) => {
        $(#[$meta])*
        pub struct $name(PullBridge<Box<dyn Read>>);

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
    |cur: Cursor<Vec<u8>>| {
        ruzstd::decoding::StreamingDecoder::new(cur)
            .map(|d| Box::new(d) as Box<dyn Read>)
            .map_err(|_| Error::Malformed("zstd: init failed"))
    }
);

read_adapter!(
    #[cfg(feature = "lz4")]
    Lz4Decoder,
    FilterId::Lz4,
    |cur: Cursor<Vec<u8>>| Ok(Box::new(lz4_flex::frame::FrameDecoder::new(cur)) as Box<dyn Read>)
);

read_adapter!(
    #[cfg(feature = "xz")]
    XzDecoder,
    FilterId::Xz,
    // Under the `std` feature, lzma-rust2's `Read` is `std::io::Read`, so the cursor and the
    // resulting reader both speak std `Read` — no shim needed. `true` allows multiple streams.
    |cur: Cursor<Vec<u8>>| Ok(Box::new(lzma_rust2::XzReader::new(cur, true)) as Box<dyn Read>)
);
