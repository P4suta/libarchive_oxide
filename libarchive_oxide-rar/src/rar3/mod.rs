// SPDX-FileCopyrightText: 2026 Karpeles Lab Inc.
//
// SPDX-License-Identifier: MIT

//! RAR 3.x LZ77 and Huffman payload decoding.
//!
//! This module is format-specific and deliberately private to the RAR codec crate.
//! RAR writing is not provided.
//! Standard in-band `RarVM` programs are delegated to the bounded `libarchive_oxide-rarvm` crate.

mod bits;
mod decoder;
mod huffman;
mod tables;

pub(crate) use decoder::Decoder;
