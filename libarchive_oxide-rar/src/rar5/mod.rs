// SPDX-FileCopyrightText: 2026 Karpeles Lab Inc.
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT

//! Locally owned RAR5 payload decoder internals.

mod bits;
mod decoder;
mod filters;
mod huffman;

pub(crate) use decoder::Decoder;
