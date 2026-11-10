// SPDX-FileCopyrightText: 2026 Karpeles Lab Inc.
//
// SPDX-License-Identifier: MIT

//! RAR 3.x lookup tables.
//!
//! These match the canonical RAR3 spec as documented in the unarr README and libarchive's `archive_read_support_format_rar.c` (BSD-licensed —
//! values cross-checked but no code copied).

/// Number of symbols in the main Huffman code.
///
/// Symbols 0..=255 are literal bytes.
/// 256 is the "new table / end of block" marker.
/// 257..=261 are filter / repeat-offset markers.
/// 262..=270 use one of eight short distance buckets.
/// 271..=298 are full match-length codes.
pub(super) const MAIN_SIZE: usize = 299;

/// Number of symbols in the offset Huffman code.
pub(super) const OFFSET_SIZE: usize = 60;

/// Number of symbols in the low-offset Huffman code (4-bit refinement of large offsets, plus a "repeat" sentinel at index 16).
pub(super) const LOW_OFFSET_SIZE: usize = 17;

/// Number of symbols in the length Huffman code (used by symbols 259..=262 of the main code, where the match length is read from this separate tree).
pub(super) const LENGTH_SIZE: usize = 28;

/// Combined size used by the precode-decoded length table.
pub(super) const HUFF_TABLE_SIZE: usize = MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE + LENGTH_SIZE;

/// Precode alphabet size (20 symbols).
pub(super) const PRECODE_SIZE: usize = 20;

/// Base value added to symbol-derived match length when no extra-bits read is needed for the length code.
/// Cross-checked against the canonical `lengthbases` array.
pub(super) const LENGTH_BASE: [u16; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];

/// Number of extra bits to read for each length-code symbol.
pub(super) const LENGTH_EXTRA_BITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// Base value for offset codes.
/// 60 entries reaching just under 4 MiB (the RAR3 dictionary maxes out at 4 MiB / 22 bits).
pub(super) const OFFSET_BASE: [u32; 60] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131_072,
    196_608, 262_144, 327_680, 393_216, 458_752, 524_288, 589_824, 655_360, 720_896, 786_432,
    851_968, 917_504, 983_040, 1_048_576, 1_310_720, 1_572_864, 1_835_008, 2_097_152, 2_359_296,
    2_621_440, 2_883_584, 3_145_728, 3_407_872, 3_670_016, 3_932_160,
];

/// Extra-bits count for each offset code.
/// The trailing 18-bit entries are used in cooperation with the `LOW_OFFSET` tree (which contributes 4 low bits, leaving offsetbits[i]-4 high bits read raw).
pub(super) const OFFSET_EXTRA_BITS: [u8; 60] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];

/// Short-offset base for main-code symbols 263..=270.
pub(super) const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];

/// Short-offset extra bits for main-code symbols 263..=270.
pub(super) const SHORT_EXTRA_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Maximum dictionary size supported by RAR3 (4 MiB).
pub(super) const DICT_MAX_SIZE: usize = 4 * 1024 * 1024;

/// Default dictionary size when the caller doesn't specify one — RAR3 most commonly uses 4 MiB.
pub(super) const DICT_DEFAULT_SIZE: usize = DICT_MAX_SIZE;
