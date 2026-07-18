//! `arca-filter` — 圧縮フィルタの具体実装。
//!
//! すべて [`arca_core::Filter`] として同形に乗る。自作 inflate（`no_std`）も、
//! `ruzstd`/`lzma-rs`/`lz4_flex` を包んだアダプタ（`std`）も、呼び出し側の型からは
//! 区別できない（出自不可視）。継ぎ目はアダプタ内部に封じ、表に出る唯一の妥協は
//! 「zstd/xz/lz4 アダプタが `std` feature である」点のみ。
//!
//! # 実装状況
//!
//! - P2: `gzip`（自作 inflate, `no_std`）。
//! - P3: `zstd`/`xz`/`lz4` アダプタ（`std`）。

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

// P2 以降で自作 inflate を実装する足場。
