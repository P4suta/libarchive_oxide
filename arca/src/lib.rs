//! `arca` — 統一 streaming アーカイブライブラリの std 高レベル API。
//!
//! [`arca_core`] の凍結されたトレイト代数の上に、実用的な std 層を載せる:
//! 圧縮/フォーマットの自動検出、`std::io::Read`/`Write` への sans-IO アダプタ、
//! ファイルシステム展開、安全なパス無害化（`../` 遮断）、割当上限（解凍爆弾対策）。
//!
//! # 実装状況
//!
//! P0 では再エクスポートのみ。sans-IO ↔ `std::io` アダプタは P1 以降。

#![forbid(unsafe_code)]

pub use arca_core;
pub use arca_filter;
