//! Filter 軸: 圧縮コーデックを表す [`Transform`] の細分。
//!
//! filter 軸は format 軸と **直交** する。format 層は `Box<dyn Decoder>` の連鎖から
//! バイトを読むだけで、圧縮の有無・種類を一切知らない。
//!
//! # 双対性（decode ⇄ encode）
//!
//! [`Decoder`] と [`Encoder`] は型レベルの双対である。任意のコーデックについて、
//! `Encoder` を通してから `Decoder` を通すと恒等（`Decoder ∘ Encoder = id`）になる。
//! この不変条件は、エンコーダ実装後に property テストで機械的に守る。
//!
//! # 出自不可視
//!
//! 自作 `Inflate`（sans-IO, `no_std`）も、`ruzstd`/`lzma-rs`/`lz4_flex` を包んだアダプタも、
//! すべて同一の [`Filter`] として同形に乗る。継ぎ目はアダプタ内部に封じられ、
//! 表に出る唯一の妥協は「zstd/xz アダプタが `std` feature である」点のみ。

use crate::transform::Transform;

/// 圧縮フィルタの識別子。検出・診断・自動レイヤリングに使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FilterId {
    /// DEFLATE + gzip フレーミング（自作 inflate、`no_std`）。
    Gzip,
    /// Zstandard（`ruzstd` アダプタ、std）。
    Zstd,
    /// XZ / LZMA2（`lzma-rs` アダプタ、std、subset）。
    Xz,
    /// LZ4 フレーム（`lz4_flex` アダプタ、std）。
    Lz4,
    /// bzip2（`bzip2-rs` アダプタ、std）。
    Bzip2,
}

impl FilterId {
    /// バイト列先頭のマジックからフィルタを推定する（自動検出用）。
    ///
    /// 判定に十分なプレフィックスが無い場合や該当なしの場合は `None`。
    #[must_use]
    pub fn sniff(prefix: &[u8]) -> Option<Self> {
        match prefix {
            [0x1f, 0x8b, ..] => Some(Self::Gzip),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Self::Zstd),
            [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Some(Self::Xz),
            [0x04, 0x22, 0x4d, 0x18, ..] => Some(Self::Lz4),
            [b'B', b'Z', b'h', ..] => Some(Self::Bzip2),
            _ => None,
        }
    }
}

/// 圧縮フィルタであることを表すマーカ。[`Decoder`]/[`Encoder`] の共通上位。
pub trait Filter: Transform {
    /// このフィルタが属するコーデック。
    const ID: FilterId;
}

/// 展開器: 圧縮バイト列 → 平文バイト列。[`Encoder`] の双対。
pub trait Decoder: Filter {}

/// 圧縮器: 平文バイト列 → 圧縮バイト列。[`Decoder`] の双対。
pub trait Encoder: Filter {}
