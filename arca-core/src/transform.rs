//! 基層: sans-IO バイト変換 [`Transform`]。
//!
//! これがすべての土台。圧縮フィルタも（将来的には）フォーマットのシリアライズも、
//! この 1 つの割当なし・caller-owned なプリミティブの上に乗る。
//!
//! # なぜ push/pull ではなく step か
//!
//! 当初のスケッチは `push`/`pull` の 2 メソッドだったが、それは変換器に内部出力バッファの
//! 保持（＝割当）を強制する。より美しい（＝割当なし・完全 caller-driven な）プリミティブは
//! zlib 系の「1 ステップ = 入力スライスを消費し出力スライスへ生成」である。
//! push（バイトが届く源）と pull（`Read` 的な消費）は、この `step` の上に構築する **アダプタ**
//! として std 側で導出する。したがって基層は最小・純粋・割当なしに保たれる。

use crate::Result;

/// 1 ステップの結果。消費した入力量・生成した出力量・次に何をすべきか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// `input` から消費したバイト数。
    pub consumed: usize,
    /// `output` へ生成したバイト数。
    pub produced: usize,
    /// この変換器が次に必要とするもの。
    pub status: Status,
}

impl Step {
    /// 進捗なし（消費 0・生成 0）で、更なる入力を要求する状態。
    pub const STALLED: Self = Self {
        consumed: 0,
        produced: 0,
        status: Status::NeedInput,
    };
}

/// [`Transform::step`] 後に呼び出し側が取るべき行動。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// 更なる入力バイトを与えれば前進できる。
    NeedInput,
    /// 入力はまだ残っているが出力が満杯。より大きな（または空にした）出力で再度呼ぶ。
    MoreOutput,
    /// 論理ストリーム終端に到達した。以降 `step` は生成 0 を返す。
    Done,
}

/// sans-IO なバイト→バイト変換器。
///
/// # 契約
///
/// - `step` は `input` から任意量を消費し `output` へ任意量を生成し、[`Step`] を返す。
/// - 割当は強制されない。すべてのバッファは呼び出し側が所有する。
/// - 入力が尽きたら `finish` を呼び、内部に滞留した末尾出力を排出させる。
/// - 実装は `no_std`（自作フィルタ）でも `std`（再利用クレートのアダプタ）でもよい。
///   その差は呼び出し側の型に漏れない（出自不可視）。
pub trait Transform {
    /// `input` を消費し `output` へ生成する 1 ステップを進める。
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step>;

    /// 入力終端を通知し、滞留出力を `output` へ排出する。
    ///
    /// [`Status::Done`] を返すまで、より大きな `output` で繰り返し呼んでよい。
    fn finish(&mut self, output: &mut [u8]) -> Result<Step>;
}
