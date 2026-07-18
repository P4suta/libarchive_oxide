//! `no_std` フレンドリなエラー型。`std::io::Error` に依存しない。

use core::fmt;

/// クレート全体の結果型。
pub type Result<T> = core::result::Result<T, Error>;

/// `arca` のエラー。sans-IO 層で発生しうる意味論的失敗を型で表す。
///
/// I/O 由来の失敗は基層では表現しない（sans-IO のためバイトは呼び出し側が運ぶ）。
/// std 側のアダプタが `std::io::Error` との相互変換を担う。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 入力バイト列がフォーマット仕様に反する（壊れたヘッダ、不正なマジック等）。
    Malformed(&'static str),
    /// 仕様上は妥当だが、この実装がまだ扱わない機能。
    Unsupported(&'static str),
    /// ヘッダ宣言サイズ等が設定した安全上限を超えた（解凍爆弾・巨大長対策）。
    LimitExceeded(&'static str),
    /// 呼び出し側の出力バッファが 1 要素も進められないほど小さい。
    OutputTooSmall,
    /// エントリのデータを読み切る前に次の操作へ進もうとした等、プロトコル違反。
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed archive: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported feature: {m}"),
            Self::LimitExceeded(m) => write!(f, "safety limit exceeded: {m}"),
            Self::OutputTooSmall => f.write_str("output buffer too small to make progress"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
        }
    }
}

impl core::error::Error for Error {}
