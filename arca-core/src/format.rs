//! Format 軸: フィルタ後のバイト列 ⇄ 構造化エントリ。
//!
//! format 層は filter 層と **直交** し、圧縮を一切知らない。読み書きの多相は
//! [`EntryReader`]/[`EntryWriter`] トレイトオブジェクトで表現され、これらは
//! 圏論的な双対をなす。
//!
//! # 借用検査された no-seek モデル
//!
//! [`EntryReader::next_entry`] は `&mut self` を借用する [`Entry`] を返す。したがって
//! **エントリのデータを読み切って `Entry` を落とすまで、次のエントリへ進めない** ことが
//! コンパイル時に保証される。C の `void*` + 手続き規約に対する型レベルの勝ち。seek 不要。

use crate::meta::EntryMeta;
use crate::Result;
use core::fmt;

pub mod cpio;
pub mod tar;

/// アーカイブフォーマットの検出結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// このフォーマットだと確信できる。
    Match,
    /// このフォーマットではない。
    NoMatch,
    /// 判定に更なるプレフィックスが必要。
    NeedMore,
}

/// アーカイブフォーマットの検出アンカー（レジストリ／自動判定の起点）。
///
/// 具体的な読み書きは [`EntryReader`]/[`EntryWriter`] を実装する型が担う。この分離により、
/// 新フォーマット追加は「同じトレイトを実装する型を足す」だけになり、既存トレイトは不変。
pub trait ArchiveFormat {
    /// 人間可読なフォーマット名（診断用）。
    const NAME: &'static str;

    /// バイト列先頭からこのフォーマットかを判定する。
    fn sniff(prefix: &[u8]) -> Detection;
}

/// エントリ本体（ペイロード）の sans-IO 読み出し。
///
/// `no_std` のため `std::io::Read` ではなくチャンク pull を採る。std 側で `Read` へ橋渡しする。
pub trait EntryData {
    /// デコード済みエントリバイトを `out` へ取り出す。返り値は生成量。0 はエントリ終端。
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize>;
}

/// アーカイブから 1 エントリを取り出すストリーミング reader。
pub trait EntryReader {
    /// 次のエントリを返す。末尾に達したら `None`。
    ///
    /// 返る [`Entry`] は `self` を可変借用するため、そのデータを読み切るまで次へ進めない。
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>>;
}

/// reader が貸し出す 1 エントリ。メタデータとペイロードストリームを保持する。
///
/// ライフタイム `'r` が親 reader を可変借用しており、no-seek 不変条件を型で担保する。
pub struct Entry<'r> {
    meta: EntryMeta<'r>,
    data: &'r mut dyn EntryData,
}

impl fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ペイロードストリームは不透明なので meta のみ表示する。
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl<'r> Entry<'r> {
    /// メタデータとペイロードストリームからエントリを組み立てる（フォーマット実装が使う）。
    pub fn new(meta: EntryMeta<'r>, data: &'r mut dyn EntryData) -> Self {
        Self { meta, data }
    }

    /// エントリのメタデータ。
    #[must_use]
    pub fn meta(&self) -> &EntryMeta<'r> {
        &self.meta
    }

    /// エントリ本体の sans-IO ストリーム。
    pub fn data(&mut self) -> &mut dyn EntryData {
        self.data
    }
}

/// エントリ本体（ペイロード）の sans-IO 書き込み。[`EntryData`] の双対。
pub trait EntryDataSink {
    /// エントリバイトを書き込む。
    fn write_chunk(&mut self, data: &[u8]) -> Result<()>;

    /// このエントリの書き込みを確定する。
    fn close(&mut self) -> Result<()>;
}

/// アーカイブへ 1 エントリを書き出すストリーミング writer。[`EntryReader`] の双対。
pub trait EntryWriter {
    /// メタデータを与えてエントリの書き込みを開始し、本体シンクを貸し出す。
    ///
    /// 返る [`EntrySink`] は `self` を可変借用するため、確定するまで次エントリを開始できない。
    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_>>;

    /// アーカイブ全体を確定する（末尾ブロック等を書く）。
    fn finish(&mut self) -> Result<()>;
}

/// writer が貸し出す 1 エントリの本体シンク。[`Entry`] の双対。
pub struct EntrySink<'w> {
    inner: &'w mut dyn EntryDataSink,
}

impl fmt::Debug for EntrySink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySink").finish_non_exhaustive()
    }
}

impl<'w> EntrySink<'w> {
    /// 本体シンクからエントリシンクを組み立てる（フォーマット実装が使う）。
    pub fn new(inner: &'w mut dyn EntryDataSink) -> Self {
        Self { inner }
    }

    /// 本体バイトを書き込む。
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_chunk(data)
    }

    /// このエントリを確定する。
    pub fn close(&mut self) -> Result<()> {
        self.inner.close()
    }
}
