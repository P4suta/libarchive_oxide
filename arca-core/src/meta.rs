//! エントリのメタデータ。read/write 双対をデータ層で担保する共有型。
//!
//! 同一の [`EntryMeta`] を、[`EntryReader`](crate::EntryReader) は **産出** し、
//! [`EntryWriter`](crate::EntryWriter) は **消費** する。これにより read/write 対称は
//! トレイトだけでなくデータの形でも保証される。
//!
//! `no_std` を保つため、パスは `std::path` ではなく生バイト列で持つ（アーカイブ内の
//! 名前はそもそも OS ネイティブなエンコーディングとは限らない）。可能な限り入力バッファから
//! 借用し（[`Cow`]）、エントリごとの割当を避ける（ゼロコピー）。

use alloc::borrow::Cow;
use alloc::vec::Vec;

/// エントリ種別。C の `mode & S_IFMT` を型付き列挙に置き換える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// 通常ファイル。
    File,
    /// ディレクトリ。
    Dir,
    /// シンボリックリンク（`link_target` を持つ）。
    Symlink,
    /// ハードリンク（`link_target` が対象を指す）。
    Hardlink,
    /// キャラクタデバイス。
    Char,
    /// ブロックデバイス。
    Block,
    /// 名前付きパイプ（FIFO）。
    Fifo,
    /// UNIX ドメインソケット。
    Socket,
}

/// 秒とナノ秒によるタイムスタンプ。`no_std` のため `SystemTime` は使わない。
///
/// エポックからのオフセット。負値（1970 以前）を許すため `i64`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// UNIX エポックからの秒。
    pub secs: i64,
    /// 秒内のナノ秒（`0..1_000_000_000`）。
    pub nanos: u32,
}

/// PAX の 1 レコード（キー・値）。いずれも可能なら入力から借用する。
type PaxRecord<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

/// PAX 拡張ヘッダ等の追加キーバリュー。可能な限り入力から借用する。
///
/// P0 では素朴な連想リスト。走査順を保ちつつ小規模を前提とする。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaxMap<'a> {
    entries: Vec<PaxRecord<'a>>,
}

impl<'a> PaxMap<'a> {
    /// 空のマップ。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// キーに対応する値を線形探索で返す。
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| v.as_ref())
    }

    /// キーバリューを追加する。
    pub fn insert(&mut self, key: Cow<'a, [u8]>, value: Cow<'a, [u8]>) {
        self.entries.push((key, value));
    }

    /// 保持している組の数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空か。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// エントリのメタデータ。reader が産出し writer が消費する双対の中核。
///
/// ライフタイム `'a` は入力バッファ（read 時）または呼び出し側の借用（write 時）を指し、
/// ゼロコピーを型で表現する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta<'a> {
    /// エントリ種別。
    pub kind: EntryKind,
    /// アーカイブ内パス（生バイト、可能なら借用）。
    pub path: Cow<'a, [u8]>,
    /// UNIX パーミッションビット（`mode & 0o7777`）。
    pub mode: u32,
    /// 所有ユーザ ID。
    pub uid: u64,
    /// 所有グループ ID。
    pub gid: u64,
    /// 更新時刻。フォーマットに無ければ `None`。
    pub mtime: Option<Timestamp>,
    /// ファイル内容のバイト長（非ファイルでは 0）。
    pub size: u64,
    /// シンボリック/ハードリンクの対象。それ以外は `None`。
    pub link_target: Option<Cow<'a, [u8]>>,
    /// PAX 等の拡張属性。
    pub pax: PaxMap<'a>,
}

impl<'a> EntryMeta<'a> {
    /// 指定種別・パスの最小メタデータ（他は既定値）を作る。
    #[must_use]
    pub fn new(kind: EntryKind, path: Cow<'a, [u8]>) -> Self {
        Self {
            kind,
            path,
            mode: 0,
            uid: 0,
            gid: 0,
            mtime: None,
            size: 0,
            link_target: None,
            pax: PaxMap::new(),
        }
    }
}
