//! tar フォーマット（ustar / pax / GNU）。
//!
//! **P1**: スライスベースの読み取りを実装。P0 で凍結した借用検査 `Entry` モデル
//! （`Entry<'r>` が reader を可変借用し、ペイロードを読み切るまで次へ進めない）と、
//! `EntryData`（ペイロードの sans-IO pull）をここで確立する。
//!
//! 対応: ustar（`prefix`+`name` 結合）、8進 / base-256 数値、チェックサム検証、
//! PAX 拡張（`x` 次エントリ用 / `g` グローバル）、GNU longname/longlink（`L`/`K`）、
//! アーカイブ終端（ゼロブロック）。GNU sparse（`S`）は現状 `Unsupported`（P1 の範囲外）。
//!
//! P1 の source モデルは **メモリ内スライス**（`&[u8]`）。std 層はファイルを mmap して
//! `&[u8]` を渡すのが一般的経路であり、これで実用の大半を覆う。逐次フィード型の
//! 完全 sans-IO source は後日の精緻化とする（凍結済みトレイトは変更しない）。

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{
    ArchiveFormat, Detection, Entry, EntryData, EntryReader, EntrySink, EntryWriter,
};
use crate::meta::{EntryKind, EntryMeta, Timestamp};

/// tar のブロックサイズ。全ヘッダ・全ペイロードはこの倍数境界に整列する。
const BLOCK: usize = 512;

// ── ustar ヘッダのフィールド範囲（512B ブロック内オフセット）。
const F_NAME: (usize, usize) = (0, 100);
const F_MODE: (usize, usize) = (100, 108);
const F_UID: (usize, usize) = (108, 116);
const F_GID: (usize, usize) = (116, 124);
const F_SIZE: (usize, usize) = (124, 136);
const F_MTIME: (usize, usize) = (136, 148);
const F_CHKSUM: (usize, usize) = (148, 156);
const O_TYPEFLAG: usize = 156;
const F_LINKNAME: (usize, usize) = (157, 257);
const F_MAGIC: (usize, usize) = (257, 263);
const F_PREFIX: (usize, usize) = (345, 500);

/// tar フォーマットの検出アンカー（零サイズ型）。
#[derive(Debug, Clone, Copy, Default)]
pub struct Tar;

impl ArchiveFormat for Tar {
    const NAME: &'static str = "tar";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < F_MAGIC.1 {
            // v7 tar はマジックを持たないため、ここでは ustar/pax/GNU のみ確信できる。
            return Detection::NeedMore;
        }
        if prefix[F_MAGIC.0..F_MAGIC.0 + 5] == *b"ustar" {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// 上位ヘッダ（PAX / GNU longname）が次エントリまたは全エントリへ課す上書き。
#[derive(Debug, Default, Clone)]
struct Overrides<'a> {
    path: Option<Cow<'a, [u8]>>,
    linkpath: Option<Cow<'a, [u8]>>,
    size: Option<u64>,
    mtime: Option<Timestamp>,
    uid: Option<u64>,
    gid: Option<u64>,
}

/// エントリ本体を指すカーソル。`bytes` は元スライス（`&'a [u8]` は Copy なので共有可）。
#[derive(Debug, Default)]
struct TarPayload<'a> {
    bytes: &'a [u8],
    start: usize,
    len: usize,
    read: usize,
}

impl EntryData for TarPayload<'_> {
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        let remaining = self.len - self.read;
        if remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let n = remaining.min(out.len());
        let from = self.start + self.read;
        out[..n].copy_from_slice(&self.bytes[from..from + n]);
        self.read += n;
        Ok(n)
    }
}

/// tar のストリーミング reader（メモリ内スライス上）。
#[derive(Debug)]
pub struct TarReader<'a> {
    data: &'a [u8],
    pos: usize,
    payload: TarPayload<'a>,
    pending: Overrides<'a>,
    global: Overrides<'a>,
    ended: bool,
}

impl<'a> TarReader<'a> {
    /// フィルタ適用後のアーカイブバイト列全体から reader を作る。
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            payload: TarPayload::default(),
            pending: Overrides::default(),
            global: Overrides::default(),
            ended: false,
        }
    }

    /// `start` から `len` バイトのペイロード/レコードを境界検査つきで切り出す。
    fn slice(data: &'a [u8], start: usize, len: usize) -> Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or(Error::Malformed("offset overflow"))?;
        data.get(start..end)
            .ok_or(Error::Malformed("truncated data"))
    }

    /// 与えられたヘッダから実エントリのメタデータを組み立てる。`pending` は消費する。
    fn build_meta(&mut self, hdr: &'a [u8], typeflag: u8) -> Result<EntryMeta<'a>> {
        let kind = kind_from_typeflag(typeflag)?;

        let name = cstr(field(hdr, F_NAME));
        let prefix = cstr(field(hdr, F_PREFIX));
        let is_ustar = field(hdr, F_MAGIC).starts_with(b"ustar");

        let path =
            take_first(&mut self.pending.path, self.global.path.as_ref()).unwrap_or_else(|| {
                if is_ustar && !prefix.is_empty() {
                    join_prefix_name(prefix, name)
                } else {
                    Cow::Borrowed(name)
                }
            });

        let link_target = match kind {
            EntryKind::Symlink | EntryKind::Hardlink => Some(
                take_first(&mut self.pending.linkpath, self.global.linkpath.as_ref())
                    .unwrap_or_else(|| Cow::Borrowed(cstr(field(hdr, F_LINKNAME)))),
            ),
            _ => None,
        };

        let size = self
            .pending
            .size
            .or(self.global.size)
            .map_or_else(|| parse_numeric(field(hdr, F_SIZE)), Ok)?;

        let mtime = self.pending.mtime.or(self.global.mtime).or_else(|| {
            parse_numeric(field(hdr, F_MTIME))
                .ok()
                .map(|secs| Timestamp {
                    secs: i64::try_from(secs).unwrap_or(i64::MAX),
                    nanos: 0,
                })
        });

        let uid = self
            .pending
            .uid
            .or(self.global.uid)
            .map_or_else(|| parse_numeric(field(hdr, F_UID)), Ok)?;
        let gid = self
            .pending
            .gid
            .or(self.global.gid)
            .map_or_else(|| parse_numeric(field(hdr, F_GID)), Ok)?;

        let mode = u32::try_from(parse_numeric(field(hdr, F_MODE))? & 0o7777).unwrap_or(0);

        Ok(EntryMeta {
            kind,
            path,
            mode,
            uid,
            gid,
            mtime,
            size,
            link_target,
            pax: crate::meta::PaxMap::new(),
        })
    }
}

impl EntryReader for TarReader<'_> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.ended {
            return Ok(None);
        }
        // `&'a [u8]` は Copy。self とは独立した 'a のスライスとして扱えるため、
        // ヘッダ由来の借用（メタデータ）と self.payload の可変借用が競合しない。
        let data = self.data;

        loop {
            // ヘッダブロックが 1 つ収まらなければ終端とみなす。
            if self.pos + BLOCK > data.len() {
                self.ended = true;
                return Ok(None);
            }
            let hdr = &data[self.pos..self.pos + BLOCK];

            // ゼロブロック = アーカイブ終端。
            if hdr.iter().all(|&b| b == 0) {
                self.ended = true;
                return Ok(None);
            }

            verify_checksum(hdr)?;

            let typeflag = hdr[O_TYPEFLAG];
            let raw_size = parse_numeric(field(hdr, F_SIZE))?;
            let data_start = self.pos + BLOCK;
            let next_pos = data_start
                .checked_add(round_up(raw_size)?)
                .ok_or(Error::Malformed("size overflow"))?;

            match typeflag {
                // PAX 拡張ヘッダ（x=次エントリ用 / g=グローバル）。
                b'x' | b'X' | b'g' => {
                    let records = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    let target = if typeflag == b'g' {
                        &mut self.global
                    } else {
                        &mut self.pending
                    };
                    parse_pax(records, target)?;
                    self.pos = next_pos;
                }
                // GNU longname / longlink: データ全体が次エントリの名前 / リンク名。
                b'L' => {
                    let raw = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    self.pending.path = Some(Cow::Borrowed(cstr(raw)));
                    self.pos = next_pos;
                }
                b'K' => {
                    let raw = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    self.pending.linkpath = Some(Cow::Borrowed(cstr(raw)));
                    self.pos = next_pos;
                }
                // 実エントリ。
                _ => {
                    let meta = self.build_meta(hdr, typeflag)?;
                    let len = usize_of(meta.size)?;
                    // ペイロードが範囲内にあることを保証。
                    let _ = Self::slice(data, data_start, len)?;
                    self.payload = TarPayload {
                        bytes: data,
                        start: data_start,
                        len,
                        read: 0,
                    };
                    self.pos = data_start
                        .checked_add(round_up(meta.size)?)
                        .ok_or(Error::Malformed("size overflow"))?;
                    self.pending = Overrides::default();
                    return Ok(Some(Entry::new(meta, &mut self.payload)));
                }
            }
        }
    }
}

/// tar のストリーミング writer。read の双対として型に載る（実装は writer フェーズ）。
#[derive(Debug)]
pub struct TarWriter<W> {
    #[allow(dead_code)] // writer フェーズで使用。
    sink: W,
}

impl<W> TarWriter<W> {
    /// バイトシンクから writer を作る。
    pub fn new(sink: W) -> Self {
        Self { sink }
    }
}

impl<W> EntryWriter for TarWriter<W> {
    fn start_entry(&mut self, _meta: &EntryMeta<'_>) -> Result<EntrySink<'_>> {
        todo!("writer phase: tar header emission")
    }

    fn finish(&mut self) -> Result<()> {
        todo!("writer phase: tar trailer (two zero blocks)")
    }
}

// ── ヘルパ（自由関数。self を借用しないため借用の絡みを避けられる） ─────────────

/// ヘッダから固定フィールドを切り出す。
fn field(hdr: &[u8], (start, end): (usize, usize)) -> &[u8] {
    &hdr[start..end]
}

/// 最初の NUL までを返す（tar の C 文字列フィールド）。
fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// `prefix` + "/" + `name` を結合する（ustar の 255B パス）。
fn join_prefix_name<'a>(prefix: &'a [u8], name: &'a [u8]) -> Cow<'a, [u8]> {
    let mut joined = Vec::with_capacity(prefix.len() + 1 + name.len());
    joined.extend_from_slice(prefix);
    joined.push(b'/');
    joined.extend_from_slice(name);
    Cow::Owned(joined)
}

/// `pending`（take）を優先し、無ければ `global`（clone）を返す。
fn take_first<'a>(
    pending: &mut Option<Cow<'a, [u8]>>,
    global: Option<&Cow<'a, [u8]>>,
) -> Option<Cow<'a, [u8]>> {
    pending.take().or_else(|| global.cloned())
}

/// typeflag を型付き種別へ。`'0'`/`'\0'`/`'7'` および未知は通常ファイル扱い（tar の慣行）。
fn kind_from_typeflag(tf: u8) -> Result<EntryKind> {
    Ok(match tf {
        b'5' => EntryKind::Dir,
        b'1' => EntryKind::Hardlink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::Char,
        b'4' => EntryKind::Block,
        b'6' => EntryKind::Fifo,
        b'S' => return Err(Error::Unsupported("GNU sparse tar entry")),
        _ => EntryKind::File,
    })
}

/// tar 数値フィールドを解釈する（8進 ASCII、または高位ビット付き base-256）。
fn parse_numeric(field: &[u8]) -> Result<u64> {
    match field.first() {
        None => Ok(0),
        // base-256（GNU 拡張、大きな値用）。先頭バイトの高位ビットが立つ。
        Some(&first) if first & 0x80 != 0 => {
            let mut val: u64 = u64::from(first & 0x7f);
            for &b in &field[1..] {
                val = val
                    .checked_shl(8)
                    .and_then(|v| v.checked_add(u64::from(b)))
                    .ok_or(Error::Malformed("base-256 numeric overflow"))?;
            }
            Ok(val)
        }
        // 8進 ASCII。前後の空白 / NUL を無視。
        _ => {
            let mut val: u64 = 0;
            let mut seen = false;
            for &b in field {
                match b {
                    b' ' | 0 => {
                        if seen {
                            break;
                        }
                    }
                    b'0'..=b'7' => {
                        val = val
                            .checked_mul(8)
                            .and_then(|v| v.checked_add(u64::from(b - b'0')))
                            .ok_or(Error::Malformed("octal numeric overflow"))?;
                        seen = true;
                    }
                    _ => return Err(Error::Malformed("invalid octal digit")),
                }
            }
            Ok(val)
        }
    }
}

/// ヘッダのチェックサムを検証する（符号なし / 符号あり両対応）。
fn verify_checksum(hdr: &[u8]) -> Result<()> {
    let stored = parse_numeric(field(hdr, F_CHKSUM))?;
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in hdr.iter().enumerate() {
        // チェックサムフィールド自身は空白（0x20）として計算する。
        let byte = if (F_CHKSUM.0..F_CHKSUM.1).contains(&i) {
            b' '
        } else {
            b
        };
        unsigned += u64::from(byte);
        signed += i64::from(i8::from_ne_bytes([byte]));
    }
    if stored == unsigned || u64::try_from(signed).is_ok_and(|s| s == stored) {
        Ok(())
    } else {
        Err(Error::Malformed("header checksum mismatch"))
    }
}

/// u64 を usize へ（32bit 環境での過大値を弾く）。
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("size exceeds usize"))
}

/// バイト長を次のブロック境界へ切り上げる。
fn round_up(size: u64) -> Result<usize> {
    let size = usize_of(size)?;
    let blocks = size
        .checked_add(BLOCK - 1)
        .ok_or(Error::Malformed("size overflow"))?
        / BLOCK;
    blocks
        .checked_mul(BLOCK)
        .ok_or(Error::Malformed("size overflow"))
}

/// PAX 拡張レコード群 `"LEN KEY=VALUE\n"...` を解釈し、`into` へ反映する。
fn parse_pax<'a>(mut records: &'a [u8], into: &mut Overrides<'a>) -> Result<()> {
    while !records.is_empty() {
        // 先頭は 10進のレコード全長（自身の桁 + 空白 + KEY=VALUE + 改行を含む）。
        let sp = records
            .iter()
            .position(|&b| b == b' ')
            .ok_or(Error::Malformed("pax: missing length separator"))?;
        let len = ascii_decimal(&records[..sp])?;
        if len < sp + 1 || len > records.len() {
            return Err(Error::Malformed("pax: bad record length"));
        }
        let record = &records[..len];
        // "LEN KEY=VALUE\n" の KEY=VALUE 部分（末尾改行を除く）。
        let body = &record[sp + 1..record.len() - 1];
        let eq = body
            .iter()
            .position(|&b| b == b'=')
            .ok_or(Error::Malformed("pax: missing '='"))?;
        let key = &body[..eq];
        let value = &body[eq + 1..];
        apply_pax(key, value, into)?;
        records = &records[len..];
    }
    Ok(())
}

/// 単一の PAX キーバリューを上書きへ反映する（未知キーは無視）。
fn apply_pax<'a>(key: &[u8], value: &'a [u8], into: &mut Overrides<'a>) -> Result<()> {
    match key {
        b"path" => into.path = Some(Cow::Borrowed(value)),
        b"linkpath" => into.linkpath = Some(Cow::Borrowed(value)),
        b"size" => into.size = Some(ascii_decimal(value)? as u64),
        b"uid" => into.uid = Some(ascii_decimal(value)? as u64),
        b"gid" => into.gid = Some(ascii_decimal(value)? as u64),
        b"mtime" => into.mtime = Some(parse_pax_time(value)?),
        _ => {} // atime/ctime/uname/gname 等は P1 では無視。
    }
    Ok(())
}

/// ASCII 10進を usize へ。
fn ascii_decimal(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() {
        return Err(Error::Malformed("empty decimal"));
    }
    let mut val: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed("invalid decimal digit"));
        }
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(b - b'0')))
            .ok_or(Error::LimitExceeded("decimal overflow"))?;
    }
    Ok(val)
}

/// PAX の mtime（`"secs"` または `"secs.nanos"`）を解釈する。
fn parse_pax_time(value: &[u8]) -> Result<Timestamp> {
    let (secs_part, frac_part) = match value.iter().position(|&b| b == b'.') {
        Some(dot) => (&value[..dot], &value[dot + 1..]),
        None => (value, &b""[..]),
    };
    let secs = i64::try_from(ascii_decimal(secs_part)?).unwrap_or(i64::MAX);
    // 小数部を最大 9 桁までナノ秒へ（不足は 0 埋め、超過は切り捨て）。
    let mut nanos: u32 = 0;
    for i in 0..9 {
        nanos *= 10;
        if let Some(&b) = frac_part.get(i) {
            if !b.is_ascii_digit() {
                return Err(Error::Malformed("invalid fractional second"));
            }
            nanos += u32::from(b - b'0');
        }
    }
    Ok(Timestamp { secs, nanos })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_and_base256() {
        assert_eq!(parse_numeric(b"0000644\0").unwrap(), 0o644);
        assert_eq!(parse_numeric(b"        ").unwrap(), 0);
        assert_eq!(parse_numeric(b"00000000144\0").unwrap(), 0o144);
        // base-256: 0x80 マーカ + 大端 0x00000100 = 256。
        assert_eq!(parse_numeric(&[0x80, 0, 0, 1, 0]).unwrap(), 256);
    }

    #[test]
    fn round_up_blocks() {
        assert_eq!(round_up(0).unwrap(), 0);
        assert_eq!(round_up(1).unwrap(), 512);
        assert_eq!(round_up(512).unwrap(), 512);
        assert_eq!(round_up(513).unwrap(), 1024);
    }

    #[test]
    fn pax_time_fractional() {
        let t = parse_pax_time(b"1700000000.5").unwrap();
        assert_eq!(t.secs, 1_700_000_000);
        assert_eq!(t.nanos, 500_000_000);
    }
}
