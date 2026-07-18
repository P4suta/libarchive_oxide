//! cpio フォーマット（SVR4 "newc" / POSIX "odc" / 旧バイナリ）。
//!
//! **直交性の証明**: 新しいフォーマットの追加は「同じ [`EntryReader`] を実装する型を足す」
//! だけで済み、既存トレイトも tar 実装も 1 行も変わらない。P0 ではその型付けを凍結する。

use crate::format::{ArchiveFormat, Detection, Entry, EntryReader};
use crate::Result;

/// cpio フォーマットの検出アンカー（零サイズ型）。
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpio;

const NEWC_MAGIC: &[u8] = b"070701";
const NEWC_CRC_MAGIC: &[u8] = b"070702";
const ODC_MAGIC: &[u8] = b"070707";
/// 旧バイナリ形式のマジック（ホストバイトオーダ両対応）。
const BIN_MAGIC_LE: [u8; 2] = [0xc7, 0x71];
const BIN_MAGIC_BE: [u8; 2] = [0x71, 0xc7];

impl ArchiveFormat for Cpio {
    const NAME: &'static str = "cpio";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < 2 {
            return Detection::NeedMore;
        }
        let head2 = [prefix[0], prefix[1]];
        if head2 == BIN_MAGIC_LE || head2 == BIN_MAGIC_BE {
            return Detection::Match;
        }
        if prefix.len() < 6 {
            return Detection::NeedMore;
        }
        let head6 = &prefix[..6];
        if head6 == NEWC_MAGIC || head6 == NEWC_CRC_MAGIC || head6 == ODC_MAGIC {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// cpio のストリーミング reader。
#[derive(Debug)]
pub struct CpioReader<S> {
    #[allow(dead_code)] // P4 で使用。
    source: S,
}

impl<S> CpioReader<S> {
    /// バイト源から reader を作る。
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S> EntryReader for CpioReader<S> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        // P4: newc(16進) / odc(8進) / 旧バイナリ のヘッダ分岐、TRAILER!!! 終端検出。
        todo!("P4: cpio header parsing")
    }
}
