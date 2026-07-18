//! 凍結された抽象の受入基準を機械的に固定するテスト。
//!
//! ここが最上位の検証: 「write も新フォーマットも、トレイト変更なしに同一トレイトへ載る」
//! ことと、filter/format の直交性・双対性を型と挙動で担保する。

use arca_core::filter::FilterId;
use arca_core::format::cpio::{Cpio, CpioReader};
use arca_core::format::tar::{Tar, TarReader, TarWriter};
use arca_core::format::{ArchiveFormat, Detection};
use arca_core::{EntryReader, EntryWriter};

/// 双対の read 側: 任意のフォーマット reader が単一トレイトオブジェクトに載る。
fn assert_is_reader(_r: &mut dyn EntryReader) {}

/// 双対の write 側: 任意のフォーマット writer が単一トレイトオブジェクトに載る。
fn assert_is_writer(_w: &mut dyn EntryWriter) {}

#[test]
fn read_write_dual_and_orthogonal_formats_load_on_same_traits() {
    // tar は read/write 双方が同一トレイトに載る（双対を型で凍結）。
    let mut tar_r = TarReader::new(&b""[..]);
    let mut tar_w = TarWriter::new(alloc_sink());
    assert_is_reader(&mut tar_r);
    assert_is_writer(&mut tar_w);

    // cpio（別フォーマット）は tar と同じ EntryReader に、トレイト変更なしで載る（直交性）。
    let mut cpio_r = CpioReader::new(&b""[..]);
    assert_is_reader(&mut cpio_r);
}

/// writer 構築のためのダミーバイトシンク。P2 まで中身は不要。
fn alloc_sink() -> alloc::vec::Vec<u8> {
    alloc::vec::Vec::new()
}

// 統合テストは std バイナリだが、no_std クレートの alloc を明示的に使うため参照を張る。
extern crate alloc;

#[test]
fn tar_detection() {
    // ustar マジックは 257 バイト目。十分な長さが無ければ NeedMore。
    assert_eq!(Tar::sniff(b"short"), Detection::NeedMore);

    let mut block = [0u8; 512];
    block[257..262].copy_from_slice(b"ustar");
    assert_eq!(Tar::sniff(&block), Detection::Match);

    let plain = [0u8; 512];
    assert_eq!(Tar::sniff(&plain), Detection::NoMatch);
    assert_eq!(Tar::NAME, "tar");
}

#[test]
fn cpio_detection() {
    assert_eq!(Cpio::sniff(b"070701rest"), Detection::Match); // newc
    assert_eq!(Cpio::sniff(b"070707rest"), Detection::Match); // odc
    assert_eq!(Cpio::sniff(&[0xc7, 0x71]), Detection::Match); // 旧バイナリ LE
    assert_eq!(Cpio::sniff(b""), Detection::NeedMore);
    assert_eq!(Cpio::sniff(b"NOTCPIO"), Detection::NoMatch);
}

#[test]
fn filter_magic_sniffing() {
    assert_eq!(FilterId::sniff(&[0x1f, 0x8b, 0x08]), Some(FilterId::Gzip));
    assert_eq!(
        FilterId::sniff(&[0x28, 0xb5, 0x2f, 0xfd]),
        Some(FilterId::Zstd)
    );
    assert_eq!(
        FilterId::sniff(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
        Some(FilterId::Xz)
    );
    assert_eq!(
        FilterId::sniff(&[0x04, 0x22, 0x4d, 0x18]),
        Some(FilterId::Lz4)
    );
    assert_eq!(FilterId::sniff(b"BZh"), Some(FilterId::Bzip2));
    assert_eq!(FilterId::sniff(b"\x00\x00"), None);
}
