//! Tests that mechanically pin down the acceptance criteria of the frozen abstraction.
//!
//! This is the top-level verification: that "both writing and new formats fit onto the
//! same trait with no trait changes," and that the orthogonality and duality of
//! filter/format are guaranteed by the types and the behavior.

use arca_core::filter::FilterId;
use arca_core::format::cpio::{Cpio, CpioReader};
use arca_core::format::tar::{Tar, TarReader, TarWriter};
use arca_core::format::{ArchiveFormat, Detection};
use arca_core::{EntryReader, EntryWriter};

/// The read side of the duality: any format reader fits onto a single trait object.
fn assert_is_reader(_r: &mut dyn EntryReader) {}

/// The write side of the duality: any format writer fits onto a single trait object.
fn assert_is_writer(_w: &mut dyn EntryWriter) {}

#[test]
fn read_write_dual_and_orthogonal_formats_load_on_same_traits() {
    // For tar, both the read and write sides fit onto the same trait (the duality is frozen by the types).
    let mut tar_r = TarReader::new(&b""[..]);
    let mut tar_w = TarWriter::new(alloc_sink());
    assert_is_reader(&mut tar_r);
    assert_is_writer(&mut tar_w);

    // cpio (a different format) fits onto the same EntryReader as tar, with no trait changes (orthogonality).
    let mut cpio_r = CpioReader::new(&b""[..]);
    assert_is_reader(&mut cpio_r);
}

/// A dummy byte sink for constructing the writer. Its contents are not needed until P2.
fn alloc_sink() -> alloc::vec::Vec<u8> {
    alloc::vec::Vec::new()
}

// The integration test is a std binary, but we pull in a reference to explicitly use the no_std crate's alloc.
extern crate alloc;

#[test]
fn tar_detection() {
    // The ustar magic is at byte 257. Without sufficient length, it's NeedMore.
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
    assert_eq!(Cpio::sniff(&[0xc7, 0x71]), Detection::Match); // old binary LE
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
