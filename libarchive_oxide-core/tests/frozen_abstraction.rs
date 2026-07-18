//! Tests that mechanically pin down the acceptance criteria of the frozen abstraction.
//!
//! This is the top-level verification: that "both writing and new formats fit onto the
//! same trait with no trait changes," and that the orthogonality and duality of
//! filter/format are guaranteed by the types and the behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::ar::ArReader;
use libarchive_oxide_core::format::cpio::{Cpio, CpioReader, CpioWriter};
use libarchive_oxide_core::format::tar::{Tar, TarReader, TarWriter};
use libarchive_oxide_core::format::{ArchiveFormat, Detection};
use libarchive_oxide_core::{AnyReader, EntryData, EntryDataSink, EntryReader, EntryWriter, SliceData};

/// The read side of the duality, asserted **statically**: any format reader satisfies the
/// `EntryReader` bound with zero type erasure (no `dyn`). Monomorphizing this over each reader
/// type is the compile-time proof.
fn assert_is_reader<R: EntryReader>(_r: &R) {}

/// The write side of the duality: any format writer satisfies `EntryWriter`, statically.
fn assert_is_writer<W: EntryWriter>(_w: &W) {}

/// Type-level check that the associated payload/sink wiring is exactly as frozen: the slice readers
/// expose `Data = SliceData`, and that type is an `EntryData`; a writer is its own `EntryDataSink`.
fn assert_wiring<'a, R, W>()
where
    R: EntryReader<Data = SliceData<'a>>,
    W: EntryWriter<Sink = W>,
    W: EntryDataSink,
    SliceData<'a>: EntryData,
{
}

#[test]
fn read_write_dual_and_orthogonal_formats_load_on_same_traits() {
    // For tar, both the read and write sides satisfy the same frozen traits (duality by types).
    let tar_r = TarReader::new(&b""[..]);
    let tar_w = TarWriter::new(alloc_sink());
    assert_is_reader(&tar_r);
    assert_is_writer(&tar_w);

    // cpio/ar (different formats) satisfy the same EntryReader, with no trait changes (orthogonality).
    let cpio_r = CpioReader::new(&b""[..]);
    let ar_r = ArReader::new(&b""[..]);
    assert_is_reader(&cpio_r);
    assert_is_reader(&ar_r);

    // The sealed AnyReader is itself an EntryReader — runtime dispatch with no type erasure.
    let any = AnyReader::tar(TarReader::new(&b""[..]));
    assert_is_reader(&any);

    // The associated-type wiring (Data = SliceData, Sink = Self) is frozen, checked at compile time.
    assert_wiring::<TarReader<'_>, TarWriter<alloc::vec::Vec<u8>>>();
    assert_wiring::<CpioReader<'_>, CpioWriter<alloc::vec::Vec<u8>>>();
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
    assert_eq!(FilterId::sniff(b"\x00\x00"), None);
}
