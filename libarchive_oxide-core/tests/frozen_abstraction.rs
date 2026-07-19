// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time checks for reader, writer, and associated-type interfaces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::ar::ArReader;
use libarchive_oxide_core::format::cpio::{Cpio, CpioReader, CpioWriter};
use libarchive_oxide_core::format::tar::{Tar, TarReader, TarWriter};
use libarchive_oxide_core::format::{ArchiveFormat, Detection};
use libarchive_oxide_core::{
    AnyReader, EntryData, EntryDataSink, EntryReader, EntryWriter, SliceData,
};

/// Requires `EntryReader`.
fn assert_is_reader<R: EntryReader>(_r: &R) {}

/// Requires `EntryWriter`.
fn assert_is_writer<W: EntryWriter>(_w: &W) {}

/// Checks reader data and writer sink associated types.
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
    // Check tar reader and writer bounds.
    let tar_r = TarReader::new(&b""[..]);
    let tar_w = TarWriter::new(alloc_sink());
    assert_is_reader(&tar_r);
    assert_is_writer(&tar_w);

    // Check cpio and ar reader bounds.
    let cpio_r = CpioReader::new(&b""[..]);
    let ar_r = ArReader::new(&b""[..]);
    assert_is_reader(&cpio_r);
    assert_is_reader(&ar_r);

    // Check runtime reader dispatch.
    let any = AnyReader::tar(TarReader::new(&b""[..]));
    assert_is_reader(&any);

    // Check associated types.
    assert_wiring::<TarReader<'_>, TarWriter<alloc::vec::Vec<u8>>>();
    assert_wiring::<CpioReader<'_>, CpioWriter<alloc::vec::Vec<u8>>>();
}

/// Byte sink used to construct writers.
fn alloc_sink() -> alloc::vec::Vec<u8> {
    alloc::vec::Vec::new()
}

// The integration test uses the no_std crate's alloc dependency.
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
