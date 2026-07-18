//! Round-trip invariant for ISO 9660 + Joliet: `read ∘ write = id` over path, kind, size, and data.
//!
//! Exercises a nested directory, a Unicode/long name that only survives via the Joliet tree, and a
//! multi-sector file (so extent spanning and sector alignment are covered).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::collections::BTreeMap;

use libarchive_oxide_core::format::iso9660::{IsoReader, IsoWriter};
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

fn write_entry<W: EntryWriter>(w: &mut W, kind: EntryKind, path: &[u8], data: &[u8]) {
    let mut m = EntryMeta::new(kind, Cow::Borrowed(path));
    m.size = data.len() as u64;
    let mut sink = w.start_entry(&m).unwrap();
    if !data.is_empty() {
        sink.write_chunk(data).unwrap();
    }
    sink.close().unwrap();
}

/// A file collected from reading back an image: kind + content, keyed by path.
#[derive(Debug, PartialEq, Eq)]
struct Rec {
    kind: EntryKind,
    data: Vec<u8>,
}

fn read_all(image: &[u8]) -> BTreeMap<Vec<u8>, Rec> {
    let mut reader = IsoReader::new(image);
    let mut map = BTreeMap::new();
    while let Some(mut entry) = reader.next_entry().unwrap() {
        let path = entry.meta().path.to_vec();
        let kind = entry.meta().kind;
        let size = entry.meta().size;
        let data = drain(&mut entry);
        assert_eq!(
            usize::try_from(size).unwrap(),
            data.len(),
            "declared size matches data length"
        );
        map.insert(path, Rec { kind, data });
    }
    map
}

#[test]
fn write_then_read_round_trips() {
    // A file spanning several 2048-byte sectors.
    let multi: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    // A long, non-ASCII name that has no valid 8.3 primary-tree form → only Joliet preserves it.
    let unicode_name = "深いディレクトリ/かなり長いファイル名-2026.txt";

    let mut w = IsoWriter::new(Vec::new());
    write_entry(
        &mut w,
        EntryKind::File,
        b"readme.txt",
        b"Hello, arca ISO!\n",
    );
    write_entry(&mut w, EntryKind::Dir, b"nested/", b"");
    write_entry(&mut w, EntryKind::Dir, b"nested/deep/", b"");
    write_entry(&mut w, EntryKind::File, b"nested/deep/data.bin", &multi);
    write_entry(
        &mut w,
        EntryKind::File,
        unicode_name.as_bytes(),
        b"joliet\n",
    );
    w.finish().unwrap();
    let image = w.into_inner();

    // Structural sanity: CD001 standard identifier at 0x8001.
    assert_eq!(&image[0x8001..0x8006], b"CD001");

    let files = read_all(&image);

    let readme = files.get(b"readme.txt".as_slice()).expect("readme present");
    assert_eq!(readme.kind, EntryKind::File);
    assert_eq!(readme.data, b"Hello, arca ISO!\n");

    let nested = files
        .get(b"nested/".as_slice())
        .expect("nested dir present");
    assert_eq!(nested.kind, EntryKind::Dir);

    let deep = files
        .get(b"nested/deep/".as_slice())
        .expect("nested/deep dir present");
    assert_eq!(deep.kind, EntryKind::Dir);

    let data = files
        .get(b"nested/deep/data.bin".as_slice())
        .expect("multi-sector file present");
    assert_eq!(data.kind, EntryKind::File);
    assert_eq!(data.data, multi, "multi-sector content round-trips exactly");

    let uni = files
        .get(unicode_name.as_bytes())
        .expect("unicode/long name survives via Joliet");
    assert_eq!(uni.kind, EntryKind::File);
    assert_eq!(uni.data, b"joliet\n");
}

#[test]
fn empty_archive_has_only_root() {
    let mut w = IsoWriter::new(Vec::new());
    w.finish().unwrap();
    let image = w.into_inner();
    assert_eq!(&image[0x8001..0x8006], b"CD001");
    // No entries: the root directory is not itself yielded.
    let files = read_all(&image);
    assert!(files.is_empty());
}
