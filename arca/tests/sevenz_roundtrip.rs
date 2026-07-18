//! Round-trip: an archive written by `SevenZWriter` must read back identically through
//! `SevenZReader` (`read ∘ write = id`) — nested directories, an empty file, a multi-file solid
//! folder, and modification times.
#![cfg(feature = "sevenz")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use arca::sevenz::{SevenZReader, SevenZWriter};
use arca_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter, Timestamp};

/// A concrete entry description for the round-trip fixture.
struct Item {
    kind: EntryKind,
    name: &'static [u8],
    mode: u32,
    mtime: Option<Timestamp>,
    data: Vec<u8>,
}

fn write(items: &[Item]) -> Vec<u8> {
    let mut w = SevenZWriter::new(Vec::new());
    for it in items {
        let mut m = EntryMeta::new(it.kind, Cow::Borrowed(it.name));
        m.mode = it.mode;
        m.mtime = it.mtime;
        m.size = it.data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        if !it.data.is_empty() {
            sink.write_chunk(&it.data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

/// Reads every entry into `(name, kind, mode, mtime, data)` tuples.
type Read = (Vec<u8>, EntryKind, u32, Option<Timestamp>, Vec<u8>);

fn read_all(bytes: &[u8]) -> Vec<Read> {
    let mut r = SevenZReader::new(bytes);
    let mut out = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let meta = e.meta();
        let name = meta.path.to_vec();
        let kind = meta.kind;
        let mode = meta.mode;
        let mtime = meta.mtime;
        let mut data = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let n = e.data().read_chunk(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        out.push((name, kind, mode, mtime, data));
    }
    out
}

#[test]
fn roundtrip_dirs_files_empty_and_mtime() {
    let ts = Timestamp {
        secs: 1_700_000_000,
        nanos: 0,
    };
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    let items = vec![
        Item {
            kind: EntryKind::Dir,
            name: b"top",
            mode: 0o755,
            mtime: Some(ts),
            data: Vec::new(),
        },
        Item {
            kind: EntryKind::Dir,
            name: b"top/nested",
            mode: 0o750,
            mtime: None,
            data: Vec::new(),
        },
        Item {
            kind: EntryKind::File,
            name: b"top/empty.txt",
            mode: 0o644,
            mtime: Some(ts),
            data: Vec::new(),
        },
        Item {
            kind: EntryKind::File,
            name: b"top/nested/one.txt",
            mode: 0o640,
            mtime: Some(ts),
            data: b"first file contents\n".to_vec(),
        },
        Item {
            kind: EntryKind::File,
            name: b"top/nested/two.txt",
            mode: 0o600,
            mtime: None,
            data: big.clone(),
        },
    ];

    let bytes = write(&items);
    let got = read_all(&bytes);

    assert_eq!(got.len(), items.len());
    for (got, want) in got.iter().zip(&items) {
        assert_eq!(got.0, want.name, "name");
        assert_eq!(got.1, want.kind, "kind of {:?}", want.name);
        assert_eq!(got.2 & 0o7777, want.mode, "mode of {:?}", want.name);
        assert_eq!(got.3, want.mtime, "mtime of {:?}", want.name);
        assert_eq!(got.4, want.data, "data of {:?}", want.name);
    }
}

#[test]
fn roundtrip_single_file() {
    let items = vec![Item {
        kind: EntryKind::File,
        name: b"only.txt",
        mode: 0o644,
        mtime: None,
        data: b"lonely payload".to_vec(),
    }];
    let bytes = write(&items);
    let got = read_all(&bytes);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, b"only.txt");
    assert_eq!(got[0].1, EntryKind::File);
    assert_eq!(got[0].4, b"lonely payload");
}

#[test]
fn roundtrip_empty_archive() {
    let bytes = write(&[]);
    let got = read_all(&bytes);
    assert!(got.is_empty());
}
