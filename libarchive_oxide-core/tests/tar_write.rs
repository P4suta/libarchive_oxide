// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writer tests: the round-trip invariant `read ∘ write = id` for the tar format, plus GNU
//! longname/longlink extension emission for over-100-byte names.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use libarchive_oxide_core::format::tar::{TarReader, TarWriter};
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 100];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

fn write_entry<W: EntryWriter>(
    w: &mut W,
    kind: EntryKind,
    path: &[u8],
    data: &[u8],
    link: Option<&[u8]>,
) {
    let mut m = EntryMeta::new(kind, Cow::Borrowed(path));
    m.mode = 0o644;
    m.size = data.len() as u64;
    m.link_target = link.map(Cow::Borrowed);
    let mut sink = w.start_entry(&m).unwrap();
    if !data.is_empty() {
        sink.write_chunk(data).unwrap();
    }
    sink.close().unwrap();
}

#[test]
fn write_then_read_round_trips() {
    // (kind, path, data, optional link target)
    type Case = (EntryKind, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

    let long_name = "dir/".repeat(30) + "file.txt"; // 128 bytes -> forces GNU longname
    let long_target = "/very/".repeat(25) + "target"; // 156 bytes -> forces GNU longlink
    let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

    let cases: Vec<Case> = vec![
        (
            EntryKind::File,
            b"hello.txt".to_vec(),
            b"Hello, arca!\n".to_vec(),
            None,
        ),
        (EntryKind::Dir, b"sub/".to_vec(), Vec::new(), None),
        (EntryKind::File, b"sub/deep.bin".to_vec(), big.clone(), None),
        (
            EntryKind::Symlink,
            b"link".to_vec(),
            Vec::new(),
            Some(b"/etc/target".to_vec()),
        ),
        (
            EntryKind::File,
            long_name.clone().into_bytes(),
            b"long!".to_vec(),
            None,
        ),
        (
            EntryKind::Symlink,
            b"biglink".to_vec(),
            Vec::new(),
            Some(long_target.clone().into_bytes()),
        ),
    ];

    let mut w = TarWriter::new(Vec::new());
    for (kind, path, data, link) in &cases {
        write_entry(&mut w, *kind, path, data, link.as_deref());
    }
    w.finish().unwrap();
    let bytes = w.into_inner();

    let mut r = TarReader::new(&bytes);
    for (kind, path, data, link) in &cases {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().kind, *kind, "kind for {path:?}");
        assert_eq!(e.meta().path.as_ref(), path.as_slice(), "path");
        assert_eq!(
            e.meta().link_target.as_deref(),
            link.as_deref(),
            "link for {path:?}"
        );
        assert_eq!(&drain(&mut e), data, "data for {path:?}");
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn writing_more_than_declared_size_errors() {
    let mut w = TarWriter::new(Vec::new());
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(b"x"));
    m.size = 2;
    let mut sink = w.start_entry(&m).unwrap();
    assert!(sink.write_chunk(b"too long").is_err());
}
