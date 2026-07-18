// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writer round-trip tests for cpio (newc) and ar: `read ∘ write = id` via our own readers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use libarchive_oxide_core::format::ar::{ArReader, ArWriter};
use libarchive_oxide_core::format::cpio::{CpioReader, CpioWriter};
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 16];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

fn write_entry<W: EntryWriter>(w: &mut W, kind: EntryKind, path: &[u8], mode: u32, data: &[u8]) {
    let mut m = EntryMeta::new(kind, Cow::Borrowed(path));
    m.mode = mode;
    m.size = data.len() as u64;
    let mut sink = w.start_entry(&m).unwrap();
    if !data.is_empty() {
        sink.write_chunk(data).unwrap();
    }
    sink.close().unwrap();
}

#[test]
fn cpio_newc_write_read_round_trips() {
    let mut w = CpioWriter::new(Vec::new());
    write_entry(
        &mut w,
        EntryKind::File,
        b"hello.txt",
        0o644,
        b"cpio write\n",
    );
    write_entry(&mut w, EntryKind::Dir, b"adir", 0o755, b"");
    // For cpio a symlink stores its target as the entry data.
    write_entry(&mut w, EntryKind::Symlink, b"lnk", 0o777, b"/target/path");
    w.finish().unwrap();
    let bytes = w.into_inner();

    let mut r = CpioReader::new(&bytes);
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().mode, 0o644);
        assert_eq!(drain(&mut e), b"cpio write\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"adir");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"lnk");
        assert_eq!(e.meta().kind, EntryKind::Symlink);
        assert_eq!(e.meta().link_target.as_deref(), Some(&b"/target/path"[..]));
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn ar_write_read_round_trips() {
    let long = b"a_very_long_member_name_exceeding_sixteen.bin"; // > 15 -> BSD "#1/LEN"
    let mut w = ArWriter::new(Vec::new());
    write_entry(&mut w, EntryKind::File, b"debian-binary", 0o644, b"2.0\n");
    write_entry(&mut w, EntryKind::File, b"short.o", 0o644, b"OBJ"); // odd length -> padded
    write_entry(&mut w, EntryKind::File, long, 0o644, b"DATA");
    w.finish().unwrap();
    let bytes = w.into_inner();

    let mut r = ArReader::new(&bytes);
    let mut seen = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let name = e.meta().path.to_vec();
        let data = drain(&mut e);
        seen.push((name, data));
    }
    assert_eq!(
        seen,
        vec![
            (b"debian-binary".to_vec(), b"2.0\n".to_vec()),
            (b"short.o".to_vec(), b"OBJ".to_vec()),
            (long.to_vec(), b"DATA".to_vec()),
        ]
    );
}
