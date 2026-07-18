// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential test: a zip produced by arca's `ZipWriter` must be readable by the external `zip`
//! crate (an independent implementation), covering store, deflate, directories, and Unix mode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::io::{Cursor, Read};

use libarchive_oxide::zip::{ZipOptions, ZipWriter};
use libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};
use zip::ZipArchive;

fn build() -> (Vec<u8>, Vec<u8>) {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());

    let entries: Vec<(EntryKind, &[u8], u32, Vec<u8>)> = vec![
        (EntryKind::File, b"readme.txt", 0o644, b"hello\n".to_vec()),
        (EntryKind::Dir, b"sub", 0o755, Vec::new()),
        (EntryKind::File, b"sub/big.txt", 0o640, big.clone()),
    ];
    for (kind, name, mode, data) in entries {
        let mut m = EntryMeta::new(kind, Cow::Borrowed(name));
        m.mode = mode;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        if !data.is_empty() {
            sink.write_chunk(&data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    (w.into_inner(), big)
}

#[test]
fn zip_crate_reads_arca_output() {
    let (bytes, big) = build();
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("zip crate opens arca archive");
    assert_eq!(archive.len(), 3);

    {
        let mut f = archive.by_name("readme.txt").unwrap();
        assert_eq!(f.unix_mode(), Some(0o100_644));
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello\n");
    }
    {
        let f = archive.by_name("sub/").unwrap();
        assert!(f.is_dir());
        assert_eq!(f.unix_mode().map(|m| m & 0o777), Some(0o755));
    }
    {
        let mut f = archive.by_name("sub/big.txt").unwrap();
        assert_eq!(f.compression(), zip::CompressionMethod::Deflated);
        let mut v = Vec::new();
        f.read_to_end(&mut v).unwrap();
        assert_eq!(v, big);
    }
}
