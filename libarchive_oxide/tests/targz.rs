// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end test for `.tar.gz`. Produces gzip via flate2 (a pure-Rust backend),
//! and verifies the full path of arca auto-detection + gzip decompression -> `TarReader`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{drain, trailer, ustar};
use flate2::write::GzEncoder;
use flate2::Compression;
use libarchive_oxide::decompress;
use libarchive_oxide_core::format::tar::TarReader;
use libarchive_oxide_core::{EntryKind, EntryReader};
use std::io::Write;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn extracts_tar_gz_end_to_end() {
    let mut tar = Vec::new();
    tar.extend(ustar("readme.txt", b'0', b"arca via gzip\n"));
    tar.extend(ustar("dir/", b'5', b""));
    tar.extend(trailer());

    let gz = gzip(&tar);
    // Confirm it is compressed (the premise for auto-detection).
    assert_eq!(&gz[..2], &[0x1f, 0x8b]);

    let plain = decompress(&gz).unwrap();
    let mut r = TarReader::new(&plain);
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"readme.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(drain(&mut e), b"arca via gzip\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"dir/");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn large_payload_spans_inflate_chunks() {
    // A larger body that guarantees spanning across the 16KB decode buffer.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut tar = Vec::new();
    tar.extend(ustar("big.bin", b'0', &payload));
    tar.extend(trailer());

    let gz = gzip(&tar);
    let plain = decompress(&gz).unwrap();
    let mut r = TarReader::new(&plain);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().size, payload.len() as u64);
    assert_eq!(drain(&mut e), payload);
}

#[test]
fn plain_tar_passes_through_uncompressed() {
    let mut tar = Vec::new();
    tar.extend(ustar("x", b'0', b"y"));
    tar.extend(trailer());
    // Uncompressed input is returned as a borrow as-is (no copy).
    let out = decompress(&tar).unwrap();
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    let mut r = TarReader::new(&out);
    assert_eq!(r.next_entry().unwrap().unwrap().meta().path.as_ref(), b"x");
}
