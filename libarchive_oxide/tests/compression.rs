// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end round-trip tests for the zstd / xz / lz4 decode adapters.
//!
//! Each codec's own pure-Rust encoder (dev-dependency) compresses a hand-built tar; arca then
//! auto-detects the codec and decompresses it, and the entries are verified via `TarReader`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;

use common::{drain, trailer, ustar};
use libarchive_oxide::decompress;
use libarchive_oxide_core::format::tar::TarReader;
use libarchive_oxide_core::{EntryKind, EntryReader};

/// A small archive with a text file and a directory, plus a compressible payload.
fn sample_tar() -> Vec<u8> {
    let mut tar = Vec::new();
    tar.extend(ustar("hello.txt", b'0', b"arca round-trip\n"));
    tar.extend(ustar("data/", b'5', b""));
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    tar.extend(ustar("data/blob.bin", b'0', &payload));
    tar.extend(trailer());
    tar
}

/// Verifies the three expected entries in a decompressed sample tar.
fn assert_sample(plain: &[u8]) {
    let mut r = TarReader::new(plain);
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(drain(&mut e), b"arca round-trip\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"data/");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"data/blob.bin");
        let expected: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(drain(&mut e), expected);
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn extracts_tar_zst() {
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};
    let tar = sample_tar();
    let zst = compress_to_vec(tar.as_slice(), CompressionLevel::Fastest);
    assert_eq!(&zst[..4], &[0x28, 0xb5, 0x2f, 0xfd]); // zstd magic

    let plain = decompress(&zst).unwrap();
    assert_sample(&plain);
}

#[test]
fn extracts_tar_xz() {
    use lzma_rust2::{XzOptions, XzWriter};
    let tar = sample_tar();
    let mut w = XzWriter::new(Vec::new(), XzOptions::with_preset(6)).unwrap();
    w.write_all(&tar).unwrap();
    let xz = w.finish().unwrap();
    assert_eq!(&xz[..6], &[0xfd, b'7', b'z', b'X', b'Z', 0x00]); // xz magic

    let plain = decompress(&xz).unwrap();
    assert_sample(&plain);
}

#[test]
fn extracts_tar_lz4() {
    use lz4_flex::frame::FrameEncoder;
    let tar = sample_tar();
    let mut enc = FrameEncoder::new(Vec::new());
    enc.write_all(&tar).unwrap();
    let lz4 = enc.finish().unwrap();
    assert_eq!(&lz4[..4], &[0x04, 0x22, 0x4d, 0x18]); // lz4 frame magic

    let plain = decompress(&lz4).unwrap();
    assert_sample(&plain);
}
