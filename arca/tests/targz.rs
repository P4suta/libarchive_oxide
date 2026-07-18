//! End-to-end test for `.tar.gz`. Produces gzip via flate2 (a pure-Rust backend),
//! and verifies the full path of arca auto-detection + gzip decompression -> `TarReader`.

use arca::decompress;
use arca_core::format::tar::TarReader;
use arca_core::{Entry, EntryKind, EntryReader};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

fn put_octal(hdr: &mut [u8; 512], start: usize, width: usize, val: u64) {
    let digits = format!("{val:0w$o}", w = width - 1);
    hdr[start..start + width - 1].copy_from_slice(digits.as_bytes());
    hdr[start + width - 1] = 0;
}

fn ustar(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    put_octal(&mut h, 100, 8, 0o644);
    put_octal(&mut h, 124, 12, data.len() as u64);
    h[156] = typeflag;
    h[257..262].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    h[154] = 0;
    h[155] = b' ';

    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    out
}

fn trailer() -> Vec<u8> {
    vec![0u8; 1024]
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn drain(entry: &mut Entry<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 9];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
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
