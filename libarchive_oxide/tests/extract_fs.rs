//! Filesystem extraction tests: real files/dirs on disk, path-traversal rejection, and the
//! decompression-bomb cap.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use libarchive_oxide::{decompress_capped, extract::extract, reader};
use common::{trailer, ustar};
use flate2::write::GzEncoder;
use flate2::Compression;

/// A unique, empty scratch directory under the system temp dir.
fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("arca-test-{}-{tag}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn extracts_files_and_rejects_traversal() {
    let mut tar = Vec::new();
    tar.extend(ustar("top.txt", b'0', b"hello\n"));
    tar.extend(ustar("sub/", b'5', b""));
    tar.extend(ustar("sub/inner.txt", b'0', b"world\n"));
    tar.extend(ustar("../evil.txt", b'0', b"pwned")); // traversal -> must be skipped
    tar.extend(trailer());

    let dir = temp_dir("extract");
    let mut r = reader(&tar).unwrap();
    let stats = extract(&mut r, &dir).unwrap();

    assert_eq!(fs::read(dir.join("top.txt")).unwrap(), b"hello\n");
    assert_eq!(
        fs::read(dir.join("sub").join("inner.txt")).unwrap(),
        b"world\n"
    );
    assert!(dir.join("sub").is_dir());
    assert_eq!(stats.files, 2);
    assert_eq!(stats.dirs, 1);
    assert_eq!(stats.skipped, 1);
    // The traversal target must not have escaped the destination.
    assert!(!dir.parent().unwrap().join("evil.txt").exists());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn decompression_bomb_is_capped() {
    // 1 MiB of zeros compresses to a few hundred bytes; refuse to expand past 64 KiB.
    let mut tar = Vec::new();
    tar.extend(ustar("zeros.bin", b'0', &vec![0u8; 1024 * 1024]));
    tar.extend(trailer());
    let gz = gzip(&tar);

    let err = decompress_capped(&gz, 64 * 1024).unwrap_err();
    assert!(matches!(err, libarchive_oxide_core::Error::LimitExceeded(_)));
}
