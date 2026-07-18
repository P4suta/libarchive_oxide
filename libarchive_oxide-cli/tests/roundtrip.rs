//! Per-tool round-trip integration tests, exercising the real built binaries.
//!
//! Each test drives an actual `ox*` process (create → extract / list) and asserts on the
//! materialized filesystem or captured stdout, so the whole flag-parsing + library-reuse path is
//! covered end-to-end.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;

use common::{code, run_in, run_stdin, TempDir};
use libarchive_oxide::zip::{ZipOptions, ZipWriter};
use libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};

const A: &[u8] = b"hello world\n";
const B: &[u8] = b"nested payload for the round-trip\n";

/// Populates `src/a.txt` and `src/data/b.txt` under `dir`.
fn seed(dir: &TempDir) {
    dir.write("src/a.txt", A);
    dir.write("src/data/b.txt", B);
}

#[test]
fn oxtar_plain_roundtrip() {
    let dir = TempDir::new("tar_plain");
    seed(&dir);

    let out = run_in(
        "oxtar",
        &["-c", "-f", "out.tar", "-C", "src", "."],
        dir.path(),
    );
    assert_eq!(code(&out), 0, "create: {out:?}");

    let out = run_in("oxtar", &["-x", "-f", "out.tar", "-C", "ex"], dir.path());
    assert_eq!(code(&out), 0, "extract: {out:?}");

    assert_eq!(std::fs::read(dir.join("ex/a.txt")).unwrap(), A);
    assert_eq!(std::fs::read(dir.join("ex/data/b.txt")).unwrap(), B);
}

#[test]
fn oxtar_gzip_roundtrip_traditional_flags() {
    let dir = TempDir::new("tar_gz");
    seed(&dir);

    // Traditional bundled form without a leading dash: `oxtar czf out.tgz ...`.
    let out = run_in("oxtar", &["czf", "out.tgz", "-C", "src", "."], dir.path());
    assert_eq!(code(&out), 0, "create: {out:?}");

    // Read side auto-detects gzip; extraction uses the bundled `xf`.
    let out = run_in("oxtar", &["xf", "out.tgz", "-C", "ex"], dir.path());
    assert_eq!(code(&out), 0, "extract: {out:?}");
    assert_eq!(std::fs::read(dir.join("ex/data/b.txt")).unwrap(), B);
}

#[test]
fn oxtar_list_selects_members() {
    let dir = TempDir::new("tar_list");
    seed(&dir);
    run_in(
        "oxtar",
        &["-c", "-f", "out.tar", "-C", "src", "."],
        dir.path(),
    );

    let out = run_in("oxtar", &["-t", "-f", "out.tar", "./data"], dir.path());
    assert_eq!(code(&out), 0);
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("data/b.txt"), "listing: {listing}");
    assert!(
        !listing.contains("a.txt"),
        "member filter leaked: {listing}"
    );
}

#[test]
fn oxtar_format_cpio_create_reads_back() {
    let dir = TempDir::new("tar_cpio");
    seed(&dir);

    let out = run_in(
        "oxtar",
        &["-c", "--format", "cpio", "-f", "out.cpio", "-C", "src", "."],
        dir.path(),
    );
    assert_eq!(code(&out), 0, "create: {out:?}");

    // oxcpio must read what oxtar --format cpio wrote (same newc writer). Copy-in extracts into
    // the working directory, so run it in a fresh subdir.
    std::fs::create_dir_all(dir.join("ex")).unwrap();
    let out = run_in("oxcpio", &["-i", "-F", "../out.cpio"], &dir.join("ex"));
    assert_eq!(code(&out), 0, "cpio extract: {out:?}");
    assert_eq!(std::fs::read(dir.join("ex/data/b.txt")).unwrap(), B);
}

#[test]
fn oxcpio_stdin_roundtrip() {
    let dir = TempDir::new("cpio");
    seed(&dir);

    // Copy-out reads filenames from stdin, relative to the working dir (src).
    let out = run_stdin(
        "oxcpio",
        &["-o", "-F", "../out.cpio"],
        &dir.join("src"),
        b"a.txt\ndata/b.txt\n",
    );
    assert_eq!(code(&out), 0, "copy-out: {out:?}");

    let out = run_in("oxcpio", &["-it", "-F", "out.cpio"], dir.path());
    assert_eq!(code(&out), 0);
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains("a.txt") && listing.contains("data/b.txt"),
        "{listing}"
    );

    // Copy-in extracts into the working directory.
    std::fs::create_dir_all(dir.join("ex2")).unwrap();
    let out = run_in("oxcpio", &["-i", "-F", "../out.cpio"], &dir.join("ex2"));
    assert_eq!(code(&out), 0, "copy-in: {out:?}");
    assert_eq!(std::fs::read(dir.join("ex2/data/b.txt")).unwrap(), B);
}

#[test]
fn oxcat_decompresses_to_stdout() {
    let dir = TempDir::new("cat");
    seed(&dir);
    run_in(
        "oxtar",
        &["-c", "-f", "plain.tar", "-C", "src", "."],
        dir.path(),
    );
    run_in(
        "oxtar",
        &["-c", "-z", "-f", "gz.tgz", "-C", "src", "."],
        dir.path(),
    );

    let plain = std::fs::read(dir.join("plain.tar")).unwrap();
    let out = run_in("oxcat", &["gz.tgz"], dir.path());
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(
        out.stdout, plain,
        "oxcat output equals the uncompressed tar"
    );
}

/// Builds a small zip with the library's writer and returns its bytes (entries `a.txt`, `data/b.txt`).
fn make_zip() -> Vec<u8> {
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());
    for (name, data) in [(&b"a.txt"[..], A), (&b"data/b.txt"[..], B)] {
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        m.mode = 0o644;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        sink.write_chunk(data).unwrap();
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

#[test]
fn oxunzip_list_and_extract() {
    let dir = TempDir::new("unzip");
    std::fs::write(dir.join("test.zip"), make_zip()).unwrap();

    let out = run_in("oxunzip", &["-l", "test.zip"], dir.path());
    assert_eq!(code(&out), 0);
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains("a.txt") && listing.contains("data/b.txt"),
        "{listing}"
    );

    let out = run_in("oxunzip", &["-o", "-d", "ex", "test.zip"], dir.path());
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(std::fs::read(dir.join("ex/a.txt")).unwrap(), A);
    assert_eq!(std::fs::read(dir.join("ex/data/b.txt")).unwrap(), B);
}
