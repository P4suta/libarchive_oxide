//! The safe defaults must survive through the CLI: path-traversal entries are refused on extract,
//! and transparent decompression is capped (bomb defense). These are the documented, intentional
//! divergences from historical tar's unsafe behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;

use common::{code, run_in, TempDir};
use libarchive_oxide::zip::{ZipOptions, ZipWriter};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::tar::TarWriter;
use libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};

/// Builds a tar containing one traversal entry (`../evil.txt`) and one safe entry (`safe.txt`).
fn tar_with_traversal() -> Vec<u8> {
    let mut w = TarWriter::new(Vec::new());
    for (name, data) in [
        (&b"../evil.txt"[..], &b"pwned\n"[..]),
        (&b"safe.txt"[..], &b"ok\n"[..]),
    ] {
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
fn oxtar_refuses_path_traversal() {
    let dir = TempDir::new("traversal");
    std::fs::write(dir.join("evil.tar"), tar_with_traversal()).unwrap();
    std::fs::create_dir_all(dir.join("dest")).unwrap();

    // Extract into dest/. A malicious `../evil.txt` must NOT escape to dest's parent.
    let out = run_in("oxtar", &["-x", "-f", "evil.tar", "-C", "dest"], dir.path());
    assert_eq!(code(&out), 0, "extraction itself succeeds: {out:?}");

    // The safe member is materialized; the traversal member is silently skipped, and crucially
    // nothing was written outside dest/.
    assert!(dir.join("dest/safe.txt").exists(), "safe member extracted");
    assert!(
        !dir.join("evil.txt").exists(),
        "traversal escaped the destination!"
    );
    assert!(
        !dir.join("dest/../evil.txt").exists(),
        "traversal escaped the destination!"
    );
}

#[test]
fn oxunzip_refuses_path_traversal() {
    let dir = TempDir::new("zip_traversal");
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());
    for (name, data) in [
        (&b"../evil.txt"[..], &b"pwned\n"[..]),
        (&b"safe.txt"[..], &b"ok\n"[..]),
    ] {
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        m.mode = 0o644;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        sink.write_chunk(data).unwrap();
        sink.close().unwrap();
    }
    w.finish().unwrap();
    std::fs::write(dir.join("evil.zip"), w.into_inner()).unwrap();
    std::fs::create_dir_all(dir.join("dest")).unwrap();

    let out = run_in("oxunzip", &["-o", "-d", "dest", "evil.zip"], dir.path());
    assert_eq!(code(&out), 0, "{out:?}");
    assert!(dir.join("dest/safe.txt").exists());
    assert!(!dir.join("evil.txt").exists(), "zip traversal escaped!");
}

/// The decompression-bomb cap is the exact library entry point the CLI wires in
/// (`decompress_capped`, fed `MAX_DECOMPRESSED`). Triggering the real 4 GiB cap through a process
/// would require materializing 4 GiB, so this verifies the mechanism the CLI depends on with an
/// injected small cap, and pins the constant the tools actually pass.
#[test]
fn decompression_is_capped() {
    // A highly compressible payload: 512 KiB of zeros gzips to a few hundred bytes but expands well
    // past a small cap.
    let plain = vec![0u8; 512 * 1024];
    let gz = libarchive_oxide::compress(&plain, FilterId::Gzip).unwrap();

    // Below the cap: succeeds and round-trips.
    let ok = libarchive_oxide::decompress_capped(&gz, plain.len() + 16).unwrap();
    assert_eq!(&ok[..], &plain[..]);

    // Above the payload but capped low: the cap fires before full expansion.
    let capped = libarchive_oxide::decompress_capped(&gz, 4096);
    assert!(capped.is_err(), "cap must reject an over-limit expansion");

    // The tools pass this exact cap.
    assert_eq!(
        libarchive_oxide_cli::MAX_DECOMPRESSED,
        4 * 1024 * 1024 * 1024
    );
    assert_eq!(
        libarchive_oxide_cli::decompress_cap() as u64,
        libarchive_oxide_cli::MAX_DECOMPRESSED.min(usize::MAX as u64)
    );
}
