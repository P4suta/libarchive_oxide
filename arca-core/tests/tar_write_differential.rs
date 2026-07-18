//! Differential test: a tar produced by `TarWriter` must be extractable by the real GNU/BSD
//! `tar`. Skips gracefully if no `tar` binary is on PATH.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use arca_core::format::tar::TarWriter;
use arca_core::{EntryKind, EntryMeta, EntryWriter};

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("arca-difftar-{}-{tag}-{n}", std::process::id()))
}

#[test]
fn system_tar_extracts_our_archive() {
    let long = "deep/".repeat(25) + "leaf.txt"; // 133 bytes -> GNU longname
    let entries: [(&str, &[u8]); 4] = [
        ("a.txt", b"AAA"),
        ("d/", b""),
        ("d/b.txt", b"BBB"),
        (long.as_str(), b"LONG"),
    ];

    let mut w = TarWriter::new(Vec::new());
    for (path, data) in entries {
        let kind = if path.ends_with('/') {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let mut m = EntryMeta::new(kind, Cow::Borrowed(path.as_bytes()));
        m.mode = 0o644;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        if !data.is_empty() {
            sink.write_chunk(data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    let bytes = w.into_inner();

    let dir = temp_dir("root");
    fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("out.tar");
    fs::write(&archive, &bytes).unwrap();
    let outdir = dir.join("x");
    fs::create_dir_all(&outdir).unwrap();

    // No `tar` on PATH: skip the differential check.
    let Ok(status) = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&outdir)
        .status()
    else {
        return;
    };
    assert!(status.success(), "system tar failed to extract our archive");

    assert_eq!(fs::read(outdir.join("a.txt")).unwrap(), b"AAA");
    assert_eq!(fs::read(outdir.join("d").join("b.txt")).unwrap(), b"BBB");
    assert_eq!(fs::read(outdir.join(&long)).unwrap(), b"LONG");

    let _ = fs::remove_dir_all(&dir);
}
