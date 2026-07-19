// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential test: a tar produced by `TarEncoder` must be extractable by the real GNU/BSD
//! `tar`. Skips gracefully if no `tar` binary is on PATH.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use libarchive_oxide_core::{
    ArchiveEncoder, ArchivePath, EncodeCommand, EncodeStatus, EntryKind, EntryMetadata, Limits,
    TarEncoder,
};

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("arca-difftar-{}-{tag}-{n}", std::process::id()))
}

fn control<'a>(
    encoder: &mut TarEncoder,
    output: &mut Vec<u8>,
    command: impl Fn() -> EncodeCommand<'a>,
) -> EncodeStatus {
    loop {
        let mut buffer = [0_u8; 73];
        let step = encoder.step(command(), &mut buffer).unwrap();
        output.extend_from_slice(&buffer[..step.produced]);
        if step.status != EncodeStatus::NeedOutput {
            return step.status;
        }
    }
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

    let mut encoder = TarEncoder::new(Limits::default());
    let mut bytes = Vec::new();
    for (path, data) in entries {
        let kind = if path.ends_with('/') {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let metadata =
            EntryMetadata::builder(kind, ArchivePath::from_bytes(path.as_bytes().to_vec()))
                .mode(Some(if kind == EntryKind::Dir { 0o755 } else { 0o644 }))
                .size(Some(data.len() as u64))
                .build();
        assert_eq!(
            control(&mut encoder, &mut bytes, || {
                EncodeCommand::BeginEntry(&metadata)
            }),
            EncodeStatus::NeedCommand
        );
        let mut remaining = data;
        while !remaining.is_empty() {
            let mut buffer = [0_u8; 2];
            let step = encoder
                .step(EncodeCommand::Data(remaining), &mut buffer)
                .unwrap();
            bytes.extend_from_slice(&buffer[..step.produced]);
            remaining = &remaining[step.consumed..];
        }
        assert_eq!(
            control(&mut encoder, &mut bytes, || EncodeCommand::EndEntry),
            EncodeStatus::NeedCommand
        );
    }
    assert_eq!(
        control(&mut encoder, &mut bytes, || EncodeCommand::Finish),
        EncodeStatus::Done
    );

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
