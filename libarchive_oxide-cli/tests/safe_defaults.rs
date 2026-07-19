// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The safe defaults must survive through the CLI: path-traversal entries are refused on extract,
//! and transparent decompression is capped (bomb defense). These are the documented, intentional
//! divergences from historical tar's unsafe behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Cursor, Read};

use common::{TempDir, code, run_in};
use libarchive_oxide::filter::gzip::GzipEncoder;
use libarchive_oxide::{ArchiveWriter, FilterReader, ZipMethod};
use libarchive_oxide_core::{
    ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata, Limits,
};

/// Builds a tar containing one traversal entry (`../evil.txt`) and one safe entry (`safe.txt`).
fn tar_with_traversal() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (name, data) in [
        (&b"../evil.txt"[..], &b"pwned\n"[..]),
        (&b"safe.txt"[..], &b"ok\n"[..]),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .mode(Some(0o644))
                .size(Some(data.len() as u64))
                .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(data).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn oxtar_refuses_path_traversal() {
    let dir = TempDir::new("traversal");
    std::fs::write(dir.join("evil.tar"), tar_with_traversal()).unwrap();
    std::fs::create_dir_all(dir.join("dest")).unwrap();

    // Extract into dest/. A malicious `../evil.txt` must NOT escape to dest's parent.
    let out = run_in("oxtar", &["-x", "-f", "evil.tar", "-C", "dest"], dir.path());
    assert_eq!(
        code(&out),
        1,
        "policy refusals are reported with a non-zero status: {out:?}"
    );

    // The safe member is materialized; the traversal member is reported and refused, and
    // crucially nothing was written outside dest/.
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
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Deflate, Limits::default());
    for (name, data) in [
        (&b"../evil.txt"[..], &b"pwned\n"[..]),
        (&b"safe.txt"[..], &b"ok\n"[..]),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .mode(Some(0o644))
                .size(Some(data.len() as u64))
                .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(data).unwrap();
        writer.end_entry().unwrap();
    }
    std::fs::write(dir.join("evil.zip"), writer.finish().unwrap()).unwrap();
    std::fs::create_dir_all(dir.join("dest")).unwrap();

    let out = run_in("oxunzip", &["-o", "-d", "dest", "evil.zip"], dir.path());
    assert_eq!(
        code(&out),
        1,
        "policy refusals are reported with a non-zero status: {out:?}"
    );
    assert!(dir.join("dest/safe.txt").exists());
    assert!(!dir.join("evil.txt").exists(), "zip traversal escaped!");
}

fn gzip(plain: &[u8]) -> Vec<u8> {
    let mut encoder = GzipEncoder::new(Limits::default());
    let mut input = plain;
    let mut output = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let step = encoder
            .process(input, &mut buffer, EndOfInput::End)
            .unwrap();
        output.extend_from_slice(&buffer[..step.produced]);
        input = &input[step.consumed..];
        if step.status == CodecStatus::Done {
            return output;
        }
    }
}

/// The bounded streaming filter used by the CLI must stop a decompression bomb
/// without first materializing the decoded stream.
#[test]
fn decompression_is_capped() {
    let plain = vec![0u8; 512 * 1024];
    let gz = gzip(&plain);

    let mut ok = FilterReader::with_limits(
        Cursor::new(gz.clone()),
        Limits::default().with_decoded_total(Some(plain.len() as u64 + 16)),
    )
    .unwrap();
    let mut decoded = Vec::new();
    ok.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);

    let mut capped = FilterReader::with_limits(
        Cursor::new(gz),
        Limits::default().with_decoded_total(Some(4096)),
    )
    .unwrap();
    assert!(
        capped.read_to_end(&mut Vec::new()).is_err(),
        "cap must reject an over-limit expansion"
    );

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
