// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified `oxarchive` command contract.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use libarchive_oxide::{ArchiveEngine, CreateOptions};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId};
use serde_json::Value;

use common::{TempDir, code, run_in, run_stdin};

fn archive(format: FormatId, filter: Option<FilterId>, path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(format).with_filter(filter),
        )
        .expect("create archive");
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(body).expect("write entry");
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish archive")
}

fn json_output(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON output: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn inspect_and_verify_cover_stream_and_seek_formats() {
    let dir = TempDir::new("oxarchive_inspect");
    let gzip = archive(
        FormatId::Tar,
        Some(FilterId::Gzip),
        b"stream.txt",
        b"stream",
    );
    let gzip_path = dir.write("stream.tar.gz", &gzip);
    let output = run_in(
        "oxarchive",
        &[
            "--json",
            "inspect",
            gzip_path.to_str().expect("UTF-8 test path"),
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(value["type"], "inspection");
    assert_eq!(value["format"], "tar");
    assert_eq!(value["entry_count"], 1);
    assert_eq!(value["entries"][0]["path"], "stream.txt");

    let zip = archive(FormatId::Zip, None, b"seek.txt", b"seek-body");
    let output = run_stdin("oxarchive", &["verify", "--json", "-"], dir.path(), &zip);
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "verify");
    assert_eq!(value["format"], "zip");
    assert_eq!(value["entries"], 1);
    assert_eq!(value["payload_bytes"], 9);
    assert_eq!(value["verified"], true);
}

#[test]
fn advisory_plan_and_apply_keep_rejections_visible() {
    let dir = TempDir::new("oxarchive_reject");
    let archive = archive(FormatId::Tar, None, b"../escape", b"blocked");
    let archive_path = dir.write("unsafe.tar", &archive);
    let archive_arg = archive_path.to_str().expect("UTF-8 test path");

    let output = run_in("oxarchive", &["plan", "--json", archive_arg], dir.path());
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "plan");
    assert_eq!(value["reusable"], false);
    assert_eq!(value["policy"]["symlinks"], false);
    assert_eq!(value["entries"][0]["disposition"], "reject:unsafepath");

    let output = run_in(
        "oxarchive",
        &["apply", "--json", archive_arg, "destination"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "apply");
    assert_eq!(value["rejected"], true);
    assert!(!dir.join("escape").exists());
}

#[test]
fn safe_apply_materializes_through_the_engine() {
    let dir = TempDir::new("oxarchive_apply");
    let archive = archive(FormatId::Tar, None, b"nested/file.txt", b"payload");
    let archive_path = dir.write("safe.tar", &archive);
    let output = run_in(
        "oxarchive",
        &[
            "apply",
            archive_path.to_str().expect("UTF-8 test path"),
            "destination",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("destination/nested/file.txt")).expect("read applied file"),
        b"payload"
    );
}

#[test]
fn malformed_and_duplicate_json_flags_have_stable_exit_codes() {
    let dir = TempDir::new("oxarchive_errors");
    dir.write("bad.bin", b"not an archive");

    let output = run_in("oxarchive", &["verify", "bad.bin"], dir.path());
    assert_eq!(code(&output), 1, "{output:?}");

    let output = run_in(
        "oxarchive",
        &["--json", "inspect", "--json", "bad.bin"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}
