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

fn archive_many(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Tar))
        .expect("create archive");
    for (path, body) in entries {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).expect("start entry");
        writer.write_data(body).expect("write entry");
        writer.end_entry().expect("end entry");
    }
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

fn json_records(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!(
                    "JSON record: {error}; line={line}; stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
        })
        .collect()
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
    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(records[0]["type"], "inspect_start");
    assert_eq!(records[1]["type"], "inspect_entry");
    assert_eq!(records[1]["path"], "stream.txt");
    assert_eq!(records[2]["type"], "inspect_complete");
    assert_eq!(records[2]["format"], "tar");
    assert_eq!(records[2]["entry_count"], 1);
    assert_eq!(records[2]["complete"], true);

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

#[test]
fn create_streams_through_common_options_to_file_and_stdout() {
    let dir = TempDir::new("oxarchive_create");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &[
            "create",
            "--json",
            "--format",
            "tar",
            "--filter",
            "gzip",
            "bundle.tar.gz",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let status = json_output(&output);
    assert_eq!(status["type"], "create");
    assert_eq!(status["format"], "tar");
    assert_eq!(status["filter"], "gzip");
    assert_eq!(status["complete"], true);
    assert_eq!(
        &std::fs::read(dir.join("bundle.tar.gz")).expect("created archive")[..2],
        &[0x1f, 0x8b]
    );

    let inspected = run_in(
        "oxarchive",
        &["--json", "inspect", "bundle.tar.gz"],
        dir.path(),
    );
    assert_eq!(code(&inspected), 0, "{inspected:?}");
    let records = json_records(&inspected);
    assert_eq!(records[1]["path"], "input.txt");
    assert_eq!(records.last().expect("complete")["complete"], true);

    let output = run_in(
        "oxarchive",
        &["create", "--format", "zip", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(output.stdout.starts_with(b"PK"));
    dir.write("stdout.zip", &output.stdout);
    let inspected = run_in(
        "oxarchive",
        &["--json", "inspect", "stdout.zip"],
        dir.path(),
    );
    assert_eq!(code(&inspected), 0, "{inspected:?}");
    assert_eq!(json_records(&inspected)[1]["path"], "input.txt");

    dir.write("--help", b"dash operand");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "dash-name.tar", "--", "--help"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "dash-prefixed input: {output:?}");
    for (format, archive_name) in [("cpio", "created.cpio"), ("ar", "created.a")] {
        let output = run_in(
            "oxarchive",
            &["create", "--format", format, archive_name, "input.txt"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{format}: {output:?}");
        let inspected = run_in(
            "oxarchive",
            &["--json", "inspect", archive_name],
            dir.path(),
        );
        assert_eq!(code(&inspected), 0, "{format}: {inspected:?}");
        let records = json_records(&inspected);
        assert_eq!(records[1]["path"], "input.txt");
        assert_eq!(records.last().expect("complete")["format"], format);
    }
}

#[test]
fn create_file_failures_never_publish_or_replace_a_destination() {
    let dir = TempDir::new("oxarchive_create_atomic");
    dir.write("input.txt", b"payload");
    dir.write("existing.tar", b"external");

    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "existing.tar", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("existing.tar")).expect("existing destination"),
        b"external"
    );

    let output = run_in(
        "oxarchive",
        &[
            "create",
            "--format",
            "tar",
            "failed.tar",
            "input.txt",
            "missing.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("failed.tar").exists());
    assert!(
        std::fs::read_dir(dir.path())
            .expect("directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".oxarchive-"))
    );

    dir.write("tree/member.txt", b"tree");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "tree/archive.tar", "tree"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("tree/archive.tar").exists());
}

#[test]
fn create_stdout_and_unsafe_path_failures_follow_the_partial_output_contract() {
    let dir = TempDir::new("oxarchive_create_partial");
    dir.write("input.txt", b"payload");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "-", "input.txt", "missing.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(
        !output.stdout.is_empty(),
        "first entry should already be streamed"
    );
    assert!(!output.stderr.is_empty());

    let output = run_in(
        "oxarchive",
        &["--json", "create", "--format", "tar", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty());

    dir.write("outside.txt", b"outside");
    std::fs::create_dir_all(dir.join("work")).expect("work directory");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "unsafe.tar", "../outside.txt"],
        &dir.join("work"),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("work/unsafe.tar").exists());
}

#[test]
fn inspect_json_stream_omits_completion_after_a_late_parser_error() {
    let dir = TempDir::new("oxarchive_inspect_partial");
    let mut malformed = archive_many(&[(b"first.txt", b"first"), (b"second.txt", b"second")]);
    malformed[1024] ^= 0xff;
    let output = run_stdin(
        "oxarchive",
        &["--json", "inspect", "-"],
        dir.path(),
        &malformed,
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records[0]["type"], "inspect_start");
    assert!(records.iter().any(|record| record["path"] == "first.txt"));
    assert!(
        records
            .iter()
            .all(|record| record["type"] != "inspect_complete")
    );
    assert!(!output.stderr.is_empty());
}
