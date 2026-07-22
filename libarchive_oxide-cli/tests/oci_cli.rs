// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxarchive oci` subcommand contract: bounded inspection, digest
//! verification, and digest-bound application share the library's OCI layer
//! engine, plan, and report types.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use libarchive_oxide::oci::OciLayerEngine;
use libarchive_oxide::{ArchiveEngine, CreateOptions};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId};
use serde_json::Value;

use common::{TempDir, code, run_in, run_stdin};

/// Builds an OCI-style tar layer (optionally compressed) from `(path, body)`
/// entries. File bodies are written; entries with an empty body and a directory
/// or link kind are emitted structurally.
fn layer(filter: Option<FilterId>, entries: &[(&[u8], EntryKind, &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create layer");
    for (path, kind, body) in entries {
        let mut builder = EntryMetadata::builder(*kind, ArchivePath::from_bytes(path.to_vec()));
        if *kind == EntryKind::File {
            builder = builder.size(Some(body.len() as u64));
        }
        let metadata = builder.build();
        writer.start_entry(&metadata).expect("start entry");
        if *kind == EntryKind::File {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish layer")
}

/// Computes the compressed digest and diffID descriptors for a layer blob.
fn digests(blob: &[u8]) -> (String, String) {
    let mut session = OciLayerEngine::new().open(blob).expect("open layer");
    let digests = session.digests().expect("digests");
    (
        digests.compressed_descriptor(),
        digests.diff_id_descriptor(),
    )
}

fn records(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("json record"))
        .collect()
}

fn object(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "json object: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn inspect_streams_bounded_json_lines_across_filters() {
    let dir = TempDir::new("oci_inspect");
    for (filter, name) in [
        (None, "plain.tar"),
        (Some(FilterId::Gzip), "gz.tar.gz"),
        (Some(FilterId::Zstd), "zst.tar.zst"),
    ] {
        let blob = layer(filter, &[(b"etc/hello.txt", EntryKind::File, b"hi")]);
        let (compressed, diff_id) = digests(&blob);
        let path = dir.write(name, &blob);
        let output = run_in(
            "oxarchive",
            &["oci", "inspect", path.to_str().expect("utf8")],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{name}: {output:?}");
        let recs = records(&output);
        assert_eq!(recs.len(), 3, "{name}: {recs:?}");
        assert_eq!(recs[0]["type"], "oci_inspect_start");
        assert_eq!(recs[0]["schema_version"], "oxarchive.output.v0alpha1");
        assert_eq!(recs[1]["type"], "oci_inspect_entry");
        assert_eq!(recs[1]["path"], "etc/hello.txt");
        assert_eq!(recs[1]["kind"], "file");
        assert_eq!(recs[1]["size"], 2);
        assert_eq!(recs[2]["type"], "oci_inspect_complete");
        assert_eq!(recs[2]["entry_count"], 1);
        assert_eq!(recs[2]["digest"], compressed);
        assert_eq!(recs[2]["diff_id"], diff_id);
        assert_eq!(recs[2]["complete"], true);
    }
}

#[test]
fn inspect_reads_standard_input() {
    let dir = TempDir::new("oci_inspect_stdin");
    let blob = layer(Some(FilterId::Gzip), &[(b"file", EntryKind::File, b"x")]);
    let output = run_stdin("oxarchive", &["oci", "inspect", "-"], dir.path(), &blob);
    assert_eq!(code(&output), 0, "{output:?}");
    let recs = records(&output);
    assert_eq!(recs.last().expect("complete")["complete"], true);
}

#[test]
fn verify_matches_and_reports_each_mismatch() {
    let dir = TempDir::new("oci_verify");
    let blob = layer(None, &[(b"file", EntryKind::File, b"payload")]);
    let (compressed, diff_id) = digests(&blob);
    let path = dir.write("layer.tar", &blob);
    let layer_arg = path.to_str().expect("utf8");

    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "verify",
            layer_arg,
            "--digest",
            &compressed,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["type"], "oci_verify");
    assert_eq!(value["verified"], true);
    assert_eq!(value["digest"], compressed);

    let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "verify",
            layer_arg,
            "--digest",
            wrong,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["verified"], false);
    assert_eq!(value["mismatch"]["kind"], "compressed digest");

    // A malformed digest argument is a usage error.
    let output = run_in(
        "oxarchive",
        &["oci", "verify", layer_arg, "--digest", "notadigest"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn apply_materializes_files_and_executes_whiteout() {
    let dir = TempDir::new("oci_apply");
    let blob = layer(
        None,
        &[
            (b"data/keep.txt", EntryKind::File, b"kept"),
            (b"data/.wh.gone", EntryKind::File, b""),
        ],
    );
    let (compressed, diff_id) = digests(&blob);
    let path = dir.write("layer.tar", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "apply",
            path.to_str().expect("utf8"),
            "dest",
            "--digest",
            &compressed,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["type"], "oci_apply");
    assert_eq!(value["applied"], true);
    assert_eq!(value["digest"], compressed);
    assert!(value["materialized"].as_u64().expect("materialized") >= 1);
    assert_eq!(value["removed"], 1);
    assert_eq!(
        std::fs::read(dir.join("dest/data/keep.txt")).expect("materialized file"),
        b"kept"
    );
}

#[test]
fn apply_digest_mismatch_leaves_destination_unchanged() {
    let dir = TempDir::new("oci_apply_mismatch");
    let blob = layer(None, &[(b"data/keep.txt", EntryKind::File, b"kept")]);
    let (_compressed, diff_id) = digests(&blob);
    let path = dir.write("layer.tar", &blob);
    let wrong = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "apply",
            path.to_str().expect("utf8"),
            "dest",
            "--digest",
            wrong,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["applied"], false);
    assert!(!dir.join("dest/data/keep.txt").exists());
}

#[test]
fn apply_refuses_unsafe_paths_with_exit_one() {
    let dir = TempDir::new("oci_apply_unsafe");
    let blob = layer(None, &[(b"../escape", EntryKind::File, b"nope")]);
    let (compressed, diff_id) = digests(&blob);
    let path = dir.write("layer.tar", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "apply",
            path.to_str().expect("utf8"),
            "dest",
            "--digest",
            &compressed,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["rejected"], 1);
    assert!(!dir.join("escape").exists());
}

#[test]
fn apply_rejects_stdin_and_missing_digests_as_usage() {
    let dir = TempDir::new("oci_apply_usage");
    let blob = layer(None, &[(b"file", EntryKind::File, b"x")]);
    let (compressed, diff_id) = digests(&blob);
    let path = dir.write("layer.tar", &blob);
    let layer_arg = path.to_str().expect("utf8");

    // Standard input cannot seek: usage error.
    let output = run_in(
        "oxarchive",
        &[
            "oci",
            "apply",
            "-",
            "dest",
            "--digest",
            &compressed,
            "--diff-id",
            &diff_id,
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");

    // Missing --diff-id is a usage error.
    let output = run_in(
        "oxarchive",
        &["oci", "apply", layer_arg, "dest", "--digest", &compressed],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn unknown_oci_subcommand_is_usage_error() {
    let dir = TempDir::new("oci_unknown");
    let output = run_in("oxarchive", &["oci", "frobnicate"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");

    let output = run_in("oxarchive", &["oci"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
}
