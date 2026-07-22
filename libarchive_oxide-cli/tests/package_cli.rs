// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxarchive package validate` subcommand contract: the CLI drives the shared
//! library validators and renders their typed findings and stable severities as
//! one JSON record, never re-deriving package structure or classification.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![allow(clippy::cast_possible_truncation)]

mod common;

use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId, Limits,
};
use libarchive_oxide::{ArchiveEngine, ArchiveWriter, CreateOptions, ZipMethod};
use serde_json::Value;

use common::{TempDir, code, run_in, run_stdin};

// --- Fixture builders (mirroring the library validator test suites) --------

/// A single tar/cpio entry: archive-native path, kind, and body bytes.
type Entry = (&'static [u8], EntryKind, Vec<u8>);

/// Builds an outer `ar` archive from named member bodies.
fn build_ar(members: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Ar))
        .expect("create ar writer");
    for (name, body) in members {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start member");
        if !body.is_empty() {
            writer.write_data(body).expect("write member");
        }
        writer.end_entry().expect("end member");
    }
    writer.finish().expect("finish ar")
}

/// Builds a tar member, optionally wrapped in a single outer filter.
fn build_tar(filter: Option<FilterId>, entries: &[Entry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create tar writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish tar")
}

/// A well-formed `.deb`: `debian-binary`, a gzip `control.tar.gz`, and a gzip
/// `data.tar.gz`.
fn build_deb() -> Vec<u8> {
    let control = vec![(
        b"control".as_slice(),
        EntryKind::File,
        b"Package: demo\n".to_vec(),
    )];
    let data = vec![(
        b"usr/bin/demo".as_slice(),
        EntryKind::File,
        b"#!/bin/sh\n".to_vec(),
    )];
    build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (b"control.tar.gz", build_tar(Some(FilterId::Gzip), &control)),
        (b"data.tar.gz", build_tar(Some(FilterId::Gzip), &data)),
    ])
}

const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TYPE_STRING: u32 = 6;

/// Builds a gzip cpio payload from named file entries.
fn build_cpio(entries: &[Entry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Cpio)
                .with_filter(Some(FilterId::Gzip)),
        )
        .expect("create cpio writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish cpio")
}

/// One 16-byte RPM header index entry.
fn index_entry(tag: u32, kind: u32, offset: u32, count: u32) -> Vec<u8> {
    let mut entry = Vec::with_capacity(16);
    entry.extend_from_slice(&tag.to_be_bytes());
    entry.extend_from_slice(&kind.to_be_bytes());
    entry.extend_from_slice(&offset.to_be_bytes());
    entry.extend_from_slice(&count.to_be_bytes());
    entry
}

/// Assembles one RPM header structure from a raw index and data store.
fn header_bytes(index: &[u8], store: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC);
    out.push(0x01); // version
    out.extend_from_slice(&[0, 0, 0, 0]); // reserved
    out.extend_from_slice(&u32::try_from(index.len() / 16).unwrap().to_be_bytes());
    out.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
    out.extend_from_slice(index);
    out.extend_from_slice(store);
    out
}

/// A well-formed RPM: 96-byte lead, empty signature header, a main header with
/// the `cpio`/`gzip` payload tags, and a gzip cpio payload.
fn build_rpm() -> Vec<u8> {
    let mut lead = vec![0u8; 96];
    lead[..4].copy_from_slice(&LEAD_MAGIC);
    lead[4] = 3; // major

    let mut store = Vec::new();
    let format_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(b"cpio");
    store.push(0);
    let compressor_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(b"gzip");
    store.push(0);
    let mut index = Vec::new();
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADFORMAT,
        TYPE_STRING,
        format_offset,
        1,
    ));
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADCOMPRESSOR,
        TYPE_STRING,
        compressor_offset,
        1,
    ));

    let payload = build_cpio(&[(
        b"usr/bin/demo".as_slice(),
        EntryKind::File,
        b"#!/bin/sh\n".to_vec(),
    )]);

    let mut rpm = lead;
    rpm.extend_from_slice(&header_bytes(&[], &[])); // signature header
    rpm.extend_from_slice(&header_bytes(&index, &store)); // main header
    rpm.extend_from_slice(&payload);
    rpm
}

/// Builds a genuine stored (uncompressed) ZIP through the crate's own writer,
/// preserving member order so EPUB `mimetype`-first checks pass.
fn build_zip_store(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::safe());
    for (name, body) in members {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish zip")
}

/// A valid JAR: requires `META-INF/MANIFEST.MF`.
fn build_jar() -> Vec<u8> {
    build_zip_store(&[
        (b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        (b"com/example/Main.class", b"payload"),
    ])
}

/// A valid EPUB: a first, stored `mimetype` member plus `META-INF/container.xml`.
fn build_epub() -> Vec<u8> {
    build_zip_store(&[
        (b"mimetype", b"application/epub+zip"),
        (b"META-INF/container.xml", b"<container/>"),
        (b"OEBPS/content.opf", b"<package/>"),
    ])
}

// --- Output helpers --------------------------------------------------------

fn object(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "json object: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Returns whether the record carries a finding with the given code.
fn has_code(value: &Value, wanted: &str) -> bool {
    value["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["code"] == wanted)
}

// --- Happy paths -----------------------------------------------------------

#[test]
fn valid_packages_report_exit_zero_and_profile_valid() {
    let dir = TempDir::new("package_valid");
    for (kind, name, blob) in [
        ("deb", "demo.deb", build_deb()),
        ("rpm", "demo.rpm", build_rpm()),
        ("jar", "demo.jar", build_jar()),
        ("epub", "demo.epub", build_epub()),
    ] {
        let path = dir.write(name, &blob);
        let output = run_in(
            "oxarchive",
            &[
                "package",
                "validate",
                path.to_str().expect("utf8"),
                "--type",
                kind,
            ],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{kind}: {output:?}");
        let value = object(&output);
        assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
        assert_eq!(value["type"], "package_validation");
        assert_eq!(value["profile"], kind);
        assert_eq!(value["container_readable"], true, "{kind}: {value:?}");
        assert_eq!(value["profile_valid"], true, "{kind}: {value:?}");
        assert!(
            value["findings"].as_array().expect("findings").is_empty(),
            "{kind} should have no findings: {value:?}"
        );
    }
}

#[test]
fn type_flag_accepts_equals_form() {
    let dir = TempDir::new("package_equals");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type=jar",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(object(&output)["profile"], "jar");
}

#[test]
fn deb_validates_from_standard_input() {
    let dir = TempDir::new("package_stdin_deb");
    let output = run_stdin(
        "oxarchive",
        &["package", "validate", "-", "--type", "deb"],
        dir.path(),
        &build_deb(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["profile"], "deb");
    assert_eq!(value["profile_valid"], true);
}

// --- Invalid packages (container read, profile not satisfied) --------------

#[test]
fn missing_debian_binary_reports_exit_one_with_typed_finding() {
    let dir = TempDir::new("package_bad_deb");
    let blob = build_ar(&[
        (
            b"control.tar.gz",
            build_tar(
                Some(FilterId::Gzip),
                &[(
                    b"control".as_slice(),
                    EntryKind::File,
                    b"Package: demo\n".to_vec(),
                )],
            ),
        ),
        (
            b"data.tar.gz",
            build_tar(
                Some(FilterId::Gzip),
                &[(b"usr/bin/demo".as_slice(), EntryKind::File, b"x".to_vec())],
            ),
        ),
    ]);
    let path = dir.write("bad.deb", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "deb",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["type"], "package_validation");
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], false);
    assert!(
        has_code(&value, "missing-debian-binary"),
        "expected missing-debian-binary: {value:?}"
    );
    // The shared severity is rendered by its stable label, not re-derived.
    let finding = value["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["code"] == "missing-debian-binary")
        .expect("the finding");
    assert_eq!(finding["severity"], "error");
}

#[test]
fn jar_without_manifest_reports_exit_one_with_typed_finding() {
    let dir = TempDir::new("package_bad_jar");
    let blob = build_zip_store(&[(b"com/example/Main.class", b"payload")]);
    let path = dir.write("bad.jar", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "jar",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], false);
    assert!(
        has_code(&value, "missing-required-member"),
        "expected missing-required-member: {value:?}"
    );
}

// --- Usage errors ----------------------------------------------------------

#[test]
fn unknown_type_is_usage_error() {
    let dir = TempDir::new("package_unknown_type");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "frob",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
}

#[test]
fn missing_type_is_usage_error() {
    let dir = TempDir::new("package_missing_type");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &["package", "validate", path.to_str().expect("utf8")],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn unknown_subcommand_is_usage_error() {
    let dir = TempDir::new("package_unknown_sub");
    let output = run_in("oxarchive", &["package", "frobnicate"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");

    let output = run_in("oxarchive", &["package"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn zip_profile_rejects_standard_input_as_usage() {
    let dir = TempDir::new("package_stdin_zip");
    let output = run_stdin(
        "oxarchive",
        &["package", "validate", "-", "--type", "jar"],
        dir.path(),
        &build_jar(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
}
