// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable filesystem creation order, duplicate refusal, and reproducible metadata.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{Cursor, Read};

use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, CreateOptions, CreateStreamError, CreationMetadataProfile,
    ReaderEvent, SeekArchiveBuilder, SeekArchiveReader, StreamingArchiveBuilder,
};
use libarchive_oxide_core::{ArchivePath, ErrorKind, FormatId, Limits};

fn build_tree(root: &std::path::Path) -> Vec<u8> {
    let mut builder =
        StreamingArchiveBuilder::new(Vec::new(), FormatId::Tar, None, Limits::default())
            .expect("create builder")
            .with_metadata_profile(CreationMetadataProfile::Reproducible);
    builder
        .append_path_as(root, &ArchivePath::from_utf8("root"))
        .expect("append tree");
    builder.finish().expect("finish archive")
}

#[test]
fn directory_entries_are_sorted_and_reproducible_metadata_ignores_host_mtime() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("tree");
    fs::create_dir(&root).expect("create tree");
    // Create in reverse lexical order; the archive order must not depend on the
    // host directory iterator.
    fs::write(root.join("z.txt"), b"z").expect("write z");
    fs::write(root.join("a.txt"), b"a").expect("write a");

    let first = build_tree(&root);
    fs::write(root.join("a.txt"), b"a").expect("rewrite to change host metadata");
    fs::write(root.join("z.txt"), b"z").expect("rewrite to change host metadata");
    let second = build_tree(&root);
    assert_eq!(first, second, "reproducible profile must be byte-identical");

    let mut reader = ArchiveReader::open(Cursor::new(first));
    let mut paths = Vec::new();
    while let Some(mut entry) = reader.next_entry().expect("read next entry") {
        paths.push(entry.metadata().path().as_bytes().to_vec());
        let mut body = Vec::new();
        entry.read_to_end(&mut body).expect("drain entry");
    }
    assert_eq!(paths, [b"root/".as_slice(), b"root/a.txt", b"root/z.txt"]);
}

#[test]
fn duplicate_archive_paths_are_rejected() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let input = temporary.path().join("input");
    fs::write(&input, b"payload").expect("write input");
    let mut builder =
        StreamingArchiveBuilder::new(Vec::new(), FormatId::Tar, None, Limits::default())
            .expect("create builder");
    let name = ArchivePath::from_utf8("same");
    builder
        .append_path_as(&input, &name)
        .expect("first path is accepted");
    let error = builder
        .append_path_as(&input, &name)
        .expect_err("duplicate path must be rejected");
    match error {
        CreateStreamError::Contract(error) => assert_eq!(error.kind(), ErrorKind::Protocol),
        other => panic!("unexpected duplicate error: {other}"),
    }
}

#[test]
fn seek_builder_reuses_the_filesystem_contract_for_xar() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("tree");
    fs::create_dir(&root).expect("create tree");
    fs::write(root.join("payload.txt"), b"seek builder payload").expect("write payload");

    let output = Cursor::new(Vec::new());
    let mut builder = SeekArchiveBuilder::with_engine(
        ArchiveEngine::new(),
        output,
        CreateOptions::new().with_format(FormatId::Xar),
    )
    .expect("create seek builder")
    .with_metadata_profile(CreationMetadataProfile::Reproducible);
    builder
        .append_path_as(&root, &ArchivePath::from_utf8("root"))
        .expect("append tree");
    let archive = builder.finish().expect("finish XAR").into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("open XAR");
    let mut paths = Vec::new();
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read XAR event") {
            ReaderEvent::Entry(entry) => paths.push(entry.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(paths, [b"root".as_slice(), b"root/payload.txt"]);
    assert_eq!(payload, b"seek builder payload");
}

#[test]
#[cfg(all(feature = "aes", feature = "sevenz"))]
fn seek_builder_reuses_the_filesystem_contract_for_encrypted_sevenz() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let input = temporary.path().join("payload.txt");
    fs::write(&input, b"encrypted seek builder payload").expect("write payload");
    let password = b"seek-builder-secret";
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(libarchive_oxide::FormatWriteOptions::SevenZip(
            libarchive_oxide::SevenZipWriteOptions::new()
                .with_compression(libarchive_oxide::SevenZipCompression::Deflate)
                .with_filter(Some(libarchive_oxide::SevenZipFilter::Delta(3)))
                .with_solid(false)
                .with_encryption(libarchive_oxide::SevenZipEncryption::Aes256),
        )));
    let mut builder = SeekArchiveBuilder::with_engine_and_password(
        ArchiveEngine::new(),
        Cursor::new(Vec::new()),
        options,
        libarchive_oxide::SecretBytes::new(password.to_vec()),
    )
    .expect("create encrypted seek builder")
    .with_metadata_profile(CreationMetadataProfile::Reproducible);
    builder
        .append_path_as(&input, &ArchivePath::from_utf8("payload.txt"))
        .expect("append payload");
    let archive = builder.finish().expect("finish encrypted 7z").into_inner();

    let mut reader = SeekArchiveReader::with_password(
        Cursor::new(archive),
        libarchive_oxide::SecretBytes::new(password.to_vec()),
    )
    .expect("open encrypted 7z");
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read encrypted 7z event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"encrypted seek builder payload");
}
