// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract test for bounded Tokio secure extraction.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Cursor;

use cap_std::{ambient_authority, fs::Dir};
use libarchive_oxide::{ArchiveWriter, TokioArchiveReader, TokioExtractor};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};

#[tokio::test(flavor = "current_thread")]
async fn filesystem_work_runs_behind_the_tokio_adapter() {
    let body = b"bounded extraction";
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("nested/file.txt"))
            .size(Some(body.len() as u64))
            .build();
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata).unwrap();
    writer.write_data(body).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let mut reader = TokioArchiveReader::new(Cursor::new(archive));
    let report = TokioExtractor::new(root)
        .extract(&mut reader)
        .await
        .unwrap();
    assert!(!report.has_rejections());
    assert_eq!(
        fs::read(temporary.path().join("nested/file.txt")).unwrap(),
        body
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tokio_extractor_propagates_explicit_limits_to_its_worker() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("limited.txt"))
        .size(Some(0))
        .build();
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let limits = Limits::default().with_entries(Some(0));
    let mut reader = TokioArchiveReader::new(Cursor::new(archive));
    let error = TokioExtractor::with_limits(root, limits)
        .extract(&mut reader)
        .await
        .unwrap_err();

    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!temporary.path().join("limited.txt").exists());
}
