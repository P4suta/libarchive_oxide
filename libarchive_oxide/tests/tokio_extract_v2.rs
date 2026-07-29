// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokio I/O remains transport-only; filesystem extraction uses a bound plan.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Cursor;

use cap_std::{ambient_authority, fs::Dir};
use libarchive_oxide::{ArchiveEngine, ArchiveWriter, Policy, ReaderEvent, TokioArchiveReader};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};

#[tokio::test(flavor = "current_thread")]
async fn tokio_transport_and_filesystem_application_share_no_bypass() {
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

    let mut reader = TokioArchiveReader::new(Cursor::new(archive.clone()));
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);

    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let mut session = ArchiveEngine::new().prepare(Cursor::new(archive)).unwrap();
    let plan = session.plan(Policy::safe()).unwrap();
    let report = session.apply(plan, root).unwrap();
    assert!(!report.extraction().has_rejections());
    assert_eq!(
        fs::read(temporary.path().join("nested/file.txt")).unwrap(),
        body
    );
}

#[test]
fn filesystem_limits_fail_during_plan_before_application() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("limited.txt"))
        .size(Some(0))
        .build();
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let temporary = tempfile::tempdir().unwrap();
    let limits = Limits::default().with_entries(Some(0));
    let error = ArchiveEngine::new()
        .with_limits(limits)
        .prepare(Cursor::new(archive))
        .and_then(|mut session| session.plan(Policy::safe()).map(drop))
        .unwrap_err();

    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!temporary.path().join("limited.txt").exists());
}
