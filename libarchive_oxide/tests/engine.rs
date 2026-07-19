// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level engine session, planning, and application contracts.

#![allow(clippy::expect_used)]

use std::io::Cursor;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits,
};
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, EntryOutcomeKind, PlanDisposition, Policy, ReaderEvent,
    RejectionReason,
};

fn archive(format: FormatId, filter: Option<FilterId>, path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(format).with_filter(filter),
        )
        .expect("test writer");
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(body).expect("write entry");
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish archive")
}

fn capability(path: &std::path::Path) -> Dir {
    Dir::open_ambient_dir(path, ambient_authority()).expect("open temporary capability")
}

#[test]
fn inspection_handles_compressed_tar_and_seek_zip() {
    let gzip = archive(FormatId::Tar, Some(FilterId::Gzip), b"gzip.txt", b"gzip");
    let mut gzip_session = ArchiveEngine::new()
        .open(Cursor::new(gzip))
        .expect("open gzip session");
    let gzip_inspection = gzip_session.inspect().expect("inspect gzip tar");
    assert_eq!(gzip_inspection.format(), FormatId::Tar);
    assert_eq!(
        gzip_inspection.entries()[0].metadata().path().as_bytes(),
        b"gzip.txt"
    );

    let bzip2 = archive(FormatId::Tar, Some(FilterId::Bzip2), b"bzip2.txt", b"bzip2");
    let mut bzip2_session = ArchiveEngine::new()
        .open(Cursor::new(bzip2))
        .expect("open bzip2 session");
    let bzip2_inspection = bzip2_session.inspect().expect("inspect bzip2 tar");
    assert_eq!(bzip2_inspection.format(), FormatId::Tar);
    assert_eq!(
        bzip2_inspection.entries()[0].metadata().path().as_bytes(),
        b"bzip2.txt"
    );

    let zip = archive(FormatId::Zip, None, b"zip.txt", b"zip");
    let mut zip_session = ArchiveEngine::new()
        .open(Cursor::new(zip))
        .expect("open zip session");
    let zip_inspection = zip_session.inspect().expect("inspect zip");
    assert_eq!(zip_inspection.format(), FormatId::Zip);
    assert_eq!(zip_inspection.entries().len(), 1);
}

#[test]
fn plans_are_session_bound_and_apply_only_once() {
    let bytes = archive(FormatId::Tar, None, b"file.txt", b"payload");
    let mut first = ArchiveEngine::new()
        .open(Cursor::new(bytes.clone()))
        .expect("first session");
    let foreign_plan = first.plan(Policy::safe()).expect("foreign plan");
    let mut second = ArchiveEngine::new()
        .open(Cursor::new(bytes))
        .expect("second session");
    let foreign_root = tempfile::tempdir().expect("foreign root");
    let error = second
        .apply(foreign_plan, capability(foreign_root.path()))
        .expect_err("cross-session plan must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Protocol)
    );

    let first_plan = first.plan(Policy::safe()).expect("first plan");
    let replay_plan = first.plan(Policy::safe()).expect("second plan");
    let root = tempfile::tempdir().expect("apply root");
    let report = first
        .apply(first_plan, capability(root.path()))
        .expect("apply bound plan");
    assert!(!report.extraction().has_rejections());
    assert_eq!(
        std::fs::read(root.path().join("file.txt")).expect("read extracted file"),
        b"payload"
    );
    let replay_root = tempfile::tempdir().expect("replay root");
    let error = first
        .apply(replay_plan, capability(replay_root.path()))
        .expect_err("session replay must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Protocol)
    );
}

#[test]
fn plan_and_report_keep_unsafe_path_rejection_visible() {
    let bytes = archive(FormatId::Tar, None, b"../escape", b"blocked");
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(bytes))
        .expect("open unsafe archive");
    let plan = session.plan(Policy::safe()).expect("plan unsafe archive");
    assert_eq!(
        plan.entries()[0].disposition(),
        PlanDisposition::Reject(RejectionReason::UnsafePath)
    );
    let root = tempfile::tempdir().expect("apply root");
    let report = session
        .apply(plan, capability(root.path()))
        .expect("apply with typed rejection");
    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::UnsafePath)
    ));
    assert!(!root.path().join("escape").exists());
}

#[test]
fn collection_and_snapshot_limits_are_enforced() {
    let bytes = archive(FormatId::Tar, None, b"metadata.txt", b"x");
    let mut session = ArchiveEngine::new()
        .with_limits(Limits::safe().with_metadata_bytes(Some(1)))
        .open(Cursor::new(bytes.clone()))
        .expect("open limited metadata session");
    let error = session
        .inspect()
        .expect_err("metadata collection must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Limit)
    );

    let error = ArchiveEngine::new()
        .with_spool_limits(1, 3)
        .open(Cursor::new(bytes))
        .expect_err("snapshot cap must fail");
    assert_eq!(
        error.io_error().map(std::io::Error::kind),
        Some(std::io::ErrorKind::FileTooLarge)
    );
}

#[test]
fn event_api_rewinds_over_the_same_digest() {
    let bytes = archive(FormatId::Tar, None, b"event.txt", b"event");
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(bytes))
        .expect("open session");
    let digest = session.digest();
    let mut entries = 0;
    loop {
        match session.next_event().expect("read event") {
            ReaderEvent::Entry(_) => entries += 1,
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    session.rewind().expect("rewind snapshot");
    let inspection = session.inspect().expect("inspect after rewind");
    assert_eq!(inspection.digest(), digest);
    assert_eq!(entries, inspection.entries().len());
}
