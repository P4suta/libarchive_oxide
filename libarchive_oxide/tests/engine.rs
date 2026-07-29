// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level engine session, planning, and application contracts.

#![allow(clippy::expect_used)]

use std::io::{Cursor, Read};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
#[cfg(feature = "aes")]
use libarchive_oxide::SecretBytes;
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, EntryOutcomeKind, PlanDisposition, Policy, PreparedArchive,
    ReaderEvent, RejectionReason,
};
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits,
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

fn tar_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Tar))
        .expect("test writer");
    for (path, body) in entries {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        writer.write_data(body).expect("write entry");
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish archive")
}

fn capability(path: &std::path::Path) -> Dir {
    Dir::open_ambient_dir(path, ambient_authority()).expect("open temporary capability")
}

#[test]
fn engine_open_streams_and_session_spooling_is_explicit() {
    let bytes = archive(FormatId::Tar, None, b"stream.txt", b"streaming");
    let mut reader = ArchiveEngine::new().open(Cursor::new(bytes.clone()));
    let mut entry = reader.next_entry().expect("next entry").expect("one entry");
    let mut body = Vec::new();
    entry.read_to_end(&mut body).expect("stream entry");
    assert_eq!(body, b"streaming");
    drop(entry);
    assert!(reader.next_entry().expect("archive end").is_none());

    let prepared = PreparedArchive::spool(Cursor::new(bytes)).expect("explicit spool");
    assert!(!prepared.is_empty());
    let digest = prepared.digest();
    let mut session = ArchiveEngine::new()
        .open_prepared(prepared)
        .expect("prepared session");
    assert_eq!(session.digest(), digest);
    assert_eq!(session.inspect().expect("inspect").format(), FormatId::Tar);
}

#[cfg(feature = "gzip")]
#[test]
fn inspection_handles_gzip_tar() {
    let gzip = archive(FormatId::Tar, Some(FilterId::Gzip), b"gzip.txt", b"gzip");
    let mut gzip_session = ArchiveEngine::new()
        .prepare(Cursor::new(gzip))
        .expect("open gzip session");
    let gzip_inspection = gzip_session.inspect().expect("inspect gzip tar");
    assert_eq!(gzip_inspection.format(), FormatId::Tar);
    assert_eq!(
        gzip_inspection.entries()[0].metadata().path().as_bytes(),
        b"gzip.txt"
    );
}

#[cfg(feature = "bzip2")]
#[test]
fn inspection_handles_bzip2_tar() {
    let bzip2 = archive(FormatId::Tar, Some(FilterId::Bzip2), b"bzip2.txt", b"bzip2");
    let mut bzip2_session = ArchiveEngine::new()
        .prepare(Cursor::new(bzip2))
        .expect("open bzip2 session");
    let bzip2_inspection = bzip2_session.inspect().expect("inspect bzip2 tar");
    assert_eq!(bzip2_inspection.format(), FormatId::Tar);
    assert_eq!(
        bzip2_inspection.entries()[0].metadata().path().as_bytes(),
        b"bzip2.txt"
    );
}

#[test]
fn inspection_handles_seek_zip() {
    let zip = archive(FormatId::Zip, None, b"zip.txt", b"zip");
    let mut zip_session = ArchiveEngine::new()
        .prepare(Cursor::new(zip))
        .expect("open zip session");
    let zip_inspection = zip_session.inspect().expect("inspect zip");
    assert_eq!(zip_inspection.format(), FormatId::Zip);
    assert_eq!(zip_inspection.entries().len(), 1);
}

#[test]
fn plans_are_session_bound_and_apply_only_once() {
    let bytes = archive(FormatId::Tar, None, b"file.txt", b"payload");
    let mut first = ArchiveEngine::new()
        .prepare(Cursor::new(bytes.clone()))
        .expect("first session");
    let foreign_plan = first.plan(Policy::safe()).expect("foreign plan");
    let mut second = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
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
        .prepare(Cursor::new(bytes))
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
fn plan_rejects_non_directory_destination_topology_conflicts() {
    let bytes = tar_entries(&[(b"node", b"file"), (b"node/child", b"blocked")]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("open topology archive");
    let plan = session.plan(Policy::safe()).expect("preflight topology");
    assert_eq!(
        plan.entries()[0].disposition(),
        PlanDisposition::Materialize
    );
    assert_eq!(
        plan.entries()[1].disposition(),
        PlanDisposition::Reject(RejectionReason::DestinationCollision)
    );
}

#[cfg(windows)]
#[test]
fn windows_plan_preflights_aliases_and_unsafe_spellings() {
    let bytes = tar_entries(&[
        (b"case.txt", b"first"),
        (b"CASE.TXT", b"alias"),
        (b"trailing-dot", b"first"),
        (b"trailing-dot.", b"alias"),
        (b"trailing-space", b"first"),
        (b"trailing-space ", b"alias"),
        ("caf\u{00e9}.txt".as_bytes(), b"first"),
        ("cafe\u{0301}.txt".as_bytes(), b"alias"),
        (b"NUL.txt", b"device"),
        (b"safe.txt:stream", b"ads"),
    ]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("open alias archive");
    let plan = session.plan(Policy::safe()).expect("preflight aliases");
    let dispositions = plan
        .entries()
        .iter()
        .map(libarchive_oxide::PlannedEntry::disposition)
        .collect::<Vec<_>>();
    assert_eq!(
        dispositions,
        vec![
            PlanDisposition::Materialize,
            PlanDisposition::Reject(RejectionReason::DestinationCollision),
            PlanDisposition::Materialize,
            PlanDisposition::Reject(RejectionReason::UnsafePath),
            PlanDisposition::Materialize,
            PlanDisposition::Reject(RejectionReason::UnsafePath),
            PlanDisposition::Materialize,
            PlanDisposition::Reject(RejectionReason::DestinationCollision),
            PlanDisposition::Reject(RejectionReason::UnsafePath),
            PlanDisposition::Reject(RejectionReason::UnsafePath),
        ]
    );
}

#[cfg(unix)]
#[test]
fn unix_plan_preserves_case_unicode_and_windows_only_spellings() {
    let bytes = tar_entries(&[
        (b"case.txt", b"lower"),
        (b"CASE.TXT", b"upper"),
        ("caf\u{00e9}.txt".as_bytes(), b"nfc"),
        ("cafe\u{0301}.txt".as_bytes(), b"nfd"),
        (b"trailing-dot.", b"dot"),
        (b"trailing-space ", b"space"),
        (b"NUL.txt", b"ordinary"),
        (b"safe.txt:stream", b"ordinary"),
    ]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("open Unix spelling archive");
    let plan = session.plan(Policy::safe()).expect("plan Unix spellings");
    assert!(
        plan.entries()
            .iter()
            .all(|entry| entry.disposition() == PlanDisposition::Materialize)
    );
}

#[test]
fn collection_and_snapshot_limits_are_enforced() {
    let bytes = archive(FormatId::Tar, None, b"metadata.txt", b"x");
    let mut session = ArchiveEngine::new()
        .with_limits(Limits::safe().with_metadata_bytes(Some(1)))
        .prepare(Cursor::new(bytes.clone()))
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
        .prepare(Cursor::new(bytes))
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
        .prepare(Cursor::new(bytes))
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

#[cfg(feature = "aes")]
#[test]
fn password_session_survives_inspect_and_explicit_rewinds() {
    const PASSWORD: &[u8] = b"engine-session-secret";
    let mut writer = ArchiveEngine::new()
        .create_with_password(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Zip),
            SecretBytes::from(PASSWORD),
        )
        .expect("encrypted ZIP writer");
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(b"protected.txt"))
            .size(Some(17))
            .build();
    writer
        .start_entry(&metadata)
        .expect("start encrypted entry");
    writer
        .write_data(b"protected payload")
        .expect("write encrypted entry");
    writer.end_entry().expect("end encrypted entry");
    let bytes = writer.finish().expect("finish encrypted ZIP");

    let mut session = ArchiveEngine::new()
        .prepare_with_password(Cursor::new(bytes.clone()), SecretBytes::from(PASSWORD))
        .expect("password session");
    let inspection = session.inspect().expect("inspect encrypted ZIP");
    assert_eq!(inspection.format(), FormatId::Zip);
    assert_eq!(inspection.entries().len(), 1);
    session.rewind().expect("rewind password session");
    let mut payload = Vec::new();
    loop {
        match session.next_event().expect("read rewound encrypted ZIP") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"protected payload");
    assert!(!format!("{session:?}").contains("engine-session-secret"));

    let error = ArchiveEngine::new()
        .prepare_with_password(Cursor::new(bytes), SecretBytes::from(&b"wrong"[..]))
        .expect("wrong password session opens")
        .inspect()
        .expect_err("wrong password must fail authentication");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Integrity)
    );
}

#[cfg(feature = "aes")]
#[test]
fn password_apis_reject_formats_that_cannot_consume_the_secret() {
    let mut output = Vec::new();
    let Err(error) = ArchiveEngine::new().create_with_password(
        &mut output,
        CreateOptions::new().with_format(FormatId::Tar),
        SecretBytes::from(&b"not-ignored"[..]),
    ) else {
        panic!("password-protected tar creation must be rejected");
    };
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Capability)
    );
    assert!(output.is_empty(), "rejection must precede output I/O");

    let tar = archive(FormatId::Tar, None, b"plain.txt", b"plain");
    let error = ArchiveEngine::new()
        .prepare_with_password(Cursor::new(tar), SecretBytes::from(&b"not-ignored"[..]))
        .expect_err("a password for tar must not be ignored");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Capability)
    );
}
