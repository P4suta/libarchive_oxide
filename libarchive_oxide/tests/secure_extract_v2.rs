// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe extraction policy contracts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::io::Cursor;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, EntryOutcomeKind, ExtractionReport, Policy, RejectionReason,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};

fn apply(archive: Vec<u8>, root: Dir, policy: Policy) -> ExtractionReport {
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(archive))
        .expect("prepare immutable archive");
    let plan = session.plan(policy).expect("preflight archive");
    session
        .apply(plan, root)
        .expect("apply preflighted archive")
        .into_extraction()
}

fn fixture() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (path, body) in [
        (&b"safe.txt"[..], &b"safe"[..]),
        (&b"/absolute.txt"[..], &b"bad"[..]),
        (&b"existing.txt"[..], &b"replace"[..]),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(body).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

fn link_fixture(hardlink_first: bool) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    let file = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"target.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    let hardlink = EntryMetadata::builder(
        EntryKind::Hardlink,
        ArchivePath::from_bytes(b"hard.txt".to_vec()),
    )
    .size(Some(0))
    .link_target(Some(ArchivePath::from_bytes(b"target.txt".to_vec())))
    .build();
    if hardlink_first {
        writer.start_entry(&hardlink).unwrap();
        writer.end_entry().unwrap();
    }
    writer.start_entry(&file).unwrap();
    writer.write_data(b"payload").unwrap();
    writer.end_entry().unwrap();
    if !hardlink_first {
        writer.start_entry(&hardlink).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

fn thin_ar_fixture() -> Vec<u8> {
    let mut archive = b"!<thin>\n".to_vec();
    for (value, width) in [
        (b"external.o/".as_slice(), 16),
        (b"0".as_slice(), 12),
        (b"0".as_slice(), 6),
        (b"0".as_slice(), 6),
        (b"100644".as_slice(), 8),
        (b"1234".as_slice(), 10),
    ] {
        archive.extend_from_slice(value);
        archive.resize(archive.len() + width - value.len(), b' ');
    }
    archive.extend_from_slice(b"`\n");
    archive
}

#[cfg(windows)]
fn windows_alias_fixture() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (path, body) in [
        ("streamed.txt", b"first".as_slice()),
        ("STREAMED.TXT", b"alias".as_slice()),
        ("caf\u{00e9}.txt", b"nfc".as_slice()),
        ("cafe\u{0301}.txt", b"nfd".as_slice()),
    ] {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(body).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn safe_policy_rejects_absolute_and_existing_destinations() {
    let destination = tempfile::tempdir().unwrap();
    fs::write(destination.path().join("existing.txt"), b"original").unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let report = apply(fixture(), root, Policy::safe());

    assert_eq!(
        fs::read(destination.path().join("safe.txt")).unwrap(),
        b"safe"
    );
    assert_eq!(
        fs::read(destination.path().join("existing.txt")).unwrap(),
        b"original"
    );
    assert!(!destination.path().join("absolute.txt").exists());
    assert!(report.has_rejections());
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome.outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::UnsafePath)
    )));
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome.outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationExists)
    )));
}

#[cfg(windows)]
#[test]
fn planned_extraction_never_dispatches_a_second_windows_alias() {
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let report = apply(windows_alias_fixture(), root, Policy::safe());

    assert_eq!(
        fs::read(destination.path().join("streamed.txt")).unwrap(),
        b"first"
    );
    assert_eq!(
        fs::read(destination.path().join("caf\u{00e9}.txt")).unwrap(),
        b"nfc"
    );
    for index in [1, 3] {
        assert!(matches!(
            report.outcomes()[index].outcome(),
            EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
        ));
    }
    assert!(fs::read_dir(destination.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".libarchive-oxide-")
    }));
}

#[test]
fn planning_enforces_entry_and_path_limits_before_filesystem_application() {
    let destination = tempfile::tempdir().unwrap();
    let limits = Limits::default().with_entries(Some(0));
    let error = ArchiveEngine::new()
        .with_limits(limits)
        .prepare(Cursor::new(fixture()))
        .and_then(|mut session| session.plan(Policy::safe()).map(drop))
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!destination.path().join("safe.txt").exists());

    let destination = tempfile::tempdir().unwrap();
    let limits = Limits::default().with_path_bytes(Some(4));
    let error = ArchiveEngine::new()
        .with_limits(limits)
        .prepare(Cursor::new(fixture()))
        .and_then(|mut session| session.plan(Policy::safe()).map(drop))
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!destination.path().join("safe.txt").exists());
}

#[test]
fn interrupted_archive_never_commits_partial_file() {
    let mut archive = fixture();
    archive.truncate(600);
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let result = ArchiveEngine::new()
        .prepare(Cursor::new(archive))
        .and_then(|mut session| {
            let plan = session.plan(Policy::safe())?;
            session.apply(plan, root).map(drop)
        });
    assert!(result.is_err());
    assert!(!destination.path().join("safe.txt").exists());
    assert!(
        fs::read_dir(destination.path()).unwrap().all(|item| !item
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp"))
    );
}

#[test]
fn restore_overwrite_atomically_replaces_only_regular_files() {
    let destination = tempfile::tempdir().unwrap();
    fs::write(destination.path().join("existing.txt"), b"original").unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let policy = Policy::restore().allow_overwrite(true);
    let report = apply(fixture(), root, policy);

    assert_eq!(
        fs::read(destination.path().join("existing.txt")).unwrap(),
        b"replace"
    );
    assert!(matches!(
        report.outcomes()[2].outcome(),
        EntryOutcomeKind::File
    ));
}

#[test]
fn restore_hardlinks_only_target_files_committed_earlier_in_the_session() {
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let policy = Policy::restore().allow_hardlinks(true);
    let report = apply(link_fixture(false), root, policy);

    assert_eq!(
        fs::read(destination.path().join("hard.txt")).unwrap(),
        b"payload"
    );
    assert!(matches!(
        report.outcomes()[1].outcome(),
        EntryOutcomeKind::Hardlink
    ));

    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let report = apply(link_fixture(true), root, policy);
    assert!(!destination.path().join("hard.txt").exists());
    assert!(matches!(
        report.outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::UnsafeLinkTarget)
    ));
}

#[test]
fn thin_ar_external_references_are_never_materialized() {
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let report = apply(thin_ar_fixture(), root, Policy::safe());
    assert!(!destination.path().join("external.o").exists());
    assert!(matches!(
        report.outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::ExternalReference)
    ));
}

#[cfg(not(windows))]
#[test]
fn restore_symlink_requires_explicit_capability_and_safe_relative_target() {
    let mut writer = ArchiveWriter::new(Vec::new());
    let symlink = EntryMetadata::builder(
        EntryKind::Symlink,
        ArchivePath::from_bytes(b"link.txt".to_vec()),
    )
    .size(Some(0))
    .link_target(Some(ArchivePath::from_bytes(b"target.txt".to_vec())))
    .build();
    writer.start_entry(&symlink).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let destination = tempfile::tempdir().unwrap();
    fs::write(destination.path().join("target.txt"), b"payload").unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let policy = Policy::restore().allow_symlinks(true);
    let report = apply(archive, root, policy);

    assert_eq!(
        fs::read_link(destination.path().join("link.txt")).unwrap(),
        std::path::Path::new("target.txt")
    );
    assert!(matches!(
        report.outcomes()[0].outcome(),
        EntryOutcomeKind::Symlink
    ));
}
