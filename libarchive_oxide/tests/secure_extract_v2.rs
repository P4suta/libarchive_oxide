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
    ArchiveReader, ArchiveWriter, EntryOutcomeKind, ExtractionPolicy, Extractor, RejectionReason,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};

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

#[test]
fn safe_policy_rejects_absolute_and_existing_destinations() {
    let destination = tempfile::tempdir().unwrap();
    fs::write(destination.path().join("existing.txt"), b"original").unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let mut extractor = Extractor::with_policy(root, ExtractionPolicy::safe());
    let mut reader = ArchiveReader::new(Cursor::new(fixture()));
    let report = extractor.extract(&mut reader).unwrap();

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

#[test]
fn extractor_enforces_its_own_entry_and_path_limits() {
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let limits = Limits::default().with_entries(Some(0));
    let mut extractor = Extractor::with_limits(root, limits);
    let mut reader = ArchiveReader::new(Cursor::new(fixture()));
    let error = extractor.extract(&mut reader).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!destination.path().join("safe.txt").exists());

    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let limits = Limits::default().with_path_bytes(Some(4));
    let mut extractor = Extractor::with_limits(root, limits);
    let mut reader = ArchiveReader::new(Cursor::new(fixture()));
    let error = extractor.extract(&mut reader).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(!destination.path().join("safe.txt").exists());
}

#[test]
fn interrupted_archive_never_commits_partial_file() {
    let mut archive = fixture();
    archive.truncate(600);
    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let mut extractor = Extractor::new(root);
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    assert!(extractor.extract(&mut reader).is_err());
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
    let policy = ExtractionPolicy::restore().allow_overwrite(true);
    let mut extractor = Extractor::with_policy(root, policy);
    let mut reader = ArchiveReader::new(Cursor::new(fixture()));
    let report = extractor.extract(&mut reader).unwrap();

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
    let policy = ExtractionPolicy::restore().allow_hardlinks(true);
    let mut extractor = Extractor::with_policy(root, policy);
    let mut reader = ArchiveReader::new(Cursor::new(link_fixture(false)));
    let report = extractor.extract(&mut reader).unwrap();

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
    let mut extractor = Extractor::with_policy(root, policy);
    let mut reader = ArchiveReader::new(Cursor::new(link_fixture(true)));
    let report = extractor.extract(&mut reader).unwrap();
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
    let mut extractor = Extractor::new(root);
    let mut reader = ArchiveReader::new(Cursor::new(thin_ar_fixture()));
    let report = extractor.extract(&mut reader).unwrap();
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
    let policy = ExtractionPolicy::restore().allow_symlinks(true);
    let mut extractor = Extractor::with_policy(root, policy);
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    let report = extractor.extract(&mut reader).unwrap();

    assert_eq!(
        fs::read_link(destination.path().join("link.txt")).unwrap(),
        std::path::Path::new("target.txt")
    );
    assert!(matches!(
        report.outcomes()[0].outcome(),
        EntryOutcomeKind::Symlink
    ));
}
