// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability-reporting filesystem adapter contracts.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{self, Cursor};
use std::path::Component;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, Timestamp,
};
#[cfg(target_os = "linux")]
use libarchive_oxide::libarchive_oxide_core::{Owner, SparseExtent};
use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, EntryOutcomeKind, FilesystemAdapter, FilesystemAdapterError,
    FilesystemCapabilities, FilesystemEntry, FilesystemEntryReport, FilesystemFinding,
    FilesystemFindingKind, FilesystemMaterialization, FilesystemOperation, Policy, RejectionReason,
};

fn archive(metadata: &EntryMetadata, logical: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(metadata).expect("start fixture entry");
    writer.write_data(logical).expect("write fixture payload");
    writer.end_entry().expect("end fixture entry");
    writer.finish().expect("finish fixture")
}

fn regular_metadata(path: &str, size: usize) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(path))
        .size(Some(size as u64))
        .build()
}

#[derive(Debug)]
struct RecordingAdapter {
    capabilities: FilesystemCapabilities,
    current: Option<(ArchivePath, EntryKind)>,
    payload: Vec<u8>,
    begin_sessions: usize,
    begin_entries: usize,
    fail_entry: bool,
}

impl RecordingAdapter {
    fn successful(capabilities: FilesystemCapabilities) -> Self {
        Self {
            capabilities,
            current: None,
            payload: Vec::new(),
            begin_sessions: 0,
            begin_entries: 0,
            fail_entry: false,
        }
    }

    fn failing() -> Self {
        let mut adapter = Self::successful(FilesystemCapabilities::none().with_atomic_commit(true));
        adapter.fail_entry = true;
        adapter
    }
}

impl FilesystemAdapter for RecordingAdapter {
    fn capabilities(&self) -> FilesystemCapabilities {
        self.capabilities
    }

    fn begin_session(&mut self) -> Result<(), FilesystemAdapterError> {
        self.begin_sessions += 1;
        self.current = None;
        self.payload.clear();
        Ok(())
    }

    fn begin_entry(&mut self, entry: FilesystemEntry<'_>) -> Result<(), FilesystemAdapterError> {
        assert!(
            entry
                .destination()
                .components()
                .all(|component| { matches!(component, Component::Normal(_)) })
        );
        assert!(self.current.is_none());
        self.begin_entries += 1;
        self.current = Some((entry.metadata().path().clone(), entry.metadata().kind()));
        Ok(())
    }

    fn write_data(&mut self, data: &[u8]) -> Result<(), FilesystemAdapterError> {
        if self.current.is_none() {
            return Err(FilesystemAdapterError::protocol("data without entry"));
        }
        self.payload.extend_from_slice(data);
        Ok(())
    }

    fn finish_entry(&mut self) -> Result<FilesystemEntryReport, FilesystemAdapterError> {
        let (path, kind) = self
            .current
            .take()
            .ok_or_else(|| FilesystemAdapterError::protocol("finish without entry"))?;
        if self.fail_entry {
            let error = io::Error::new(io::ErrorKind::PermissionDenied, "injected refusal");
            return Ok(FilesystemEntryReport::new(
                FilesystemMaterialization::Failed,
                vec![FilesystemFinding::os_error(
                    path,
                    FilesystemOperation::Entry,
                    "injected adapter failure",
                    &error,
                )],
            ));
        }
        let materialization = match kind {
            EntryKind::File => FilesystemMaterialization::File,
            EntryKind::Dir => FilesystemMaterialization::Directory,
            EntryKind::Symlink => FilesystemMaterialization::Symlink,
            EntryKind::Hardlink => FilesystemMaterialization::Hardlink,
            _ => FilesystemMaterialization::Special,
        };
        let mut findings = vec![FilesystemFinding::applied(
            path.clone(),
            FilesystemOperation::Entry,
        )];
        if kind == EntryKind::File {
            findings.push(FilesystemFinding::applied(
                path,
                FilesystemOperation::AtomicCommit,
            ));
        }
        Ok(FilesystemEntryReport::new(materialization, findings))
    }

    fn abort_entry(&mut self) {
        self.current = None;
    }

    fn finish_session(&mut self) -> Result<Vec<FilesystemFinding>, FilesystemAdapterError> {
        if self.current.is_some() {
            return Err(FilesystemAdapterError::protocol("session ended with entry"));
        }
        Ok(Vec::new())
    }
}

#[test]
fn custom_adapter_receives_normalized_stream_and_missing_fidelity_is_typed() {
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_utf8("nested/payload.bin"),
    )
    .size(Some(7))
    .mode(Some(0o640))
    .times(EntryTimes {
        modified: Some(Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        }),
        changed: Some(Timestamp {
            secs: 1_700_000_001,
            nanos: 0,
        }),
        ..EntryTimes::default()
    })
    .xattr(b"user.rm104".to_vec(), b"evidence".to_vec())
    .build();
    let bytes = archive(&metadata, b"payload");
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(bytes))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let capabilities = FilesystemCapabilities::none()
        .with_atomic_commit(true)
        .with_mode(true)
        .with_modification_time(true);
    let mut adapter = RecordingAdapter::successful(capabilities);
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("apply");

    assert_eq!(adapter.payload, b"payload");
    assert_eq!(adapter.begin_sessions, 1);
    assert_eq!(adapter.begin_entries, 1);
    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::File
    ));
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::Mode
            && finding.kind() == FilesystemFindingKind::Partial
    }));
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::ModificationTime
            && finding.kind() == FilesystemFindingKind::Partial
    }));
    assert!(report.filesystem_findings().iter().any(|finding| {
        matches!(finding.operation(), FilesystemOperation::ExtendedAttribute(name) if name == b"user.rm104")
            && finding.kind() == FilesystemFindingKind::Unsupported
    }));
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::ChangeTime
            && finding.kind() == FilesystemFindingKind::Unsupported
    }));
    assert!(report.has_filesystem_findings());
}

#[test]
fn adapter_os_errors_remain_in_the_apply_report() {
    let metadata = regular_metadata("failed.bin", 3);
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(archive(&metadata, b"bad")))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let mut adapter = RecordingAdapter::failing();
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("typed failure report");

    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::FilesystemError)
    ));
    let finding = report
        .filesystem_findings()
        .iter()
        .find(|finding| {
            finding.operation() == &FilesystemOperation::Entry
                && finding.kind() == FilesystemFindingKind::OsError
        })
        .expect("OS error finding");
    assert_eq!(
        finding.io_error_kind(),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(finding.detail(), "injected adapter failure");
}
fn capability(path: &std::path::Path) -> Dir {
    Dir::open_ambient_dir(path, ambient_authority()).expect("open capability")
}

#[test]
fn session_mismatch_does_not_touch_the_adapter() {
    let metadata = regular_metadata("identity.bin", 1);
    let bytes = archive(&metadata, b"x");
    let mut first = ArchiveEngine::new()
        .open(Cursor::new(bytes.clone()))
        .expect("first");
    let foreign_plan = first.plan(Policy::safe()).expect("foreign plan");
    let mut second = ArchiveEngine::new()
        .open(Cursor::new(bytes))
        .expect("second");
    let mut adapter =
        RecordingAdapter::successful(FilesystemCapabilities::none().with_atomic_commit(true));
    assert!(
        second
            .apply_with_adapter(foreign_plan, &mut adapter)
            .is_err()
    );
    assert_eq!(adapter.begin_sessions, 0);
    assert_eq!(adapter.begin_entries, 0);
}

#[test]
fn unsafe_paths_are_refused_before_adapter_dispatch() {
    let metadata = regular_metadata("../escape.bin", 1);
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(archive(&metadata, b"x")))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let mut adapter =
        RecordingAdapter::successful(FilesystemCapabilities::none().with_atomic_commit(true));
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("typed rejection");

    assert_eq!(adapter.begin_entries, 0);
    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::UnsafePath)
    ));
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::Entry
            && finding.kind() == FilesystemFindingKind::Refused
    }));
}

#[test]
fn destination_appearing_after_plan_is_not_replaced() {
    let metadata = regular_metadata("race.bin", 7);
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(archive(&metadata, b"archive")))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let destination = tempfile::tempdir().expect("destination");
    std::fs::write(destination.path().join("race.bin"), b"external").expect("inject race");
    let report = session
        .apply(plan, capability(destination.path()))
        .expect("apply");

    assert_eq!(
        std::fs::read(destination.path().join("race.bin")).expect("read destination"),
        b"external"
    );
    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationExists)
    ));
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::Entry
            && finding.kind() == FilesystemFindingKind::Refused
    }));
    assert!(
        std::fs::read_dir(destination.path())
            .expect("list destination")
            .all(|item| {
                !item
                    .expect("directory item")
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp")
            })
    );
}

#[test]
fn standard_shortcut_reports_atomic_commit_success() {
    let metadata = regular_metadata("committed.bin", 7);
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(archive(&metadata, b"payload")))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let destination = tempfile::tempdir().expect("destination");
    let report = session
        .apply(plan, capability(destination.path()))
        .expect("apply");

    assert_eq!(
        std::fs::read(destination.path().join("committed.bin")).expect("read committed"),
        b"payload"
    );
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::AtomicCommit
            && finding.kind() == FilesystemFindingKind::Applied
    }));
    assert!(!report.filesystem_findings().iter().any(|finding| {
        matches!(
            finding.operation(),
            FilesystemOperation::Entry | FilesystemOperation::AtomicCommit
        ) && finding.kind() != FilesystemFindingKind::Applied
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_reference_adapter_restores_mode_time_xattr_acl_and_sparse_layout() {
    use std::os::unix::fs::MetadataExt;

    let destination = tempfile::tempdir().expect("destination");
    let root_metadata = std::fs::metadata(destination.path()).expect("root metadata");
    let logical_size = 1024 * 1024;
    let mut logical = vec![0_u8; logical_size];
    logical[0] = b'A';
    logical[logical_size - 1] = b'Z';
    let timestamp = Timestamp {
        secs: 1_700_000_000,
        nanos: 123_000_000,
    };
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse.bin"))
        .size(Some(logical_size as u64))
        .mode(Some(0o640))
        .owner(Owner {
            uid: Some(root_metadata.uid().into()),
            gid: Some(root_metadata.gid().into()),
            user: None,
            group: None,
        })
        .times(EntryTimes {
            accessed: Some(timestamp),
            modified: Some(timestamp),
            ..EntryTimes::default()
        })
        .sparse_extent(SparseExtent {
            offset: 0,
            length: 1,
        })
        .sparse_extent(SparseExtent {
            offset: logical_size as u64 - 1,
            length: 1,
        })
        .xattr(b"user.rm104".to_vec(), b"evidence".to_vec())
        .acl(b"user::rw-,group::r--,other::---".to_vec())
        .build();
    let mut session = ArchiveEngine::new()
        .open(Cursor::new(archive(&metadata, &logical)))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let report = session
        .apply(plan, capability(destination.path()))
        .expect("apply");
    let output = destination.path().join("sparse.bin");
    let filesystem_metadata = std::fs::metadata(&output).expect("output metadata");

    assert_eq!(std::fs::read(&output).expect("output payload"), logical);
    assert_eq!(filesystem_metadata.mode() & 0o7777, 0o640);
    assert_eq!(filesystem_metadata.mtime(), timestamp.secs);
    assert!(filesystem_metadata.blocks() * 512 < logical_size as u64);
    for operation in [
        FilesystemOperation::Mode,
        FilesystemOperation::Ownership,
        FilesystemOperation::AccessTime,
        FilesystemOperation::ModificationTime,
        FilesystemOperation::Sparse,
        FilesystemOperation::ExtendedAttribute(b"user.rm104".to_vec()),
        FilesystemOperation::Acl(0),
    ] {
        assert!(
            report.filesystem_findings().iter().any(|finding| {
                finding.operation() == &operation
                    && finding.kind() == FilesystemFindingKind::Applied
            }),
            "missing applied finding for {operation:?}"
        );
    }
    assert!(!report.has_filesystem_findings());
}
