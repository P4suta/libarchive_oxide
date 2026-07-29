// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability-reporting filesystem adapter contracts.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{self, Cursor};
use std::path::Component;
#[cfg(unix)]
use std::path::PathBuf;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
#[cfg(unix)]
use libarchive_oxide::CapStdFilesystemAdapter;
use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, EntryOutcomeKind, FilesystemAdapter, FilesystemAdapterError,
    FilesystemCapabilities, FilesystemEntry, FilesystemEntryReport, FilesystemFinding,
    FilesystemFindingKind, FilesystemMaterialization, FilesystemOperation, PlanDisposition, Policy,
    RejectionReason,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, EntryTimes, Timestamp};
#[cfg(target_os = "linux")]
use libarchive_oxide_core::{Owner, SparseExtent};

fn archive(metadata: &EntryMetadata, logical: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(metadata).expect("start fixture entry");
    writer.write_data(logical).expect("write fixture payload");
    writer.end_entry().expect("end fixture entry");
    writer.finish().expect("finish fixture")
}

fn archive_many(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (path, logical) in entries {
        let metadata = regular_metadata(path, logical.len());
        writer.start_entry(&metadata).expect("start fixture entry");
        writer.write_data(logical).expect("write fixture payload");
        writer.end_entry().expect("end fixture entry");
    }
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

#[cfg(unix)]
#[derive(Debug)]
struct AncestorSwapAdapter {
    inner: CapStdFilesystemAdapter,
    root: PathBuf,
    outside: PathBuf,
    swapped: bool,
}

#[cfg(unix)]
impl FilesystemAdapter for AncestorSwapAdapter {
    fn capabilities(&self) -> FilesystemCapabilities {
        self.inner.capabilities()
    }

    fn begin_session(&mut self) -> Result<(), FilesystemAdapterError> {
        self.inner.begin_session()
    }

    fn begin_entry(&mut self, entry: FilesystemEntry<'_>) -> Result<(), FilesystemAdapterError> {
        self.inner.begin_entry(entry)
    }

    fn write_data(&mut self, data: &[u8]) -> Result<(), FilesystemAdapterError> {
        self.inner.write_data(data)
    }

    fn finish_entry(&mut self) -> Result<FilesystemEntryReport, FilesystemAdapterError> {
        if !self.swapped {
            let original = self.root.join("pivot");
            let held = self.root.join("pivot-held");
            let temporary = std::fs::read_dir(&original)
                .expect("created extraction parent")
                .map(|entry| entry.expect("temporary entry").file_name())
                .find(|name| name.to_string_lossy().starts_with(".libarchive-oxide-"))
                .expect("temporary sibling");
            std::fs::rename(&original, &held).expect("move prepared parent");
            std::os::unix::fs::symlink(&self.outside, &original)
                .expect("replace parent with outside symlink");
            std::fs::write(self.outside.join(temporary), b"attacker-controlled")
                .expect("plant matching temporary name outside");
            self.swapped = true;
        }
        self.inner.finish_entry()
    }

    fn abort_entry(&mut self) {
        self.inner.abort_entry();
    }

    fn finish_session(&mut self) -> Result<Vec<FilesystemFinding>, FilesystemAdapterError> {
        self.inner.finish_session()
    }
}

#[cfg(unix)]
#[test]
fn atomic_commit_is_bound_to_the_prepared_parent_directory_handle() {
    let bytes = archive_many(&[("pivot/escaped.txt", b"archive-payload")]);
    let destination = tempfile::tempdir().expect("destination");
    let outside = tempfile::tempdir().expect("outside directory");
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).expect("root");
    let mut adapter = AncestorSwapAdapter {
        inner: CapStdFilesystemAdapter::new(root),
        root: destination.path().to_path_buf(),
        outside: outside.path().to_path_buf(),
        swapped: false,
    };
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("prepare");
    let plan = session.plan(Policy::safe()).expect("plan");
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("apply through race injector");

    assert!(matches!(
        report.extraction().outcomes()[0].outcome(),
        EntryOutcomeKind::File
    ));
    assert_eq!(
        std::fs::read(destination.path().join("pivot-held/escaped.txt"))
            .expect("file committed through stable parent handle"),
        b"archive-payload"
    );
    assert!(
        !outside.path().join("escaped.txt").exists(),
        "ancestor replacement redirected the atomic commit outside the root"
    );
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
        modified: Some(Timestamp::from_seconds(1_700_000_000)),
        changed: Some(Timestamp::from_seconds(1_700_000_001)),
        ..EntryTimes::default()
    })
    .xattr(b"user.rm104".to_vec(), b"evidence".to_vec())
    .build();
    let bytes = archive(&metadata, b"payload");
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
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
        .prepare(Cursor::new(archive(&metadata, b"bad")))
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
        .prepare(Cursor::new(bytes.clone()))
        .expect("first");
    let foreign_plan = first.plan(Policy::safe()).expect("foreign plan");
    let mut second = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
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
        .prepare(Cursor::new(archive(&metadata, b"x")))
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
fn late_topology_collision_is_preflighted_before_any_entry_dispatch() {
    let bytes = archive_many(&[("node", b"first"), ("node/child", b"must-not-dispatch")]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("whole-archive plan");
    assert_eq!(
        plan.entries()[1].disposition(),
        PlanDisposition::Reject(RejectionReason::DestinationCollision)
    );

    let mut adapter =
        RecordingAdapter::successful(FilesystemCapabilities::none().with_atomic_commit(true));
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("apply authoritative plan");

    assert_eq!(adapter.begin_sessions, 1);
    assert_eq!(adapter.begin_entries, 1);
    assert_eq!(adapter.payload, b"first");
    assert!(matches!(
        report.extraction().outcomes()[1].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
    ));
}

#[cfg(windows)]
#[test]
fn windows_alias_collisions_are_refused_before_adapter_dispatch() {
    let bytes = archive_many(&[
        ("name.txt", b"case-first"),
        ("NAME.TXT", b"case-alias"),
        ("caf\u{00e9}.txt", b"nfc-first"),
        ("cafe\u{0301}.txt", b"nfd-alias"),
    ]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let mut adapter =
        RecordingAdapter::successful(FilesystemCapabilities::none().with_atomic_commit(true));
    let report = session
        .apply_with_adapter(plan, &mut adapter)
        .expect("typed alias rejections");

    assert_eq!(adapter.begin_sessions, 1);
    assert_eq!(adapter.begin_entries, 2);
    assert_eq!(adapter.payload, b"case-firstnfc-first");
    assert!(matches!(
        report.extraction().outcomes()[1].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
    ));
    assert!(matches!(
        report.extraction().outcomes()[3].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
    ));
}

#[cfg(windows)]
#[test]
fn windows_real_filesystem_refuses_aliases_without_leaking_temporary_files() {
    let bytes = archive_many(&[
        ("published.txt", b"committed"),
        ("PUBLISHED.TXT", b"must-not-replace"),
        ("trailing.", b"must-not-write"),
        ("trailing-space ", b"must-not-write"),
        ("NUL.txt", b"must-not-write"),
        ("published.txt:secret", b"must-not-write"),
        ("caf\u{00e9}.txt", b"nfc"),
        ("cafe\u{0301}.txt", b"must-not-replace"),
    ]);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(bytes))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let destination = tempfile::tempdir().expect("destination");
    let report = session
        .apply(plan, capability(destination.path()))
        .expect("apply");

    assert_eq!(
        std::fs::read(destination.path().join("published.txt")).expect("published payload"),
        b"committed"
    );
    assert!(matches!(
        report.extraction().outcomes()[1].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
    ));
    for outcome in &report.extraction().outcomes()[2..6] {
        assert!(matches!(
            outcome.outcome(),
            EntryOutcomeKind::Rejected(RejectionReason::UnsafePath)
        ));
    }
    assert!(matches!(
        report.extraction().outcomes()[7].outcome(),
        EntryOutcomeKind::Rejected(RejectionReason::DestinationCollision)
    ));
    assert_eq!(
        std::fs::read(destination.path().join("caf\u{00e9}.txt")).expect("NFC payload"),
        b"nfc"
    );
    let mut names = std::fs::read_dir(destination.path())
        .expect("list destination")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        vec![
            std::ffi::OsString::from("caf\u{00e9}.txt"),
            std::ffi::OsString::from("published.txt"),
        ]
    );
}

#[test]
fn destination_appearing_after_plan_is_not_replaced() {
    let metadata = regular_metadata("race.bin", 7);
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(archive(&metadata, b"archive")))
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
        .prepare(Cursor::new(archive(&metadata, b"payload")))
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
    let timestamp = Timestamp::new(1_700_000_000, 123_000_000).expect("valid timestamp");
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
        .sparse_extent(SparseExtent::new(0, 1).expect("valid sparse extent"))
        .sparse_extent(SparseExtent::new(logical_size as u64 - 1, 1).expect("valid sparse extent"))
        .xattr(b"user.rm104".to_vec(), b"evidence".to_vec())
        .acl(b"user::rw-,group::r--,other::---".to_vec())
        .build();
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(archive(&metadata, &logical)))
        .expect("session");
    let plan = session.plan(Policy::safe()).expect("plan");
    let report = session
        .apply(plan, capability(destination.path()))
        .expect("apply");
    let output = destination.path().join("sparse.bin");
    let filesystem_metadata = std::fs::metadata(&output).expect("output metadata");

    assert_eq!(std::fs::read(&output).expect("output payload"), logical);
    assert_eq!(filesystem_metadata.mode() & 0o7777, 0o640);
    assert_eq!(filesystem_metadata.mtime(), timestamp.seconds());
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
