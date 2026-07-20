// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared event-to-filesystem adapter driver.

use std::collections::BTreeSet;
use std::io::{Read, Seek};
use std::path::PathBuf;

use libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits,
};

use crate::extractor::{
    EntryOutcome, EntryOutcomeKind, ExtractionPolicy, ExtractionReport, RejectionReason,
};
use crate::filesystem::{
    FilesystemAdapter, FilesystemCapabilities, FilesystemEntry, FilesystemFinding,
    FilesystemFindingKind, FilesystemMaterialization, FilesystemOperation,
};
use crate::path::sanitize_archive_path;
use crate::provider::{StaticCodecProviders, StaticFormatProviders};
use crate::{ArchiveReader, ReaderEvent, SeekArchiveReader, StreamError};

pub(crate) struct AdapterExtraction {
    pub(crate) extraction: ExtractionReport,
    pub(crate) findings: Vec<FilesystemFinding>,
}

struct CurrentEntry {
    path: ArchivePath,
    kind: EntryKind,
    materializing: bool,
    direct_outcome: Option<EntryOutcomeKind>,
    requests: Vec<FilesystemOperation>,
}
enum Preflight<T> {
    Ready(T),
    Rejected,
}

struct AdapterDriver<'a, A: FilesystemAdapter> {
    adapter: &'a mut A,
    policy: ExtractionPolicy,
    limits: Limits,
    capabilities: FilesystemCapabilities,
    extraction: ExtractionReport,
    findings: Vec<FilesystemFinding>,
    expected: Vec<(ArchivePath, FilesystemOperation)>,
    committed_files: BTreeSet<PathBuf>,
    current: Option<CurrentEntry>,
    entries_seen: u64,
}

impl<'a, A: FilesystemAdapter> AdapterDriver<'a, A> {
    fn new(
        adapter: &'a mut A,
        policy: ExtractionPolicy,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        let capabilities = adapter.capabilities();
        adapter.begin_session().map_err(adapter_error)?;
        Ok(Self {
            adapter,
            policy,
            limits,
            capabilities,
            extraction: ExtractionReport::default(),
            findings: Vec::new(),
            expected: Vec::new(),
            committed_files: BTreeSet::new(),
            current: None,
            entries_seen: 0,
        })
    }

    fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        if self.current.is_some() {
            return Err(protocol_error(
                "entry began before the preceding entry ended",
            ));
        }
        self.observe_entry(metadata)?;
        let path = metadata.path().clone();
        let requests = requested_operations(metadata);
        self.expected.extend(
            requests
                .iter()
                .cloned()
                .map(|operation| (path.clone(), operation)),
        );
        let destination = match self.destination_for(metadata, &requests) {
            Preflight::Ready(destination) => destination,
            Preflight::Rejected => return Ok(()),
        };
        let link_target = match self.link_target_for(metadata, &requests) {
            Preflight::Ready(target) => target,
            Preflight::Rejected => return Ok(()),
        };
        if !self.entry_kind_allowed(metadata, &requests) {
            return Ok(());
        }
        for operation in &requests {
            if !self.capabilities.supports(operation) {
                self.findings.push(FilesystemFinding::unsupported(
                    path.clone(),
                    operation.clone(),
                    "filesystem adapter does not advertise this metadata capability",
                ));
            }
        }
        self.adapter
            .begin_entry(FilesystemEntry::new(
                metadata,
                &destination,
                link_target.as_deref(),
                self.policy.overwrites(),
            ))
            .map_err(adapter_error)?;
        self.current = Some(CurrentEntry {
            path,
            kind: metadata.kind(),
            materializing: true,
            direct_outcome: None,
            requests,
        });
        Ok(())
    }

    fn destination_for(
        &mut self,
        metadata: &EntryMetadata,
        requests: &[FilesystemOperation],
    ) -> Preflight<PathBuf> {
        let path = metadata.path().clone();
        if metadata.extensions().iter().any(|extension| {
            extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
        }) {
            self.reject(
                metadata,
                requests,
                RejectionReason::ExternalReference,
                "external archive references are never materialized",
            );
            return Preflight::Rejected;
        }
        if metadata.kind() == EntryKind::Dir && matches!(path.as_bytes(), b"." | b"./") {
            self.findings.push(FilesystemFinding::applied(
                path.clone(),
                FilesystemOperation::Entry,
            ));
            self.current = Some(CurrentEntry {
                path,
                kind: metadata.kind(),
                materializing: false,
                direct_outcome: Some(EntryOutcomeKind::Skipped),
                requests: requests.to_vec(),
            });
            return Preflight::Rejected;
        }
        if let Some(destination) = sanitize_archive_path(&path) {
            Preflight::Ready(destination)
        } else {
            self.reject(
                metadata,
                requests,
                RejectionReason::UnsafePath,
                "archive path is unsafe or cannot be represented",
            );
            Preflight::Rejected
        }
    }

    fn link_target_for(
        &mut self,
        metadata: &EntryMetadata,
        requests: &[FilesystemOperation],
    ) -> Preflight<Option<PathBuf>> {
        match metadata.kind() {
            EntryKind::Symlink => {
                if !self.policy.symlinks() {
                    self.reject(
                        metadata,
                        requests,
                        RejectionReason::EntryKind,
                        "symbolic-link restoration is disabled by policy",
                    );
                    return Preflight::Rejected;
                }
                if !self.capabilities.symlinks() {
                    self.reject(
                        metadata,
                        requests,
                        RejectionReason::UnsupportedRestore,
                        "filesystem adapter does not support symbolic links",
                    );
                    return Preflight::Rejected;
                }
                if let Some(target) = metadata.link_target().and_then(sanitize_archive_path) {
                    Preflight::Ready(Some(target))
                } else {
                    self.reject(
                        metadata,
                        requests,
                        RejectionReason::UnsafeLinkTarget,
                        "symbolic-link target is absent or unsafe",
                    );
                    Preflight::Rejected
                }
            },
            EntryKind::Hardlink => self.hardlink_target_for(metadata, requests),
            _ => Preflight::Ready(None),
        }
    }

    fn hardlink_target_for(
        &mut self,
        metadata: &EntryMetadata,
        requests: &[FilesystemOperation],
    ) -> Preflight<Option<PathBuf>> {
        if !self.policy.hardlinks() {
            self.reject(
                metadata,
                requests,
                RejectionReason::EntryKind,
                "hard-link restoration is disabled by policy",
            );
            return Preflight::Rejected;
        }
        if !self.capabilities.hardlinks() {
            self.reject(
                metadata,
                requests,
                RejectionReason::UnsupportedRestore,
                "filesystem adapter does not support hard links",
            );
            return Preflight::Rejected;
        }
        if let Some(target) = metadata
            .link_target()
            .and_then(sanitize_archive_path)
            .filter(|target| self.committed_files.contains(target))
        {
            Preflight::Ready(Some(target))
        } else {
            self.reject(
                metadata,
                requests,
                RejectionReason::UnsafeLinkTarget,
                "hard-link target was not committed earlier in this session",
            );
            Preflight::Rejected
        }
    }

    fn entry_kind_allowed(
        &mut self,
        metadata: &EntryMetadata,
        requests: &[FilesystemOperation],
    ) -> bool {
        let rejection = match metadata.kind() {
            EntryKind::File if !self.capabilities.atomic_commit() => Some((
                RejectionReason::UnsupportedRestore,
                "filesystem adapter cannot atomically publish regular files",
            )),
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
                if !self.policy.special_files() =>
            {
                Some((
                    RejectionReason::EntryKind,
                    "special-file restoration is disabled by policy",
                ))
            },
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
                if !self.capabilities.special_files() =>
            {
                Some((
                    RejectionReason::UnsupportedRestore,
                    "filesystem adapter does not support special files",
                ))
            },
            kind if !self.capabilities.supports_entry(kind) => Some((
                RejectionReason::EntryKind,
                "entry kind is not supported by the filesystem adapter",
            )),
            _ => None,
        };
        if let Some((reason, detail)) = rejection {
            self.reject(metadata, requests, reason, detail);
            false
        } else {
            true
        }
    }

    fn reject(
        &mut self,
        metadata: &EntryMetadata,
        requests: &[FilesystemOperation],
        reason: RejectionReason,
        detail: &'static str,
    ) {
        let path = metadata.path().clone();
        for operation in requests {
            self.findings.push(FilesystemFinding::refused(
                path.clone(),
                operation.clone(),
                detail,
            ));
        }
        self.current = Some(CurrentEntry {
            path,
            kind: metadata.kind(),
            materializing: false,
            direct_outcome: Some(EntryOutcomeKind::Rejected(reason)),
            requests: requests.to_vec(),
        });
    }
    fn write_data(&mut self, data: &[u8]) -> Result<(), StreamError> {
        let current = self
            .current
            .as_ref()
            .ok_or_else(|| protocol_error("archive data appeared outside an entry"))?;
        if current.materializing {
            self.adapter.write_data(data).map_err(adapter_error)?;
        }
        Ok(())
    }
    fn end_entry(&mut self) -> Result<(), StreamError> {
        let current = self
            .current
            .take()
            .ok_or_else(|| protocol_error("archive ended an entry that was not open"))?;
        if !current.materializing {
            self.extraction.push(EntryOutcome::new(
                current.path,
                current
                    .direct_outcome
                    .ok_or_else(|| protocol_error("non-materializing entry lost its outcome"))?,
            ));
            return Ok(());
        }

        let report = self.adapter.finish_entry().map_err(adapter_error)?;
        let (materialization, mut findings) = report.into_parts();
        let outcome = match materialization {
            FilesystemMaterialization::File if current.kind == EntryKind::File => {
                self.committed_files
                    .insert(sanitize_archive_path(&current.path).ok_or_else(|| {
                        protocol_error("adapter completed a file whose path became invalid")
                    })?);
                EntryOutcomeKind::File
            },
            FilesystemMaterialization::Directory if current.kind == EntryKind::Dir => {
                EntryOutcomeKind::Directory
            },
            FilesystemMaterialization::Symlink if current.kind == EntryKind::Symlink => {
                EntryOutcomeKind::Symlink
            },
            FilesystemMaterialization::Hardlink if current.kind == EntryKind::Hardlink => {
                self.committed_files
                    .insert(sanitize_archive_path(&current.path).ok_or_else(|| {
                        protocol_error("adapter completed a hard link whose path became invalid")
                    })?);
                EntryOutcomeKind::Hardlink
            },
            FilesystemMaterialization::Special
                if matches!(
                    current.kind,
                    EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
                ) =>
            {
                EntryOutcomeKind::Special
            },
            FilesystemMaterialization::DestinationExists => {
                fill_missing_findings(
                    &current.path,
                    &current.requests,
                    &mut findings,
                    FilesystemFindingKind::Refused,
                    "destination conflict prevented metadata restoration",
                );
                EntryOutcomeKind::Rejected(RejectionReason::DestinationExists)
            },
            FilesystemMaterialization::Failed => {
                fill_missing_findings(
                    &current.path,
                    &current.requests,
                    &mut findings,
                    FilesystemFindingKind::Refused,
                    "entry-level filesystem failure prevented metadata restoration",
                );
                EntryOutcomeKind::Rejected(RejectionReason::FilesystemError)
            },
            _ => {
                self.adapter.abort_entry();
                return Err(protocol_error(
                    "filesystem adapter returned a materialization kind that disagrees with the entry",
                ));
            },
        };
        self.findings.append(&mut findings);
        self.extraction
            .push(EntryOutcome::new(current.path, outcome));
        Ok(())
    }

    fn finish(mut self) -> Result<AdapterExtraction, StreamError> {
        if self.current.is_some() {
            self.adapter.abort_entry();
            return Err(StreamError::io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "archive ended with an incomplete entry",
            )));
        }
        if self.adapter.capabilities() != self.capabilities {
            return Err(protocol_error(
                "filesystem adapter capabilities changed during an apply session",
            ));
        }
        let mut deferred = self.adapter.finish_session().map_err(adapter_error)?;
        self.findings.append(&mut deferred);
        for (path, operation) in self.expected {
            if !self
                .findings
                .iter()
                .any(|finding| finding.path() == &path && finding.operation() == &operation)
            {
                self.findings.push(FilesystemFinding::partial(
                    path,
                    operation,
                    "adapter declared support but did not report the requested operation",
                ));
            }
        }
        Ok(AdapterExtraction {
            extraction: self.extraction,
            findings: self.findings,
        })
    }

    fn abort(&mut self) {
        self.adapter.abort_entry();
    }

    fn observe_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        let index = self.entries_seen;
        self.entries_seen = self.entries_seen.checked_add(1).ok_or_else(|| {
            limit_error(
                index,
                metadata.path(),
                "filesystem driver entry count overflowed",
            )
        })?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.entries_seen > maximum)
        {
            return Err(limit_error(
                index,
                metadata.path(),
                "filesystem driver entry count exceeds configured limit",
            ));
        }
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| metadata.path().as_bytes().len() > maximum)
        {
            return Err(limit_error(
                index,
                metadata.path(),
                "filesystem driver path length exceeds configured limit",
            ));
        }
        if self
            .limits
            .nesting()
            .is_some_and(|maximum| archive_path_nesting(metadata.path().as_bytes()) > maximum)
        {
            return Err(limit_error(
                index,
                metadata.path(),
                "filesystem driver path nesting exceeds configured limit",
            ));
        }
        Ok(())
    }
}

pub(crate) fn extract_registered_with_adapter<R, F, C, A>(
    reader: &mut ArchiveReader<R, F, C>,
    adapter: &mut A,
    policy: ExtractionPolicy,
    limits: Limits,
) -> Result<AdapterExtraction, StreamError>
where
    R: Read,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
    A: FilesystemAdapter,
{
    let mut driver = AdapterDriver::new(adapter, policy, limits)?;
    loop {
        let event = match reader.next_event() {
            Ok(event) => event,
            Err(error) => {
                driver.abort();
                return Err(error);
            },
        };
        match event {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => driver.start_entry(&metadata)?,
            ReaderEvent::Data(data) => driver.write_data(data)?,
            ReaderEvent::EndEntry => driver.end_entry()?,
            ReaderEvent::Done => return driver.finish(),
        }
    }
}

pub(crate) fn extract_seek_with_adapter<R, A>(
    reader: &mut SeekArchiveReader<R>,
    adapter: &mut A,
    policy: ExtractionPolicy,
    limits: Limits,
) -> Result<AdapterExtraction, StreamError>
where
    R: Read + Seek,
    A: FilesystemAdapter,
{
    let mut driver = AdapterDriver::new(adapter, policy, limits)?;
    loop {
        let event = match reader.next_event() {
            Ok(event) => event,
            Err(error) => {
                driver.abort();
                return Err(error);
            },
        };
        match event {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => driver.start_entry(&metadata)?,
            ReaderEvent::Data(data) => driver.write_data(data)?,
            ReaderEvent::EndEntry => driver.end_entry()?,
            ReaderEvent::Done => return driver.finish(),
        }
    }
}

fn requested_operations(metadata: &EntryMetadata) -> Vec<FilesystemOperation> {
    let mut operations = vec![FilesystemOperation::Entry];
    if metadata.kind() == EntryKind::File {
        operations.push(FilesystemOperation::AtomicCommit);
    }
    if metadata.mode().is_some() {
        operations.push(FilesystemOperation::Mode);
    }
    let owner = metadata.owner();
    if owner.uid.is_some() || owner.gid.is_some() || owner.user.is_some() || owner.group.is_some() {
        operations.push(FilesystemOperation::Ownership);
    }
    let times = metadata.times();
    if times.accessed.is_some() {
        operations.push(FilesystemOperation::AccessTime);
    }
    if times.modified.is_some() {
        operations.push(FilesystemOperation::ModificationTime);
    }
    if times.changed.is_some() {
        operations.push(FilesystemOperation::ChangeTime);
    }
    if times.created.is_some() {
        operations.push(FilesystemOperation::CreationTime);
    }
    if !metadata.sparse_extents().is_empty() {
        operations.push(FilesystemOperation::Sparse);
    }
    operations.extend(
        metadata
            .xattrs()
            .iter()
            .map(|(name, _)| FilesystemOperation::ExtendedAttribute(name.clone())),
    );
    operations.extend((0..metadata.acl().len()).map(FilesystemOperation::Acl));
    if metadata.file_flags() != 0 {
        operations.push(FilesystemOperation::FileFlags);
    }
    operations
}

fn fill_missing_findings(
    path: &ArchivePath,
    operations: &[FilesystemOperation],
    findings: &mut Vec<FilesystemFinding>,
    kind: FilesystemFindingKind,
    detail: &'static str,
) {
    for operation in operations {
        if findings
            .iter()
            .any(|finding| finding.operation() == operation)
        {
            continue;
        }
        let finding = match kind {
            FilesystemFindingKind::Refused => {
                FilesystemFinding::refused(path.clone(), operation.clone(), detail)
            },
            _ => FilesystemFinding::partial(path.clone(), operation.clone(), detail),
        };
        findings.push(finding);
    }
}

fn adapter_error(error: crate::filesystem::FilesystemAdapterError) -> StreamError {
    StreamError::io(error.into_io())
}

fn protocol_error(context: &'static str) -> StreamError {
    StreamError::archive(ArchiveError::new(ErrorKind::Protocol).with_context(context))
}

fn limit_error(index: u64, path: &ArchivePath, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(ErrorKind::Limit)
            .with_entry(index, path.as_bytes())
            .with_context(context),
    )
}

fn archive_path_nesting(path: &[u8]) -> usize {
    path.split(|byte| matches!(*byte, b'/' | b'\\'))
        .filter(|component| !component.is_empty() && *component != b".")
        .count()
}
