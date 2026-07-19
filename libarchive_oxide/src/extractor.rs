// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability-based streaming extraction.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cap_fs_ext::{DirExt, SystemTimeSpec};
use cap_std::fs::{Dir, File, OpenOptions};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Timestamp};

use crate::path::sanitize_archive_path;
use crate::{ArchiveReader, ReaderEvent, SeekArchiveReader, StreamError};

#[cfg(feature = "tokio")]
pub(crate) enum ExtractionMessage {
    Entry(Box<EntryMetadata>),
    Data(Vec<u8>),
    EndEntry,
    Done,
}

/// Extraction security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExtractionPolicy {
    overwrite: bool,
    symlinks: bool,
    hardlinks: bool,
    special_files: bool,
}

impl ExtractionPolicy {
    /// Conservative policy used by default.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            overwrite: false,
            symlinks: false,
            hardlinks: false,
            special_files: false,
        }
    }

    /// Restore-oriented profile. Individual high-risk capabilities still need
    /// to be enabled with the builder methods.
    #[must_use]
    pub const fn restore() -> Self {
        Self::safe()
    }

    /// Allows replacing an existing regular file.
    #[must_use]
    pub const fn allow_overwrite(mut self, allow: bool) -> Self {
        self.overwrite = allow;
        self
    }

    /// Allows symbolic-link creation.
    #[must_use]
    pub const fn allow_symlinks(mut self, allow: bool) -> Self {
        self.symlinks = allow;
        self
    }

    /// Allows session-local hard links.
    #[must_use]
    pub const fn allow_hardlinks(mut self, allow: bool) -> Self {
        self.hardlinks = allow;
        self
    }

    /// Allows device, FIFO, and socket entries.
    #[must_use]
    pub const fn allow_special_files(mut self, allow: bool) -> Self {
        self.special_files = allow;
        self
    }
}

impl Default for ExtractionPolicy {
    fn default() -> Self {
        Self::safe()
    }
}

/// Why one entry was not materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The archive path was absolute, traversing, reserved, or unrepresentable.
    UnsafePath,
    /// A destination object existed before this extraction session.
    DestinationExists,
    /// Safe policy forbids this entry kind.
    EntryKind,
    /// A link target was absent, unsafe, or not created earlier in this session.
    UnsafeLinkTarget,
    /// The entry refers to data outside the archive (for example a thin-ar member).
    ExternalReference,
    /// The requested restore capability is not implemented on this platform.
    UnsupportedRestore,
}

/// Materialization result for one archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryOutcomeKind {
    /// A regular file was atomically committed.
    File,
    /// A directory was created.
    Directory,
    /// A symbolic link was created by an explicitly enabled restore policy.
    Symlink,
    /// A hard link to an earlier session-local file was created.
    Hardlink,
    /// A FIFO, socket inode, or device was created by an explicitly enabled policy.
    Special,
    /// Policy rejected the entry.
    Rejected(RejectionReason),
    /// The caller's member selector excluded the entry.
    Skipped,
}

/// Per-entry extraction result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryOutcome {
    path: ArchivePath,
    outcome: EntryOutcomeKind,
}

impl EntryOutcome {
    /// Archive-native entry path.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Materialization result.
    #[must_use]
    pub const fn outcome(&self) -> &EntryOutcomeKind {
        &self.outcome
    }
}

/// Complete extraction report. Rejections are never silently converted to success.
#[derive(Debug, Default)]
pub struct ExtractionReport {
    outcomes: Vec<EntryOutcome>,
}

impl ExtractionReport {
    /// Per-entry results in archive order.
    #[must_use]
    pub fn outcomes(&self) -> &[EntryOutcome] {
        &self.outcomes
    }

    /// Whether policy rejected at least one entry.
    #[must_use]
    pub fn has_rejections(&self) -> bool {
        self.outcomes
            .iter()
            .any(|item| matches!(item.outcome, EntryOutcomeKind::Rejected(_)))
    }
}

#[derive(Debug)]
struct PendingFile {
    file: File,
    temporary: PathBuf,
    destination: PathBuf,
    overwrite: bool,
    final_metadata: FinalMetadata,
}

#[derive(Debug, Clone, Copy)]
struct FinalMetadata {
    mode: Option<u32>,
    accessed: Option<Timestamp>,
    modified: Option<Timestamp>,
}

impl FinalMetadata {
    fn from_entry(metadata: &EntryMetadata) -> Self {
        Self {
            mode: metadata.mode(),
            accessed: metadata.times().accessed,
            modified: metadata.times().modified,
        }
    }

    const fn implicit_directory() -> Self {
        Self {
            mode: Some(0o755),
            accessed: None,
            modified: None,
        }
    }
}

#[derive(Debug)]
enum PendingMaterialization {
    File(PendingFile),
    Directory,
    Symlink {
        target: PathBuf,
        destination: PathBuf,
    },
    Hardlink {
        target: PathBuf,
        destination: PathBuf,
    },
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Special {
        destination: PathBuf,
        kind: EntryKind,
        mode: u32,
        device: Option<libarchive_oxide_core::Device>,
    },
    Rejected(RejectionReason),
    Skipped,
}

#[derive(Debug)]
struct PendingEntry {
    path: ArchivePath,
    materialization: PendingMaterialization,
}

/// Streaming extractor rooted at a directory capability.
#[derive(Debug)]
pub struct Extractor {
    root: Dir,
    policy: ExtractionPolicy,
    created_directories: BTreeSet<PathBuf>,
    directory_metadata: BTreeMap<PathBuf, FinalMetadata>,
    committed_files: BTreeSet<PathBuf>,
    temporary_counter: u64,
}

impl Extractor {
    /// Creates an extractor. No ambient path is retained internally.
    #[must_use]
    pub fn new(root: Dir) -> Self {
        Self::with_policy(root, ExtractionPolicy::safe())
    }

    /// Creates an extractor with an explicit policy.
    #[must_use]
    pub fn with_policy(root: Dir, policy: ExtractionPolicy) -> Self {
        Self {
            root,
            policy,
            created_directories: BTreeSet::new(),
            directory_metadata: BTreeMap::new(),
            committed_files: BTreeSet::new(),
            temporary_counter: 0,
        }
    }

    /// Extracts a sequential archive while retaining at most the current chunk.
    pub fn extract<R: Read>(
        &mut self,
        reader: &mut ArchiveReader<R>,
    ) -> Result<ExtractionReport, StreamError> {
        self.extract_matching(reader, |_| true)
    }

    /// Extracts entries accepted by `select`, consuming skipped payload without
    /// treating selection as a security-policy rejection.
    pub fn extract_matching<R: Read>(
        &mut self,
        reader: &mut ArchiveReader<R>,
        mut select: impl FnMut(&EntryMetadata) -> bool,
    ) -> Result<ExtractionReport, StreamError> {
        self.begin_session();
        let mut report = ExtractionReport::default();
        let mut pending: Option<PendingEntry> = None;
        loop {
            let event = match reader.next_event() {
                Ok(event) => event,
                Err(error) => {
                    self.remove_pending(pending.as_ref());
                    return Err(error);
                },
            };
            match event {
                ReaderEvent::ArchiveMetadata(_) => {},
                ReaderEvent::Entry(metadata) => {
                    if pending.is_some() {
                        self.remove_pending(pending.as_ref());
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry began before the preceding entry ended",
                        )));
                    }
                    pending = Some(if select(&metadata) {
                        self.prepare_entry(&metadata)?
                    } else {
                        PendingEntry {
                            path: metadata.path().clone(),
                            materialization: PendingMaterialization::Skipped,
                        }
                    });
                },
                ReaderEvent::Data(bytes) => {
                    let Some(entry) = &mut pending else {
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "archive data appeared outside an entry",
                        )));
                    };
                    if let PendingMaterialization::File(file) = &mut entry.materialization {
                        if let Err(error) = file.file.write_all(bytes) {
                            self.remove_pending(pending.as_ref());
                            return Err(StreamError::io(error));
                        }
                    }
                },
                ReaderEvent::EndEntry => {
                    let Some(entry) = pending.take() else {
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "archive ended an entry that was not open",
                        )));
                    };
                    let outcome = self.commit_entry(entry)?;
                    report.outcomes.push(outcome);
                },
                ReaderEvent::Done => {
                    if pending.is_some() {
                        self.remove_pending(pending.as_ref());
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "archive ended with an incomplete entry",
                        )));
                    }
                    self.finalize_directories()?;
                    return Ok(report);
                },
            }
        }
    }

    /// Extracts a seek-required archive with the same policy and atomic-commit
    /// semantics as [`Self::extract_matching`].
    #[allow(clippy::too_many_lines)]
    pub fn extract_seek_matching<R: Read + Seek>(
        &mut self,
        reader: &mut SeekArchiveReader<R>,
        mut select: impl FnMut(&EntryMetadata) -> bool,
    ) -> Result<ExtractionReport, StreamError> {
        self.begin_session();
        let mut report = ExtractionReport::default();
        let mut pending: Option<PendingEntry> = None;
        loop {
            let event = match reader.next_event() {
                Ok(event) => event,
                Err(error) => {
                    self.remove_pending(pending.as_ref());
                    return Err(error);
                },
            };
            match event {
                ReaderEvent::ArchiveMetadata(_) => {},
                ReaderEvent::Entry(metadata) => {
                    if pending.is_some() {
                        self.remove_pending(pending.as_ref());
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry began before the preceding entry ended",
                        )));
                    }
                    pending = Some(if select(&metadata) {
                        self.prepare_entry(&metadata)?
                    } else {
                        PendingEntry {
                            path: metadata.path().clone(),
                            materialization: PendingMaterialization::Skipped,
                        }
                    });
                },
                ReaderEvent::Data(bytes) => {
                    let Some(entry) = &mut pending else {
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "archive data appeared outside an entry",
                        )));
                    };
                    if let PendingMaterialization::File(file) = &mut entry.materialization {
                        if let Err(error) = file.file.write_all(bytes) {
                            self.remove_pending(pending.as_ref());
                            return Err(StreamError::io(error));
                        }
                    }
                },
                ReaderEvent::EndEntry => {
                    let Some(entry) = pending.take() else {
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "archive ended an entry that was not open",
                        )));
                    };
                    let outcome = self.commit_entry(entry)?;
                    report.outcomes.push(outcome);
                },
                ReaderEvent::Done => {
                    if pending.is_some() {
                        self.remove_pending(pending.as_ref());
                        return Err(StreamError::io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "archive ended with an incomplete entry",
                        )));
                    }
                    self.finalize_directories()?;
                    return Ok(report);
                },
            }
        }
    }

    fn prepare_entry(&mut self, metadata: &EntryMetadata) -> Result<PendingEntry, StreamError> {
        let path = metadata.path().clone();
        if metadata.extensions().iter().any(|extension| {
            extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
        }) {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::ExternalReference,
                ),
            });
        }
        if metadata.kind() == EntryKind::Dir && matches!(path.as_bytes(), b"." | b"./") {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Skipped,
            });
        }
        let Some(relative) = sanitize_archive_path(&path) else {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(RejectionReason::UnsafePath),
            });
        };
        match metadata.kind() {
            EntryKind::Dir => self.prepare_directory(path, relative, metadata),
            EntryKind::File => self.prepare_file(path, relative, metadata),
            EntryKind::Symlink if self.policy.symlinks => {
                self.prepare_symlink(path, relative, metadata)
            },
            EntryKind::Hardlink if self.policy.hardlinks => {
                self.prepare_hardlink(path, relative, metadata)
            },
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
                if self.policy.special_files =>
            {
                self.prepare_special(path, relative, metadata)
            },
            _ => Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(RejectionReason::EntryKind),
            }),
        }
    }

    fn prepare_directory(
        &mut self,
        path: ArchivePath,
        relative: PathBuf,
        metadata: &EntryMetadata,
    ) -> Result<PendingEntry, StreamError> {
        if let Some(reason) = self.ensure_parents(&relative)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(reason),
            });
        }
        if self.created_directories.contains(&relative) {
            self.directory_metadata
                .insert(relative, FinalMetadata::from_entry(metadata));
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Directory,
            });
        }
        if self.exists(&relative)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::DestinationExists,
                ),
            });
        }
        self.root.create_dir(&relative).map_err(StreamError::io)?;
        self.restrict_directory(&relative)?;
        self.root
            .open_dir_nofollow(&relative)
            .map_err(StreamError::io)?;
        self.created_directories.insert(relative.clone());
        self.directory_metadata
            .insert(relative, FinalMetadata::from_entry(metadata));
        Ok(PendingEntry {
            path,
            materialization: PendingMaterialization::Directory,
        })
    }

    fn prepare_file(
        &mut self,
        path: ArchivePath,
        relative: PathBuf,
        metadata: &EntryMetadata,
    ) -> Result<PendingEntry, StreamError> {
        if let Some(reason) = self.ensure_parents(&relative)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(reason),
            });
        }
        let destination_exists = self.exists(&relative)?;
        if destination_exists && !self.policy.overwrite {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::DestinationExists,
                ),
            });
        }
        if destination_exists {
            let existing = self
                .root
                .symlink_metadata(&relative)
                .map_err(StreamError::io)?;
            if !existing.file_type().is_file() || existing.file_type().is_symlink() {
                return Ok(PendingEntry {
                    path,
                    materialization: PendingMaterialization::Rejected(
                        RejectionReason::DestinationExists,
                    ),
                });
            }
        }
        let (file, temporary) = self.create_temporary_sibling(&relative)?;
        Ok(PendingEntry {
            path,
            materialization: PendingMaterialization::File(PendingFile {
                file,
                temporary,
                destination: relative,
                overwrite: destination_exists,
                final_metadata: FinalMetadata::from_entry(metadata),
            }),
        })
    }

    fn prepare_symlink(
        &mut self,
        path: ArchivePath,
        destination: PathBuf,
        metadata: &EntryMetadata,
    ) -> Result<PendingEntry, StreamError> {
        if let Some(reason) = self.ensure_parents(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(reason),
            });
        }
        if self.exists(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::DestinationExists,
                ),
            });
        }
        let Some(target) = metadata.link_target().and_then(sanitize_archive_path) else {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::UnsafeLinkTarget,
                ),
            });
        };
        Ok(PendingEntry {
            path,
            materialization: PendingMaterialization::Symlink {
                target,
                destination,
            },
        })
    }

    fn prepare_hardlink(
        &mut self,
        path: ArchivePath,
        destination: PathBuf,
        metadata: &EntryMetadata,
    ) -> Result<PendingEntry, StreamError> {
        if let Some(reason) = self.ensure_parents(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(reason),
            });
        }
        if self.exists(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::DestinationExists,
                ),
            });
        }
        let Some(target) = metadata
            .link_target()
            .and_then(sanitize_archive_path)
            .filter(|target| self.committed_files.contains(target))
        else {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::UnsafeLinkTarget,
                ),
            });
        };
        Ok(PendingEntry {
            path,
            materialization: PendingMaterialization::Hardlink {
                target,
                destination,
            },
        })
    }

    fn prepare_special(
        &mut self,
        path: ArchivePath,
        destination: PathBuf,
        metadata: &EntryMetadata,
    ) -> Result<PendingEntry, StreamError> {
        if let Some(reason) = self.ensure_parents(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(reason),
            });
        }
        if self.exists(&destination)? {
            return Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::DestinationExists,
                ),
            });
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Special {
                    destination,
                    kind: metadata.kind(),
                    mode: metadata.mode().unwrap_or(0o600),
                    device: metadata.referenced_device(),
                },
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (destination, metadata);
            Ok(PendingEntry {
                path,
                materialization: PendingMaterialization::Rejected(
                    RejectionReason::UnsupportedRestore,
                ),
            })
        }
    }

    fn ensure_parents(&mut self, path: &Path) -> Result<Option<RejectionReason>, StreamError> {
        let Some(parent) = path.parent() else {
            return Ok(None);
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            if self.created_directories.contains(&current) {
                self.root
                    .open_dir_nofollow(&current)
                    .map_err(StreamError::io)?;
                continue;
            }
            match self.root.symlink_metadata(&current) {
                Ok(_) => return Ok(Some(RejectionReason::DestinationExists)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.root.create_dir(&current).map_err(StreamError::io)?;
                    self.restrict_directory(&current)?;
                    self.root
                        .open_dir_nofollow(&current)
                        .map_err(StreamError::io)?;
                    self.created_directories.insert(current.clone());
                    self.directory_metadata
                        .insert(current.clone(), FinalMetadata::implicit_directory());
                },
                Err(error) => return Err(StreamError::io(error)),
            }
        }
        Ok(None)
    }

    fn exists(&self, path: &Path) -> Result<bool, StreamError> {
        match self.root.symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StreamError::io(error)),
        }
    }

    fn create_temporary_sibling(
        &mut self,
        destination: &Path,
    ) -> Result<(File, PathBuf), StreamError> {
        let parent = destination.parent().unwrap_or_else(|| Path::new(""));
        for _ in 0..128 {
            self.temporary_counter = self.temporary_counter.wrapping_add(1);
            let name = format!(".libarchive-oxide-{:016x}.tmp", self.temporary_counter);
            let temporary = parent.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            match self.root.open_with(&temporary, &options) {
                Ok(file) => return Ok((file, temporary)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(StreamError::io(error)),
            }
        }
        Err(StreamError::io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique extraction sibling",
        )))
    }

    fn commit_entry(&mut self, entry: PendingEntry) -> Result<EntryOutcome, StreamError> {
        let outcome = match entry.materialization {
            PendingMaterialization::File(mut pending) => {
                if let Err(error) = pending.file.flush() {
                    let _ = self.root.remove_file(&pending.temporary);
                    return Err(StreamError::io(error));
                }
                if let Err(error) = pending.file.sync_all() {
                    let _ = self.root.remove_file(&pending.temporary);
                    return Err(StreamError::io(error));
                }
                drop(pending.file);
                if let Err(error) =
                    self.apply_final_metadata(&pending.temporary, pending.final_metadata)
                {
                    let _ = self.root.remove_file(&pending.temporary);
                    return Err(error);
                }
                if pending.overwrite {
                    if let Err(error) =
                        self.root
                            .rename(&pending.temporary, &self.root, &pending.destination)
                    {
                        let _ = self.root.remove_file(&pending.temporary);
                        return Err(StreamError::io(error));
                    }
                    self.committed_files.insert(pending.destination);
                    return Ok(EntryOutcome {
                        path: entry.path,
                        outcome: EntryOutcomeKind::File,
                    });
                }
                if let Err(error) =
                    self.root
                        .hard_link(&pending.temporary, &self.root, &pending.destination)
                {
                    let _ = self.root.remove_file(&pending.temporary);
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        EntryOutcomeKind::Rejected(RejectionReason::DestinationExists)
                    } else {
                        return Err(StreamError::io(error));
                    }
                } else {
                    self.root
                        .remove_file(&pending.temporary)
                        .map_err(StreamError::io)?;
                    self.committed_files.insert(pending.destination);
                    EntryOutcomeKind::File
                }
            },
            PendingMaterialization::Directory => EntryOutcomeKind::Directory,
            PendingMaterialization::Symlink {
                target,
                destination,
            } => {
                #[cfg(not(windows))]
                self.root
                    .symlink(&target, &destination)
                    .map_err(StreamError::io)?;
                #[cfg(windows)]
                self.root
                    .symlink_file(&target, &destination)
                    .map_err(StreamError::io)?;
                EntryOutcomeKind::Symlink
            },
            PendingMaterialization::Hardlink {
                target,
                destination,
            } => {
                self.root
                    .hard_link(&target, &self.root, &destination)
                    .map_err(StreamError::io)?;
                self.committed_files.insert(destination);
                EntryOutcomeKind::Hardlink
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            PendingMaterialization::Special {
                destination,
                kind,
                mode,
                device,
            } => {
                self.create_special(&destination, kind, mode, device)?;
                EntryOutcomeKind::Special
            },
            PendingMaterialization::Rejected(reason) => EntryOutcomeKind::Rejected(reason),
            PendingMaterialization::Skipped => EntryOutcomeKind::Skipped,
        };
        Ok(EntryOutcome {
            path: entry.path,
            outcome,
        })
    }

    fn remove_pending(&self, pending: Option<&PendingEntry>) {
        if let Some(PendingEntry {
            materialization: PendingMaterialization::File(file),
            ..
        }) = pending
        {
            let _ = self.root.remove_file(&file.temporary);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn create_special(
        &self,
        destination: &Path,
        kind: EntryKind,
        mode: u32,
        device: Option<libarchive_oxide_core::Device>,
    ) -> Result<(), StreamError> {
        use rustix::fs::{FileType, Mode, makedev, mknodat};

        let file_type = match kind {
            EntryKind::Char => FileType::CharacterDevice,
            EntryKind::Block => FileType::BlockDevice,
            EntryKind::Fifo => FileType::Fifo,
            EntryKind::Socket => FileType::Socket,
            _ => {
                return Err(StreamError::io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-special entry reached special-file creation",
                )));
            },
        };
        let raw_device = match kind {
            EntryKind::Char | EntryKind::Block => {
                let device = device.ok_or_else(|| {
                    StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "device entry is missing major/minor numbers",
                    ))
                })?;
                let major = u32::try_from(device.major).map_err(|_| {
                    StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "device major number exceeds platform range",
                    ))
                })?;
                let minor = u32::try_from(device.minor).map_err(|_| {
                    StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "device minor number exceeds platform range",
                    ))
                })?;
                makedev(major, minor)
            },
            _ => 0,
        };
        mknodat(
            &self.root,
            destination,
            file_type,
            Mode::from_bits_truncate(mode),
            raw_device,
        )
        .map_err(|error| StreamError::io(io::Error::from_raw_os_error(error.raw_os_error())))
    }

    fn begin_session(&mut self) {
        self.created_directories.clear();
        self.directory_metadata.clear();
        self.committed_files.clear();
        self.temporary_counter = 0;
    }

    #[cfg_attr(not(unix), allow(clippy::unused_self, clippy::unnecessary_wraps))]
    fn restrict_directory(&self, path: &Path) -> Result<(), StreamError> {
        #[cfg(unix)]
        {
            use cap_std::fs::{Permissions, PermissionsExt};

            self.root
                .set_permissions(path, Permissions::from_mode(0o700))
                .map_err(StreamError::io)?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    fn apply_final_metadata(
        &self,
        path: &Path,
        metadata: FinalMetadata,
    ) -> Result<(), StreamError> {
        #[cfg(unix)]
        if let Some(mode) = metadata.mode {
            use cap_std::fs::{Permissions, PermissionsExt};

            self.root
                .set_permissions(path, Permissions::from_mode(mode & 0o7777))
                .map_err(StreamError::io)?;
        }
        #[cfg(not(unix))]
        let _ = metadata.mode;

        let accessed = metadata
            .accessed
            .map(timestamp_spec)
            .transpose()
            .map_err(StreamError::io)?;
        let modified = metadata
            .modified
            .map(timestamp_spec)
            .transpose()
            .map_err(StreamError::io)?;
        if accessed.is_some() || modified.is_some() {
            self.root
                .set_times(path, accessed, modified)
                .map_err(StreamError::io)?;
        }
        Ok(())
    }

    fn finalize_directories(&mut self) -> Result<(), StreamError> {
        let mut directories: Vec<_> = self.directory_metadata.iter().collect();
        directories.sort_by_key(|(path, _)| Reverse(path.components().count()));
        for (path, metadata) in directories {
            self.root.open_dir_nofollow(path).map_err(StreamError::io)?;
            self.apply_final_metadata(path, *metadata)?;
        }
        self.directory_metadata.clear();
        Ok(())
    }
}

fn timestamp_spec(timestamp: Timestamp) -> io::Result<SystemTimeSpec> {
    if timestamp.nanos >= 1_000_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive timestamp nanoseconds are out of range",
        ));
    }
    let absolute = if timestamp.secs >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(
            timestamp.secs.unsigned_abs(),
            timestamp.nanos,
        ))
    } else if timestamp.nanos == 0 {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::new(timestamp.secs.unsigned_abs(), 0))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::new(
            timestamp.secs.unsigned_abs() - 1,
            1_000_000_000 - timestamp.nanos,
        ))
    }
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "archive timestamp is out of range",
        )
    })?;
    Ok(SystemTimeSpec::Absolute(
        cap_std::time::SystemTime::from_std(absolute),
    ))
}

#[cfg(feature = "tokio")]
pub(crate) fn run_extraction_worker(
    root: Dir,
    policy: ExtractionPolicy,
    mut receiver: tokio::sync::mpsc::Receiver<ExtractionMessage>,
) -> Result<ExtractionReport, StreamError> {
    let mut extractor = Extractor::with_policy(root, policy);
    extractor.begin_session();
    let mut report = ExtractionReport::default();
    let mut pending: Option<PendingEntry> = None;
    while let Some(message) = receiver.blocking_recv() {
        match message {
            ExtractionMessage::Entry(metadata) => {
                if pending.is_some() {
                    extractor.remove_pending(pending.as_ref());
                    return Err(StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "entry began before the preceding entry ended",
                    )));
                }
                pending = Some(extractor.prepare_entry(&metadata)?);
            },
            ExtractionMessage::Data(bytes) => {
                let Some(entry) = &mut pending else {
                    return Err(StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "archive data appeared outside an entry",
                    )));
                };
                if let PendingMaterialization::File(file) = &mut entry.materialization {
                    if let Err(error) = file.file.write_all(&bytes) {
                        extractor.remove_pending(pending.as_ref());
                        return Err(StreamError::io(error));
                    }
                }
            },
            ExtractionMessage::EndEntry => {
                let Some(entry) = pending.take() else {
                    return Err(StreamError::io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "archive ended an entry that was not open",
                    )));
                };
                report.outcomes.push(extractor.commit_entry(entry)?);
            },
            ExtractionMessage::Done => {
                if pending.is_some() {
                    extractor.remove_pending(pending.as_ref());
                    return Err(StreamError::io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "archive ended with an incomplete entry",
                    )));
                }
                extractor.finalize_directories()?;
                return Ok(report);
            },
        }
    }
    extractor.remove_pending(pending.as_ref());
    Err(StreamError::io(io::Error::new(
        io::ErrorKind::Interrupted,
        "asynchronous extraction was cancelled",
    )))
}
