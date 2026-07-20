// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in capability-rooted filesystem adapter.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::time::{Duration, SystemTime};

use cap_fs_ext::DirExt;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use cap_fs_ext::SystemTimeSpec;
use cap_std::fs::{Dir, File, OpenOptions};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Timestamp};

use crate::filesystem::{
    FilesystemAdapter, FilesystemAdapterError, FilesystemCapabilities, FilesystemEntry,
    FilesystemEntryReport, FilesystemFinding, FilesystemMaterialization, FilesystemOperation,
};

#[derive(Debug)]
struct PendingFile {
    file: File,
    temporary: PathBuf,
    destination: PathBuf,
    overwrite: bool,
    metadata: EntryMetadata,
    logical_position: u64,
    findings: Vec<FilesystemFinding>,
}

#[derive(Debug)]
enum PendingMaterialization {
    File(Box<PendingFile>),
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
    DestinationExists,
    Failed(FilesystemFinding),
}

#[derive(Debug)]
struct PendingEntry {
    path: ArchivePath,
    materialization: PendingMaterialization,
}

/// Built-in adapter rooted at a `cap-std` directory capability.
///
/// Regular files are written into a unique `create_new` sibling, synchronized,
/// decorated through the open file descriptor where the platform permits, and
/// then atomically published. Parent and destination checks never follow an
/// archive-created symbolic link.
#[derive(Debug)]
pub struct CapStdFilesystemAdapter {
    root: Dir,
    pending: Option<PendingEntry>,
    created_directories: BTreeSet<PathBuf>,
    directory_metadata: BTreeMap<PathBuf, (ArchivePath, EntryMetadata)>,
    temporary_counter: u64,
}

impl CapStdFilesystemAdapter {
    /// Creates a standard adapter from an existing directory capability.
    #[must_use]
    pub fn new(root: Dir) -> Self {
        Self {
            root,
            pending: None,
            created_directories: BTreeSet::new(),
            directory_metadata: BTreeMap::new(),
            temporary_counter: 0,
        }
    }

    /// Returns the underlying directory capability.
    #[must_use]
    pub const fn root(&self) -> &Dir {
        &self.root
    }

    /// Consumes the adapter and returns its directory capability.
    #[must_use]
    pub fn into_inner(self) -> Dir {
        self.root
    }

    fn failed(path: ArchivePath, detail: &'static str, error: &io::Error) -> PendingEntry {
        PendingEntry {
            path: path.clone(),
            materialization: PendingMaterialization::Failed(FilesystemFinding::os_error(
                path,
                FilesystemOperation::Entry,
                detail,
                error,
            )),
        }
    }

    fn exists(&self, path: &Path) -> io::Result<bool> {
        match self.root.symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn ensure_parents(&mut self, path: &Path) -> io::Result<bool> {
        let Some(parent) = path.parent() else {
            return Ok(true);
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            if self.created_directories.contains(&current) {
                self.root.open_dir_nofollow(&current)?;
                continue;
            }
            match self.root.symlink_metadata(&current) {
                Ok(_) => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.root.create_dir(&current)?;
                    self.restrict_directory(&current)?;
                    self.root.open_dir_nofollow(&current)?;
                    self.created_directories.insert(current.clone());
                },
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    #[cfg_attr(not(unix), allow(clippy::unused_self, clippy::unnecessary_wraps))]
    fn restrict_directory(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use cap_std::fs::{Permissions, PermissionsExt};
            self.root
                .set_permissions(path, Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    fn create_temporary_sibling(&mut self, destination: &Path) -> io::Result<(File, PathBuf)> {
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
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique extraction sibling",
        ))
    }

    fn prepare(&mut self, entry: FilesystemEntry<'_>) -> PendingEntry {
        let metadata = entry.metadata();
        let path = metadata.path().clone();
        let destination = entry.destination().to_path_buf();
        if let Some(reused) = self.reuse_directory(metadata, &destination) {
            return reused;
        }
        match self.destination_available(entry, &destination) {
            Ok(true) => self.prepare_kind(entry, destination),
            Ok(false) => PendingEntry {
                path,
                materialization: PendingMaterialization::DestinationExists,
            },
            Err(error) => Self::failed(path, "failed to prepare destination", &error),
        }
    }

    fn reuse_directory(
        &mut self,
        metadata: &EntryMetadata,
        destination: &Path,
    ) -> Option<PendingEntry> {
        if metadata.kind() != EntryKind::Dir || !self.created_directories.contains(destination) {
            return None;
        }
        let path = metadata.path().clone();
        if let Err(error) = self.root.open_dir_nofollow(destination) {
            return Some(Self::failed(
                path,
                "previously created directory changed before reuse",
                &error,
            ));
        }
        self.directory_metadata
            .insert(destination.to_path_buf(), (path.clone(), metadata.clone()));
        Some(PendingEntry {
            path,
            materialization: PendingMaterialization::Directory,
        })
    }

    fn destination_available(
        &mut self,
        entry: FilesystemEntry<'_>,
        destination: &Path,
    ) -> io::Result<bool> {
        if !self.ensure_parents(destination)? {
            return Ok(false);
        }
        if !self.exists(destination)? {
            return Ok(true);
        }
        if entry.metadata().kind() != EntryKind::File || !entry.overwrite() {
            return Ok(false);
        }
        let existing = self.root.symlink_metadata(destination)?;
        Ok(existing.file_type().is_file() && !existing.file_type().is_symlink())
    }

    fn prepare_kind(&mut self, entry: FilesystemEntry<'_>, destination: PathBuf) -> PendingEntry {
        let metadata = entry.metadata();
        let path = metadata.path().clone();
        match metadata.kind() {
            EntryKind::File => self.prepare_file(entry, destination),
            EntryKind::Dir => self.prepare_directory(metadata, destination),
            EntryKind::Symlink => PendingEntry {
                path,
                materialization: PendingMaterialization::Symlink {
                    target: entry
                        .link_target()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                    destination,
                },
            },
            EntryKind::Hardlink => PendingEntry {
                path,
                materialization: PendingMaterialization::Hardlink {
                    target: entry
                        .link_target()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                    destination,
                },
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket => {
                PendingEntry {
                    path,
                    materialization: PendingMaterialization::Special {
                        destination,
                        kind: metadata.kind(),
                        mode: metadata.mode().unwrap_or(0o600),
                        device: metadata.referenced_device(),
                    },
                }
            },
            _ => PendingEntry {
                path: path.clone(),
                materialization: PendingMaterialization::Failed(FilesystemFinding::refused(
                    path,
                    FilesystemOperation::Entry,
                    "standard adapter received an unsupported entry kind",
                )),
            },
        }
    }

    fn prepare_file(&mut self, entry: FilesystemEntry<'_>, destination: PathBuf) -> PendingEntry {
        let metadata = entry.metadata();
        let path = metadata.path().clone();
        match self.create_temporary_sibling(&destination) {
            Ok((file, temporary)) => PendingEntry {
                path,
                materialization: PendingMaterialization::File(Box::new(PendingFile {
                    file,
                    temporary,
                    destination,
                    overwrite: entry.overwrite(),
                    metadata: metadata.clone(),
                    logical_position: 0,
                    findings: Vec::new(),
                })),
            },
            Err(error) => Self::failed(path, "failed to create temporary sibling", &error),
        }
    }

    fn prepare_directory(
        &mut self,
        metadata: &EntryMetadata,
        destination: PathBuf,
    ) -> PendingEntry {
        let path = metadata.path().clone();
        if let Err(error) = self.root.create_dir(&destination).and_then(|()| {
            self.restrict_directory(&destination)
                .and_then(|()| self.root.open_dir_nofollow(&destination).map(|_| ()))
        }) {
            return Self::failed(path, "failed to create or secure directory", &error);
        }
        self.created_directories.insert(destination.clone());
        self.directory_metadata
            .insert(destination, (path.clone(), metadata.clone()));
        PendingEntry {
            path,
            materialization: PendingMaterialization::Directory,
        }
    }
    fn remove_pending_file(&self) {
        if let Some(PendingEntry {
            materialization: PendingMaterialization::File(file),
            ..
        }) = &self.pending
        {
            let _ = self.root.remove_file(&file.temporary);
        }
    }
}
impl PendingFile {
    fn write_chunk(&mut self, bytes: &[u8]) {
        if self.findings.iter().any(|finding| {
            finding.operation() == &FilesystemOperation::Entry
                && finding.kind() == crate::filesystem::FilesystemFindingKind::OsError
        }) {
            return;
        }
        let result = if self.metadata.sparse_extents().is_empty() || cfg!(windows) {
            self.file.write_all(bytes)
        } else {
            self.write_sparse_chunk(bytes)
        };
        if let Err(error) = result {
            self.findings.push(FilesystemFinding::os_error(
                self.metadata.path().clone(),
                FilesystemOperation::Entry,
                "failed while writing temporary entry payload",
                &error,
            ));
        }
    }

    fn write_sparse_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        let length = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "payload chunk length exceeds u64",
            )
        })?;
        let chunk_start = self.logical_position;
        let chunk_end = chunk_start.checked_add(length).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse logical position overflow",
            )
        })?;
        for extent in self.metadata.sparse_extents() {
            let extent_end = extent.offset.checked_add(extent.length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "sparse extent overflow")
            })?;
            let start = chunk_start.max(extent.offset);
            let end = chunk_end.min(extent_end);
            if start >= end {
                continue;
            }
            let source_start = usize::try_from(start - chunk_start).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sparse source offset exceeds usize",
                )
            })?;
            let source_end = usize::try_from(end - chunk_start).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sparse source end exceeds usize",
                )
            })?;
            self.file.seek(SeekFrom::Start(start))?;
            self.file.write_all(&bytes[source_start..source_end])?;
        }
        self.logical_position = chunk_end;
        Ok(())
    }

    fn finish_sparse(&mut self) {
        if self.metadata.sparse_extents().is_empty() || cfg!(windows) {
            return;
        }
        let logical_size = self.metadata.size().unwrap_or(self.logical_position);
        match self.file.set_len(logical_size) {
            Ok(()) => self.findings.push(FilesystemFinding::applied(
                self.metadata.path().clone(),
                FilesystemOperation::Sparse,
            )),
            Err(error) => {
                self.findings.push(FilesystemFinding::os_error(
                    self.metadata.path().clone(),
                    FilesystemOperation::Sparse,
                    "failed to set sparse logical size",
                    &error,
                ));
                self.findings.push(FilesystemFinding::os_error(
                    self.metadata.path().clone(),
                    FilesystemOperation::Entry,
                    "sparse file could not be completed",
                    &error,
                ));
            },
        }
    }

    fn entry_failed(&self) -> bool {
        self.findings.iter().any(|finding| {
            finding.operation() == &FilesystemOperation::Entry
                && finding.kind() != crate::filesystem::FilesystemFindingKind::Applied
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_metadata<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    apply_linux_xattrs(fd, metadata, findings);
    apply_linux_acls(fd, metadata, findings);
    apply_linux_ownership(fd, metadata, findings);
    apply_linux_times(fd, metadata, findings);
    apply_linux_mode(fd, metadata, findings);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_xattrs<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    use rustix::fs::{XattrFlags, fsetxattr};

    let path = metadata.path();
    for (name, value) in metadata.xattrs() {
        let operation = FilesystemOperation::ExtendedAttribute(name.clone());
        if name.is_empty() || name.contains(&0) {
            findings.push(FilesystemFinding::refused(
                path.clone(),
                operation,
                "extended-attribute name is empty or contains NUL",
            ));
            continue;
        }
        match fsetxattr(fd, name.as_slice(), value, XattrFlags::empty()) {
            Ok(()) => findings.push(FilesystemFinding::applied(path.clone(), operation)),
            Err(error) => {
                let error = io::Error::from_raw_os_error(error.raw_os_error());
                findings.push(FilesystemFinding::os_error(
                    path.clone(),
                    operation,
                    "failed to restore extended attribute",
                    &error,
                ));
            },
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_acls<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    use rustix::fs::{XattrFlags, fsetxattr};

    let path = metadata.path();
    let acl_keys: Vec<&[u8]> = metadata
        .extensions()
        .iter()
        .filter(|extension| {
            extension.namespace() == "pax"
                && (extension.key().starts_with(b"SCHILY.acl.")
                    || extension.key().starts_with(b"LIBARCHIVE.acl."))
        })
        .map(libarchive_oxide_core::Extension::key)
        .collect();
    for (index, acl) in metadata.acl().iter().enumerate() {
        let operation = FilesystemOperation::Acl(index);
        match encode_posix_acl(acl) {
            Ok(encoded) => {
                let name = if acl_keys
                    .get(index)
                    .is_some_and(|key| key.ends_with(b".default"))
                {
                    b"system.posix_acl_default".as_slice()
                } else {
                    b"system.posix_acl_access".as_slice()
                };
                match fsetxattr(fd, name, &encoded, XattrFlags::empty()) {
                    Ok(()) => findings.push(FilesystemFinding::applied(path.clone(), operation)),
                    Err(error) => {
                        let error = io::Error::from_raw_os_error(error.raw_os_error());
                        findings.push(FilesystemFinding::os_error(
                            path.clone(),
                            operation,
                            "failed to restore POSIX ACL",
                            &error,
                        ));
                    },
                }
            },
            Err(detail) => findings.push(FilesystemFinding::unsupported(
                path.clone(),
                operation,
                detail,
            )),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_ownership<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    use rustix::fs::{Gid, Uid, fchown};

    let owner = metadata.owner();
    if owner.uid.is_none() && owner.gid.is_none() && owner.user.is_none() && owner.group.is_none() {
        return;
    }
    let uid = owner
        .uid
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != u32::MAX)
        .map(Uid::from_raw);
    let gid = owner
        .gid
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != u32::MAX)
        .map(Gid::from_raw);
    let path = metadata.path();
    if (owner.uid.is_some() && uid.is_none())
        || (owner.gid.is_some() && gid.is_none())
        || (owner.uid.is_none() && owner.user.is_some())
        || (owner.gid.is_none() && owner.group.is_some())
    {
        findings.push(FilesystemFinding::unsupported(
            path.clone(),
            FilesystemOperation::Ownership,
            "ownership requires representable numeric uid/gid; names are not resolved",
        ));
        return;
    }
    match fchown(fd, uid, gid) {
        Ok(()) => findings.push(FilesystemFinding::applied(
            path.clone(),
            FilesystemOperation::Ownership,
        )),
        Err(error) => {
            let error = io::Error::from_raw_os_error(error.raw_os_error());
            findings.push(FilesystemFinding::os_error(
                path.clone(),
                FilesystemOperation::Ownership,
                "failed to restore numeric ownership",
                &error,
            ));
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_times<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    use rustix::fs::{Timespec, Timestamps, UTIME_OMIT, futimens};

    let times = metadata.times();
    if times.accessed.is_none() && times.modified.is_none() {
        return;
    }
    let converted = times
        .accessed
        .map(linux_timespec)
        .transpose()
        .and_then(|accessed| {
            times
                .modified
                .map(linux_timespec)
                .transpose()
                .map(|modified| (accessed, modified))
        });
    let path = metadata.path();
    match converted {
        Ok((accessed, modified)) => {
            let timestamps = Timestamps {
                last_access: accessed.unwrap_or(Timespec {
                    tv_sec: 0,
                    tv_nsec: UTIME_OMIT,
                }),
                last_modification: modified.unwrap_or(Timespec {
                    tv_sec: 0,
                    tv_nsec: UTIME_OMIT,
                }),
            };
            match futimens(fd, &timestamps) {
                Ok(()) => record_linux_time_findings(metadata, findings, None, false),
                Err(error) => {
                    let error = io::Error::from_raw_os_error(error.raw_os_error());
                    record_linux_time_findings(metadata, findings, Some(&error), false);
                },
            }
        },
        Err(error) => record_linux_time_findings(metadata, findings, Some(&error), true),
    }
    let _ = path;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn record_linux_time_findings(
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
    error: Option<&io::Error>,
    conversion_failed: bool,
) {
    let path = metadata.path();
    for (present, operation, restore_failure, conversion_failure) in [
        (
            metadata.times().accessed.is_some(),
            FilesystemOperation::AccessTime,
            "failed to restore access time",
            "archive access time is not representable",
        ),
        (
            metadata.times().modified.is_some(),
            FilesystemOperation::ModificationTime,
            "failed to restore modification time",
            "archive modification time is not representable",
        ),
    ] {
        if !present {
            continue;
        }
        if let Some(error) = error {
            findings.push(FilesystemFinding::os_error(
                path.clone(),
                operation,
                if conversion_failed {
                    conversion_failure
                } else {
                    restore_failure
                },
                error,
            ));
        } else {
            findings.push(FilesystemFinding::applied(path.clone(), operation));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_linux_mode<Fd: std::os::fd::AsFd>(
    fd: &Fd,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    use rustix::fs::{Mode, fchmod};

    let Some(mode) = metadata.mode() else {
        return;
    };
    let path = metadata.path();
    match fchmod(fd, Mode::from_bits_truncate(mode & 0o7777)) {
        Ok(()) => findings.push(FilesystemFinding::applied(
            path.clone(),
            FilesystemOperation::Mode,
        )),
        Err(error) => {
            let error = io::Error::from_raw_os_error(error.raw_os_error());
            findings.push(FilesystemFinding::os_error(
                path.clone(),
                FilesystemOperation::Mode,
                "failed to restore mode",
                &error,
            ));
        },
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_timespec(timestamp: Timestamp) -> io::Result<rustix::fs::Timespec> {
    if timestamp.nanos >= 1_000_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive timestamp nanoseconds are out of range",
        ));
    }
    Ok(rustix::fs::Timespec {
        tv_sec: timestamp.secs,
        tv_nsec: timestamp.nanos.into(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn encode_posix_acl(raw: &[u8]) -> Result<Vec<u8>, String> {
    const ACL_XATTR_VERSION: u32 = 0x0002;
    const USER_OBJ: u16 = 0x0001;
    const USER: u16 = 0x0002;
    const GROUP_OBJ: u16 = 0x0004;
    const GROUP: u16 = 0x0008;
    const MASK: u16 = 0x0010;
    const OTHER: u16 = 0x0020;

    let text =
        std::str::from_utf8(raw).map_err(|_| "ACL is not UTF-8 POSIX access text".to_owned())?;
    let mut encoded = ACL_XATTR_VERSION.to_le_bytes().to_vec();
    let mut count = 0_usize;
    for record in text
        .split([',', '\n'])
        .map(str::trim)
        .filter(|record| !record.is_empty())
    {
        let record = record.strip_prefix("default:").unwrap_or(record);
        let fields: Vec<_> = record.split(':').collect();
        if fields.len() < 3 || fields.len() > 4 {
            return Err("ACL record is not tag:qualifier:permissions text".to_owned());
        }
        let qualifier = fields[1];
        let (tag, id) = match fields[0] {
            "user" | "u" if qualifier.is_empty() => (USER_OBJ, u32::MAX),
            "user" | "u" => (USER, acl_numeric_id(qualifier, fields.get(3).copied())?),
            "group" | "g" if qualifier.is_empty() => (GROUP_OBJ, u32::MAX),
            "group" | "g" => (GROUP, acl_numeric_id(qualifier, fields.get(3).copied())?),
            "mask" | "m" => (MASK, u32::MAX),
            "other" | "o" => (OTHER, u32::MAX),
            _ => return Err("ACL contains an unsupported tag".to_owned()),
        };
        let permissions = acl_permissions(fields[2])?;
        encoded.extend_from_slice(&tag.to_le_bytes());
        encoded.extend_from_slice(&permissions.to_le_bytes());
        encoded.extend_from_slice(&id.to_le_bytes());
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err("ACL contains no entries".to_owned());
    }
    Ok(encoded)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn acl_numeric_id(qualifier: &str, alternate: Option<&str>) -> Result<u32, String> {
    qualifier
        .parse::<u32>()
        .or_else(|_| alternate.unwrap_or("").parse::<u32>())
        .map_err(|_| "named ACL qualifier has no numeric id".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn acl_permissions(value: &str) -> Result<u16, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 3
        || !matches!(bytes[0], b'r' | b'-')
        || !matches!(bytes[1], b'w' | b'-')
        || !matches!(bytes[2], b'x' | b'-')
    {
        return Err("ACL permissions are not rwx text".to_owned());
    }
    Ok((u16::from(bytes[0] == b'r') * 4)
        | (u16::from(bytes[1] == b'w') * 2)
        | u16::from(bytes[2] == b'x'))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_file_metadata(
    root: &Dir,
    filesystem_path: &Path,
    file: &File,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    apply_portable_times(root, filesystem_path, metadata, findings);
    #[cfg(not(unix))]
    let _ = file;
    #[cfg(unix)]
    if let Some(mode) = metadata.mode() {
        use cap_std::fs::{Permissions, PermissionsExt};
        match file.set_permissions(Permissions::from_mode(mode & 0o7777)) {
            Ok(()) => findings.push(FilesystemFinding::applied(
                metadata.path().clone(),
                FilesystemOperation::Mode,
            )),
            Err(error) => findings.push(FilesystemFinding::os_error(
                metadata.path().clone(),
                FilesystemOperation::Mode,
                "failed to restore mode",
                &error,
            )),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_directory_metadata(
    root: &Dir,
    filesystem_path: &Path,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    apply_portable_times(root, filesystem_path, metadata, findings);
    #[cfg(unix)]
    if let Some(mode) = metadata.mode() {
        use cap_std::fs::{Permissions, PermissionsExt};
        match root.set_permissions(filesystem_path, Permissions::from_mode(mode & 0o7777)) {
            Ok(()) => findings.push(FilesystemFinding::applied(
                metadata.path().clone(),
                FilesystemOperation::Mode,
            )),
            Err(error) => findings.push(FilesystemFinding::os_error(
                metadata.path().clone(),
                FilesystemOperation::Mode,
                "failed to restore directory mode",
                &error,
            )),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_portable_times(
    root: &Dir,
    filesystem_path: &Path,
    metadata: &EntryMetadata,
    findings: &mut Vec<FilesystemFinding>,
) {
    let times = metadata.times();
    let accessed = times.accessed.map(timestamp_spec).transpose();
    let modified = times.modified.map(timestamp_spec).transpose();
    match accessed.and_then(|accessed| modified.map(|modified| (accessed, modified))) {
        Ok((accessed, modified)) if accessed.is_some() || modified.is_some() => {
            match root.set_times(filesystem_path, accessed, modified) {
                Ok(()) => {
                    if times.accessed.is_some() {
                        findings.push(FilesystemFinding::applied(
                            metadata.path().clone(),
                            FilesystemOperation::AccessTime,
                        ));
                    }
                    if times.modified.is_some() {
                        findings.push(FilesystemFinding::applied(
                            metadata.path().clone(),
                            FilesystemOperation::ModificationTime,
                        ));
                    }
                },
                Err(error) => {
                    if times.accessed.is_some() {
                        findings.push(FilesystemFinding::os_error(
                            metadata.path().clone(),
                            FilesystemOperation::AccessTime,
                            "failed to restore access time",
                            &error,
                        ));
                    }
                    if times.modified.is_some() {
                        findings.push(FilesystemFinding::os_error(
                            metadata.path().clone(),
                            FilesystemOperation::ModificationTime,
                            "failed to restore modification time",
                            &error,
                        ));
                    }
                },
            }
        },
        Ok(_) => {},
        Err(error) => {
            if times.accessed.is_some() {
                findings.push(FilesystemFinding::os_error(
                    metadata.path().clone(),
                    FilesystemOperation::AccessTime,
                    "archive access time is not representable",
                    &error,
                ));
            }
            if times.modified.is_some() {
                findings.push(FilesystemFinding::os_error(
                    metadata.path().clone(),
                    FilesystemOperation::ModificationTime,
                    "archive modification time is not representable",
                    &error,
                ));
            }
        },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
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
impl FilesystemAdapter for CapStdFilesystemAdapter {
    fn capabilities(&self) -> FilesystemCapabilities {
        FilesystemCapabilities::standard()
    }

    fn begin_session(&mut self) -> Result<(), FilesystemAdapterError> {
        self.abort_entry();
        self.created_directories.clear();
        self.directory_metadata.clear();
        self.temporary_counter = 0;
        Ok(())
    }

    fn begin_entry(&mut self, entry: FilesystemEntry<'_>) -> Result<(), FilesystemAdapterError> {
        if self.pending.is_some() {
            return Err(FilesystemAdapterError::protocol(
                "filesystem entry began before the previous entry finished",
            ));
        }
        self.pending = Some(self.prepare(entry));
        Ok(())
    }

    fn write_data(&mut self, data: &[u8]) -> Result<(), FilesystemAdapterError> {
        let pending = self.pending.as_mut().ok_or_else(|| {
            FilesystemAdapterError::protocol("filesystem data arrived outside an entry")
        })?;
        if let PendingMaterialization::File(file) = &mut pending.materialization {
            file.write_chunk(data);
        }
        Ok(())
    }

    fn finish_entry(&mut self) -> Result<FilesystemEntryReport, FilesystemAdapterError> {
        let pending = self.pending.take().ok_or_else(|| {
            FilesystemAdapterError::protocol("filesystem entry ended without a begin call")
        })?;
        Ok(self.commit(pending))
    }

    fn abort_entry(&mut self) {
        self.remove_pending_file();
        self.pending = None;
    }

    fn finish_session(&mut self) -> Result<Vec<FilesystemFinding>, FilesystemAdapterError> {
        if self.pending.is_some() {
            return Err(FilesystemAdapterError::protocol(
                "filesystem session finished with an entry in flight",
            ));
        }
        let mut directories: Vec<_> = self.directory_metadata.iter().collect();
        directories.sort_by_key(|(path, _)| Reverse(path.components().count()));
        let mut findings = Vec::new();
        for (filesystem_path, (_, metadata)) in directories {
            match self.root.open_dir_nofollow(filesystem_path) {
                Ok(directory) => {
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    apply_linux_metadata(&directory, metadata, &mut findings);
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    {
                        drop(directory);
                        apply_directory_metadata(
                            &self.root,
                            filesystem_path,
                            metadata,
                            &mut findings,
                        );
                    }
                },
                Err(error) => metadata_error_findings(
                    metadata,
                    "directory changed before final metadata application",
                    &error,
                    &mut findings,
                ),
            }
        }
        self.directory_metadata.clear();
        Ok(findings)
    }
}

impl CapStdFilesystemAdapter {
    fn commit(&self, pending: PendingEntry) -> FilesystemEntryReport {
        let path = pending.path;
        match pending.materialization {
            PendingMaterialization::File(file) => self.commit_file(path, *file),
            PendingMaterialization::Directory => FilesystemEntryReport::new(
                FilesystemMaterialization::Directory,
                vec![FilesystemFinding::applied(path, FilesystemOperation::Entry)],
            ),
            PendingMaterialization::Symlink {
                target,
                destination,
            } => {
                #[cfg(not(windows))]
                let result = self.root.symlink(&target, &destination);
                #[cfg(windows)]
                let result = self.root.symlink_file(&target, &destination);
                materialization_result(
                    path,
                    FilesystemMaterialization::Symlink,
                    result,
                    "failed to create symbolic link",
                )
            },
            PendingMaterialization::Hardlink {
                target,
                destination,
            } => {
                let result = self.root.hard_link(&target, &self.root, &destination);
                materialization_result(
                    path,
                    FilesystemMaterialization::Hardlink,
                    result,
                    "failed to create hard link",
                )
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            PendingMaterialization::Special {
                destination,
                kind,
                mode,
                device,
            } => {
                let result = create_special(&self.root, &destination, kind, mode, device);
                materialization_result(
                    path,
                    FilesystemMaterialization::Special,
                    result,
                    "failed to create special file",
                )
            },
            PendingMaterialization::DestinationExists => FilesystemEntryReport::new(
                FilesystemMaterialization::DestinationExists,
                vec![FilesystemFinding::refused(
                    path,
                    FilesystemOperation::Entry,
                    "destination already exists or changed before materialization",
                )],
            ),
            PendingMaterialization::Failed(finding) => {
                FilesystemEntryReport::new(FilesystemMaterialization::Failed, vec![finding])
            },
        }
    }

    fn commit_file(&self, path: ArchivePath, mut pending: PendingFile) -> FilesystemEntryReport {
        pending.finish_sparse();
        if let Err(error) = pending.file.flush() {
            pending.findings.push(FilesystemFinding::os_error(
                path.clone(),
                FilesystemOperation::Entry,
                "failed to flush temporary file",
                &error,
            ));
        }
        if !pending.entry_failed() {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            apply_linux_metadata(&pending.file, &pending.metadata, &mut pending.findings);
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            apply_file_metadata(
                &self.root,
                &pending.temporary,
                &pending.file,
                &pending.metadata,
                &mut pending.findings,
            );
            if let Err(error) = pending.file.sync_all() {
                pending.findings.push(FilesystemFinding::os_error(
                    path.clone(),
                    FilesystemOperation::Entry,
                    "failed to synchronize temporary file",
                    &error,
                ));
            }
        }
        let entry_failed = pending.entry_failed();
        drop(pending.file);

        if entry_failed {
            let _ = self.root.remove_file(&pending.temporary);
            if !pending
                .findings
                .iter()
                .any(|finding| finding.operation() == &FilesystemOperation::AtomicCommit)
            {
                pending.findings.push(FilesystemFinding::partial(
                    path,
                    FilesystemOperation::AtomicCommit,
                    "temporary file was discarded before publication",
                ));
            }
            return FilesystemEntryReport::new(FilesystemMaterialization::Failed, pending.findings);
        }

        let commit = if pending.overwrite {
            self.root
                .rename(&pending.temporary, &self.root, &pending.destination)
        } else {
            self.root
                .hard_link(&pending.temporary, &self.root, &pending.destination)
        };
        if let Err(error) = commit {
            let _ = self.root.remove_file(&pending.temporary);
            let materialization = if error.kind() == io::ErrorKind::AlreadyExists {
                pending.findings.push(FilesystemFinding::refused(
                    path.clone(),
                    FilesystemOperation::Entry,
                    "destination appeared before atomic commit",
                ));
                FilesystemMaterialization::DestinationExists
            } else {
                pending.findings.push(FilesystemFinding::os_error(
                    path.clone(),
                    FilesystemOperation::Entry,
                    "atomic publication failed",
                    &error,
                ));
                FilesystemMaterialization::Failed
            };
            pending.findings.push(FilesystemFinding::os_error(
                path,
                FilesystemOperation::AtomicCommit,
                "atomic publication failed",
                &error,
            ));
            return FilesystemEntryReport::new(materialization, pending.findings);
        }

        if !pending.overwrite {
            if let Err(error) = self.root.remove_file(&pending.temporary) {
                pending.findings.push(FilesystemFinding::partial(
                    path.clone(),
                    FilesystemOperation::AtomicCommit,
                    format!("destination committed but temporary link cleanup failed: {error}"),
                ));
            }
        }
        pending.findings.push(FilesystemFinding::applied(
            path.clone(),
            FilesystemOperation::AtomicCommit,
        ));
        pending
            .findings
            .push(FilesystemFinding::applied(path, FilesystemOperation::Entry));
        FilesystemEntryReport::new(FilesystemMaterialization::File, pending.findings)
    }
}

fn materialization_result(
    path: ArchivePath,
    success: FilesystemMaterialization,
    result: io::Result<()>,
    detail: &'static str,
) -> FilesystemEntryReport {
    match result {
        Ok(()) => FilesystemEntryReport::new(
            success,
            vec![FilesystemFinding::applied(path, FilesystemOperation::Entry)],
        ),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => FilesystemEntryReport::new(
            FilesystemMaterialization::DestinationExists,
            vec![FilesystemFinding::refused(
                path,
                FilesystemOperation::Entry,
                "destination appeared before commit",
            )],
        ),
        Err(error) => FilesystemEntryReport::new(
            FilesystemMaterialization::Failed,
            vec![FilesystemFinding::os_error(
                path,
                FilesystemOperation::Entry,
                detail,
                &error,
            )],
        ),
    }
}

fn requested_metadata_operations(metadata: &EntryMetadata) -> Vec<FilesystemOperation> {
    let mut operations = Vec::new();
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

fn metadata_error_findings(
    metadata: &EntryMetadata,
    detail: &'static str,
    error: &io::Error,
    findings: &mut Vec<FilesystemFinding>,
) {
    for operation in requested_metadata_operations(metadata) {
        findings.push(FilesystemFinding::os_error(
            metadata.path().clone(),
            operation,
            detail,
            error,
        ));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn create_special(
    root: &Dir,
    destination: &Path,
    kind: EntryKind,
    mode: u32,
    device: Option<libarchive_oxide_core::Device>,
) -> io::Result<()> {
    use rustix::fs::{FileType, Mode, makedev, mknodat};
    let file_type = match kind {
        EntryKind::Char => FileType::CharacterDevice,
        EntryKind::Block => FileType::BlockDevice,
        EntryKind::Fifo => FileType::Fifo,
        EntryKind::Socket => FileType::Socket,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-special entry reached special-file creation",
            ));
        },
    };
    let raw_device = match kind {
        EntryKind::Char | EntryKind::Block => {
            let device = device.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device entry is missing major/minor numbers",
                )
            })?;
            let major = u32::try_from(device.major).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device major number exceeds platform range",
                )
            })?;
            let minor = u32::try_from(device.minor).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device minor number exceeds platform range",
                )
            })?;
            makedev(major, minor)
        },
        _ => 0,
    };
    mknodat(
        root,
        destination,
        file_type,
        Mode::from_bits_truncate(mode),
        raw_device,
    )
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}
