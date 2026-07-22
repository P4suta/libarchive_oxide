// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability-reporting filesystem adapter contract.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata};

/// Filesystem operations whose fidelity is tracked by [`FilesystemFinding`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FilesystemOperation {
    /// Materialize the entry itself.
    Entry,
    /// Atomically publish a completed regular file.
    AtomicCommit,
    /// Restore Unix-style mode bits.
    Mode,
    /// Restore numeric or named ownership.
    Ownership,
    /// Restore access time.
    AccessTime,
    /// Restore modification time.
    ModificationTime,
    /// Restore metadata-change time.
    ChangeTime,
    /// Restore creation/birth time.
    CreationTime,
    /// Preserve a sparse extent map.
    Sparse,
    /// Restore one extended attribute.
    ExtendedAttribute(Vec<u8>),
    /// Restore one ACL record.
    Acl(usize),
    /// Restore filesystem flags.
    FileFlags,
    /// Remove a whiteout target path, including any subtree it roots.
    RemovePath,
    /// Clear the contents of an opaque directory in place.
    ClearDirectory,
}

/// Outcome of one requested filesystem operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilesystemFindingKind {
    /// The operation was applied completely.
    Applied,
    /// The adapter or platform does not implement the operation.
    Unsupported,
    /// Policy or platform permissions refused the operation.
    Refused,
    /// Only part of the requested semantics was applied.
    Partial,
    /// The operating system returned an error.
    OsError,
}

/// Typed evidence for one entry or metadata operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemFinding {
    path: ArchivePath,
    operation: FilesystemOperation,
    kind: FilesystemFindingKind,
    detail: String,
    io_error_kind: Option<io::ErrorKind>,
    raw_os_error: Option<i32>,
}

impl FilesystemFinding {
    /// Records a completely applied operation.
    #[must_use]
    pub fn applied(path: ArchivePath, operation: FilesystemOperation) -> Self {
        Self::new(
            path,
            operation,
            FilesystemFindingKind::Applied,
            "filesystem operation applied",
        )
    }

    /// Records an operation unsupported by the adapter or platform.
    #[must_use]
    pub fn unsupported(
        path: ArchivePath,
        operation: FilesystemOperation,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(path, operation, FilesystemFindingKind::Unsupported, detail)
    }

    /// Records an operation refused by policy or platform permissions.
    #[must_use]
    pub fn refused(
        path: ArchivePath,
        operation: FilesystemOperation,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(path, operation, FilesystemFindingKind::Refused, detail)
    }

    /// Records an operation that was only partly applied.
    #[must_use]
    pub fn partial(
        path: ArchivePath,
        operation: FilesystemOperation,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(path, operation, FilesystemFindingKind::Partial, detail)
    }

    /// Records an operating-system error without discarding its typed category
    /// or raw platform code.
    #[must_use]
    pub fn os_error(
        path: ArchivePath,
        operation: FilesystemOperation,
        detail: impl Into<String>,
        error: &io::Error,
    ) -> Self {
        Self {
            path,
            operation,
            kind: FilesystemFindingKind::OsError,
            detail: detail.into(),
            io_error_kind: Some(error.kind()),
            raw_os_error: error.raw_os_error(),
        }
    }

    fn new(
        path: ArchivePath,
        operation: FilesystemOperation,
        kind: FilesystemFindingKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            path,
            operation,
            kind,
            detail: detail.into(),
            io_error_kind: None,
            raw_os_error: None,
        }
    }

    /// Archive-native path associated with the operation.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Operation that was attempted.
    #[must_use]
    pub const fn operation(&self) -> &FilesystemOperation {
        &self.operation
    }

    /// Applied, unsupported, refused, partial, or OS-error classification.
    #[must_use]
    pub const fn kind(&self) -> FilesystemFindingKind {
        self.kind
    }

    /// Stable human-readable context.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Portable I/O error category, when the finding came from the OS.
    #[must_use]
    pub const fn io_error_kind(&self) -> Option<io::ErrorKind> {
        self.io_error_kind
    }

    /// Raw platform error code, when available.
    #[must_use]
    pub const fn raw_os_error(&self) -> Option<i32> {
        self.raw_os_error
    }
}

/// Filesystem fidelity advertised for the lifetime of one adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FilesystemCapabilities {
    atomic_commit: bool,
    mode: bool,
    ownership: bool,
    access_time: bool,
    modification_time: bool,
    change_time: bool,
    creation_time: bool,
    symlinks: bool,
    hardlinks: bool,
    xattrs: bool,
    acls: bool,
    sparse: bool,
    special_files: bool,
    file_flags: bool,
    removals: bool,
}

impl FilesystemCapabilities {
    /// A closed adapter that only accepts entries carrying no filesystem
    /// restoration semantics.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            atomic_commit: false,
            mode: false,
            ownership: false,
            access_time: false,
            modification_time: false,
            change_time: false,
            creation_time: false,
            symlinks: false,
            hardlinks: false,
            xattrs: false,
            acls: false,
            sparse: false,
            special_files: false,
            file_flags: false,
            removals: false,
        }
    }

    /// Capabilities implemented by the built-in `cap-std` adapter on this target.
    #[must_use]
    pub const fn standard() -> Self {
        Self::none()
            .with_atomic_commit(true)
            .with_mode(cfg!(unix))
            .with_ownership(cfg!(any(target_os = "linux", target_os = "android")))
            .with_access_time(true)
            .with_modification_time(true)
            .with_symlinks(true)
            .with_hardlinks(true)
            .with_xattrs(cfg!(any(target_os = "linux", target_os = "android")))
            .with_acls(cfg!(any(target_os = "linux", target_os = "android")))
            .with_sparse(cfg!(unix))
            .with_special_files(cfg!(any(target_os = "linux", target_os = "android")))
            .with_removals(true)
    }

    /// Enables or disables atomic regular-file publication.
    #[must_use]
    pub const fn with_atomic_commit(mut self, enabled: bool) -> Self {
        self.atomic_commit = enabled;
        self
    }
    /// Enables or disables mode restoration.
    #[must_use]
    pub const fn with_mode(mut self, enabled: bool) -> Self {
        self.mode = enabled;
        self
    }
    /// Enables or disables ownership restoration.
    #[must_use]
    pub const fn with_ownership(mut self, enabled: bool) -> Self {
        self.ownership = enabled;
        self
    }
    /// Enables or disables access-time restoration.
    #[must_use]
    pub const fn with_access_time(mut self, enabled: bool) -> Self {
        self.access_time = enabled;
        self
    }
    /// Enables or disables modification-time restoration.
    #[must_use]
    pub const fn with_modification_time(mut self, enabled: bool) -> Self {
        self.modification_time = enabled;
        self
    }
    /// Enables or disables metadata-change-time restoration.
    #[must_use]
    pub const fn with_change_time(mut self, enabled: bool) -> Self {
        self.change_time = enabled;
        self
    }
    /// Enables or disables creation-time restoration.
    #[must_use]
    pub const fn with_creation_time(mut self, enabled: bool) -> Self {
        self.creation_time = enabled;
        self
    }
    /// Enables or disables symbolic links.
    #[must_use]
    pub const fn with_symlinks(mut self, enabled: bool) -> Self {
        self.symlinks = enabled;
        self
    }
    /// Enables or disables hard links.
    #[must_use]
    pub const fn with_hardlinks(mut self, enabled: bool) -> Self {
        self.hardlinks = enabled;
        self
    }
    /// Enables or disables extended attributes.
    #[must_use]
    pub const fn with_xattrs(mut self, enabled: bool) -> Self {
        self.xattrs = enabled;
        self
    }
    /// Enables or disables ACL restoration.
    #[must_use]
    pub const fn with_acls(mut self, enabled: bool) -> Self {
        self.acls = enabled;
        self
    }
    /// Enables or disables sparse extent preservation.
    #[must_use]
    pub const fn with_sparse(mut self, enabled: bool) -> Self {
        self.sparse = enabled;
        self
    }
    /// Enables or disables explicitly permitted special files.
    #[must_use]
    pub const fn with_special_files(mut self, enabled: bool) -> Self {
        self.special_files = enabled;
        self
    }
    /// Enables or disables platform filesystem flags.
    #[must_use]
    pub const fn with_file_flags(mut self, enabled: bool) -> Self {
        self.file_flags = enabled;
        self
    }
    /// Enables or disables whiteout removal and opaque-directory clearing.
    #[must_use]
    pub const fn with_removals(mut self, enabled: bool) -> Self {
        self.removals = enabled;
        self
    }

    /// Whether regular files are published atomically.
    #[must_use]
    pub const fn atomic_commit(self) -> bool {
        self.atomic_commit
    }
    /// Whether mode bits can be restored.
    #[must_use]
    pub const fn mode(self) -> bool {
        self.mode
    }
    /// Whether numeric ownership can be restored.
    #[must_use]
    pub const fn ownership(self) -> bool {
        self.ownership
    }
    /// Whether access time can be restored.
    #[must_use]
    pub const fn access_time(self) -> bool {
        self.access_time
    }
    /// Whether modification time can be restored.
    #[must_use]
    pub const fn modification_time(self) -> bool {
        self.modification_time
    }
    /// Whether metadata-change time can be restored.
    #[must_use]
    pub const fn change_time(self) -> bool {
        self.change_time
    }
    /// Whether creation/birth time can be restored.
    #[must_use]
    pub const fn creation_time(self) -> bool {
        self.creation_time
    }
    /// Whether symbolic links can be materialized.
    #[must_use]
    pub const fn symlinks(self) -> bool {
        self.symlinks
    }
    /// Whether hard links can be materialized.
    #[must_use]
    pub const fn hardlinks(self) -> bool {
        self.hardlinks
    }
    /// Whether extended attributes can be restored.
    #[must_use]
    pub const fn xattrs(self) -> bool {
        self.xattrs
    }
    /// Whether ACLs can be restored.
    #[must_use]
    pub const fn acls(self) -> bool {
        self.acls
    }
    /// Whether sparse extent maps can be preserved.
    #[must_use]
    pub const fn sparse(self) -> bool {
        self.sparse
    }
    /// Whether special files can be materialized.
    #[must_use]
    pub const fn special_files(self) -> bool {
        self.special_files
    }
    /// Whether filesystem flags can be restored.
    #[must_use]
    pub const fn file_flags(self) -> bool {
        self.file_flags
    }
    /// Whether whiteout removal and opaque-directory clearing are supported.
    #[must_use]
    pub const fn removals(self) -> bool {
        self.removals
    }

    /// Whether this capability covers an operation.
    #[must_use]
    pub fn supports(self, operation: &FilesystemOperation) -> bool {
        match operation {
            FilesystemOperation::Entry => true,
            FilesystemOperation::AtomicCommit => self.atomic_commit,
            FilesystemOperation::Mode => self.mode,
            FilesystemOperation::Ownership => self.ownership,
            FilesystemOperation::AccessTime => self.access_time,
            FilesystemOperation::ModificationTime => self.modification_time,
            FilesystemOperation::ChangeTime => self.change_time,
            FilesystemOperation::CreationTime => self.creation_time,
            FilesystemOperation::Sparse => self.sparse,
            FilesystemOperation::ExtendedAttribute(_) => self.xattrs,
            FilesystemOperation::Acl(_) => self.acls,
            FilesystemOperation::FileFlags => self.file_flags,
            FilesystemOperation::RemovePath | FilesystemOperation::ClearDirectory => self.removals,
        }
    }

    /// Whether this capability covers an entry kind.
    #[must_use]
    pub const fn supports_entry(self, kind: EntryKind) -> bool {
        match kind {
            EntryKind::File | EntryKind::Dir => true,
            EntryKind::Symlink => self.symlinks,
            EntryKind::Hardlink => self.hardlinks,
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket => {
                self.special_files
            },
            _ => false,
        }
    }
}
/// One policy-validated entry passed to a filesystem adapter.
///
/// `destination` and `link_target` are normalized relative paths. The engine
/// has already rejected absolute paths, traversal, drive prefixes, and
/// hardlink targets that were not committed earlier in this session. Adapters
/// must still resolve paths without following untrusted intermediate links.
#[derive(Debug, Clone, Copy)]
pub struct FilesystemEntry<'a> {
    metadata: &'a EntryMetadata,
    destination: &'a Path,
    link_target: Option<&'a Path>,
    overwrite: bool,
}

impl<'a> FilesystemEntry<'a> {
    pub(crate) const fn new(
        metadata: &'a EntryMetadata,
        destination: &'a Path,
        link_target: Option<&'a Path>,
        overwrite: bool,
    ) -> Self {
        Self {
            metadata,
            destination,
            link_target,
            overwrite,
        }
    }

    /// Archive metadata for the entry.
    #[must_use]
    pub const fn metadata(self) -> &'a EntryMetadata {
        self.metadata
    }
    /// Normalized relative destination.
    #[must_use]
    pub const fn destination(self) -> &'a Path {
        self.destination
    }
    /// Normalized relative link target, when applicable.
    #[must_use]
    pub const fn link_target(self) -> Option<&'a Path> {
        self.link_target
    }
    /// Whether policy permits atomically replacing an existing regular file.
    #[must_use]
    pub const fn overwrite(self) -> bool {
        self.overwrite
    }
}

/// A policy-validated whiteout or opaque-directory request.
///
/// `destination` is a normalized relative path; the engine has already rejected
/// absolute paths, traversal, drive prefixes, and unrepresentable bytes. An
/// empty destination denotes the extraction root itself. Adapters must still
/// resolve the path without following untrusted intermediate links.
#[derive(Debug, Clone, Copy)]
pub struct FilesystemRemoval<'a> {
    path: &'a ArchivePath,
    destination: &'a Path,
}

impl<'a> FilesystemRemoval<'a> {
    pub(crate) const fn new(path: &'a ArchivePath, destination: &'a Path) -> Self {
        Self { path, destination }
    }

    /// Archive-native path of the whiteout or opaque marker entry.
    #[must_use]
    pub const fn path(self) -> &'a ArchivePath {
        self.path
    }

    /// Normalized relative destination the request targets.
    #[must_use]
    pub const fn destination(self) -> &'a Path {
        self.destination
    }
}

/// Materialization result returned by an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilesystemMaterialization {
    /// A regular file was published.
    File,
    /// A directory was created or updated.
    Directory,
    /// A symbolic link was created.
    Symlink,
    /// A hard link was created.
    Hardlink,
    /// A special file was created.
    Special,
    /// An existing destination prevented materialization.
    DestinationExists,
    /// The adapter refused or failed the entry operation.
    Failed,
}

/// Result returned after an adapter finishes one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemEntryReport {
    materialization: FilesystemMaterialization,
    findings: Vec<FilesystemFinding>,
}

impl FilesystemEntryReport {
    /// Creates an entry report.
    #[must_use]
    pub const fn new(
        materialization: FilesystemMaterialization,
        findings: Vec<FilesystemFinding>,
    ) -> Self {
        Self {
            materialization,
            findings,
        }
    }

    /// Materialization result.
    #[must_use]
    pub const fn materialization(&self) -> FilesystemMaterialization {
        self.materialization
    }
    /// Operation findings produced while applying the entry.
    #[must_use]
    pub fn findings(&self) -> &[FilesystemFinding] {
        &self.findings
    }
    /// Consumes the report.
    #[must_use]
    pub fn into_parts(self) -> (FilesystemMaterialization, Vec<FilesystemFinding>) {
        (self.materialization, self.findings)
    }
}

/// Fatal adapter error.
///
/// Expected per-entry policy, capability, permission, and OS failures should
/// be returned as [`FilesystemFinding`] values so they remain visible in the
/// final apply report. This error is reserved for broken adapter state or an
/// infrastructure failure that prevents continued streaming.
#[derive(Debug)]
pub struct FilesystemAdapterError {
    operation: &'static str,
    source: io::Error,
}

impl FilesystemAdapterError {
    /// Wraps an infrastructure I/O error.
    #[must_use]
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self { operation, source }
    }
    /// Creates a protocol-state error.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self {
            operation: "adapter protocol",
            source: io::Error::new(io::ErrorKind::InvalidData, message.into()),
        }
    }
    /// Operation being performed.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }
    /// Underlying portable I/O category.
    #[must_use]
    pub fn io_error_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
    /// Raw OS code, when present.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }

    pub(crate) fn into_io(self) -> io::Error {
        io::Error::new(self.source.kind(), self)
    }
}

impl fmt::Display for FilesystemAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.source)
    }
}

impl Error for FilesystemAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Stateful, compile-time filesystem materialization adapter.
///
/// The engine calls methods in strict
/// `begin_session -> (begin_entry -> write_data* -> finish_entry)* ->
/// finish_session` order. `abort_entry` is called when archive decoding fails
/// with an entry in flight. Implementations retain their own bounded pending
/// state; no trait object or ambient path is required.
pub trait FilesystemAdapter {
    /// Stable capabilities for this adapter instance.
    fn capabilities(&self) -> FilesystemCapabilities;
    /// Starts a new apply session.
    fn begin_session(&mut self) -> Result<(), FilesystemAdapterError>;
    /// Starts one policy-validated entry.
    fn begin_entry(&mut self, entry: FilesystemEntry<'_>) -> Result<(), FilesystemAdapterError>;
    /// Streams entry payload bytes.
    fn write_data(&mut self, data: &[u8]) -> Result<(), FilesystemAdapterError>;
    /// Finishes and reports one entry.
    fn finish_entry(&mut self) -> Result<FilesystemEntryReport, FilesystemAdapterError>;
    /// Aborts and cleans up the current entry.
    fn abort_entry(&mut self);
    /// Finalizes deferred directory metadata and returns additional findings.
    fn finish_session(&mut self) -> Result<Vec<FilesystemFinding>, FilesystemAdapterError>;

    /// Removes a whiteout target path, including any subtree it roots.
    ///
    /// The default implementation reports the operation as unsupported, so
    /// existing adapters and test doubles keep compiling and refusing removals
    /// until they opt in.
    ///
    /// # Errors
    ///
    /// Returns an error only for broken adapter state or infrastructure
    /// failures; expected refusals and OS errors are returned as findings.
    fn remove_path(
        &mut self,
        request: FilesystemRemoval<'_>,
    ) -> Result<FilesystemFinding, FilesystemAdapterError> {
        Ok(FilesystemFinding::unsupported(
            request.path().clone(),
            FilesystemOperation::RemovePath,
            "filesystem adapter does not support whiteout removal",
        ))
    }

    /// Clears the contents of an opaque directory in place.
    ///
    /// The default implementation reports the operation as unsupported.
    ///
    /// # Errors
    ///
    /// Returns an error only for broken adapter state or infrastructure
    /// failures; expected refusals and OS errors are returned as findings.
    fn clear_directory(
        &mut self,
        request: FilesystemRemoval<'_>,
    ) -> Result<FilesystemFinding, FilesystemAdapterError> {
        Ok(FilesystemFinding::unsupported(
            request.path().clone(),
            FilesystemOperation::ClearDirectory,
            "filesystem adapter does not support opaque-directory clearing",
        ))
    }
}
