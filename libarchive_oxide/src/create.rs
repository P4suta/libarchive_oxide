// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded filesystem-to-archive streaming.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind, FormatId, Limits,
    Owner, PathEncoding, Timestamp,
};

use crate::path::sanitize_archive_path;
use crate::{ArchiveEngine, ArchiveWriter, CreateOptions, StreamError};

const COPY_BUFFER: usize = 64 * 1024;

/// Error from a filesystem-to-archive streaming operation.
#[derive(Debug)]
pub enum CreateStreamError {
    /// Filesystem or output I/O failed.
    Io(io::Error),
    /// Archive protocol, capability, or output-adapter failure.
    Archive(StreamError),
    /// Archive configuration, resource limit, or safe-name contract failed.
    Contract(ArchiveError),
}

impl fmt::Display for CreateStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Archive(error) => error.fmt(f),
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CreateStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Archive(error) => Some(error),
            Self::Contract(error) => Some(error),
        }
    }
}

impl From<io::Error> for CreateStreamError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StreamError> for CreateStreamError {
    fn from(value: StreamError) -> Self {
        Self::Archive(value)
    }
}

impl From<ArchiveError> for CreateStreamError {
    fn from(value: ArchiveError) -> Self {
        Self::Contract(value)
    }
}

/// Filesystem walker backed by the common bounded archive state machine.
///
/// Regular-file payload is copied in 64 KiB chunks. The builder never retains
/// a complete file or archive.
pub struct StreamingArchiveBuilder<W: Write> {
    writer: ArchiveWriter<W>,
    copy_buffer: Vec<u8>,
    limits: Limits,
}

impl<W: Write> fmt::Debug for StreamingArchiveBuilder<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingArchiveBuilder")
            .field("format", &self.writer.format())
            .finish_non_exhaustive()
    }
}

impl<W: Write> StreamingArchiveBuilder<W> {
    /// Creates a builder for a sequential format and optional outer filter.
    ///
    /// This compatibility constructor delegates to [`Self::with_engine`] so
    /// filesystem creation and direct engine creation use the same writer
    /// state machine and [`CreateOptions`] contract.
    pub fn new(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
    ) -> Result<Self, CreateStreamError> {
        Self::with_engine(
            ArchiveEngine::new().with_limits(limits),
            output,
            CreateOptions::new().with_format(format).with_filter(filter),
        )
    }

    /// Creates a bounded filesystem builder through an [`ArchiveEngine`].
    pub fn with_engine(
        engine: ArchiveEngine,
        output: W,
        options: CreateOptions,
    ) -> Result<Self, CreateStreamError> {
        let limits = options.limits().unwrap_or(engine.limits());
        let writer = engine.create(output, options)?;
        Ok(Self {
            writer,
            copy_buffer: vec![0; COPY_BUFFER],
            limits,
        })
    }

    /// Recursively appends a filesystem path using the supplied archive name.
    pub fn append_path_as(
        &mut self,
        filesystem_path: impl AsRef<Path>,
        archive_path: &ArchivePath,
    ) -> Result<(), CreateStreamError> {
        if archive_path.as_bytes() != b"." && sanitize_archive_path(archive_path).is_none() {
            return Err(unsafe_archive_name(archive_path.as_bytes()));
        }
        self.append_path_bytes(filesystem_path.as_ref(), archive_path.as_bytes())
    }

    /// Recursively appends a path, deriving a safe relative archive name.
    pub fn append_path(
        &mut self,
        filesystem_path: impl AsRef<Path>,
    ) -> Result<(), CreateStreamError> {
        let path = filesystem_path.as_ref();
        let name = normalize_name(path)?;
        self.append_path_bytes(path, &name)
    }

    /// Finalizes the archive and returns the destination.
    pub fn finish(self) -> Result<W, CreateStreamError> {
        self.writer.finish().map_err(CreateStreamError::Archive)
    }

    fn append_path_bytes(
        &mut self,
        filesystem_path: &Path,
        archive_name: &[u8],
    ) -> Result<(), CreateStreamError> {
        validate_archive_name(archive_name, self.limits)?;
        let metadata = fs::symlink_metadata(filesystem_path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(filesystem_path)?;
            let target = os_bytes_checked(target.as_os_str())?;
            let body = matches!(self.writer.format(), FormatId::Cpio | FormatId::Zip)
                .then_some(target.as_slice())
                .unwrap_or_default();
            let entry = metadata_for(
                EntryKind::Symlink,
                archive_name,
                body.len() as u64,
                &metadata,
                Some(&target),
            );
            self.writer.start_entry(&entry)?;
            self.writer.write_data(body)?;
            self.writer.end_entry()?;
            return Ok(());
        }
        if file_type.is_dir() {
            let mut directory_name = archive_name.to_vec();
            if !directory_name.ends_with(b"/") {
                directory_name.push(b'/');
            }
            let entry = metadata_for(EntryKind::Dir, &directory_name, 0, &metadata, None);
            self.writer.start_entry(&entry)?;
            self.writer.end_entry()?;
            for child in fs::read_dir(filesystem_path)? {
                let child = child?;
                let component = os_bytes_checked(&child.file_name())?;
                let mut child_name = archive_name.to_vec();
                if !child_name.ends_with(b"/") {
                    child_name.push(b'/');
                }
                child_name.extend_from_slice(&component);
                self.append_path_bytes(&child.path(), &child_name)?;
            }
            return Ok(());
        }
        if file_type.is_file() {
            let entry = metadata_for(
                EntryKind::File,
                archive_name,
                metadata.len(),
                &metadata,
                None,
            );
            self.writer.start_entry(&entry)?;
            let mut input = fs::File::open(filesystem_path)?;
            loop {
                let read = input.read(&mut self.copy_buffer)?;
                if read == 0 {
                    break;
                }
                self.writer.write_data(&self.copy_buffer[..read])?;
            }
            self.writer.end_entry()?;
            return Ok(());
        }
        Err(CreateStreamError::Contract(
            ArchiveError::new(ErrorKind::Capability).with_context(
                "input filesystem object is not a regular file, directory, or symlink",
            ),
        ))
    }
}

fn metadata_for(
    kind: EntryKind,
    path: &[u8],
    size: u64,
    metadata: &fs::Metadata,
    link_target: Option<&[u8]>,
) -> EntryMetadata {
    let (mode, owner, modified) = platform_metadata(metadata);
    EntryMetadata::builder(
        kind,
        ArchivePath::from_encoded(path.to_vec(), PathEncoding::Bytes),
    )
    .size(Some(size))
    .mode(Some(mode))
    .owner(owner)
    .times(EntryTimes {
        modified,
        ..EntryTimes::default()
    })
    .link_target(link_target.map(|target| ArchivePath::from_bytes(target.to_vec())))
    .build()
}

#[cfg(unix)]
fn platform_metadata(metadata: &fs::Metadata) -> (u32, Owner, Option<Timestamp>) {
    use std::os::unix::fs::MetadataExt;

    (
        metadata.mode() & 0o7777,
        Owner {
            uid: Some(u64::from(metadata.uid())),
            gid: Some(u64::from(metadata.gid())),
            ..Owner::default()
        },
        Some(Timestamp {
            secs: metadata.mtime(),
            nanos: u32::try_from(metadata.mtime_nsec()).unwrap_or(0),
        }),
    )
}

#[cfg(not(unix))]
fn platform_metadata(metadata: &fs::Metadata) -> (u32, Owner, Option<Timestamp>) {
    let mode = if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| Timestamp {
            secs: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: duration.subsec_nanos(),
        });
    (mode, Owner::default(), modified)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Keep one fallible signature across host path encodings.
fn os_bytes_checked(value: &OsStr) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    Ok(value.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn os_bytes_checked(value: &OsStr) -> io::Result<Vec<u8>> {
    value
        .to_str()
        .map(|value| value.as_bytes().to_vec())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "path is not representable"))
}

/// Derives a safe relative archive name without lossy host-path conversion.
fn normalize_name(path: &Path) -> io::Result<Vec<u8>> {
    let mut name = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                if !name.is_empty() {
                    name.push(b'/');
                }
                name.extend_from_slice(&os_bytes_checked(value)?);
            },
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "create input contains a parent-directory component",
                ));
            },
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {},
        }
    }
    if name.is_empty() && path == Path::new(".") {
        return Ok(b".".to_vec());
    }
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "create input has no safe relative archive name",
        ));
    }
    Ok(name)
}

fn validate_archive_name(name: &[u8], limits: Limits) -> Result<(), CreateStreamError> {
    if name != b"." && name != b"./" {
        let archive_path = ArchivePath::from_bytes(name.to_vec());
        if sanitize_archive_path(&archive_path).is_none() {
            return Err(unsafe_archive_name(name));
        }
    }
    if limits
        .path_bytes()
        .is_some_and(|maximum| name.len() > maximum)
    {
        return Err(CreateStreamError::Contract(
            ArchiveError::new(ErrorKind::Limit)
                .with_entry(0, name)
                .with_context("create path exceeds the configured byte limit"),
        ));
    }
    let nesting = name
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .count();
    if limits.nesting().is_some_and(|maximum| nesting > maximum) {
        return Err(CreateStreamError::Contract(
            ArchiveError::new(ErrorKind::Limit)
                .with_entry(0, name)
                .with_context("create path exceeds the configured nesting limit"),
        ));
    }
    Ok(())
}

fn unsafe_archive_name(name: &[u8]) -> CreateStreamError {
    CreateStreamError::Contract(
        ArchiveError::new(ErrorKind::Policy)
            .with_entry(0, name)
            .with_context("create input would produce an unsafe archive path"),
    )
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use super::normalize_name;

    #[test]
    fn normalize_strips_roots_and_dot_without_lossy_text_conversion() {
        assert_eq!(
            normalize_name(Path::new("/etc/hosts")).unwrap(),
            b"etc/hosts"
        );
        assert_eq!(normalize_name(Path::new("./a/b")).unwrap(), b"a/b");
        assert_eq!(normalize_name(Path::new("dir/")).unwrap(), b"dir");
        assert_eq!(normalize_name(Path::new("plain")).unwrap(), b"plain");
        assert_eq!(normalize_name(Path::new(".")).unwrap(), b".");
    }

    #[test]
    fn normalize_rejects_parent_components() {
        assert!(normalize_name(Path::new("../outside")).is_err());
        assert!(normalize_name(Path::new("inside/../../outside")).is_err());
    }
}
