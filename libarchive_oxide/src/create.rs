// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded filesystem-to-archive streaming.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata,
    EntryTimes, ErrorKind, FormatId, Limits, Owner, PathEncoding, Timestamp,
};

use crate::filter::gzip::GzipEncoder;
use crate::{ArchiveWriter, StreamError};

const COPY_BUFFER: usize = 64 * 1024;

/// Error from a filesystem-to-archive streaming operation.
#[derive(Debug)]
pub enum CreateStreamError {
    /// Filesystem or output I/O failed.
    Io(io::Error),
    /// Archive protocol, capability, or output-adapter failure.
    Archive(StreamError),
    /// The requested archive/filter configuration is unavailable.
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

enum FilteredOutput<W: Write> {
    Plain(W),
    Gzip(Box<GzipWrite<W>>),
    #[cfg(feature = "bzip2")]
    Bzip2(Box<bzip2::write::BzEncoder<W>>),
    #[cfg(feature = "zstd")]
    Zstd(Box<zstd_codec::stream::write::Encoder<'static, W>>),
    #[cfg(feature = "xz")]
    Xz(Box<lzma_rust2::XzWriter<W>>),
    #[cfg(feature = "lz4")]
    Lz4(Box<lz4_flex::frame::FrameEncoder<W>>),
}

impl<W: Write> FilteredOutput<W> {
    fn new(output: W, filter: Option<FilterId>, limits: Limits) -> Result<Self, CreateStreamError> {
        match filter {
            None => Ok(Self::Plain(output)),
            Some(FilterId::Gzip) => Ok(Self::Gzip(Box::new(GzipWrite::new(output, limits)))),
            #[cfg(feature = "bzip2")]
            Some(FilterId::Bzip2) => Ok(Self::Bzip2(Box::new(bzip2::write::BzEncoder::new(
                output,
                bzip2::Compression::default(),
            )))),
            #[cfg(feature = "zstd")]
            Some(FilterId::Zstd) => zstd_codec::stream::write::Encoder::new(output, 3)
                .map(Box::new)
                .map(Self::Zstd)
                .map_err(CreateStreamError::Io),
            #[cfg(feature = "xz")]
            Some(FilterId::Xz) => {
                lzma_rust2::XzWriter::new(output, lzma_rust2::XzOptions::with_preset(6))
                    .map(Box::new)
                    .map(Self::Xz)
                    .map_err(CreateStreamError::Io)
            },
            #[cfg(feature = "lz4")]
            Some(FilterId::Lz4) => Ok(Self::Lz4(Box::new(lz4_flex::frame::FrameEncoder::new(
                output,
            )))),
            Some(_) => Err(CreateStreamError::Contract(
                ArchiveError::new(ErrorKind::Capability)
                    .with_context("filter has no incremental filesystem writer"),
            )),
        }
    }

    fn finish(self) -> io::Result<W> {
        match self {
            Self::Plain(output) => Ok(output),
            Self::Gzip(output) => (*output).finish(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => (*output).finish(),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => (*output).finish(),
            #[cfg(feature = "xz")]
            Self::Xz(output) => (*output).finish(),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => (*output)
                .finish()
                .map_err(|error| io::Error::other(error.to_string())),
        }
    }
}

impl<W: Write> Write for FilteredOutput<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(output) => output.write(buffer),
            Self::Gzip(output) => output.write(buffer),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => output.write(buffer),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => output.write(buffer),
            #[cfg(feature = "xz")]
            Self::Xz(output) => output.write(buffer),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => output.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(output) => output.flush(),
            Self::Gzip(output) => output.flush(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => output.flush(),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => output.flush(),
            #[cfg(feature = "xz")]
            Self::Xz(output) => output.flush(),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => output.flush(),
        }
    }
}

struct GzipWrite<W> {
    output: W,
    codec: GzipEncoder,
    buffer: Vec<u8>,
}

impl<W: Write> GzipWrite<W> {
    fn new(output: W, limits: Limits) -> Self {
        Self {
            output,
            codec: GzipEncoder::new(limits),
            buffer: vec![0; COPY_BUFFER],
        }
    }

    fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self
                .codec
                .process(&[], &mut self.buffer, EndOfInput::End)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if matches!(step.status, CodecStatus::Done) {
                self.output.flush()?;
                return Ok(self.output);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gzip encoder made no finish progress",
                ));
            }
        }
    }
}

impl<W: Write> Write for GzipWrite<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let original = input.len();
        while !input.is_empty() {
            let step = self
                .codec
                .process(input, &mut self.buffer, EndOfInput::More)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            self.output.write_all(&self.buffer[..step.produced])?;
            input = &input[step.consumed..];
            if step.consumed == 0 && step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gzip encoder made no write progress",
                ));
            }
        }
        Ok(original)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Filesystem walker backed by the common bounded archive state machine.
///
/// Regular-file payload is copied in 64 KiB chunks. The builder never retains
/// a complete file or archive.
pub struct StreamingArchiveBuilder<W: Write> {
    writer: ArchiveWriter<FilteredOutput<W>>,
    copy_buffer: Vec<u8>,
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
    pub fn new(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
    ) -> Result<Self, CreateStreamError> {
        let output = FilteredOutput::new(output, filter, limits)?;
        let writer = ArchiveWriter::with_format_and_limits(output, format, limits)?;
        Ok(Self {
            writer,
            copy_buffer: vec![0; COPY_BUFFER],
        })
    }

    /// Recursively appends a filesystem path using the supplied archive name.
    pub fn append_path_as(
        &mut self,
        filesystem_path: impl AsRef<Path>,
        archive_path: &ArchivePath,
    ) -> Result<(), CreateStreamError> {
        self.append_path_bytes(filesystem_path.as_ref(), archive_path.as_bytes())
    }

    /// Recursively appends a path, deriving a safe relative archive name.
    pub fn append_path(
        &mut self,
        filesystem_path: impl AsRef<Path>,
    ) -> Result<(), CreateStreamError> {
        let path = filesystem_path.as_ref();
        let display = path.to_string_lossy();
        let name = normalize_name(&display);
        self.append_path_bytes(path, &name)
    }

    /// Finalizes the archive and returns the destination.
    pub fn finish(self) -> Result<W, CreateStreamError> {
        self.writer
            .finish()
            .map_err(CreateStreamError::Archive)?
            .finish()
            .map_err(CreateStreamError::Io)
    }

    fn append_path_bytes(
        &mut self,
        filesystem_path: &Path,
        archive_name: &[u8],
    ) -> Result<(), CreateStreamError> {
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
        }
        Ok(())
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

/// Normalizes a filesystem argument into a safe relative tar entry name (raw bytes):
/// strips a leading `/` (so members are never absolute) and any `./` prefix or trailing `/`.
/// On Windows, backslashes are treated as separators; on other platforms they are left literal.
fn normalize_name(arg: &str) -> Vec<u8> {
    #[cfg(windows)]
    let owned = arg.replace('\\', "/");
    #[cfg(windows)]
    let mut s: &str = &owned;
    #[cfg(not(windows))]
    let mut s: &str = arg;

    s = s.trim_end_matches('/');
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s = s.trim_start_matches('/');
    s.as_bytes().to_vec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::normalize_name;

    #[test]
    fn normalize_strips_leading_slash_and_dot() {
        assert_eq!(normalize_name("/etc/hosts"), b"etc/hosts");
        assert_eq!(normalize_name("./a/b"), b"a/b");
        assert_eq!(normalize_name("dir/"), b"dir");
        assert_eq!(normalize_name("plain"), b"plain");
    }
}
