// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded `Read` adapters for outer filters with codec-specific streaming APIs.

use std::cell::RefCell;
use std::fmt;
use std::io::{self, BufReader, Read, Write};
use std::rc::Rc;

use libarchive_oxide_core::Codec;
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, CodecStatus, EndOfInput, ErrorKind, Limits};

use crate::capability::{Backend, BackendPreference};
use crate::codec_read::CodecReader;
use crate::filter::gzip::GzipEncoder;
use crate::pipeline_codec::PipelineCodec;

const BUFFER: usize = 64 * 1024;

/// A bounded outer-filter reader: the shared [`CodecReader`] engine driving a [`PipelineCodec`].
type PipelineRead<R> = CodecReader<R, PipelineCodec>;

/// Builds a [`PipelineRead`] for an outer filter, constructing its [`PipelineCodec`] first.
fn pipeline_reader<R: Read>(
    input: R,
    filter: FilterId,
    limits: Limits,
    backend: BackendPreference,
) -> io::Result<PipelineRead<R>> {
    let name = match filter {
        FilterId::Zstd => "zstd",
        FilterId::Lz4 => "LZ4",
        FilterId::Compress => "compress",
        FilterId::Lzip => "lzip",
        FilterId::Base64 => "Base64",
        FilterId::Uuencode => "uuencode",
        FilterId::Lzop => "lzop",
        FilterId::Rpm => "RPM",
        _ => "codec",
    };
    let codec = PipelineCodec::with_backend(filter, limits, backend).map_err(codec_archive_io)?;
    Ok(CodecReader::new(input, codec, name))
}

/// Auto-detecting streaming input filter.
///
/// gzip uses the common sans-I/O codec. The other variants use bounded
/// incremental Rust APIs without retaining the compressed or decoded stream.
pub struct FilterReader<R: Read> {
    inner: FilterReaderInner<R>,
    decoded: u64,
    decoded_limit: Option<u64>,
}

enum FilterReaderInner<R: Read> {
    /// Unfiltered input, including gzip for the common pipeline.
    Plain(BufReader<PrefixReader<R>>),
    /// gzip members decoded by the common sans-I/O codec.
    Gzip(Box<GzipRead<BufReader<PrefixReader<R>>>>),
    /// Concatenated bzip2 streams.
    #[cfg(feature = "bzip2")]
    Bzip2(Box<bzip2::read::MultiBzDecoder<BufReader<PrefixReader<R>>>>),
    /// Zstandard frame.
    #[cfg(feature = "zstd")]
    Zstd(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// Concatenated XZ streams.
    #[cfg(feature = "xz")]
    Xz(Box<XzRead<BufReader<PrefixReader<R>>>>),
    /// LZ4 frame.
    #[cfg(feature = "lz4")]
    Lz4(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// Unix `compress(1)` LZW stream.
    #[cfg(feature = "compress")]
    Compress(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// Concatenated lzip members.
    #[cfg(feature = "lzip")]
    Lzip(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// Explicit-only LZMA-alone stream.
    #[cfg(feature = "lzma")]
    Lzma(Box<LzmaRead<BufReader<PrefixReader<R>>>>),
    /// Explicit-only RFC 4648 Base64 stream.
    Base64(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// POSIX uuencoded member.
    Uuencode(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// RPM package wrapper, yielding its normally compressed cpio payload.
    Rpm(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
    /// lzop member stream.
    #[cfg(feature = "lzop")]
    Lzop(Box<PipelineRead<BufReader<PrefixReader<R>>>>),
}

impl<R: Read> FilterReader<R> {
    /// Decodes an explicitly selected outer filter.
    ///
    /// This is required for signatureless filters such as [`FilterId::Base64`] and [`FilterId::Lzma`].
    /// Framed filters can also be selected explicitly; [`Self::new`] remains the normal auto-detecting path.
    #[allow(clippy::too_many_lines)] // One ownership-preserving dispatch over built-in filters.
    pub fn with_filter(input: R, filter: FilterId, limits: Limits) -> io::Result<Self> {
        let backend = BackendPreference::Auto;
        let input = BufReader::new(PrefixReader {
            prefix: [0; 9],
            prefix_len: 0,
            prefix_position: 0,
            input,
        });
        let inner = match filter {
            FilterId::Gzip => {
                FilterReaderInner::Gzip(Box::new(GzipRead::new(input, limits, backend)?))
            },
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    FilterReaderInner::Bzip2(Box::new(bzip2::read::MultiBzDecoder::new(input)))
                }
                #[cfg(not(feature = "bzip2"))]
                return Err(disabled_filter("bzip2"));
            },
            FilterId::Zstd => {
                #[cfg(feature = "zstd")]
                {
                    pipeline_reader(input, filter, limits, backend)
                        .map(Box::new)
                        .map(FilterReaderInner::Zstd)?
                }
                #[cfg(not(feature = "zstd"))]
                return Err(disabled_filter("zstd"));
            },
            FilterId::Xz => {
                #[cfg(feature = "xz")]
                {
                    FilterReaderInner::Xz(Box::new(XzRead::new(input, limits, backend)?))
                }
                #[cfg(not(feature = "xz"))]
                return Err(disabled_filter("XZ"));
            },
            FilterId::Lz4 => {
                #[cfg(feature = "lz4")]
                {
                    pipeline_reader(input, filter, limits, backend)
                        .map(Box::new)
                        .map(FilterReaderInner::Lz4)?
                }
                #[cfg(not(feature = "lz4"))]
                return Err(disabled_filter("LZ4"));
            },
            FilterId::Compress => {
                #[cfg(feature = "compress")]
                {
                    pipeline_reader(input, filter, limits, backend)
                        .map(Box::new)
                        .map(FilterReaderInner::Compress)?
                }
                #[cfg(not(feature = "compress"))]
                return Err(disabled_filter("compress/LZW"));
            },
            FilterId::Lzip => {
                #[cfg(feature = "lzip")]
                {
                    pipeline_reader(input, filter, limits, backend)
                        .map(Box::new)
                        .map(FilterReaderInner::Lzip)?
                }
                #[cfg(not(feature = "lzip"))]
                return Err(disabled_filter("lzip"));
            },
            FilterId::Base64 => pipeline_reader(input, filter, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Base64)?,
            FilterId::Uuencode => pipeline_reader(input, filter, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Uuencode)?,
            FilterId::Rpm => pipeline_reader(input, filter, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Rpm)?,
            FilterId::Lzop => {
                #[cfg(feature = "lzop")]
                {
                    pipeline_reader(input, filter, limits, backend)
                        .map(Box::new)
                        .map(FilterReaderInner::Lzop)?
                }
                #[cfg(not(feature = "lzop"))]
                return Err(disabled_filter("lzop"));
            },
            FilterId::Lzma => {
                #[cfg(feature = "lzma")]
                {
                    FilterReaderInner::Lzma(Box::new(LzmaRead::new(input, limits)?))
                }
                #[cfg(not(feature = "lzma"))]
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "LZMA-alone filter is not enabled",
                ));
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the selected outer filter has no streaming reader",
                ));
            },
        };
        Ok(Self {
            inner,
            decoded: 0,
            decoded_limit: limits.decoded_total(),
        })
    }

    /// Detects an enabled outer filter from a buffered prefix.
    pub fn new(input: R) -> io::Result<Self> {
        Self::with_limits(input, Limits::default())
    }

    /// Detects an outer filter with explicit decoded-output budgets.
    pub fn with_limits(input: R, limits: Limits) -> io::Result<Self> {
        Self::with_backend(input, limits, BackendPreference::Auto)
    }

    /// Detects an outer filter using the selected portable or native codec backend.
    #[allow(clippy::too_many_lines)] // One ownership-preserving dispatch over all built-in filters.
    pub fn with_backend(
        mut input: R,
        limits: Limits,
        backend: BackendPreference,
    ) -> io::Result<Self> {
        let mut prefix = [0_u8; 9];
        let mut prefix_len = 0;
        while prefix_len != prefix.len() {
            let read = input.read(&mut prefix[prefix_len..])?;
            if read == 0 {
                break;
            }
            prefix_len += read;
        }
        let input = BufReader::new(PrefixReader {
            prefix,
            prefix_len,
            prefix_position: 0,
            input,
        });
        let available = &prefix[..prefix_len];
        if available.starts_with(b"LZIP") {
            #[cfg(feature = "lzip")]
            {
                return pipeline_reader(input, FilterId::Lzip, limits, backend)
                    .map(Box::new)
                    .map(FilterReaderInner::Lzip)
                    .map(|inner| Self {
                        inner,
                        decoded: 0,
                        decoded_limit: limits.decoded_total(),
                    });
            }
            #[cfg(not(feature = "lzip"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "lzip filter is not enabled",
            ));
        }
        backend.resolve().map_err(codec_archive_io)?;
        if available.starts_with(&[0x1f, 0x8b]) {
            return Ok(Self {
                inner: FilterReaderInner::Gzip(Box::new(GzipRead::new(input, limits, backend)?)),
                decoded: 0,
                decoded_limit: limits.decoded_total(),
            });
        }
        if available.starts_with(&[0x1f, 0x9d]) {
            #[cfg(feature = "compress")]
            {
                return pipeline_reader(input, FilterId::Compress, limits, backend)
                    .map(Box::new)
                    .map(FilterReaderInner::Compress)
                    .map(|inner| Self {
                        inner,
                        decoded: 0,
                        decoded_limit: limits.decoded_total(),
                    });
            }
            #[cfg(not(feature = "compress"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compress/LZW filter is not enabled",
            ));
        }
        if available.starts_with(b"begin ") {
            return pipeline_reader(input, FilterId::Uuencode, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Uuencode)
                .map(|inner| Self {
                    inner,
                    decoded: 0,
                    decoded_limit: limits.decoded_total(),
                });
        }
        if available.starts_with(b"\xed\xab\xee\xdb") {
            return pipeline_reader(input, FilterId::Rpm, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Rpm)
                .map(|inner| Self {
                    inner,
                    decoded: 0,
                    decoded_limit: limits.decoded_total(),
                });
        }
        if available.starts_with(b"\x89LZO\0\r\n\x1a\n") {
            #[cfg(feature = "lzop")]
            {
                return pipeline_reader(input, FilterId::Lzop, limits, backend)
                    .map(Box::new)
                    .map(FilterReaderInner::Lzop)
                    .map(|inner| Self {
                        inner,
                        decoded: 0,
                        decoded_limit: limits.decoded_total(),
                    });
            }
            #[cfg(not(feature = "lzop"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "lzop filter is not enabled",
            ));
        }
        if available.starts_with(b"BZh") {
            #[cfg(feature = "bzip2")]
            return Ok(Self {
                inner: FilterReaderInner::Bzip2(Box::new(bzip2::read::MultiBzDecoder::new(input))),
                decoded: 0,
                decoded_limit: limits.decoded_total(),
            });
            #[cfg(not(feature = "bzip2"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bzip2 filter is not enabled",
            ));
        }
        if available.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            #[cfg(feature = "zstd")]
            {
                return pipeline_reader(input, FilterId::Zstd, limits, backend)
                    .map(Box::new)
                    .map(FilterReaderInner::Zstd)
                    .map(|inner| Self {
                        inner,
                        decoded: 0,
                        decoded_limit: limits.decoded_total(),
                    })
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
            #[cfg(not(feature = "zstd"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zstd filter is not enabled",
            ));
        }
        if available.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
            #[cfg(feature = "xz")]
            return XzRead::new(input, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Xz)
                .map(|inner| Self {
                    inner,
                    decoded: 0,
                    decoded_limit: limits.decoded_total(),
                });
            #[cfg(not(feature = "xz"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XZ filter is not enabled",
            ));
        }
        if available.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
            #[cfg(feature = "lz4")]
            return pipeline_reader(input, FilterId::Lz4, limits, backend)
                .map(Box::new)
                .map(FilterReaderInner::Lz4)
                .map(|inner| Self {
                    inner,
                    decoded: 0,
                    decoded_limit: limits.decoded_total(),
                });
            #[cfg(not(feature = "lz4"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "LZ4 filter is not enabled",
            ));
        }
        Ok(Self {
            inner: FilterReaderInner::Plain(input),
            decoded: 0,
            decoded_limit: limits.decoded_total(),
        })
    }

    /// Returns the wrapped compressed input at its current physical position.
    #[must_use]
    pub fn into_inner(self) -> R {
        match self.inner {
            FilterReaderInner::Plain(input) => input.into_inner().input,
            FilterReaderInner::Gzip(input) => input.input.into_inner().input,
            #[cfg(feature = "bzip2")]
            FilterReaderInner::Bzip2(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "zstd")]
            FilterReaderInner::Zstd(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "xz")]
            FilterReaderInner::Xz(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "lz4")]
            FilterReaderInner::Lz4(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "compress")]
            FilterReaderInner::Compress(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "lzip")]
            FilterReaderInner::Lzip(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "lzma")]
            FilterReaderInner::Lzma(input) => input.into_inner().into_inner().input,
            FilterReaderInner::Base64(input) => input.into_inner().into_inner().input,
            FilterReaderInner::Uuencode(input) => input.into_inner().into_inner().input,
            FilterReaderInner::Rpm(input) => input.into_inner().into_inner().input,
            #[cfg(feature = "lzop")]
            FilterReaderInner::Lzop(input) => input.into_inner().into_inner().input,
        }
    }

    /// Borrows the original encoded source below every filter adapter.
    pub(crate) fn source_ref(&self) -> &R {
        match &self.inner {
            FilterReaderInner::Plain(input) => &input.get_ref().input,
            FilterReaderInner::Gzip(input) => &input.input.get_ref().input,
            #[cfg(feature = "bzip2")]
            FilterReaderInner::Bzip2(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "zstd")]
            FilterReaderInner::Zstd(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "xz")]
            FilterReaderInner::Xz(input) => &input.input.get_ref().input,
            #[cfg(feature = "lz4")]
            FilterReaderInner::Lz4(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "compress")]
            FilterReaderInner::Compress(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "lzip")]
            FilterReaderInner::Lzip(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "lzma")]
            FilterReaderInner::Lzma(input) => &input.decoder.inner().get_ref().input,
            FilterReaderInner::Base64(input) => &input.get_ref().get_ref().input,
            FilterReaderInner::Uuencode(input) => &input.get_ref().get_ref().input,
            FilterReaderInner::Rpm(input) => &input.get_ref().get_ref().input,
            #[cfg(feature = "lzop")]
            FilterReaderInner::Lzop(input) => &input.get_ref().get_ref().input,
        }
    }
}

#[allow(dead_code)] // Called only when at least one optional filter feature is disabled.
fn disabled_filter(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{name} filter is not enabled"),
    )
}

#[cfg(feature = "lzma")]
struct LzmaRead<R: Read> {
    decoder: lzma_rust2::LzmaReader<R>,
}

#[cfg(feature = "lzma")]
impl<R: Read> LzmaRead<R> {
    fn new(mut input: R, limits: Limits) -> io::Result<Self> {
        let mut header = [0_u8; 13];
        input.read_exact(&mut header).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                codec_archive_io(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("lzma")
                        .with_context("truncated LZMA-alone header"),
                )
            } else {
                error
            }
        })?;
        let properties = header[0];
        let dictionary = u32::from_le_bytes(header[1..5].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid LZMA dictionary field")
        })?);
        let declared_size =
            u64::from_le_bytes(header[5..13].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid LZMA size field")
            })?);
        let memory_kib = lzma_rust2::lzma_get_memory_usage_by_props(dictionary, properties)
            .map_err(|error| {
                codec_archive_io(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("lzma")
                        .with_context(error.to_string()),
                )
            })?;
        let memory = u64::from(memory_kib).saturating_mul(1024);
        if limits
            .codec_memory()
            .is_some_and(|maximum| memory > maximum as u64)
        {
            return Err(codec_archive_io(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("lzma")
                    .with_context("LZMA dictionary exceeds the configured codec-memory limit"),
            ));
        }
        if declared_size != u64::MAX
            && limits
                .decoded_total()
                .is_some_and(|maximum| declared_size > maximum)
        {
            return Err(codec_archive_io(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("lzma")
                    .with_context("LZMA declared size exceeds the configured decoded limit"),
            ));
        }
        let decoder = lzma_rust2::LzmaReader::new_with_props(
            input,
            declared_size,
            properties,
            dictionary,
            None,
        )
        .map_err(|error| {
            codec_archive_io(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("lzma")
                    .with_context(error.to_string()),
            )
        })?;
        Ok(Self { decoder })
    }

    fn into_inner(self) -> R {
        self.decoder.into_inner()
    }
}

#[cfg(feature = "lzma")]
impl<R: Read> Read for LzmaRead<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.decoder
            .read(output)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

struct PrefixReader<R> {
    prefix: [u8; 9],
    prefix_len: usize,
    prefix_position: usize,
    input: R,
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.prefix_position != self.prefix_len {
            let count = (self.prefix_len - self.prefix_position).min(output.len());
            output[..count]
                .copy_from_slice(&self.prefix[self.prefix_position..self.prefix_position + count]);
            self.prefix_position += count;
            return Ok(count);
        }
        self.input.read(output)
    }
}

#[cfg(feature = "xz")]
struct XzRead<R: Read> {
    input: R,
    decoder: PipelineCodec,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    state: XzReadState,
    limits: Limits,
    backend: BackendPreference,
}

#[cfg(feature = "xz")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum XzReadState {
    Running,
    Between { padding: usize },
    Done,
    Failed,
}

#[cfg(feature = "xz")]
impl<R: Read> XzRead<R> {
    fn new(input: R, limits: Limits, backend: BackendPreference) -> io::Result<Self> {
        Ok(Self {
            input,
            decoder: PipelineCodec::with_backend(FilterId::Xz, limits, backend)
                .map_err(codec_archive_io)?,
            buffer: vec![0; BUFFER],
            start: 0,
            end: 0,
            eof: false,
            state: XzReadState::Running,
            limits,
            backend,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start != 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() || self.eof {
            return Ok(());
        }
        let read = self.input.read(&mut self.buffer[self.end..])?;
        if read == 0 {
            self.eof = true;
        } else {
            self.end += read;
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.state = XzReadState::Failed;
        Err(error)
    }

    fn drive_between_members(&mut self) -> io::Result<()> {
        const MAGIC: &[u8; 6] = &[0xfd, b'7', b'z', b'X', b'Z', 0];

        let XzReadState::Between { mut padding } = self.state else {
            return Ok(());
        };
        loop {
            while self.buffer[self.start..self.end].first() == Some(&0) {
                self.start += 1;
                padding = padding.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::OutOfMemory, "XZ padding count overflow")
                })?;
                self.state = XzReadState::Between { padding };
            }
            if self.start == self.end {
                if self.eof {
                    if !padding.is_multiple_of(4) {
                        return self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "XZ stream padding is not a multiple of four bytes",
                        ));
                    }
                    self.state = XzReadState::Done;
                    return Ok(());
                }
                self.fill()?;
                continue;
            }
            if !padding.is_multiple_of(4) {
                return self.fail(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XZ stream padding is not a multiple of four bytes",
                ));
            }
            if self.end - self.start < MAGIC.len() && !self.eof {
                self.fill()?;
                continue;
            }
            let remaining = &self.buffer[self.start..self.end];
            if remaining.len() < MAGIC.len() || !remaining.starts_with(MAGIC) {
                return self.fail(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-member trailing filter data",
                ));
            }
            self.decoder = PipelineCodec::with_backend(FilterId::Xz, self.limits, self.backend)
                .map_err(codec_archive_io)?;
            self.state = XzReadState::Running;
            return Ok(());
        }
    }

    fn into_inner(self) -> R {
        self.input
    }
}

#[cfg(feature = "xz")]
impl<R: Read> Read for XzRead<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.state == XzReadState::Done {
            return Ok(0);
        }
        if self.state == XzReadState::Failed {
            return self.fail(io::Error::new(
                io::ErrorKind::InvalidData,
                "XZ reader is in a failed state",
            ));
        }
        loop {
            if matches!(self.state, XzReadState::Between { .. }) {
                self.drive_between_members()?;
                if self.state == XzReadState::Done {
                    return Ok(0);
                }
            }
            if self.start == self.end && !self.eof {
                self.fill()?;
            }
            let end = if self.eof {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let input_len = self.end - self.start;
            let step = match self
                .decoder
                .process(&self.buffer[self.start..self.end], output, end)
                .and_then(|step| step.validate(input_len, output.len()))
            {
                Ok(step) => step,
                Err(error) => {
                    return self.fail(codec_archive_io(error));
                },
            };
            self.start += step.consumed;
            if matches!(step.status, CodecStatus::Done) {
                self.state = XzReadState::Between { padding: 0 };
            }
            if step.produced != 0 {
                return Ok(step.produced);
            }
            if step.consumed == 0 {
                match step.status {
                    CodecStatus::NeedInput if !self.eof => {
                        let buffered = self.end - self.start;
                        self.fill()?;
                        if self.end - self.start == buffered {
                            return self.fail(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XZ reader could not make input progress",
                            ));
                        }
                    },
                    CodecStatus::Done => {},
                    _ => {
                        return self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "XZ reader made no progress",
                        ));
                    },
                }
            }
        }
    }
}

impl<R: Read> Read for FilterReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let allowed = match self.decoded_limit {
            Some(limit) => {
                let remaining = limit.saturating_sub(self.decoded);
                if remaining == 0 {
                    let mut probe = [0_u8; 1];
                    let read = read_inner(&mut self.inner, &mut probe)?;
                    return if read == 0 {
                        Ok(0)
                    } else {
                        Err(codec_archive_io(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_context("decoded stream exceeds configured limit"),
                        ))
                    };
                }
                usize::try_from(remaining.min(output.len() as u64)).unwrap_or(output.len())
            },
            None => output.len(),
        };
        let read = read_inner(&mut self.inner, &mut output[..allowed])?;
        self.decoded = self.decoded.checked_add(read as u64).ok_or_else(|| {
            codec_archive_io(
                ArchiveError::new(ErrorKind::Limit).with_context("decoded stream size overflow"),
            )
        })?;
        Ok(read)
    }
}

fn read_inner<R: Read>(input: &mut FilterReaderInner<R>, output: &mut [u8]) -> io::Result<usize> {
    match input {
        FilterReaderInner::Plain(input) => input.read(output),
        FilterReaderInner::Gzip(input) => input.read(output),
        #[cfg(feature = "bzip2")]
        FilterReaderInner::Bzip2(input) => input.read(output).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof
            ) {
                io::Error::new(io::ErrorKind::InvalidData, error)
            } else {
                error
            }
        }),
        #[cfg(feature = "zstd")]
        FilterReaderInner::Zstd(input) => input.read(output),
        #[cfg(feature = "xz")]
        FilterReaderInner::Xz(input) => input.read(output),
        #[cfg(feature = "lz4")]
        FilterReaderInner::Lz4(input) => input.read(output),
        #[cfg(feature = "compress")]
        FilterReaderInner::Compress(input) => input.read(output),
        #[cfg(feature = "lzip")]
        FilterReaderInner::Lzip(input) => input.read(output),
        #[cfg(feature = "lzma")]
        FilterReaderInner::Lzma(input) => input.read(output),
        FilterReaderInner::Base64(input) => input.read(output),
        FilterReaderInner::Uuencode(input) => input.read(output),
        FilterReaderInner::Rpm(input) => input.read(output),
        #[cfg(feature = "lzop")]
        FilterReaderInner::Lzop(input) => input.read(output),
    }
}

impl<R: Read> fmt::Debug for FilterReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filter = match self.inner {
            FilterReaderInner::Plain(_) => "plain",
            FilterReaderInner::Gzip(_) => "gzip",
            #[cfg(feature = "bzip2")]
            FilterReaderInner::Bzip2(_) => "bzip2",
            #[cfg(feature = "zstd")]
            FilterReaderInner::Zstd(_) => "zstd",
            #[cfg(feature = "xz")]
            FilterReaderInner::Xz(_) => "xz",
            #[cfg(feature = "lz4")]
            FilterReaderInner::Lz4(_) => "lz4",
            #[cfg(feature = "compress")]
            FilterReaderInner::Compress(_) => "compress",
            #[cfg(feature = "lzip")]
            FilterReaderInner::Lzip(_) => "lzip",
            #[cfg(feature = "lzma")]
            FilterReaderInner::Lzma(_) => "lzma",
            FilterReaderInner::Base64(_) => "base64",
            FilterReaderInner::Uuencode(_) => "uuencode",
            FilterReaderInner::Rpm(_) => "rpm",
            #[cfg(feature = "lzop")]
            FilterReaderInner::Lzop(_) => "lzop",
        };
        f.debug_tuple("FilterReader").field(&filter).finish()
    }
}

struct GzipRead<R> {
    input: R,
    decoder: PipelineCodec,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    between_members: bool,
    done: bool,
    limits: Limits,
    backend: BackendPreference,
}

impl<R: Read> GzipRead<R> {
    fn new(input: R, limits: Limits, backend: BackendPreference) -> io::Result<Self> {
        Ok(Self {
            input,
            decoder: PipelineCodec::with_backend(FilterId::Gzip, limits, backend)
                .map_err(codec_archive_io)?,
            buffer: vec![0; BUFFER],
            start: 0,
            end: 0,
            eof: false,
            between_members: false,
            done: false,
            limits,
            backend,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start != 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() || self.eof {
            return Ok(());
        }
        let read = self.input.read(&mut self.buffer[self.end..])?;
        if read == 0 {
            self.eof = true;
        } else {
            self.end += read;
        }
        Ok(())
    }
}

impl<R: Read> Read for GzipRead<R> {
    #[allow(clippy::too_many_lines)]
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.between_members {
                if self.end - self.start < 2 && !self.eof {
                    self.fill()?;
                    if self.end - self.start < 2 && !self.eof {
                        continue;
                    }
                }
                let remaining = &self.buffer[self.start..self.end];
                if remaining.is_empty() && self.eof {
                    self.done = true;
                    return Ok(0);
                }
                if remaining.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing byte after gzip member",
                    ));
                }
                if !remaining.starts_with(&[0x1f, 0x8b]) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing data after gzip member",
                    ));
                }
                self.decoder =
                    PipelineCodec::with_backend(FilterId::Gzip, self.limits, self.backend)
                        .map_err(codec_archive_io)?;
                self.between_members = false;
            }
            if self.start == self.end && !self.eof {
                self.fill()?;
            }
            let end = if self.eof {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = self
                .decoder
                .process(&self.buffer[self.start..self.end], output, end)
                .map_err(codec_archive_io)?;
            self.start += step.consumed;
            if matches!(step.status, CodecStatus::Done) {
                self.between_members = true;
            }
            if step.produced != 0 {
                return Ok(step.produced);
            }
            if step.consumed == 0 {
                match step.status {
                    CodecStatus::NeedInput if !self.eof => self.fill()?,
                    CodecStatus::Done => {},
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "gzip reader made no progress",
                        ));
                    },
                }
            }
        }
    }
}

fn codec_archive_io(error: ArchiveError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Limit => io::ErrorKind::OutOfMemory,
        ErrorKind::Unsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

fn filter_writer_error(error: &io::Error) -> ArchiveError {
    let kind = if error.kind() == io::ErrorKind::Unsupported {
        ErrorKind::Capability
    } else {
        ErrorKind::Protocol
    };
    ArchiveError::new(kind).with_context(error.to_string())
}

pub(crate) struct SharedOutput<W>(Rc<RefCell<Option<W>>>);

impl<W> SharedOutput<W> {
    fn new(output: W) -> Self {
        Self(Rc::new(RefCell::new(Some(output))))
    }

    fn take(self) -> io::Result<W> {
        let cell = Rc::try_unwrap(self.0)
            .map_err(|_| io::Error::other("filter retained an output reference after shutdown"))?;
        cell.into_inner()
            .ok_or_else(|| io::Error::other("filter output was already recovered"))
    }
}

impl<W> Clone for SharedOutput<W> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<W: Write> Write for SharedOutput<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .borrow_mut()
            .as_mut()
            .ok_or_else(|| io::Error::other("filter output is unavailable"))?
            .write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .borrow_mut()
            .as_mut()
            .ok_or_else(|| io::Error::other("filter output is unavailable"))?
            .flush()
    }
}

pub(crate) struct GzipFilterWrite<W: Write> {
    inner: GzipFilterWriteInner<W>,
}

enum GzipFilterWriteInner<W: Write> {
    Portable {
        output: W,
        encoder: GzipEncoder,
        buffer: Vec<u8>,
    },
    #[cfg(feature = "native-codecs")]
    Native(flate2::write::GzEncoder<W>),
}

impl<W: Write> GzipFilterWrite<W> {
    pub(crate) fn with_backend(
        output: W,
        limits: Limits,
        preference: BackendPreference,
    ) -> io::Result<Self> {
        let inner = match preference.resolve().map_err(io::Error::other)? {
            Backend::Portable => GzipFilterWriteInner::Portable {
                output,
                encoder: GzipEncoder::new(limits),
                buffer: vec![0; BUFFER],
            },
            Backend::Native => {
                #[cfg(feature = "native-codecs")]
                {
                    GzipFilterWriteInner::Native(flate2::write::GzEncoder::new(
                        output,
                        flate2::Compression::default(),
                    ))
                }
                #[cfg(not(feature = "native-codecs"))]
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "native codec backend is not compiled",
                    ));
                }
            },
        };
        Ok(Self { inner })
    }

    pub(crate) fn finish(self) -> io::Result<W> {
        match self.inner {
            GzipFilterWriteInner::Portable {
                mut output,
                mut encoder,
                mut buffer,
            } => loop {
                let step = encoder
                    .process(&[], &mut buffer, EndOfInput::End)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                output.write_all(&buffer[..step.produced])?;
                if matches!(step.status, CodecStatus::Done) {
                    output.flush()?;
                    return Ok(output);
                }
                if step.produced == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gzip encoder made no finish progress",
                    ));
                }
            },
            #[cfg(feature = "native-codecs")]
            GzipFilterWriteInner::Native(encoder) => encoder.finish(),
        }
    }
}

impl<W: Write> Write for GzipFilterWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        match &mut self.inner {
            GzipFilterWriteInner::Portable {
                output,
                encoder,
                buffer,
            } => loop {
                let step = encoder
                    .process(bytes, buffer, EndOfInput::More)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                output.write_all(&buffer[..step.produced])?;
                if step.consumed != 0 {
                    return Ok(step.consumed);
                }
                if step.produced == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gzip encoder made no write progress",
                    ));
                }
            },
            #[cfg(feature = "native-codecs")]
            GzipFilterWriteInner::Native(encoder) => encoder.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            GzipFilterWriteInner::Portable { output, .. } => output.flush(),
            #[cfg(feature = "native-codecs")]
            GzipFilterWriteInner::Native(encoder) => encoder.flush(),
        }
    }
}

pub(crate) struct Base64FilterWrite<W: Write> {
    output: W,
    encoder: libarchive_oxide_codecs::base64::Base64Encoder,
    buffer: Vec<u8>,
}

pub(crate) struct UuencodeFilterWrite<W: Write> {
    output: W,
    encoder: libarchive_oxide_codecs::uuencode::UuencodeEncoder,
    buffer: Vec<u8>,
}

#[cfg(feature = "lzop")]
pub(crate) struct LzopFilterWrite<W: Write> {
    output: W,
    encoder: libarchive_oxide_codecs::lzop::LzopEncoder,
    buffer: Vec<u8>,
}

#[cfg(feature = "compress")]
pub(crate) struct CompressFilterWrite<W: Write> {
    output: W,
    encoder: libarchive_oxide_codecs::lzw::CompressEncoder,
    buffer: Vec<u8>,
}

#[cfg(feature = "compress")]
impl<W: Write> CompressFilterWrite<W> {
    pub(crate) fn new(output: W, limits: Limits) -> Result<Self, ArchiveError> {
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::lzw::CompressEncoder::with_limits(limits)?,
            buffer: vec![0; BUFFER],
        })
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self
                .encoder
                .process(&[], &mut self.buffer, EndOfInput::End)
                .and_then(|step| step.validate(0, self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.status == CodecStatus::Done {
                self.output.flush()?;
                return Ok(self.output);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compress/LZW encoder made no finish progress",
                ));
            }
        }
    }
}

#[cfg(feature = "compress")]
impl<W: Write> Write for CompressFilterWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let step = self
                .encoder
                .process(bytes, &mut self.buffer, EndOfInput::More)
                .and_then(|step| step.validate(bytes.len(), self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.consumed != 0 {
                return Ok(step.consumed);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compress/LZW encoder made no write progress",
                ));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl<W: Write> Base64FilterWrite<W> {
    pub(crate) fn new(output: W, limits: Limits) -> Self {
        Self {
            output,
            encoder: libarchive_oxide_codecs::base64::Base64Encoder::new(limits),
            buffer: vec![0; BUFFER],
        }
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self
                .encoder
                .process(&[], &mut self.buffer, EndOfInput::End)
                .and_then(|step| step.validate(0, self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.status == CodecStatus::Done {
                self.output.flush()?;
                return Ok(self.output);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Base64 encoder made no finish progress",
                ));
            }
        }
    }
}

impl<W: Write> Write for Base64FilterWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let step = self
                .encoder
                .process(bytes, &mut self.buffer, EndOfInput::More)
                .and_then(|step| step.validate(bytes.len(), self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.consumed != 0 {
                return Ok(step.consumed);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Base64 encoder made no write progress",
                ));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl<W: Write> UuencodeFilterWrite<W> {
    pub(crate) fn new(output: W, limits: Limits) -> Result<Self, ArchiveError> {
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::uuencode::UuencodeEncoder::new(limits)?,
            buffer: vec![0; BUFFER],
        })
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self
                .encoder
                .process(&[], &mut self.buffer, EndOfInput::End)
                .and_then(|step| step.validate(0, self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.status == CodecStatus::Done {
                self.output.flush()?;
                return Ok(self.output);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uuencode encoder made no finish progress",
                ));
            }
        }
    }
}

impl<W: Write> Write for UuencodeFilterWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let step = self
                .encoder
                .process(bytes, &mut self.buffer, EndOfInput::More)
                .and_then(|step| step.validate(bytes.len(), self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.consumed != 0 {
                return Ok(step.consumed);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uuencode encoder made no write progress",
                ));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
pub(crate) fn encode_profile_frame_with_backend(
    filter: FilterId,
    input: &[u8],
    preference: BackendPreference,
) -> io::Result<Vec<u8>> {
    match preference.resolve().map_err(io::Error::other)? {
        Backend::Portable => match filter {
            #[cfg(feature = "zstd")]
            FilterId::Zstd => {
                crate::filter::zstd::encode_frame(input, Limits::safe()).map_err(io::Error::other)
            },
            #[cfg(feature = "xz")]
            FilterId::Xz => crate::filter::xz::encode_frame(input),
            #[cfg(feature = "lz4")]
            FilterId::Lz4 => crate::filter::lz4::encode_frame(input).map_err(io::Error::other),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filter has no frame encoder in the selected codec profile",
            )),
        },
        Backend::Native => {
            #[cfg(feature = "native-codecs")]
            return crate::backend_codec::encode_frame(filter, input);
            #[cfg(not(feature = "native-codecs"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native codec backend is not compiled",
            ));
        },
    }
}
#[cfg(feature = "zstd")]
pub(crate) struct ZstdFrameWrite<W: Write> {
    output: W,
    input: Vec<u8>,
    wrote_frame: bool,
    backend: BackendPreference,
}

#[cfg(feature = "lzop")]
impl<W: Write> LzopFilterWrite<W> {
    pub(crate) fn new(output: W, limits: Limits) -> Result<Self, ArchiveError> {
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::lzop::LzopEncoder::new(limits)?,
            buffer: vec![0; BUFFER],
        })
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        loop {
            let step = self
                .encoder
                .process(&[], &mut self.buffer, EndOfInput::End)
                .and_then(|step| step.validate(0, self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.status == CodecStatus::Done {
                self.output.flush()?;
                return Ok(self.output);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lzop encoder made no finish progress",
                ));
            }
        }
    }
}

#[cfg(feature = "lzop")]
impl<W: Write> Write for LzopFilterWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let step = self
                .encoder
                .process(bytes, &mut self.buffer, EndOfInput::More)
                .and_then(|step| step.validate(bytes.len(), self.buffer.len()))
                .map_err(codec_archive_io)?;
            self.output.write_all(&self.buffer[..step.produced])?;
            if step.consumed != 0 {
                return Ok(step.consumed);
            }
            if step.produced == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lzop encoder made no write progress",
                ));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(feature = "zstd")]
impl<W: Write> ZstdFrameWrite<W> {
    pub(crate) fn with_backend(output: W, backend: BackendPreference) -> Self {
        Self {
            output,
            input: Vec::with_capacity(BUFFER),
            wrote_frame: false,
            backend,
        }
    }

    fn emit_frame(&mut self) -> io::Result<()> {
        let encoded = encode_profile_frame_with_backend(FilterId::Zstd, &self.input, self.backend)?;
        self.output.write_all(&encoded)?;
        self.input.clear();
        self.wrote_frame = true;
        Ok(())
    }

    fn finish_output(mut self) -> io::Result<()> {
        if !self.input.is_empty() || !self.wrote_frame {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

#[cfg(feature = "zstd")]
impl<W: Write> Write for ZstdFrameWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        let consumed = (BUFFER - self.input.len()).min(bytes.len());
        self.input.extend_from_slice(&bytes[..consumed]);
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.input.is_empty() {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

#[cfg(feature = "xz")]
pub(crate) struct XzFrameWrite<W: Write> {
    output: W,
    input: Vec<u8>,
    wrote_frame: bool,
    backend: BackendPreference,
}

#[cfg(feature = "xz")]
impl<W: Write> XzFrameWrite<W> {
    pub(crate) fn with_backend(output: W, backend: BackendPreference) -> Self {
        Self {
            output,
            input: Vec::with_capacity(BUFFER),
            wrote_frame: false,
            backend,
        }
    }

    fn emit_frame(&mut self) -> io::Result<()> {
        let encoded = encode_profile_frame_with_backend(FilterId::Xz, &self.input, self.backend)?;
        self.output.write_all(&encoded)?;
        self.input.clear();
        self.wrote_frame = true;
        Ok(())
    }

    fn finish_output(mut self) -> io::Result<()> {
        if !self.input.is_empty() || !self.wrote_frame {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

#[cfg(feature = "xz")]
impl<W: Write> Write for XzFrameWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        let consumed = (BUFFER - self.input.len()).min(bytes.len());
        self.input.extend_from_slice(&bytes[..consumed]);
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.input.is_empty() {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

#[cfg(feature = "lz4")]
pub(crate) struct Lz4FrameWrite<W: Write> {
    output: W,
    input: Vec<u8>,
    wrote_frame: bool,
    backend: BackendPreference,
}

#[cfg(feature = "lz4")]
impl<W: Write> Lz4FrameWrite<W> {
    pub(crate) fn with_backend(output: W, backend: BackendPreference) -> Self {
        Self {
            output,
            input: Vec::with_capacity(BUFFER),
            wrote_frame: false,
            backend,
        }
    }

    fn emit_frame(&mut self) -> io::Result<()> {
        let encoded = encode_profile_frame_with_backend(FilterId::Lz4, &self.input, self.backend)?;
        self.output.write_all(&encoded)?;
        self.input.clear();
        self.wrote_frame = true;
        Ok(())
    }

    fn finish_output(mut self) -> io::Result<()> {
        if !self.input.is_empty() || !self.wrote_frame {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

#[cfg(feature = "lz4")]
impl<W: Write> Write for Lz4FrameWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        let consumed = (BUFFER - self.input.len()).min(bytes.len());
        self.input.extend_from_slice(&bytes[..consumed]);
        if self.input.len() == BUFFER {
            self.emit_frame()?;
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.input.is_empty() {
            self.emit_frame()?;
        }
        self.output.flush()
    }
}

/// Incremental synchronous filter sink used by the common archive writer.
pub(crate) enum SyncFilterWriter<W: Write> {
    Plain(SharedOutput<W>),
    Gzip {
        writer: Box<GzipFilterWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    Base64 {
        writer: Box<Base64FilterWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    Uuencode {
        writer: Box<UuencodeFilterWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "lzop")]
    Lzop {
        writer: Box<LzopFilterWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "compress")]
    Compress {
        writer: Box<CompressFilterWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "bzip2")]
    Bzip2 {
        writer: Box<bzip2::write::BzEncoder<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "zstd")]
    Zstd {
        writer: Box<ZstdFrameWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "xz")]
    Xz {
        writer: Box<XzFrameWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "lz4")]
    Lz4 {
        writer: Box<Lz4FrameWrite<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "lzma")]
    Lzma {
        writer: Box<lzma_rust2::LzmaWriter<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
    #[cfg(feature = "lzip")]
    Lzip {
        writer: Box<lzma_rust2::LzipWriter<SharedOutput<W>>>,
        output: SharedOutput<W>,
    },
}

impl<W: Write> SyncFilterWriter<W> {
    pub(crate) fn plain(output: W) -> Self {
        Self::Plain(SharedOutput::new(output))
    }

    #[cfg(feature = "compress")]
    fn compress(
        output: SharedOutput<W>,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        if matches!(backend, BackendPreference::Native) {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format("compress")
                .with_context("the compress/LZW filter has no native backend"));
        }
        Ok(Self::Compress {
            writer: Box::new(CompressFilterWrite::new(output.clone(), limits)?),
            output,
        })
    }

    #[allow(clippy::too_many_lines)] // One ownership-preserving writer dispatch over filters.
    pub(crate) fn with_backend(
        output: W,
        filter: Option<FilterId>,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        backend.resolve()?;
        let shared = SharedOutput::new(output);
        match filter {
            None => Ok(Self::Plain(shared)),
            #[cfg(feature = "lzip")]
            Some(FilterId::Lzip) => {
                if matches!(backend, BackendPreference::Native) {
                    return Err(ArchiveError::new(ErrorKind::Capability)
                        .with_format("lzip")
                        .with_context("the lzip filter has no native backend"));
                }
                let options = lzma_rust2::LzipOptions::with_preset(0);
                let encoder_memory = u64::from(options.lzma_options.get_memory_usage());
                if limits
                    .codec_memory()
                    .is_some_and(|maximum| encoder_memory > maximum as u64)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("lzip")
                        .with_context("lzip encoder exceeds the configured codec-memory limit"));
                }
                Ok(Self::Lzip {
                    writer: Box::new(lzma_rust2::LzipWriter::new(shared.clone(), options)),
                    output: shared,
                })
            },
            Some(FilterId::Gzip) => Ok(Self::Gzip {
                writer: Box::new(
                    GzipFilterWrite::with_backend(shared.clone(), limits, backend)
                        .map_err(|error| filter_writer_error(&error))?,
                ),
                output: shared,
            }),
            Some(FilterId::Base64) => Ok(Self::Base64 {
                writer: Box::new(Base64FilterWrite::new(shared.clone(), limits)),
                output: shared,
            }),
            Some(FilterId::Uuencode) => Ok(Self::Uuencode {
                writer: Box::new(UuencodeFilterWrite::new(shared.clone(), limits)?),
                output: shared,
            }),
            #[cfg(feature = "lzop")]
            Some(FilterId::Lzop) => {
                if matches!(backend, BackendPreference::Native) {
                    return Err(ArchiveError::new(ErrorKind::Capability)
                        .with_format("lzop")
                        .with_context("the lzop filter has no native backend"));
                }
                Ok(Self::Lzop {
                    writer: Box::new(LzopFilterWrite::new(shared.clone(), limits)?),
                    output: shared,
                })
            },
            #[cfg(feature = "compress")]
            Some(FilterId::Compress) => Self::compress(shared, limits, backend),
            #[cfg(feature = "lzma")]
            Some(FilterId::Lzma) => {
                if matches!(backend, BackendPreference::Native) {
                    return Err(ArchiveError::new(ErrorKind::Capability)
                        .with_format("lzma")
                        .with_context("the LZMA-alone filter has no native backend"));
                }
                let options = lzma_rust2::LzmaOptions::with_preset(0);
                // lzma-rust2's encoder estimate is expressed in bytes (its dictionary window dominates the returned value).
                let encoder_memory = u64::from(options.get_memory_usage());
                if limits
                    .codec_memory()
                    .is_some_and(|maximum| encoder_memory > maximum as u64)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("lzma")
                        .with_context("LZMA encoder exceeds the configured codec-memory limit"));
                }
                let writer = lzma_rust2::LzmaWriter::new_use_header(shared.clone(), &options, None)
                    .map_err(|error| {
                        ArchiveError::new(ErrorKind::Capability)
                            .with_format("lzma")
                            .with_context(error.to_string())
                    })?;
                Ok(Self::Lzma {
                    writer: Box::new(writer),
                    output: shared,
                })
            },
            #[cfg(feature = "bzip2")]
            Some(FilterId::Bzip2) => Ok(Self::Bzip2 {
                writer: Box::new(bzip2::write::BzEncoder::new(
                    shared.clone(),
                    bzip2::Compression::default(),
                )),
                output: shared,
            }),
            #[cfg(feature = "zstd")]
            Some(FilterId::Zstd) => Ok(Self::Zstd {
                writer: Box::new(ZstdFrameWrite::with_backend(shared.clone(), backend)),
                output: shared,
            }),
            #[cfg(feature = "xz")]
            Some(FilterId::Xz) => Ok(Self::Xz {
                writer: Box::new(XzFrameWrite::with_backend(shared.clone(), backend)),
                output: shared,
            }),
            #[cfg(feature = "lz4")]
            Some(FilterId::Lz4) => Ok(Self::Lz4 {
                writer: Box::new(Lz4FrameWrite::with_backend(shared.clone(), backend)),
                output: shared,
            }),
            Some(_) => Err(ArchiveError::new(ErrorKind::Capability)
                .with_context("filter is disabled or has no incremental writer")),
        }
    }

    pub(crate) fn finish(self) -> io::Result<W> {
        match self {
            Self::Plain(mut output) => {
                output.flush()?;
                output.take()
            },
            Self::Gzip { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            Self::Base64 { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            Self::Uuencode { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            #[cfg(feature = "lzop")]
            Self::Lzop { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            #[cfg(feature = "compress")]
            Self::Compress { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, output } => {
                (*writer).finish_output()?;
                output.take()
            },
            #[cfg(feature = "xz")]
            Self::Xz { writer, output } => {
                (*writer).finish_output()?;
                output.take()
            },
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, output } => {
                (*writer).finish_output()?;
                output.take()
            },
            #[cfg(feature = "lzma")]
            Self::Lzma { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
            #[cfg(feature = "lzip")]
            Self::Lzip { writer, output } => {
                drop((*writer).finish()?);
                output.take()
            },
        }
    }

    pub(crate) fn abort(self) -> io::Result<W> {
        match self {
            Self::Plain(output) => output.take(),
            Self::Gzip { writer, output } => {
                drop(writer);
                output.take()
            },
            Self::Base64 { writer, output } => {
                drop(writer);
                output.take()
            },
            Self::Uuencode { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "lzop")]
            Self::Lzop { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "compress")]
            Self::Compress { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "xz")]
            Self::Xz { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "lzma")]
            Self::Lzma { writer, output } => {
                drop(writer);
                output.take()
            },
            #[cfg(feature = "lzip")]
            Self::Lzip { writer, output } => {
                drop(writer);
                output.take()
            },
        }
    }
}

impl<W: Write> Write for SyncFilterWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(output) => output.write(bytes),
            Self::Gzip { writer, .. } => writer.write(bytes),
            Self::Base64 { writer, .. } => writer.write(bytes),
            Self::Uuencode { writer, .. } => writer.write(bytes),
            #[cfg(feature = "lzop")]
            Self::Lzop { writer, .. } => writer.write(bytes),
            #[cfg(feature = "compress")]
            Self::Compress { writer, .. } => writer.write(bytes),
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, .. } => writer.write(bytes),
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, .. } => writer.write(bytes),
            #[cfg(feature = "xz")]
            Self::Xz { writer, .. } => writer.write(bytes),
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, .. } => writer.write(bytes),
            #[cfg(feature = "lzma")]
            Self::Lzma { writer, .. } => writer.write(bytes),
            #[cfg(feature = "lzip")]
            Self::Lzip { writer, .. } => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(output) => output.flush(),
            Self::Gzip { writer, .. } => writer.flush(),
            Self::Base64 { writer, .. } => writer.flush(),
            Self::Uuencode { writer, .. } => writer.flush(),
            #[cfg(feature = "lzop")]
            Self::Lzop { writer, .. } => writer.flush(),
            #[cfg(feature = "compress")]
            Self::Compress { writer, .. } => writer.flush(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, .. } => writer.flush(),
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, .. } => writer.flush(),
            #[cfg(feature = "xz")]
            Self::Xz { writer, .. } => writer.flush(),
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, .. } => writer.flush(),
            #[cfg(feature = "lzma")]
            Self::Lzma { writer, .. } => writer.flush(),
            #[cfg(feature = "lzip")]
            Self::Lzip { writer, .. } => writer.flush(),
        }
    }
}

impl<W: Write> fmt::Debug for SyncFilterWriter<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filter = match self {
            Self::Plain(_) => "plain",
            Self::Gzip { .. } => "gzip",
            Self::Base64 { .. } => "base64",
            Self::Uuencode { .. } => "uuencode",
            #[cfg(feature = "lzop")]
            Self::Lzop { .. } => "lzop",
            #[cfg(feature = "compress")]
            Self::Compress { .. } => "compress",
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { .. } => "bzip2",
            #[cfg(feature = "zstd")]
            Self::Zstd { .. } => "zstd",
            #[cfg(feature = "xz")]
            Self::Xz { .. } => "xz",
            #[cfg(feature = "lz4")]
            Self::Lz4 { .. } => "lz4",
            #[cfg(feature = "lzma")]
            Self::Lzma { .. } => "lzma",
            #[cfg(feature = "lzip")]
            Self::Lzip { .. } => "lzip",
        };
        formatter
            .debug_tuple("SyncFilterWriter")
            .field(&filter)
            .finish()
    }
}
