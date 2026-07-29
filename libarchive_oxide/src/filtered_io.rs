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
#[cfg(any(
    feature = "zstd",
    feature = "lz4",
    feature = "compress",
    feature = "lzip"
))]
use crate::codec_read::CodecReader;
use crate::filter::gzip::GzipEncoder;
use crate::pipeline_codec::PipelineCodec;

const BUFFER: usize = 64 * 1024;

/// A bounded outer-filter reader: the shared [`CodecReader`] engine driving a [`PipelineCodec`].
#[cfg(any(
    feature = "zstd",
    feature = "lz4",
    feature = "compress",
    feature = "lzip"
))]
type PipelineRead<R> = CodecReader<R, PipelineCodec>;

/// Builds a [`PipelineRead`] for an outer filter, constructing its [`PipelineCodec`] first.
#[cfg(any(
    feature = "zstd",
    feature = "lz4",
    feature = "compress",
    feature = "lzip"
))]
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
}

impl<R: Read> FilterReader<R> {
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
        let mut prefix = [0_u8; 6];
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
        }
    }
}

struct PrefixReader<R> {
    prefix: [u8; 6],
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
                        Err(io::Error::other("decoded stream exceeds configured limit"))
                    };
                }
                usize::try_from(remaining.min(output.len() as u64)).unwrap_or(output.len())
            },
            None => output.len(),
        };
        let read = read_inner(&mut self.inner, &mut output[..allowed])?;
        self.decoded = self
            .decoded
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("decoded stream size overflow"))?;
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
                .map_err(archive_io)?;
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

fn archive_io(error: ArchiveError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Limit => io::ErrorKind::Other,
        ErrorKind::Unsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
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
}

impl<W: Write> SyncFilterWriter<W> {
    pub(crate) fn plain(output: W) -> Self {
        Self::Plain(SharedOutput::new(output))
    }

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
            Some(FilterId::Lzip) => Err(ArchiveError::new(ErrorKind::Capability)
                .with_format("lzip")
                .with_context("lzip filter is read-only")),
            Some(FilterId::Gzip) => Ok(Self::Gzip {
                writer: Box::new(
                    GzipFilterWrite::with_backend(shared.clone(), limits, backend)
                        .map_err(|error| filter_writer_error(&error))?,
                ),
                output: shared,
            }),
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
        }
    }

    pub(crate) fn abort(self) -> io::Result<W> {
        match self {
            Self::Plain(output) => output.take(),
            Self::Gzip { writer, output } => {
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
        }
    }
}

impl<W: Write> Write for SyncFilterWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(output) => output.write(bytes),
            Self::Gzip { writer, .. } => writer.write(bytes),
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, .. } => writer.write(bytes),
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, .. } => writer.write(bytes),
            #[cfg(feature = "xz")]
            Self::Xz { writer, .. } => writer.write(bytes),
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, .. } => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(output) => output.flush(),
            Self::Gzip { writer, .. } => writer.flush(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { writer, .. } => writer.flush(),
            #[cfg(feature = "zstd")]
            Self::Zstd { writer, .. } => writer.flush(),
            #[cfg(feature = "xz")]
            Self::Xz { writer, .. } => writer.flush(),
            #[cfg(feature = "lz4")]
            Self::Lz4 { writer, .. } => writer.flush(),
        }
    }
}

impl<W: Write> fmt::Debug for SyncFilterWriter<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filter = match self {
            Self::Plain(_) => "plain",
            Self::Gzip { .. } => "gzip",
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { .. } => "bzip2",
            #[cfg(feature = "zstd")]
            Self::Zstd { .. } => "zstd",
            #[cfg(feature = "xz")]
            Self::Xz { .. } => "xz",
            #[cfg(feature = "lz4")]
            Self::Lz4 { .. } => "lz4",
        };
        formatter
            .debug_tuple("SyncFilterWriter")
            .field(&filter)
            .finish()
    }
}
