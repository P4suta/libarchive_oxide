// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral, bounded asynchronous outer-filter adapters.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_compression::futures::bufread::GzipDecoder;
use async_compression::futures::write::GzipEncoder;
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, CodecStatus, EndOfInput, ErrorKind, Limits};

use crate::pipeline_codec::PipelineCodec;

const PREFIX: usize = 6;
const BUFFER: usize = 64 * 1024;

#[derive(Debug)]
struct PrefixReader<R> {
    prefix: [u8; PREFIX],
    prefix_length: usize,
    prefix_position: usize,
    input: R,
    wrap_source_errors: bool,
    physical_read: u64,
}

impl<R> PrefixReader<R> {
    fn into_inner(self) -> R {
        self.input
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.prefix_position != this.prefix_length {
            let count = (this.prefix_length - this.prefix_position).min(output.len());
            output[..count]
                .copy_from_slice(&this.prefix[this.prefix_position..this.prefix_position + count]);
            this.prefix_position += count;
            return Poll::Ready(Ok(count));
        }
        match Pin::new(&mut this.input).poll_read(cx, output) {
            Poll::Ready(Ok(read)) => {
                this.physical_read = this
                    .physical_read
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                Poll::Ready(Ok(read))
            },
            Poll::Ready(Err(error)) if this.wrap_source_errors => {
                let kind = error.kind();
                Poll::Ready(Err(io::Error::new(kind, SourceError(error))))
            },
            other => other,
        }
    }
}

#[derive(Debug)]
struct SourceError(io::Error);

impl std::fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn codec_error(error: io::Error) -> io::Error {
    let is_source_error = match error.get_ref() {
        Some(source) => source.is::<SourceError>(),
        None => false,
    };
    if is_source_error {
        let kind = error.kind();
        if let Some(source) = error.into_inner() {
            return match source.downcast::<SourceError>() {
                Ok(source) => source.0,
                Err(source) => io::Error::new(kind, source),
            };
        }
        return io::Error::from(kind);
    }
    let kind = if error.kind() == io::ErrorKind::OutOfMemory {
        io::ErrorKind::OutOfMemory
    } else {
        io::ErrorKind::InvalidData
    };
    io::Error::new(kind, error)
}

fn archive_codec_error(error: ArchiveError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Limit => io::ErrorKind::OutOfMemory,
        ErrorKind::Unsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

fn codec_poll(result: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
    match result {
        Poll::Ready(Err(error)) => Poll::Ready(Err(codec_error(error))),
        other => other,
    }
}

#[derive(Debug)]
struct Buffered<R> {
    input: R,
    bytes: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R> Buffered<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            bytes: vec![0; BUFFER],
            start: 0,
            end: 0,
        }
    }

    fn into_inner(self) -> R {
        self.input
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Buffered<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.start != this.end {
            let count = (this.end - this.start).min(output.len());
            output[..count].copy_from_slice(&this.bytes[this.start..this.start + count]);
            this.start += count;
            return Poll::Ready(Ok(count));
        }
        Pin::new(&mut this.input).poll_read(cx, output)
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for Buffered<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.start == this.end {
            match Pin::new(&mut this.input).poll_read(cx, &mut this.bytes) {
                Poll::Ready(Ok(read)) => {
                    this.start = 0;
                    this.end = read;
                },
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(&this.bytes[this.start..this.end]))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.start = (this.start + amount).min(this.end);
    }
}

type FilterInput<R> = Buffered<PrefixReader<R>>;

#[derive(Debug)]
struct AsyncCodecReader<R> {
    input: R,
    codec: PipelineCodec,
    compressed: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    done: bool,
}

impl<R> AsyncCodecReader<R> {
    fn new(input: R, filter: FilterId, limits: Limits) -> io::Result<Self> {
        Ok(Self {
            input,
            codec: PipelineCodec::new(filter, limits).map_err(archive_codec_error)?,
            compressed: vec![0; BUFFER],
            start: 0,
            end: 0,
            eof: false,
            done: false,
        })
    }

    fn into_inner(self) -> R {
        self.input
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncCodecReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() || this.done {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.start == this.end && !this.eof {
                this.start = 0;
                this.end = 0;
                match Pin::new(&mut this.input).poll_read(cx, &mut this.compressed) {
                    Poll::Ready(Ok(0)) => this.eof = true,
                    Poll::Ready(Ok(read)) => this.end = read,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let input_length = this.end - this.start;
            let end = if this.eof {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = match this
                .codec
                .process(&this.compressed[this.start..this.end], output, end)
                .and_then(|step| step.validate(input_length, output.len()))
            {
                Ok(step) => step,
                Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
            };
            this.start += step.consumed;
            if step.produced != 0 {
                return Poll::Ready(Ok(step.produced));
            }
            match step.status {
                CodecStatus::Done => {
                    this.done = true;
                    return Poll::Ready(Ok(0));
                },
                CodecStatus::NeedInput if this.start == this.end && !this.eof => {},
                CodecStatus::NeedOutput if step.consumed != 0 => {},
                CodecStatus::NeedInput if this.eof => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "codec requested input after the source ended",
                    )));
                },
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "async codec reader made no progress",
                    )));
                },
            }
        }
    }
}

#[derive(Debug)]
enum ReaderInner<R> {
    Detecting {
        input: Option<R>,
        prefix: [u8; PREFIX],
        prefix_length: usize,
        eof: bool,
    },
    Plain(FilterInput<R>),
    Gzip(GzipDecoder<FilterInput<R>>),
    #[cfg(feature = "bzip2")]
    Bzip2(async_compression::futures::bufread::BzDecoder<FilterInput<R>>),
    #[cfg(feature = "zstd")]
    Zstd(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "xz")]
    Xz(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "lz4")]
    Lz4(Box<AsyncCodecReader<FilterInput<R>>>),
    Finished {
        input: FilterInput<R>,
        filter: FilterId,
    },
    #[allow(dead_code)]
    Failed(Option<R>),
}

/// Auto-detecting async filter reader shared by futures-io and Tokio adapters.
#[derive(Debug)]
pub(crate) struct AsyncFilterReader<R> {
    inner: ReaderInner<R>,
    decoded: u64,
    decoded_limit: Option<u64>,
    limits: Limits,
}

impl<R> AsyncFilterReader<R> {
    pub(crate) fn new(input: R, limits: Limits) -> Self {
        Self {
            inner: ReaderInner::Detecting {
                input: Some(input),
                prefix: [0; PREFIX],
                prefix_length: 0,
                eof: false,
            },
            decoded: 0,
            decoded_limit: limits.decoded_total(),
            limits,
        }
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn into_inner(self) -> R {
        match self.inner {
            ReaderInner::Detecting { input, .. } | ReaderInner::Failed(input) => {
                input.expect("async filter reader always owns its input")
            },
            ReaderInner::Plain(input) => input.into_inner().into_inner(),
            ReaderInner::Gzip(input) => input.into_inner().into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            ReaderInner::Bzip2(input) => input.into_inner().into_inner().into_inner(),
            #[cfg(feature = "zstd")]
            ReaderInner::Zstd(input) => (*input).into_inner().into_inner().into_inner(),
            #[cfg(feature = "xz")]
            ReaderInner::Xz(input) => (*input).into_inner().into_inner().into_inner(),
            #[cfg(feature = "lz4")]
            ReaderInner::Lz4(input) => (*input).into_inner().into_inner().into_inner(),
            ReaderInner::Finished { input, .. } => input.into_inner().into_inner(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncFilterReader<R> {
    #[allow(clippy::too_many_lines)] // One ownership-preserving dispatch over all built-in codecs.
    fn poll_detect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ReaderInner::Detecting {
            input,
            prefix,
            prefix_length,
            eof,
        } = &mut self.inner
        else {
            return Poll::Ready(Ok(()));
        };
        while *prefix_length != PREFIX && !*eof {
            let Some(reader) = input.as_mut() else {
                return Poll::Ready(Err(io::Error::other(
                    "async filter input disappeared during detection",
                )));
            };
            match Pin::new(reader).poll_read(cx, &mut prefix[*prefix_length..]) {
                Poll::Ready(Ok(0)) => *eof = true,
                Poll::Ready(Ok(read)) => *prefix_length += read,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let length = *prefix_length;
        let saved_prefix = *prefix;
        let reader = input
            .take()
            .ok_or_else(|| io::Error::other("async filter input is missing"))?;
        let mut buffered = Buffered::new(PrefixReader {
            prefix: saved_prefix,
            prefix_length: length,
            prefix_position: 0,
            input: reader,
            wrap_source_errors: false,
            physical_read: u64::try_from(length).unwrap_or(u64::MAX),
        });
        let available = &saved_prefix[..length];
        if available.starts_with(&[0x1f, 0x8b]) {
            buffered.input.wrap_source_errors = true;
            let mut decoder = GzipDecoder::new(buffered);
            decoder.multiple_members(true);
            self.inner = ReaderInner::Gzip(decoder);
        } else if available.starts_with(b"BZh") {
            #[cfg(feature = "bzip2")]
            {
                buffered.input.wrap_source_errors = true;
                let mut decoder = async_compression::futures::bufread::BzDecoder::new(buffered);
                decoder.multiple_members(true);
                self.inner = ReaderInner::Bzip2(decoder);
            }
            #[cfg(not(feature = "bzip2"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "bzip2 filter is not enabled",
                )));
            }
        } else if available.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            #[cfg(feature = "zstd")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Zstd(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Zstd,
                    self.limits,
                )?));
            }
            #[cfg(not(feature = "zstd"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "zstd filter is not enabled",
                )));
            }
        } else if available.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
            #[cfg(feature = "xz")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Xz(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Xz,
                    self.limits,
                )?));
            }
            #[cfg(not(feature = "xz"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "XZ filter is not enabled",
                )));
            }
        } else if available.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
            #[cfg(feature = "lz4")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Lz4(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Lz4,
                    self.limits,
                )?));
            }
            #[cfg(not(feature = "lz4"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "LZ4 filter is not enabled",
                )));
            }
        } else {
            self.inner = ReaderInner::Plain(buffered);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_decoded(&mut self, cx: &mut Context<'_>, output: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            if matches!(self.inner, ReaderInner::Detecting { .. }) {
                match self.poll_detect(cx) {
                    Poll::Ready(Ok(())) => {},
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            let (result, filtered) = match &mut self.inner {
                ReaderInner::Plain(input) => (Pin::new(input).poll_read(cx, output), false),
                ReaderInner::Gzip(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "bzip2")]
                ReaderInner::Bzip2(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "zstd")]
                ReaderInner::Zstd(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "xz")]
                ReaderInner::Xz(input) => (codec_poll(Pin::new(input).poll_read(cx, output)), true),
                #[cfg(feature = "lz4")]
                ReaderInner::Lz4(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                ReaderInner::Finished { input, filter } => {
                    let mut probe = [0_u8; 1];
                    let result = codec_poll(Pin::new(&mut *input).poll_read(cx, &mut probe));
                    return match result {
                        Poll::Ready(Ok(0))
                            if *filter == FilterId::Xz
                                && !input.input.physical_read.is_multiple_of(4) =>
                        {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XZ stream padding is not a multiple of four bytes",
                            )))
                        },
                        Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "non-member trailing filter data",
                        ))),
                        other => other,
                    };
                },
                ReaderInner::Failed(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "async filter reader is in a failed state",
                    )));
                },
                ReaderInner::Detecting { .. } => continue,
            };
            if filtered && matches!(result, Poll::Ready(Ok(0))) {
                let previous = core::mem::replace(&mut self.inner, ReaderInner::Failed(None));
                let (input, filter) = match previous {
                    ReaderInner::Gzip(input) => (input.into_inner(), FilterId::Gzip),
                    #[cfg(feature = "bzip2")]
                    ReaderInner::Bzip2(input) => (input.into_inner(), FilterId::Bzip2),
                    #[cfg(feature = "zstd")]
                    ReaderInner::Zstd(input) => ((*input).into_inner(), FilterId::Zstd),
                    #[cfg(feature = "xz")]
                    ReaderInner::Xz(input) => ((*input).into_inner(), FilterId::Xz),
                    #[cfg(feature = "lz4")]
                    ReaderInner::Lz4(input) => ((*input).into_inner(), FilterId::Lz4),
                    _ => {
                        return Poll::Ready(Err(io::Error::other(
                            "async filter state changed while checking trailing data",
                        )));
                    },
                };
                self.inner = ReaderInner::Finished { input, filter };
                continue;
            }
            return result;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncFilterReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let allowed = match this.decoded_limit {
            Some(limit) => {
                let remaining = limit.saturating_sub(this.decoded);
                if remaining == 0 {
                    let mut probe = [0_u8; 1];
                    return match this.poll_decoded(cx, &mut probe) {
                        Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::other(
                            "decoded stream exceeds configured limit",
                        ))),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Pending,
                    };
                }
                usize::try_from(remaining.min(output.len() as u64)).unwrap_or(output.len())
            },
            None => output.len(),
        };
        match this.poll_decoded(cx, &mut output[..allowed]) {
            Poll::Ready(Ok(read)) => {
                this.decoded = match this
                    .decoded
                    .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                {
                    Some(total) => total,
                    None => {
                        return Poll::Ready(Err(io::Error::other("decoded stream size overflow")));
                    },
                };
                Poll::Ready(Ok(read))
            },
            other => other,
        }
    }
}

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
#[derive(Debug)]
pub(crate) struct AsyncFrameEncoder<W> {
    output: W,
    filter: FilterId,
    input: Vec<u8>,
    pending: Vec<u8>,
    pending_position: usize,
    wrote_frame: bool,
    closed: bool,
}

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
impl<W> AsyncFrameEncoder<W> {
    fn new(output: W, filter: FilterId) -> Self {
        Self {
            output,
            filter,
            input: Vec::with_capacity(BUFFER),
            pending: Vec::new(),
            pending_position: 0,
            wrote_frame: false,
            closed: false,
        }
    }

    fn into_inner(self) -> W {
        self.output
    }

    fn encode_frame(&mut self) -> io::Result<()> {
        debug_assert_eq!(self.pending_position, self.pending.len());
        self.pending = crate::filtered_io::encode_profile_frame(self.filter, &self.input)?;
        self.pending_position = 0;
        self.input.clear();
        self.wrote_frame = true;
        Ok(())
    }
}

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
impl<W: AsyncWrite + Unpin> AsyncFrameEncoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending.len() {
            match Pin::new(&mut self.output).poll_write(cx, &self.pending[self.pending_position..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "frame output stopped accepting bytes",
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.pending.is_empty() {
            self.pending.clear();
            self.pending_position = 0;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncFrameEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "frame encoder is closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if this.input.len() == BUFFER {
            if let Err(error) = this.encode_frame() {
                return Poll::Ready(Err(error));
            }
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let consumed = (BUFFER - this.input.len()).min(bytes.len());
        this.input.extend_from_slice(&bytes[..consumed]);
        if this.input.len() == BUFFER {
            if let Err(error) = this.encode_frame() {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_position == this.pending.len() && !this.input.is_empty() {
            if let Err(error) = this.encode_frame() {
                return Poll::Ready(Err(error));
            }
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.output).poll_flush(cx),
            other => other,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if this.pending_position == this.pending.len()
            && (!this.input.is_empty() || !this.wrote_frame)
        {
            if let Err(error) = this.encode_frame() {
                return Poll::Ready(Err(error));
            }
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => match Pin::new(&mut this.output).poll_close(cx) {
                Poll::Ready(Ok(())) => {
                    this.closed = true;
                    Poll::Ready(Ok(()))
                },
                other => other,
            },
            other => other,
        }
    }
}

#[derive(Debug)]
pub(crate) enum AsyncFilterWriter<W> {
    Plain(W),
    Gzip(GzipEncoder<W>),
    #[cfg(feature = "bzip2")]
    Bzip2(async_compression::futures::write::BzEncoder<W>),
    #[cfg(feature = "zstd")]
    Zstd(AsyncFrameEncoder<W>),
    #[cfg(feature = "xz")]
    Xz(AsyncFrameEncoder<W>),
    #[cfg(feature = "lz4")]
    Lz4(AsyncFrameEncoder<W>),
}

impl<W> AsyncFilterWriter<W> {
    pub(crate) fn new(
        output: W,
        filter: Option<FilterId>,
    ) -> Result<Self, libarchive_oxide_core::ArchiveError>
    where
        W: AsyncWrite,
    {
        let writer = match filter {
            None => Self::Plain(output),
            Some(FilterId::Gzip) => Self::Gzip(GzipEncoder::new(output)),
            #[cfg(feature = "bzip2")]
            Some(FilterId::Bzip2) => {
                Self::Bzip2(async_compression::futures::write::BzEncoder::new(output))
            },
            #[cfg(feature = "zstd")]
            Some(FilterId::Zstd) => Self::Zstd(AsyncFrameEncoder::new(output, FilterId::Zstd)),
            #[cfg(feature = "xz")]
            Some(FilterId::Xz) => Self::Xz(AsyncFrameEncoder::new(output, FilterId::Xz)),
            #[cfg(feature = "lz4")]
            Some(FilterId::Lz4) => Self::Lz4(AsyncFrameEncoder::new(output, FilterId::Lz4)),
            Some(_) => {
                return Err(libarchive_oxide_core::ArchiveError::new(
                    libarchive_oxide_core::ErrorKind::Capability,
                )
                .with_context("filter is disabled or has no async encoder"));
            },
        };
        Ok(writer)
    }

    pub(crate) fn into_inner(self) -> W {
        match self {
            Self::Plain(output) => output,
            Self::Gzip(output) => output.into_inner(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => output.into_inner(),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => output.into_inner(),
            #[cfg(feature = "xz")]
            Self::Xz(output) => output.into_inner(),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => output.into_inner(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncFilterWriter<W> {
    pub(crate) fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Plain(output) => Pin::new(output).poll_flush(cx),
            Self::Gzip(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_close(cx),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncFilterWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(output) => Pin::new(output).poll_write(cx, bytes),
            Self::Gzip(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_write(cx, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(output) => Pin::new(output).poll_flush(cx),
            Self::Gzip(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_finish(cx)
    }
}
