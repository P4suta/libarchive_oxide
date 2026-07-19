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
use libarchive_oxide_core::Limits;
use libarchive_oxide_core::filter::FilterId;

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
    io::Error::new(io::ErrorKind::InvalidData, error)
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
enum ReaderInner<R> {
    Detecting {
        input: Option<R>,
        prefix: [u8; PREFIX],
        prefix_length: usize,
        eof: bool,
    },
    Plain(FilterInput<R>),
    Gzip(GzipDecoder<FilterInput<R>>),
    #[cfg(feature = "zstd")]
    Zstd(async_compression::futures::bufread::ZstdDecoder<FilterInput<R>>),
    #[cfg(feature = "xz")]
    Xz(async_compression::futures::bufread::XzDecoder<FilterInput<R>>),
    #[cfg(feature = "lz4")]
    Lz4(async_compression::futures::bufread::Lz4Decoder<FilterInput<R>>),
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
            #[cfg(feature = "zstd")]
            ReaderInner::Zstd(input) => input.into_inner().into_inner().into_inner(),
            #[cfg(feature = "xz")]
            ReaderInner::Xz(input) => input.into_inner().into_inner().into_inner(),
            #[cfg(feature = "lz4")]
            ReaderInner::Lz4(input) => input.into_inner().into_inner().into_inner(),
            ReaderInner::Finished { input, .. } => input.into_inner().into_inner(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncFilterReader<R> {
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
        } else if available.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            #[cfg(feature = "zstd")]
            {
                buffered.input.wrap_source_errors = true;
                let mut decoder = async_compression::futures::bufread::ZstdDecoder::new(buffered);
                decoder.multiple_members(true);
                self.inner = ReaderInner::Zstd(decoder);
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
                let mut decoder = async_compression::futures::bufread::XzDecoder::new(buffered);
                decoder.multiple_members(true);
                self.inner = ReaderInner::Xz(decoder);
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
                let mut decoder = async_compression::futures::bufread::Lz4Decoder::new(buffered);
                decoder.multiple_members(true);
                self.inner = ReaderInner::Lz4(decoder);
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
                    #[cfg(feature = "zstd")]
                    ReaderInner::Zstd(input) => (input.into_inner(), FilterId::Zstd),
                    #[cfg(feature = "xz")]
                    ReaderInner::Xz(input) => (input.into_inner(), FilterId::Xz),
                    #[cfg(feature = "lz4")]
                    ReaderInner::Lz4(input) => (input.into_inner(), FilterId::Lz4),
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

#[derive(Debug)]
pub(crate) enum AsyncFilterWriter<W> {
    Plain(W),
    Gzip(GzipEncoder<W>),
    #[cfg(feature = "zstd")]
    Zstd(async_compression::futures::write::ZstdEncoder<W>),
    #[cfg(feature = "xz")]
    Xz(async_compression::futures::write::XzEncoder<W>),
    #[cfg(feature = "lz4")]
    Lz4(async_compression::futures::write::Lz4Encoder<W>),
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
            #[cfg(feature = "zstd")]
            Some(FilterId::Zstd) => {
                Self::Zstd(async_compression::futures::write::ZstdEncoder::new(output))
            },
            #[cfg(feature = "xz")]
            Some(FilterId::Xz) => {
                Self::Xz(async_compression::futures::write::XzEncoder::new(output))
            },
            #[cfg(feature = "lz4")]
            Some(FilterId::Lz4) => {
                Self::Lz4(async_compression::futures::write::Lz4Encoder::new(output))
            },
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
