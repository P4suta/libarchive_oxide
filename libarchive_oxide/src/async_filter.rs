// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral, bounded asynchronous outer-filter adapters.

use std::io;
#[cfg(any(feature = "lzma", feature = "lzip"))]
use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::BackendPreference;
use crate::pipeline_codec::PipelineCodec;
use async_compression::futures::bufread::GzipDecoder;
use async_compression::futures::write::GzipEncoder;
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

const PREFIX: usize = 9;
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
    let kind = match error.kind() {
        io::ErrorKind::OutOfMemory => ErrorKind::Limit,
        io::ErrorKind::Unsupported => ErrorKind::Unsupported,
        _ => ErrorKind::Malformed,
    };
    archive_codec_error(
        ArchiveError::new(kind)
            .with_format("outer-filter")
            .with_context(error.to_string()),
    )
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
    fn new(
        input: R,
        filter: FilterId,
        limits: Limits,
        backend: BackendPreference,
    ) -> io::Result<Self> {
        Ok(Self {
            input,
            codec: PipelineCodec::with_backend(filter, limits, backend)
                .map_err(archive_codec_error)?,
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
                .poll_process(
                    &this.compressed[this.start..this.end],
                    output,
                    end,
                    cx.waker(),
                )
                .transpose()
            {
                Some(result) => {
                    match result.and_then(|step| step.validate(input_length, output.len())) {
                        Ok(step) => step,
                        Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
                    }
                },
                None => return Poll::Pending,
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
    Gzip(Box<GzipDecoder<FilterInput<R>>>),
    #[cfg(feature = "bzip2")]
    Bzip2(async_compression::futures::bufread::BzDecoder<FilterInput<R>>),
    #[cfg(feature = "zstd")]
    Zstd(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "xz")]
    Xz(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "lz4")]
    Lz4(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "compress")]
    Compress(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "lzip")]
    Lzip(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "lzma")]
    Lzma(Box<AsyncCodecReader<FilterInput<R>>>),
    Base64(Box<AsyncCodecReader<FilterInput<R>>>),
    Uuencode(Box<AsyncCodecReader<FilterInput<R>>>),
    Rpm(Box<AsyncCodecReader<FilterInput<R>>>),
    #[cfg(feature = "lzop")]
    Lzop(Box<AsyncCodecReader<FilterInput<R>>>),
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
    backend: BackendPreference,
}

impl<R> AsyncFilterReader<R> {
    pub(crate) fn with_backend(input: R, limits: Limits, backend: BackendPreference) -> Self {
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
            backend,
        }
    }

    #[allow(clippy::too_many_lines)] // One ownership-preserving dispatch over all filter variants.
    pub(crate) fn with_filter(
        input: R,
        filter: FilterId,
        limits: Limits,
        backend: BackendPreference,
    ) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let input = Buffered::new(PrefixReader {
            prefix: [0; PREFIX],
            prefix_length: 0,
            prefix_position: 0,
            input,
            wrap_source_errors: true,
            physical_read: 0,
        });
        let inner = match filter {
            FilterId::Gzip => {
                let mut decoder = GzipDecoder::new(input);
                decoder.multiple_members(true);
                ReaderInner::Gzip(Box::new(decoder))
            },
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    let mut decoder = async_compression::futures::bufread::BzDecoder::new(input);
                    decoder.multiple_members(true);
                    ReaderInner::Bzip2(decoder)
                }
                #[cfg(not(feature = "bzip2"))]
                return Err(disabled_filter("bzip2"));
            },
            FilterId::Zstd => {
                #[cfg(feature = "zstd")]
                {
                    ReaderInner::Zstd(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "zstd"))]
                return Err(disabled_filter("zstd"));
            },
            FilterId::Xz => {
                #[cfg(feature = "xz")]
                {
                    ReaderInner::Xz(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "xz"))]
                return Err(disabled_filter("XZ"));
            },
            FilterId::Lz4 => {
                #[cfg(feature = "lz4")]
                {
                    ReaderInner::Lz4(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "lz4"))]
                return Err(disabled_filter("LZ4"));
            },
            FilterId::Compress => {
                #[cfg(feature = "compress")]
                {
                    ReaderInner::Compress(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "compress"))]
                return Err(disabled_filter("compress/LZW"));
            },
            FilterId::Lzip => {
                #[cfg(feature = "lzip")]
                {
                    ReaderInner::Lzip(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "lzip"))]
                return Err(disabled_filter("lzip"));
            },
            FilterId::Base64 => ReaderInner::Base64(Box::new(AsyncCodecReader::new(
                input, filter, limits, backend,
            )?)),
            FilterId::Uuencode => ReaderInner::Uuencode(Box::new(AsyncCodecReader::new(
                input, filter, limits, backend,
            )?)),
            FilterId::Rpm => ReaderInner::Rpm(Box::new(AsyncCodecReader::new(
                input, filter, limits, backend,
            )?)),
            FilterId::Lzop => {
                #[cfg(feature = "lzop")]
                {
                    ReaderInner::Lzop(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
                }
                #[cfg(not(feature = "lzop"))]
                return Err(disabled_filter("lzop"));
            },
            FilterId::Lzma => {
                #[cfg(feature = "lzma")]
                {
                    ReaderInner::Lzma(Box::new(AsyncCodecReader::new(
                        input, filter, limits, backend,
                    )?))
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
                    "the selected outer filter has no async streaming reader",
                ));
            },
        };
        Ok(Self {
            inner,
            decoded: 0,
            decoded_limit: limits.decoded_total(),
            limits,
            backend,
        })
    }

    pub(crate) fn into_inner(self) -> Result<R, ArchiveError> {
        match self.inner {
            ReaderInner::Detecting {
                input: Some(input), ..
            }
            | ReaderInner::Failed(Some(input)) => Ok(input),
            ReaderInner::Detecting { input: None, .. } | ReaderInner::Failed(None) => {
                Err(ArchiveError::new(ErrorKind::Protocol).with_context(
                    "async filter input is unavailable after codec initialization failed",
                ))
            },
            ReaderInner::Plain(input) => Ok(input.into_inner().into_inner()),
            ReaderInner::Gzip(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "bzip2")]
            ReaderInner::Bzip2(input) => Ok(input.into_inner().into_inner().into_inner()),
            #[cfg(feature = "zstd")]
            ReaderInner::Zstd(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "xz")]
            ReaderInner::Xz(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "lz4")]
            ReaderInner::Lz4(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "compress")]
            ReaderInner::Compress(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "lzip")]
            ReaderInner::Lzip(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "lzma")]
            ReaderInner::Lzma(input) => Ok((*input).into_inner().into_inner().into_inner()),
            ReaderInner::Base64(input) => Ok((*input).into_inner().into_inner().into_inner()),
            ReaderInner::Uuencode(input) => Ok((*input).into_inner().into_inner().into_inner()),
            ReaderInner::Rpm(input) => Ok((*input).into_inner().into_inner().into_inner()),
            #[cfg(feature = "lzop")]
            ReaderInner::Lzop(input) => Ok((*input).into_inner().into_inner().into_inner()),
            ReaderInner::Finished { input, .. } => Ok(input.into_inner().into_inner()),
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
        if available.starts_with(b"LZIP") {
            #[cfg(feature = "lzip")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Lzip(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Lzip,
                    self.limits,
                    self.backend,
                )?));
            }
            #[cfg(not(feature = "lzip"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "lzip filter is not enabled",
                )));
            }
        } else if available.starts_with(&[0x1f, 0x8b]) {
            buffered.input.wrap_source_errors = true;
            let mut decoder = GzipDecoder::new(buffered);
            decoder.multiple_members(true);
            self.inner = ReaderInner::Gzip(Box::new(decoder));
        } else if available.starts_with(&[0x1f, 0x9d]) {
            #[cfg(feature = "compress")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Compress(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Compress,
                    self.limits,
                    self.backend,
                )?));
            }
            #[cfg(not(feature = "compress"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "compress/LZW filter is not enabled",
                )));
            }
        } else if available.starts_with(b"begin ") {
            buffered.input.wrap_source_errors = true;
            self.inner = ReaderInner::Uuencode(Box::new(AsyncCodecReader::new(
                buffered,
                FilterId::Uuencode,
                self.limits,
                self.backend,
            )?));
        } else if available.starts_with(b"\xed\xab\xee\xdb") {
            buffered.input.wrap_source_errors = true;
            self.inner = ReaderInner::Rpm(Box::new(AsyncCodecReader::new(
                buffered,
                FilterId::Rpm,
                self.limits,
                self.backend,
            )?));
        } else if available.starts_with(b"\x89LZO\0\r\n\x1a\n") {
            #[cfg(feature = "lzop")]
            {
                buffered.input.wrap_source_errors = true;
                self.inner = ReaderInner::Lzop(Box::new(AsyncCodecReader::new(
                    buffered,
                    FilterId::Lzop,
                    self.limits,
                    self.backend,
                )?));
            }
            #[cfg(not(feature = "lzop"))]
            {
                self.inner = ReaderInner::Failed(Some(buffered.into_inner().into_inner()));
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "lzop filter is not enabled",
                )));
            }
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
                    self.backend,
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
                    self.backend,
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
                    self.backend,
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

    #[allow(clippy::too_many_lines)] // One ownership-preserving dispatch over every reader state.
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
                #[cfg(feature = "compress")]
                ReaderInner::Compress(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "lzip")]
                ReaderInner::Lzip(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "lzma")]
                ReaderInner::Lzma(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                ReaderInner::Base64(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                ReaderInner::Uuencode(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                ReaderInner::Rpm(input) => {
                    (codec_poll(Pin::new(input).poll_read(cx, output)), true)
                },
                #[cfg(feature = "lzop")]
                ReaderInner::Lzop(input) => {
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
                    ReaderInner::Gzip(input) => ((*input).into_inner(), FilterId::Gzip),
                    #[cfg(feature = "bzip2")]
                    ReaderInner::Bzip2(input) => (input.into_inner(), FilterId::Bzip2),
                    #[cfg(feature = "zstd")]
                    ReaderInner::Zstd(input) => ((*input).into_inner(), FilterId::Zstd),
                    #[cfg(feature = "xz")]
                    ReaderInner::Xz(input) => ((*input).into_inner(), FilterId::Xz),
                    #[cfg(feature = "lz4")]
                    ReaderInner::Lz4(input) => ((*input).into_inner(), FilterId::Lz4),
                    #[cfg(feature = "compress")]
                    ReaderInner::Compress(input) => ((*input).into_inner(), FilterId::Compress),
                    #[cfg(feature = "lzip")]
                    ReaderInner::Lzip(input) => ((*input).into_inner(), FilterId::Lzip),
                    #[cfg(feature = "lzma")]
                    ReaderInner::Lzma(input) => ((*input).into_inner(), FilterId::Lzma),
                    ReaderInner::Base64(input) => ((*input).into_inner(), FilterId::Base64),
                    ReaderInner::Uuencode(input) => ((*input).into_inner(), FilterId::Uuencode),
                    ReaderInner::Rpm(input) => ((*input).into_inner(), FilterId::Rpm),
                    #[cfg(feature = "lzop")]
                    ReaderInner::Lzop(input) => ((*input).into_inner(), FilterId::Lzop),
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
    backend: BackendPreference,
}

#[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
impl<W> AsyncFrameEncoder<W> {
    fn new(output: W, filter: FilterId, backend: BackendPreference) -> Self {
        Self {
            output,
            filter,
            input: Vec::with_capacity(BUFFER),
            pending: Vec::new(),
            pending_position: 0,
            wrote_frame: false,
            closed: false,
            backend,
        }
    }

    fn into_inner(self) -> W {
        self.output
    }

    fn encode_frame(&mut self) -> io::Result<()> {
        debug_assert_eq!(self.pending_position, self.pending.len());
        self.pending = crate::filtered_io::encode_profile_frame_with_backend(
            self.filter,
            &self.input,
            self.backend,
        )?;
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
            match this.encode_frame() {
                Ok(()) => {},
                Err(error) => return Poll::Ready(Err(error)),
            }
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let consumed = (BUFFER - this.input.len()).min(bytes.len());
        this.input.extend_from_slice(&bytes[..consumed]);
        if this.input.len() == BUFFER
            && let Err(error) = this.encode_frame()
        {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_position == this.pending.len()
            && !this.input.is_empty()
            && let Err(error) = this.encode_frame()
        {
            return Poll::Ready(Err(error));
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
            && let Err(error) = this.encode_frame()
        {
            return Poll::Ready(Err(error));
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
pub(crate) struct AsyncBase64Encoder<W> {
    output: W,
    encoder: libarchive_oxide_codecs::base64::Base64Encoder,
    pending: [u8; 4],
    pending_position: usize,
    pending_length: usize,
    finished: bool,
    closed: bool,
}

#[derive(Debug)]
pub(crate) struct AsyncUuencodeEncoder<W> {
    output: W,
    encoder: libarchive_oxide_codecs::uuencode::UuencodeEncoder,
    pending: Vec<u8>,
    pending_position: usize,
    pending_length: usize,
    finished: bool,
    closed: bool,
}

impl<W> AsyncUuencodeEncoder<W> {
    fn new(output: W, limits: Limits) -> Result<Self, ArchiveError> {
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::uuencode::UuencodeEncoder::new(limits)?,
            pending: vec![0; BUFFER],
            pending_position: 0,
            pending_length: 0,
            finished: false,
            closed: false,
        })
    }

    fn into_inner(self) -> W {
        self.output
    }
}

impl<W: AsyncWrite + Unpin> AsyncUuencodeEncoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending_length {
            match Pin::new(&mut self.output).poll_write(
                cx,
                &self.pending[self.pending_position..self.pending_length],
            ) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "uuencode output stopped accepting bytes",
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_position = 0;
        self.pending_length = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncUuencodeEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "uuencode encoder is closed",
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
        let step = match this
            .encoder
            .process(bytes, &mut this.pending, EndOfInput::More)
            .and_then(|step| step.validate(bytes.len(), this.pending.len()))
        {
            Ok(step) => step,
            Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
        };
        this.pending_length = step.produced;
        if step.consumed == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "uuencode encoder made no write progress",
            )));
        }
        Poll::Ready(Ok(step.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.finished {
            let step = match this
                .encoder
                .process(&[], &mut this.pending, EndOfInput::End)
                .and_then(|step| step.validate(0, this.pending.len()))
            {
                Ok(step) => step,
                Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
            };
            this.pending_length = step.produced;
            this.finished = step.status == CodecStatus::Done;
            if !this.finished && step.produced == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uuencode encoder made no finish progress",
                )));
            }
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if !this.finished {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        match Pin::new(&mut this.output).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

#[cfg(feature = "lzop")]
#[derive(Debug)]
pub(crate) struct AsyncLzopEncoder<W> {
    output: W,
    encoder: libarchive_oxide_codecs::lzop::LzopEncoder,
    pending: Vec<u8>,
    pending_position: usize,
    pending_length: usize,
    finished: bool,
    closed: bool,
}

#[cfg(feature = "lzop")]
impl<W> AsyncLzopEncoder<W> {
    fn new(output: W, limits: Limits, backend: BackendPreference) -> Result<Self, ArchiveError> {
        if matches!(backend, BackendPreference::Native) {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format("lzop")
                .with_context("the lzop filter has no native backend"));
        }
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::lzop::LzopEncoder::new(limits)?,
            pending: vec![0; BUFFER],
            pending_position: 0,
            pending_length: 0,
            finished: false,
            closed: false,
        })
    }

    fn into_inner(self) -> W {
        self.output
    }
}

#[cfg(feature = "lzop")]
impl<W: AsyncWrite + Unpin> AsyncLzopEncoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending_length {
            match Pin::new(&mut self.output).poll_write(
                cx,
                &self.pending[self.pending_position..self.pending_length],
            ) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "lzop output stopped accepting bytes",
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_position = 0;
        self.pending_length = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "lzop")]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncLzopEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "lzop encoder is closed",
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
        let step = match this
            .encoder
            .process(bytes, &mut this.pending, EndOfInput::More)
            .and_then(|step| step.validate(bytes.len(), this.pending.len()))
        {
            Ok(step) => step,
            Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
        };
        this.pending_length = step.produced;
        if step.consumed == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lzop encoder made no write progress",
            )));
        }
        Poll::Ready(Ok(step.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.finished {
            let step = match this
                .encoder
                .process(&[], &mut this.pending, EndOfInput::End)
                .and_then(|step| step.validate(0, this.pending.len()))
            {
                Ok(step) => step,
                Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
            };
            this.pending_length = step.produced;
            this.finished = step.status == CodecStatus::Done;
            if !this.finished && step.produced == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lzop encoder made no finish progress",
                )));
            }
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if !this.finished {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        match Pin::new(&mut this.output).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

#[cfg(feature = "compress")]
#[derive(Debug)]
pub(crate) struct AsyncCompressEncoder<W> {
    output: W,
    encoder: libarchive_oxide_codecs::lzw::CompressEncoder,
    pending: Vec<u8>,
    pending_position: usize,
    pending_length: usize,
    finished: bool,
    closed: bool,
}

#[cfg(feature = "compress")]
impl<W> AsyncCompressEncoder<W> {
    fn new(output: W, limits: Limits, backend: BackendPreference) -> Result<Self, ArchiveError> {
        if matches!(backend, BackendPreference::Native) {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format("compress")
                .with_context("the compress/LZW filter has no native backend"));
        }
        Ok(Self {
            output,
            encoder: libarchive_oxide_codecs::lzw::CompressEncoder::with_limits(limits)?,
            pending: vec![0; BUFFER],
            pending_position: 0,
            pending_length: 0,
            finished: false,
            closed: false,
        })
    }

    fn into_inner(self) -> W {
        self.output
    }
}

#[cfg(feature = "compress")]
impl<W: AsyncWrite + Unpin> AsyncCompressEncoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending_length {
            match Pin::new(&mut self.output).poll_write(
                cx,
                &self.pending[self.pending_position..self.pending_length],
            ) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "compress/LZW output stopped accepting bytes",
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_position = 0;
        self.pending_length = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "compress")]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncCompressEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "compress/LZW encoder is closed",
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
        let step = match this
            .encoder
            .process(bytes, &mut this.pending, EndOfInput::More)
            .and_then(|step| step.validate(bytes.len(), this.pending.len()))
        {
            Ok(step) => step,
            Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
        };
        this.pending_length = step.produced;
        if step.consumed == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compress/LZW encoder made no write progress",
            )));
        }
        Poll::Ready(Ok(step.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.finished {
            let step = match this
                .encoder
                .process(&[], &mut this.pending, EndOfInput::End)
                .and_then(|step| step.validate(0, this.pending.len()))
            {
                Ok(step) => step,
                Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
            };
            this.pending_length = step.produced;
            this.finished = step.status == CodecStatus::Done;
            if !this.finished && step.produced == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compress/LZW encoder made no finish progress",
                )));
            }
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if !this.finished {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        match Pin::new(&mut this.output).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

impl<W> AsyncBase64Encoder<W> {
    fn new(output: W, limits: Limits) -> Self {
        Self {
            output,
            encoder: libarchive_oxide_codecs::base64::Base64Encoder::new(limits),
            pending: [0; 4],
            pending_position: 0,
            pending_length: 0,
            finished: false,
            closed: false,
        }
    }

    fn into_inner(self) -> W {
        self.output
    }
}

impl<W: AsyncWrite + Unpin> AsyncBase64Encoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending_length {
            match Pin::new(&mut self.output).poll_write(
                cx,
                &self.pending[self.pending_position..self.pending_length],
            ) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Base64 output stopped accepting bytes",
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_position = 0;
        self.pending_length = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncBase64Encoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Base64 encoder is closed",
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
        let step = match this
            .encoder
            .process(bytes, &mut this.pending, EndOfInput::More)
            .and_then(|step| step.validate(bytes.len(), this.pending.len()))
        {
            Ok(step) => step,
            Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
        };
        this.pending_length = step.produced;
        if step.consumed == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Base64 encoder made no write progress",
            )));
        }
        Poll::Ready(Ok(step.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.finished {
            let step = match this
                .encoder
                .process(&[], &mut this.pending, EndOfInput::End)
                .and_then(|step| step.validate(0, this.pending.len()))
            {
                Ok(step) => step,
                Err(error) => return Poll::Ready(Err(archive_codec_error(error))),
            };
            this.pending_length = step.produced;
            if step.status != CodecStatus::Done {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Base64 encoder did not finish with a bounded output block",
                )));
            }
            this.finished = true;
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.output).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
enum LzmaFamilyWriter {
    #[cfg(feature = "lzma")]
    Alone(lzma_rust2::LzmaWriter<Vec<u8>>),
    #[cfg(feature = "lzip")]
    Lzip(lzma_rust2::LzipWriter<Vec<u8>>),
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
impl LzmaFamilyWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(feature = "lzma")]
            Self::Alone(writer) => writer.write(bytes),
            #[cfg(feature = "lzip")]
            Self::Lzip(writer) => writer.write(bytes),
        }
    }

    fn take_pending(&mut self) -> Vec<u8> {
        match self {
            #[cfg(feature = "lzma")]
            Self::Alone(writer) => core::mem::take(writer.inner_mut()),
            #[cfg(feature = "lzip")]
            Self::Lzip(writer) => core::mem::take(writer.inner_mut()),
        }
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        match self {
            #[cfg(feature = "lzma")]
            Self::Alone(writer) => writer.finish(),
            #[cfg(feature = "lzip")]
            Self::Lzip(writer) => writer.finish(),
        }
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
pub(crate) struct AsyncLzmaFamilyEncoder<W> {
    output: W,
    writer: Option<LzmaFamilyWriter>,
    pending: Vec<u8>,
    pending_position: usize,
    closed: bool,
    format: &'static str,
}

#[cfg(feature = "lzma")]
impl<W> AsyncLzmaFamilyEncoder<W> {
    fn new(output: W, limits: Limits, backend: BackendPreference) -> Result<Self, ArchiveError> {
        if matches!(backend, BackendPreference::Native) {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format("lzma")
                .with_context("the LZMA-alone filter has no native backend"));
        }
        let options = lzma_rust2::LzmaOptions::with_preset(0);
        let encoder_memory = u64::from(options.get_memory_usage());
        if limits
            .codec_memory()
            .is_some_and(|maximum| encoder_memory > maximum as u64)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("lzma")
                .with_context("LZMA encoder exceeds the configured codec-memory limit"));
        }
        let writer = lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, None).map_err(
            |error| {
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("lzma")
                    .with_context(error.to_string())
            },
        )?;
        Ok(Self::from_writer(
            output,
            LzmaFamilyWriter::Alone(writer),
            "lzma",
        ))
    }
}

#[cfg(feature = "lzip")]
impl<W> AsyncLzmaFamilyEncoder<W> {
    fn new_lzip(
        output: W,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, ArchiveError> {
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
        Ok(Self::from_writer(
            output,
            LzmaFamilyWriter::Lzip(lzma_rust2::LzipWriter::new(Vec::new(), options)),
            "lzip",
        ))
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
impl<W> AsyncLzmaFamilyEncoder<W> {
    fn from_writer(output: W, mut writer: LzmaFamilyWriter, format: &'static str) -> Self {
        let pending = writer.take_pending();
        Self {
            output,
            writer: Some(writer),
            pending,
            pending_position: 0,
            closed: false,
            format,
        }
    }

    fn into_inner(self) -> W {
        self.output
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
impl<W: AsyncWrite + Unpin> AsyncLzmaFamilyEncoder<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_position != self.pending.len() {
            match Pin::new(&mut self.output).poll_write(cx, &self.pending[self.pending_position..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("{} output stopped accepting bytes", self.format),
                    )));
                },
                Poll::Ready(Ok(written)) => self.pending_position += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_position = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncLzmaFamilyEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.writer.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{} encoder is closed", this.format),
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
        let accepted = bytes.len().min(BUFFER);
        let Some(writer) = this.writer.as_mut() else {
            return Poll::Ready(Err(io::Error::other(format!(
                "{} writer is unavailable",
                this.format
            ))));
        };
        let written = match writer.write(&bytes[..accepted]) {
            Ok(written) => written,
            Err(error) => return Poll::Ready(Err(error)),
        };
        this.pending = writer.take_pending();
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if let Some(writer) = this.writer.take() {
            this.pending = match writer.finish() {
                Ok(bytes) => bytes,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.output).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

#[cfg(any(feature = "lzma", feature = "lzip"))]
impl<W> std::fmt::Debug for AsyncLzmaFamilyEncoder<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AsyncLzmaFamilyEncoder")
            .field("format", &self.format)
            .field("pending", &(self.pending.len() - self.pending_position))
            .field("finishing", &self.writer.is_none())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) enum AsyncFilterWriter<W> {
    Plain(W),
    Gzip(GzipEncoder<W>),
    Base64(AsyncBase64Encoder<W>),
    Uuencode(Box<AsyncUuencodeEncoder<W>>),
    #[cfg(feature = "lzop")]
    Lzop(Box<AsyncLzopEncoder<W>>),
    #[cfg(feature = "compress")]
    Compress(Box<AsyncCompressEncoder<W>>),
    #[cfg(feature = "bzip2")]
    Bzip2(async_compression::futures::write::BzEncoder<W>),
    #[cfg(feature = "zstd")]
    Zstd(AsyncFrameEncoder<W>),
    #[cfg(feature = "xz")]
    Xz(AsyncFrameEncoder<W>),
    #[cfg(feature = "lz4")]
    Lz4(AsyncFrameEncoder<W>),
    #[cfg(feature = "lzma")]
    Lzma(Box<AsyncLzmaFamilyEncoder<W>>),
    #[cfg(feature = "lzip")]
    Lzip(Box<AsyncLzmaFamilyEncoder<W>>),
}

impl<W> AsyncFilterWriter<W> {
    pub(crate) fn with_backend(
        output: W,
        filter: Option<FilterId>,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, libarchive_oxide_core::ArchiveError>
    where
        W: AsyncWrite,
    {
        backend.resolve()?;
        let writer = match filter {
            None => Self::Plain(output),
            #[cfg(feature = "lzip")]
            Some(FilterId::Lzip) => Self::Lzip(Box::new(AsyncLzmaFamilyEncoder::new_lzip(
                output, limits, backend,
            )?)),
            Some(FilterId::Gzip) => Self::Gzip(GzipEncoder::new(output)),
            Some(FilterId::Base64) => Self::Base64(AsyncBase64Encoder::new(output, limits)),
            Some(FilterId::Uuencode) => {
                Self::Uuencode(Box::new(AsyncUuencodeEncoder::new(output, limits)?))
            },
            #[cfg(feature = "lzop")]
            Some(FilterId::Lzop) => {
                Self::Lzop(Box::new(AsyncLzopEncoder::new(output, limits, backend)?))
            },
            #[cfg(feature = "compress")]
            Some(FilterId::Compress) => Self::Compress(Box::new(AsyncCompressEncoder::new(
                output, limits, backend,
            )?)),
            #[cfg(feature = "lzma")]
            Some(FilterId::Lzma) => Self::Lzma(Box::new(AsyncLzmaFamilyEncoder::new(
                output, limits, backend,
            )?)),
            #[cfg(feature = "bzip2")]
            Some(FilterId::Bzip2) => {
                Self::Bzip2(async_compression::futures::write::BzEncoder::new(output))
            },
            #[cfg(feature = "zstd")]
            Some(FilterId::Zstd) => {
                Self::Zstd(AsyncFrameEncoder::new(output, FilterId::Zstd, backend))
            },
            #[cfg(feature = "xz")]
            Some(FilterId::Xz) => Self::Xz(AsyncFrameEncoder::new(output, FilterId::Xz, backend)),
            #[cfg(feature = "lz4")]
            Some(FilterId::Lz4) => {
                Self::Lz4(AsyncFrameEncoder::new(output, FilterId::Lz4, backend))
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
            Self::Base64(output) => output.into_inner(),
            Self::Uuencode(output) => output.into_inner(),
            #[cfg(feature = "lzop")]
            Self::Lzop(output) => output.into_inner(),
            #[cfg(feature = "compress")]
            Self::Compress(output) => output.into_inner(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => output.into_inner(),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => output.into_inner(),
            #[cfg(feature = "xz")]
            Self::Xz(output) => output.into_inner(),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => output.into_inner(),
            #[cfg(feature = "lzma")]
            Self::Lzma(output) => output.into_inner(),
            #[cfg(feature = "lzip")]
            Self::Lzip(output) => output.into_inner(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncFilterWriter<W> {
    pub(crate) fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Plain(output) => Pin::new(output).poll_flush(cx),
            Self::Gzip(output) => Pin::new(output).poll_close(cx),
            Self::Base64(output) => Pin::new(output).poll_close(cx),
            Self::Uuencode(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "lzop")]
            Self::Lzop(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "compress")]
            Self::Compress(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "lzma")]
            Self::Lzma(output) => Pin::new(output).poll_close(cx),
            #[cfg(feature = "lzip")]
            Self::Lzip(output) => Pin::new(output).poll_close(cx),
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
            Self::Base64(output) => Pin::new(output).poll_write(cx, bytes),
            Self::Uuencode(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "lzop")]
            Self::Lzop(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "compress")]
            Self::Compress(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "lzma")]
            Self::Lzma(output) => Pin::new(output).poll_write(cx, bytes),
            #[cfg(feature = "lzip")]
            Self::Lzip(output) => Pin::new(output).poll_write(cx, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(output) => Pin::new(output).poll_flush(cx),
            Self::Gzip(output) => Pin::new(output).poll_flush(cx),
            Self::Base64(output) => Pin::new(output).poll_flush(cx),
            Self::Uuencode(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "lzop")]
            Self::Lzop(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "compress")]
            Self::Compress(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "zstd")]
            Self::Zstd(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "xz")]
            Self::Xz(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "lz4")]
            Self::Lz4(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "lzma")]
            Self::Lzma(output) => Pin::new(output).poll_flush(cx),
            #[cfg(feature = "lzip")]
            Self::Lzip(output) => Pin::new(output).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_finish(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_async_filter_input_is_a_protocol_error() {
        let reader = AsyncFilterReader {
            inner: ReaderInner::<Vec<u8>>::Failed(None),
            decoded: 0,
            decoded_limit: None,
            limits: Limits::safe(),
            backend: BackendPreference::Auto,
        };

        assert!(matches!(
            reader.into_inner(),
            Err(error) if error.kind() == ErrorKind::Protocol
        ));
    }
}
