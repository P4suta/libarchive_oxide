// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral asynchronous archive adapters.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveEncoder, ArchiveError, ArchiveMetadata, CpioDialect, EncodeCommand, EncodeStatus,
    EntryMetadata, ErrorKind, FormatId, Limits,
};

use crate::BackendPreference;
#[cfg(feature = "aes")]
use crate::SecretBytes;
use crate::async_filter::{AsyncFilterReader, AsyncFilterWriter};
use crate::provider::ProviderArchiveEncoder;
use crate::stream::{Pipeline, PipelineEvent, ReaderEvent, RuntimeEncoder, StreamError};
use crate::zip::ZipMethod;

const BUFFER: usize = 64 * 1024;

/// Runtime-neutral asynchronous archive reader.
///
/// Dropping this value cancels reads without performing hidden I/O.
#[derive(Debug)]
pub struct AsyncArchiveReader<R> {
    reader: AsyncReaderInput<R>,
    pipeline: Pipeline,
    read_buffer: Vec<u8>,
    event_data: Vec<u8>,
}

#[derive(Debug)]
enum AsyncReaderInput<R> {
    Plain(R),
    One(Box<AsyncFilterReader<R>>),
    Two(Box<AsyncFilterReader<AsyncFilterReader<R>>>),
    Three(Box<AsyncFilterReader<AsyncFilterReader<AsyncFilterReader<R>>>>),
    Four(Box<AsyncFilterReader<AsyncFilterReader<AsyncFilterReader<AsyncFilterReader<R>>>>>),
}

impl<R: AsyncRead + Unpin> AsyncReaderInput<R> {
    fn new(input: R, limits: Limits, backend: BackendPreference) -> Self {
        let depth = limits.filter_depth().unwrap_or(4).min(4);
        if depth == 0 {
            return Self::Plain(input);
        }
        let one = AsyncFilterReader::with_backend(input, limits, backend);
        if depth == 1 {
            return Self::One(Box::new(one));
        }
        let two = AsyncFilterReader::with_backend(one, limits, backend);
        if depth == 2 {
            return Self::Two(Box::new(two));
        }
        let three = AsyncFilterReader::with_backend(two, limits, backend);
        if depth == 3 {
            return Self::Three(Box::new(three));
        }
        Self::Four(Box::new(AsyncFilterReader::with_backend(
            three, limits, backend,
        )))
    }

    fn poll_read(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match self {
            Self::Plain(input) => Pin::new(input).poll_read(context, output),
            Self::One(input) => Pin::new(input.as_mut()).poll_read(context, output),
            Self::Two(input) => Pin::new(input.as_mut()).poll_read(context, output),
            Self::Three(input) => Pin::new(input.as_mut()).poll_read(context, output),
            Self::Four(input) => Pin::new(input.as_mut()).poll_read(context, output),
        }
    }

    fn into_inner(self) -> Result<R, ArchiveError> {
        match self {
            Self::Plain(input) => Ok(input),
            Self::One(input) => (*input).into_inner(),
            Self::Two(input) => (*input).into_inner()?.into_inner(),
            Self::Three(input) => (*input).into_inner()?.into_inner()?.into_inner(),
            Self::Four(input) => (*input)
                .into_inner()?
                .into_inner()?
                .into_inner()?
                .into_inner(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncArchiveReader<R> {
    /// Creates a reader using safe default resource limits.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::default())
    }

    /// Creates a reader with explicit resource limits.
    #[must_use]
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self::with_backend(reader, limits, BackendPreference::Auto)
    }

    /// Creates a reader with explicit limits and codec backend preference.
    #[must_use]
    pub fn with_backend(reader: R, limits: Limits, backend: BackendPreference) -> Self {
        Self {
            reader: AsyncReaderInput::new(reader, limits, backend),
            pipeline: Pipeline::after_filter_adapters_with_backend(limits, backend),
            read_buffer: vec![0; BUFFER],
            event_data: Vec::with_capacity(BUFFER),
        }
    }

    /// Creates an asynchronous reader for an explicit sequential format.
    ///
    /// This is required for signatureless formats such as [`FormatId::Raw`].
    /// Outer compression filters remain auto-detected.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is unknown, disabled, write-only, or
    /// requires seekable input.
    pub fn with_format(reader: R, format: FormatId) -> Result<Self, ArchiveError> {
        Self::with_format_and_limits(reader, format, Limits::default())
    }

    /// Creates an explicit-format asynchronous reader with custom limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the format cannot be decoded by the sequential
    /// built-in provider.
    pub fn with_format_and_limits(
        reader: R,
        format: FormatId,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::with_backend_and_format(reader, format, limits, BackendPreference::Auto)
    }

    /// Creates an explicit-format asynchronous reader and selects a codec backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the format cannot be decoded by the sequential
    /// built-in provider.
    pub fn with_backend_and_format(
        reader: R,
        format: FormatId,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        Ok(Self {
            reader: AsyncReaderInput::new(reader, limits, backend),
            pipeline: Pipeline::after_filter_adapters_with_format(limits, backend, format)?,
            read_buffer: vec![0; BUFFER],
            event_data: Vec::with_capacity(BUFFER),
        })
    }

    /// Produces the next structural event with bounded backpressure.
    pub async fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        #[allow(clippy::large_enum_variant)]
        enum OwnedEvent {
            NeedInput,
            ArchiveMetadata(ArchiveMetadata),
            Entry(EntryMetadata),
            Data,
            EndEntry,
            Done,
        }

        loop {
            let event = match self.pipeline.poll_event().map_err(StreamError::archive)? {
                PipelineEvent::NeedInput => OwnedEvent::NeedInput,
                PipelineEvent::ArchiveMetadata(meta) => OwnedEvent::ArchiveMetadata(meta),
                PipelineEvent::Entry(meta) => OwnedEvent::Entry(meta),
                PipelineEvent::Data(data) => {
                    self.event_data.clear();
                    self.event_data.extend_from_slice(data);
                    OwnedEvent::Data
                },
                PipelineEvent::EndEntry => OwnedEvent::EndEntry,
                PipelineEvent::Done => OwnedEvent::Done,
            };

            match event {
                OwnedEvent::NeedInput => {
                    let capacity = self.pipeline.feed_capacity().min(self.read_buffer.len());
                    if capacity == 0 {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_context("pipeline requested input without capacity"),
                        ));
                    }
                    let buffer = &mut self.read_buffer[..capacity];
                    let read = poll_fn(|cx| self.reader.poll_read(cx, buffer))
                        .await
                        .map_err(StreamError::io)?;
                    if read == 0 {
                        self.pipeline.finish_input().map_err(StreamError::archive)?;
                    } else {
                        let accepted = self
                            .pipeline
                            .feed(&self.read_buffer[..read])
                            .map_err(StreamError::archive)?;
                        if accepted != read {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_context("pipeline accepted a partial async read"),
                            ));
                        }
                    }
                },
                OwnedEvent::ArchiveMetadata(meta) => {
                    return Ok(ReaderEvent::ArchiveMetadata(meta));
                },
                OwnedEvent::Entry(meta) => return Ok(ReaderEvent::Entry(meta)),
                OwnedEvent::Data => return Ok(ReaderEvent::Data(&self.event_data)),
                OwnedEvent::EndEntry => return Ok(ReaderEvent::EndEntry),
                OwnedEvent::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    /// Returns the wrapped asynchronous input when ownership is recoverable.
    ///
    /// # Errors
    ///
    /// Returns a protocol error if codec construction failed after consuming
    /// ownership of an inner adapter.
    pub fn into_inner(self) -> Result<R, ArchiveError> {
        self.reader.into_inner()
    }

    /// Detected format, once the first archive event is available.
    #[must_use]
    pub const fn format(&self) -> Option<FormatId> {
        self.pipeline.format()
    }
}

/// Runtime-neutral asynchronous archive writer.
///
/// Drop and cancellation never synthesize a tar trailer. Call [`Self::finish`]
/// explicitly or use [`Self::abort`] to recover an intentionally incomplete
/// destination.
#[derive(Debug)]
pub struct AsyncArchiveWriter<W> {
    output: AsyncFilterWriter<W>,
    encoder: RuntimeEncoder,
    format: FormatId,
    buffer: Vec<u8>,
    failed: bool,
}

impl<W: AsyncWrite + Unpin> AsyncArchiveWriter<W> {
    /// Creates a sequential asynchronous tar writer.
    #[must_use]
    pub fn new(output: W) -> Self {
        Self {
            output: AsyncFilterWriter::Plain(output),
            encoder: RuntimeEncoder::tar(Limits::default()),
            format: FormatId::Tar,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a sequential asynchronous writer for an explicit format.
    pub fn with_format(output: W, format: FormatId) -> Result<Self, ArchiveError> {
        Self::with_format_and_limits(output, format, Limits::default())
    }

    /// Creates an asynchronous writer with explicit format and limits.
    pub fn with_format_and_limits(
        output: W,
        format: FormatId,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Ok(Self {
            output: AsyncFilterWriter::Plain(output),
            encoder: RuntimeEncoder::sequential(format, limits)?,
            format,
            buffer: vec![0; BUFFER],
            failed: false,
        })
    }

    /// Creates a sequential asynchronous ZIP writer with an explicit method.
    pub fn with_zip_method(output: W, method: ZipMethod, limits: Limits) -> Self {
        Self::with_zip_method_and_backend(output, method, limits, BackendPreference::Auto)
    }

    /// Creates an asynchronous ZIP writer with an explicit codec backend.
    #[must_use]
    pub fn with_zip_method_and_backend(
        output: W,
        method: ZipMethod,
        limits: Limits,
        backend: BackendPreference,
    ) -> Self {
        Self {
            output: AsyncFilterWriter::Plain(output),
            encoder: RuntimeEncoder::zip_with_backend(limits, method, backend),
            format: FormatId::Zip,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a sequential asynchronous cpio writer for an explicit dialect.
    pub fn with_cpio_dialect(output: W, dialect: CpioDialect, limits: Limits) -> Self {
        Self {
            output: AsyncFilterWriter::Plain(output),
            encoder: RuntimeEncoder::cpio(limits, dialect),
            format: FormatId::Cpio,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a streaming asynchronous `WinZip` AES-256 AE-2 writer.
    #[cfg(feature = "aes")]
    pub fn with_zip_password(
        output: W,
        method: ZipMethod,
        password: SecretBytes,
        limits: Limits,
    ) -> Self {
        Self::with_zip_password_and_backend(
            output,
            method,
            password,
            limits,
            BackendPreference::Auto,
        )
    }

    /// Creates an encrypted asynchronous ZIP writer with a codec backend.
    #[cfg(feature = "aes")]
    #[must_use]
    pub fn with_zip_password_and_backend(
        output: W,
        method: ZipMethod,
        password: SecretBytes,
        limits: Limits,
        backend: BackendPreference,
    ) -> Self {
        Self {
            output: AsyncFilterWriter::Plain(output),
            encoder: RuntimeEncoder::encrypted_zip_with_backend(limits, method, password, backend),
            format: FormatId::Zip,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates an asynchronous writer with an optional outer filter.
    pub fn with_filter(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::with_filter_and_backend(output, format, filter, limits, BackendPreference::Auto)
    }

    /// Creates an asynchronous writer with an outer filter and codec backend.
    pub fn with_filter_and_backend(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
        backend: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        Ok(Self {
            output: AsyncFilterWriter::with_backend(output, filter, backend)?,
            encoder: RuntimeEncoder::sequential_with_backend(format, limits, backend)?,
            format,
            buffer: vec![0; BUFFER],
            failed: false,
        })
    }

    fn ensure_live(&self) -> Result<(), StreamError> {
        if self.failed {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive writer is poisoned by an earlier I/O error"),
            ));
        }
        Ok(())
    }

    /// Sets archive-level metadata before the first entry.
    pub fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        self.encoder
            .set_archive_metadata(metadata)
            .map_err(StreamError::archive)
    }

    async fn write_output(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut produced = bytes.len();
        let mut offset = 0;
        while produced != 0 {
            let output = &mut self.output;
            let chunk = &bytes[offset..offset + produced];
            let written = match poll_fn(|cx| Pin::new(&mut *output).poll_write(cx, chunk)).await {
                Ok(0) => {
                    self.failed = true;
                    return Err(StreamError::io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "asynchronous archive destination made no progress",
                    )));
                },
                Ok(written) => written,
                Err(error) => {
                    self.failed = true;
                    return Err(StreamError::io(error));
                },
            };
            offset += written;
            produced -= written;
        }
        Ok(())
    }

    async fn emit(&mut self, produced: usize) -> Result<(), StreamError> {
        if produced == 0 {
            return Ok(());
        }
        let bytes = self.buffer[..produced].to_vec();
        self.write_output(&bytes).await
    }

    async fn finish_filter(&mut self) -> Result<(), StreamError> {
        poll_fn(|cx| self.output.poll_finish(cx))
            .await
            .map_err(StreamError::io)
    }

    /// Begins an entry. Tar requires a declared size.
    pub async fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        metadata.validate().map_err(StreamError::archive)?;
        loop {
            let step = self
                .encoder
                .step(EncodeCommand::BeginEntry(metadata), &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced).await?;
            if step.consumed == 1 {
                return Ok(());
            }
            if step.produced == 0 && !matches!(step.status, EncodeStatus::NeedOutput) {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder did not accept begin-entry"),
                ));
            }
        }
    }

    /// Writes entry body bytes with bounded backpressure.
    pub async fn write_data(&mut self, mut data: &[u8]) -> Result<(), StreamError> {
        self.ensure_live()?;
        while !data.is_empty() {
            let step = self
                .encoder
                .step(EncodeCommand::Data(data), &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced).await?;
            data = &data[step.consumed..];
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder made no async write progress"),
                ));
            }
        }
        Ok(())
    }

    /// Ends the current entry and verifies its declared size.
    pub async fn end_entry(&mut self) -> Result<(), StreamError> {
        self.ensure_live()?;
        loop {
            let step = self
                .encoder
                .step(EncodeCommand::EndEntry, &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced).await?;
            if step.consumed == 1 {
                return Ok(());
            }
            if step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder did not accept end-entry"),
                ));
            }
        }
    }

    /// Finishes the archive and returns its destination.
    pub async fn finish(mut self) -> Result<W, StreamError> {
        self.ensure_live()?;
        loop {
            let step = self
                .encoder
                .step(EncodeCommand::Finish, &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced).await?;
            if matches!(step.status, EncodeStatus::Done) {
                self.finish_filter().await?;
                return Ok(self.output.into_inner());
            }
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder made no async finish progress"),
                ));
            }
        }
    }

    /// Recovers the destination without completing the archive.
    #[must_use]
    pub fn abort(self) -> W {
        self.output.into_inner()
    }

    /// Output archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }
}
