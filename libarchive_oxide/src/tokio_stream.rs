// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokio poll shims over the runtime-neutral asynchronous archive adapters.

use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use cap_std::fs::Dir;
use futures_io::{AsyncRead as FuturesRead, AsyncSeek as FuturesSeek, AsyncWrite as FuturesWrite};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use crate::async_seek::{AsyncSeekArchiveReader, AsyncSeekArchiveWriter};
use crate::async_stream::{AsyncArchiveReader, AsyncArchiveWriter};
use crate::extractor::{ExtractionMessage, run_extraction_worker};
use crate::{ExtractionPolicy, ExtractionReport, ReaderEvent, StreamError};
#[cfg(feature = "aes")]
use crate::{SecretBytes, ZipMethod};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, CpioDialect, EntryMetadata, FormatId, Limits,
};

/// Converts Tokio I/O traits into the runtime-neutral futures-io traits.
#[derive(Debug)]
pub struct TokioIo<T> {
    inner: T,
    seek_started: bool,
}

impl<T> TokioIo<T> {
    /// Wraps a Tokio I/O object.
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            seek_started: false,
        }
    }

    /// Returns the wrapped object.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> FuturesRead for TokioIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buffer = ReadBuf::new(output);
        match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> FuturesWrite for TokioIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncSeek + Unpin> FuturesSeek for TokioIo<T> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        if !self.seek_started {
            if let Err(error) = Pin::new(&mut self.inner).start_seek(position) {
                return Poll::Ready(Err(error));
            }
            self.seek_started = true;
        }
        match Pin::new(&mut self.inner).poll_complete(cx) {
            Poll::Ready(result) => {
                self.seek_started = false;
                Poll::Ready(result)
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Tokio archive reader backed by the shared sans-I/O pipeline.
#[derive(Debug)]
pub struct TokioArchiveReader<R>(AsyncArchiveReader<TokioIo<R>>);

impl<R: AsyncRead + Unpin> TokioArchiveReader<R> {
    /// Creates a Tokio reader with safe default limits.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self(AsyncArchiveReader::new(TokioIo::new(reader)))
    }

    /// Creates a Tokio reader with explicit limits.
    #[must_use]
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self(AsyncArchiveReader::with_limits(
            TokioIo::new(reader),
            limits,
        ))
    }

    /// Produces the next structural event.
    pub async fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.0.next_event().await
    }

    /// Returns the wrapped Tokio input.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.0.into_inner().into_inner()
    }
}

/// Tokio reader for ZIP, 7z, and ISO 9660 sources with async seek capability.
#[derive(Debug)]
pub struct TokioSeekArchiveReader<R>(AsyncSeekArchiveReader<TokioIo<R>>);

impl<R: AsyncRead + AsyncSeek + Unpin> TokioSeekArchiveReader<R> {
    /// Opens a seek-required archive with safe default limits.
    pub async fn new(reader: R) -> Result<Self, StreamError> {
        AsyncSeekArchiveReader::new(TokioIo::new(reader))
            .await
            .map(Self)
    }

    /// Opens a seek-required archive with explicit limits.
    pub async fn with_limits(reader: R, limits: Limits) -> Result<Self, StreamError> {
        AsyncSeekArchiveReader::with_limits(TokioIo::new(reader), limits)
            .await
            .map(Self)
    }

    /// Opens an encrypted seek archive with a zeroizing password.
    #[cfg(feature = "aes")]
    pub async fn with_limits_and_password(
        reader: R,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        AsyncSeekArchiveReader::with_limits_and_password(TokioIo::new(reader), limits, password)
            .await
            .map(Self)
    }

    /// Produces the next structural event.
    pub async fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.0.next_event().await
    }

    /// Skips the currently open payload.
    pub async fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.0.skip_entry().await
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.0.format()
    }

    /// Returns the Tokio input.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.0.into_inner().into_inner()
    }
}

/// Tokio archive writer backed by the shared tar encoder.
#[derive(Debug)]
pub struct TokioArchiveWriter<W>(AsyncArchiveWriter<TokioIo<W>>);

impl<W: AsyncWrite + Unpin> TokioArchiveWriter<W> {
    /// Creates a Tokio tar writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self(AsyncArchiveWriter::new(TokioIo::new(writer)))
    }

    /// Creates a Tokio writer for an explicit sequential format.
    pub fn with_format(writer: W, format: FormatId) -> Result<Self, ArchiveError> {
        AsyncArchiveWriter::with_format(TokioIo::new(writer), format).map(Self)
    }

    /// Creates a Tokio writer with an optional outer filter.
    pub fn with_filter(
        writer: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        AsyncArchiveWriter::with_filter(TokioIo::new(writer), format, filter, limits).map(Self)
    }

    /// Creates a Tokio cpio writer for an explicit header dialect.
    #[must_use]
    pub fn with_cpio_dialect(writer: W, dialect: CpioDialect, limits: Limits) -> Self {
        Self(AsyncArchiveWriter::with_cpio_dialect(
            TokioIo::new(writer),
            dialect,
            limits,
        ))
    }

    /// Creates a streaming Tokio `WinZip` AES-256 AE-2 writer.
    #[cfg(feature = "aes")]
    #[must_use]
    pub fn with_zip_password(
        writer: W,
        method: ZipMethod,
        password: SecretBytes,
        limits: Limits,
    ) -> Self {
        Self(AsyncArchiveWriter::with_zip_password(
            TokioIo::new(writer),
            method,
            password,
            limits,
        ))
    }

    /// Begins an entry.
    pub async fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.0.start_entry(metadata).await
    }

    /// Sets archive-level metadata before the first entry.
    pub fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), StreamError> {
        self.0.set_archive_metadata(metadata)
    }

    /// Writes body bytes.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), StreamError> {
        self.0.write_data(data).await
    }

    /// Ends the current entry.
    pub async fn end_entry(&mut self) -> Result<(), StreamError> {
        self.0.end_entry().await
    }

    /// Finishes the archive and returns its destination.
    pub async fn finish(self) -> Result<W, StreamError> {
        self.0.finish().await.map(TokioIo::into_inner)
    }

    /// Recovers the destination without completing the archive.
    #[must_use]
    pub fn abort(self) -> W {
        self.0.abort().into_inner()
    }
}

/// Tokio writer for every seek and sequential archive format.
#[derive(Debug)]
pub struct TokioSeekArchiveWriter<W>(AsyncSeekArchiveWriter<TokioIo<W>>);

impl<W: AsyncWrite + AsyncSeek + Unpin> TokioSeekArchiveWriter<W> {
    /// Creates a writer for an explicit format.
    pub async fn with_format(
        writer: W,
        format: FormatId,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        AsyncSeekArchiveWriter::with_format(TokioIo::new(writer), format, limits)
            .await
            .map(Self)
    }

    /// Sets archive-level metadata before the first entry.
    pub async fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        self.0.set_archive_metadata(metadata).await
    }

    /// Begins an entry.
    pub async fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.0.start_entry(metadata).await
    }

    /// Writes entry body bytes.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), StreamError> {
        self.0.write_data(data).await
    }

    /// Ends the current entry.
    pub async fn end_entry(&mut self) -> Result<(), StreamError> {
        self.0.end_entry().await
    }

    /// Finishes the archive and returns its Tokio destination.
    pub async fn finish(self) -> Result<W, StreamError> {
        self.0.finish().await.map(TokioIo::into_inner)
    }

    /// Recovers the destination without completing the archive.
    #[must_use]
    pub fn abort(self) -> W {
        self.0.abort().into_inner()
    }
}

/// Secure Tokio extraction adapter.
///
/// Archive reads remain asynchronous. Capability-based filesystem operations
/// run on one blocking worker behind a bounded channel, so neither the Tokio
/// executor nor memory grows with archive size.
#[derive(Debug)]
pub struct TokioExtractor {
    root: Dir,
    policy: ExtractionPolicy,
    limits: Limits,
}

impl TokioExtractor {
    /// Creates a safe-policy extractor rooted at a directory capability.
    #[must_use]
    pub fn new(root: Dir) -> Self {
        Self::with_policy_and_limits(root, ExtractionPolicy::safe(), Limits::default())
    }

    /// Creates an extractor with an explicit restore policy.
    #[must_use]
    pub const fn with_policy(root: Dir, policy: ExtractionPolicy) -> Self {
        Self::with_policy_and_limits(root, policy, Limits::safe())
    }

    /// Creates a safe-policy extractor with explicit resource budgets.
    #[must_use]
    pub const fn with_limits(root: Dir, limits: Limits) -> Self {
        Self::with_policy_and_limits(root, ExtractionPolicy::safe(), limits)
    }

    /// Creates an extractor with explicit policy and resource budgets.
    #[must_use]
    pub const fn with_policy_and_limits(
        root: Dir,
        policy: ExtractionPolicy,
        limits: Limits,
    ) -> Self {
        Self {
            root,
            policy,
            limits,
        }
    }

    /// Returns the resource budgets enforced by this extractor.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Extracts from a sequential Tokio archive reader.
    pub async fn extract<R: AsyncRead + Unpin>(
        self,
        reader: &mut TokioArchiveReader<R>,
    ) -> Result<ExtractionReport, StreamError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        let worker = tokio::task::spawn_blocking(move || {
            run_extraction_worker(self.root, self.policy, self.limits, receiver)
        });
        produce_extraction(sender, reader, worker).await
    }

    /// Extracts from a seek-capable Tokio archive reader.
    pub async fn extract_seek<R: AsyncRead + AsyncSeek + Unpin>(
        self,
        reader: &mut TokioSeekArchiveReader<R>,
    ) -> Result<ExtractionReport, StreamError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        let worker = tokio::task::spawn_blocking(move || {
            run_extraction_worker(self.root, self.policy, self.limits, receiver)
        });
        produce_seek_extraction(sender, reader, worker).await
    }
}

async fn produce_extraction<R: AsyncRead + Unpin>(
    sender: tokio::sync::mpsc::Sender<ExtractionMessage>,
    reader: &mut TokioArchiveReader<R>,
    worker: tokio::task::JoinHandle<Result<ExtractionReport, StreamError>>,
) -> Result<ExtractionReport, StreamError> {
    let mut worker = Some(worker);
    loop {
        let event = match reader.next_event().await {
            Ok(event) => event,
            Err(error) => {
                drop(sender);
                let _ = join_extraction_worker(worker.take()).await;
                return Err(error);
            },
        };
        let Some((message, done)) = owned_extraction_message(event) else {
            continue;
        };
        if sender.send(message).await.is_err() {
            return join_extraction_worker(worker.take()).await;
        }
        if done {
            drop(sender);
            return join_extraction_worker(worker.take()).await;
        }
    }
}

async fn produce_seek_extraction<R: AsyncRead + AsyncSeek + Unpin>(
    sender: tokio::sync::mpsc::Sender<ExtractionMessage>,
    reader: &mut TokioSeekArchiveReader<R>,
    worker: tokio::task::JoinHandle<Result<ExtractionReport, StreamError>>,
) -> Result<ExtractionReport, StreamError> {
    let mut worker = Some(worker);
    loop {
        let event = match reader.next_event().await {
            Ok(event) => event,
            Err(error) => {
                drop(sender);
                let _ = join_extraction_worker(worker.take()).await;
                return Err(error);
            },
        };
        let Some((message, done)) = owned_extraction_message(event) else {
            continue;
        };
        if sender.send(message).await.is_err() {
            return join_extraction_worker(worker.take()).await;
        }
        if done {
            drop(sender);
            return join_extraction_worker(worker.take()).await;
        }
    }
}

fn owned_extraction_message(event: ReaderEvent<'_>) -> Option<(ExtractionMessage, bool)> {
    match event {
        ReaderEvent::ArchiveMetadata(_) => None,
        ReaderEvent::Entry(metadata) => Some((ExtractionMessage::Entry(Box::new(metadata)), false)),
        ReaderEvent::Data(bytes) => Some((ExtractionMessage::Data(bytes.to_vec()), false)),
        ReaderEvent::EndEntry => Some((ExtractionMessage::EndEntry, false)),
        ReaderEvent::Done => Some((ExtractionMessage::Done, true)),
    }
}

async fn join_extraction_worker(
    worker: Option<tokio::task::JoinHandle<Result<ExtractionReport, StreamError>>>,
) -> Result<ExtractionReport, StreamError> {
    let worker = worker.ok_or_else(|| {
        StreamError::io(io::Error::other(
            "Tokio extraction worker was already joined",
        ))
    })?;
    worker.await.map_err(|error| {
        StreamError::io(io::Error::other(format!(
            "Tokio extraction worker failed: {error}",
        )))
    })?
}
