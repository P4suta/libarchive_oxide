// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral asynchronous adapters for seek-required archive formats.
//!
//! Parsing remains in the synchronous seek state machine. A demand reader
//! exposes only cached ranges to that parser and turns cache misses into
//! bounded asynchronous seek/read operations. The writer records seek/write
//! operations and drains them before returning from each public command.

use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, EntryMetadata, ErrorKind, FormatId, Limits,
};

use crate::{ReaderEvent, SecretBytes, SeekArchiveReader, SeekArchiveWriter, StreamError};

const BUFFER: usize = 64 * 1024;

#[derive(Debug)]
struct DemandState {
    length: u64,
    demand: Option<(u64, usize)>,
    cache: BTreeMap<u64, Vec<u8>>,
    cached_bytes: usize,
    cache_limit: Option<usize>,
    read_ahead: usize,
}

#[derive(Debug, Clone)]
struct DemandReader {
    shared: Arc<Mutex<DemandState>>,
    position: u64,
}

impl DemandReader {
    fn new(length: u64, limits: Limits) -> Self {
        Self {
            shared: Arc::new(Mutex::new(DemandState {
                length,
                demand: None,
                cache: BTreeMap::new(),
                cached_bytes: 0,
                cache_limit: limits.metadata_bytes(),
                read_ahead: limits
                    .in_flight_bytes()
                    .map_or(BUFFER * 2, |limit| limit.min(BUFFER * 2))
                    .max(1),
            })),
            position: 0,
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, DemandState>> {
        self.shared
            .lock()
            .map_err(|_| io::Error::other("async seek demand cache was poisoned"))
    }

    fn take_demand(&self) -> io::Result<Option<(u64, usize)>> {
        Ok(self.lock()?.demand.take())
    }

    fn insert(&self, offset: u64, bytes: Vec<u8>) -> Result<(), StreamError> {
        let mut state = self.lock().map_err(StreamError::io)?;
        let previous = state.cache.get(&offset).map_or(0, Vec::len);
        let next = state
            .cached_bytes
            .checked_sub(previous)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_context("async seek cache accounting overflow"),
                )
            })?;
        if state.cache_limit.is_some_and(|limit| next > limit) {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_context("async seek cache exceeds metadata budget"),
            ));
        }
        state.cache.insert(offset, bytes);
        state.cached_bytes = next;
        Ok(())
    }

    fn clear_cache(&self) -> Result<(), StreamError> {
        let mut state = self.lock().map_err(StreamError::io)?;
        state.cache.clear();
        state.cached_bytes = 0;
        state.demand = None;
        Ok(())
    }
}

impl Read for DemandReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut state = self.lock()?;
        if self.position >= state.length {
            return Ok(0);
        }
        let available = usize::try_from((state.length - self.position).min(output.len() as u64))
            .unwrap_or(output.len());
        if let Some((&start, bytes)) = state.cache.range(..=self.position).next_back() {
            let relative = usize::try_from(self.position - start)
                .map_err(|_| io::Error::other("async seek cache offset exceeds usize"))?;
            if relative
                .checked_add(available)
                .is_some_and(|end| end <= bytes.len())
            {
                output[..available].copy_from_slice(&bytes[relative..relative + available]);
                drop(state);
                self.position += available as u64;
                return Ok(available);
            }
        }
        state.demand = Some((self.position, available));
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "async seek input range is not cached",
        ))
    }
}

impl Seek for DemandReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let length = self.lock()?.length;
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => length.checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek position overflow"))?;
        self.position = next;
        Ok(next)
    }
}

/// Runtime-neutral async reader for ZIP, 7z, and ISO 9660.
#[derive(Debug)]
pub struct AsyncSeekArchiveReader<R> {
    input: R,
    reader: SeekArchiveReader<DemandReader>,
    demand: DemandReader,
    event_data: Vec<u8>,
}

impl<R: AsyncRead + AsyncSeek + Unpin> AsyncSeekArchiveReader<R> {
    /// Opens a seek archive with safe default limits.
    pub async fn new(input: R) -> Result<Self, StreamError> {
        Self::with_limits(input, Limits::default()).await
    }

    /// Opens a seek archive with explicit resource limits.
    pub async fn with_limits(mut input: R, limits: Limits) -> Result<Self, StreamError> {
        let length = poll_fn(|context| Pin::new(&mut input).poll_seek(context, SeekFrom::End(0)))
            .await
            .map_err(StreamError::io)?;
        let demand = DemandReader::new(length, limits);
        let reader = loop {
            match SeekArchiveReader::with_limits(demand.clone(), limits) {
                Ok(reader) => break reader,
                Err(error) if is_demand(&error) => {
                    fulfill(&mut input, &demand).await?;
                },
                Err(error) => return Err(error),
            }
        };
        demand.clear_cache()?;
        Ok(Self {
            input,
            reader,
            demand,
            event_data: Vec::with_capacity(BUFFER),
        })
    }

    /// Opens an encrypted seek archive with a zeroizing password.
    pub async fn with_limits_and_password(
        mut input: R,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        let length = poll_fn(|context| Pin::new(&mut input).poll_seek(context, SeekFrom::End(0)))
            .await
            .map_err(StreamError::io)?;
        let demand = DemandReader::new(length, limits);
        let reader = loop {
            match SeekArchiveReader::with_limits_and_password(
                demand.clone(),
                limits,
                password.clone(),
            ) {
                Ok(reader) => break reader,
                Err(error) if is_demand(&error) => {
                    fulfill(&mut input, &demand).await?;
                },
                Err(error) => return Err(error),
            }
        };
        demand.clear_cache()?;
        Ok(Self {
            input,
            reader,
            demand,
            event_data: Vec::with_capacity(BUFFER),
        })
    }

    /// Produces the next structural event with bounded payload buffering.
    pub async fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        enum OwnedEvent {
            ArchiveMetadata(ArchiveMetadata),
            Entry(Box<EntryMetadata>),
            Data,
            EndEntry,
            Done,
        }

        loop {
            let event = match self.reader.next_event() {
                Ok(ReaderEvent::ArchiveMetadata(metadata)) => OwnedEvent::ArchiveMetadata(metadata),
                Ok(ReaderEvent::Entry(metadata)) => OwnedEvent::Entry(Box::new(metadata)),
                Ok(ReaderEvent::Data(bytes)) => {
                    self.event_data.clear();
                    self.event_data.extend_from_slice(bytes);
                    OwnedEvent::Data
                },
                Ok(ReaderEvent::EndEntry) => OwnedEvent::EndEntry,
                Ok(ReaderEvent::Done) => OwnedEvent::Done,
                Err(error) if is_demand(&error) => {
                    fulfill(&mut self.input, &self.demand).await?;
                    continue;
                },
                Err(error) => return Err(error),
            };
            self.demand.clear_cache()?;
            return Ok(match event {
                OwnedEvent::ArchiveMetadata(metadata) => ReaderEvent::ArchiveMetadata(metadata),
                OwnedEvent::Entry(metadata) => ReaderEvent::Entry(*metadata),
                OwnedEvent::Data => ReaderEvent::Data(&self.event_data),
                OwnedEvent::EndEntry => ReaderEvent::EndEntry,
                OwnedEvent::Done => ReaderEvent::Done,
            });
        }
    }

    /// Skips the currently open payload.
    pub async fn skip_entry(&mut self) -> Result<(), StreamError> {
        loop {
            match self.reader.skip_entry() {
                Ok(()) => {
                    self.demand.clear_cache()?;
                    return Ok(());
                },
                Err(error) if is_demand(&error) => {
                    fulfill(&mut self.input, &self.demand).await?;
                },
                Err(error) => return Err(error),
            }
        }
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.reader.format()
    }

    /// Returns the asynchronous input.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.input
    }
}

fn is_demand(error: &StreamError) -> bool {
    error
        .io_error()
        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
}

async fn fulfill<R: AsyncRead + AsyncSeek + Unpin>(
    input: &mut R,
    demand: &DemandReader,
) -> Result<(), StreamError> {
    let (offset, requested) = demand
        .take_demand()
        .map_err(StreamError::io)?
        .ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("seek parser blocked without requesting a range"),
            )
        })?;
    let (length, cache_limit) = {
        let state = demand.lock().map_err(StreamError::io)?;
        let remaining = usize::try_from(state.length.saturating_sub(offset)).unwrap_or(usize::MAX);
        let desired = requested.max(state.read_ahead).min(remaining);
        (
            state
                .cache_limit
                .map_or(desired, |limit| desired.min(limit.max(requested))),
            state.cache_limit,
        )
    };
    if cache_limit.is_some_and(|limit| requested > limit) {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_context("async seek request exceeds configured cache budget"),
        ));
    }
    poll_fn(|context| Pin::new(&mut *input).poll_seek(context, SeekFrom::Start(offset)))
        .await
        .map_err(StreamError::io)?;
    let mut bytes = vec![0; length];
    let mut filled = 0;
    while filled != length {
        let read =
            poll_fn(|context| Pin::new(&mut *input).poll_read(context, &mut bytes[filled..]))
                .await
                .map_err(StreamError::io)?;
        if read == 0 {
            return Err(StreamError::io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "seek archive range ended early",
            )));
        }
        filled += read;
    }
    demand.insert(offset, bytes)
}

#[derive(Debug)]
enum WriteOperation {
    Seek(u64),
    Write(Vec<u8>),
}

#[derive(Debug, Default)]
struct OperationQueue {
    operations: VecDeque<WriteOperation>,
    bytes: usize,
}

#[derive(Debug)]
struct OperationWriter {
    queue: Arc<Mutex<OperationQueue>>,
    position: u64,
    length: u64,
    queue_limit: Option<usize>,
}

impl OperationWriter {
    fn new(limits: Limits) -> (Self, Arc<Mutex<OperationQueue>>) {
        let queue = Arc::new(Mutex::new(OperationQueue::default()));
        (
            Self {
                queue: Arc::clone(&queue),
                position: 0,
                length: 0,
                queue_limit: match (limits.metadata_bytes(), limits.in_flight_bytes()) {
                    (Some(metadata), Some(in_flight)) => Some(metadata.max(in_flight)),
                    (Some(limit), None) | (None, Some(limit)) => Some(limit),
                    (None, None) => None,
                },
            },
            queue,
        )
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, OperationQueue>> {
        self.queue
            .lock()
            .map_err(|_| io::Error::other("async seek operation queue was poisoned"))
    }
}

impl Write for OperationWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_position = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("async seek output position overflow"))?;
        {
            let mut queue = self.lock()?;
            let next = queue
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("async seek queue accounting overflow"))?;
            if self.queue_limit.is_some_and(|limit| next > limit) {
                return Err(io::Error::other(
                    "async seek output queue exceeds configured budget",
                ));
            }
            queue
                .operations
                .push_back(WriteOperation::Write(bytes.to_vec()));
            queue.bytes = next;
        }
        self.position = next_position;
        self.length = self.length.max(self.position);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for OperationWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek position overflow"))?;
        self.lock()?
            .operations
            .push_back(WriteOperation::Seek(next));
        self.position = next;
        Ok(next)
    }
}

/// Runtime-neutral async writer for every seek and sequential format.
#[derive(Debug)]
pub struct AsyncSeekArchiveWriter<W> {
    output: W,
    writer: Option<SeekArchiveWriter<OperationWriter>>,
    queue: Arc<Mutex<OperationQueue>>,
    failed: bool,
}

impl<W: AsyncWrite + AsyncSeek + Unpin> AsyncSeekArchiveWriter<W> {
    /// Creates a writer and applies any initial seek/write operations.
    pub async fn with_format(
        output: W,
        format: FormatId,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        let (operation_writer, queue) = OperationWriter::new(limits);
        let writer = SeekArchiveWriter::with_format(operation_writer, format, limits)?;
        let mut this = Self {
            output,
            writer: Some(writer),
            queue,
            failed: false,
        };
        this.flush_operations().await?;
        Ok(this)
    }

    fn writer(&mut self) -> Result<&mut SeekArchiveWriter<OperationWriter>, StreamError> {
        if self.failed {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("async seek writer is poisoned by an I/O failure"),
            ));
        }
        self.writer.as_mut().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("async seek writer was already finalized"),
            )
        })
    }

    async fn flush_operations(&mut self) -> Result<(), StreamError> {
        loop {
            let operation = {
                let mut queue = self.queue.lock().map_err(|_| {
                    StreamError::io(io::Error::other("async seek operation queue was poisoned"))
                })?;
                let operation = queue.operations.pop_front();
                if let Some(WriteOperation::Write(bytes)) = &operation {
                    queue.bytes = queue.bytes.saturating_sub(bytes.len());
                }
                operation
            };
            let Some(operation) = operation else {
                return Ok(());
            };
            let result = match operation {
                WriteOperation::Seek(position) => poll_fn(|context| {
                    Pin::new(&mut self.output).poll_seek(context, SeekFrom::Start(position))
                })
                .await
                .map(|_| ()),
                WriteOperation::Write(bytes) => {
                    async {
                        let mut offset = 0;
                        while offset != bytes.len() {
                            let written = poll_fn(|context| {
                                Pin::new(&mut self.output).poll_write(context, &bytes[offset..])
                            })
                            .await?;
                            if written == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "async seek destination made no progress",
                                ));
                            }
                            offset += written;
                        }
                        Ok(())
                    }
                    .await
                },
            };
            if let Err(error) = result {
                self.failed = true;
                return Err(StreamError::io(error));
            }
        }
    }

    /// Sets archive-level metadata before the first entry.
    pub async fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        self.writer()?.set_archive_metadata(metadata)?;
        self.flush_operations().await
    }

    /// Begins one entry.
    pub async fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.writer()?.start_entry(metadata)?;
        self.flush_operations().await
    }

    /// Writes body bytes in bounded chunks.
    pub async fn write_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        if bytes.is_empty() {
            self.writer()?.write_data(bytes)?;
            return self.flush_operations().await;
        }
        for chunk in bytes.chunks(BUFFER) {
            self.writer()?.write_data(chunk)?;
            self.flush_operations().await?;
        }
        Ok(())
    }

    /// Ends the current entry.
    pub async fn end_entry(&mut self) -> Result<(), StreamError> {
        self.writer()?.end_entry()?;
        self.flush_operations().await
    }

    /// Finishes the archive and returns the asynchronous destination.
    pub async fn finish(mut self) -> Result<W, StreamError> {
        let writer = self.writer.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("async seek writer was already finalized"),
            )
        })?;
        writer.finish()?;
        self.flush_operations().await?;
        poll_fn(|context| Pin::new(&mut self.output).poll_flush(context))
            .await
            .map_err(StreamError::io)?;
        Ok(self.output)
    }

    /// Recovers the destination without synthesizing terminal metadata.
    #[must_use]
    pub fn abort(mut self) -> W {
        self.writer.take();
        if let Ok(mut queue) = self.queue.lock() {
            queue.operations.clear();
            queue.bytes = 0;
        }
        self.output
    }
}
