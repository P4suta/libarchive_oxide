// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral asynchronous immutable range sources.
//!
//! The async provider only supplies bytes. Parsing is performed by the same
//! synchronous [`crate::SeekArchiveReader`] state machine used for local files
//! and synchronous range sources.

use std::io;

use libarchive_oxide_core::{ArchiveMetadata, EntryMetadata, FormatId, Limits};

use crate::async_seek::{DemandReader, is_demand};
use crate::range_source::{RangeMetrics, RangeReadError, SourceIdentity, range_error};
use crate::{ReaderEvent, SecretBytes, SeekArchiveReader, StreamError};

const BUFFER: usize = 64 * 1024;

/// Runtime-neutral asynchronous immutable random-access byte source.
///
/// This trait uses static dispatch and intentionally has no HTTP or cloud SDK
/// dependency. Implementations may return short chunks.
#[allow(async_fn_in_trait)]
pub trait AsyncRangeSource {
    /// Declared byte length for this source version.
    fn len(&self) -> u64;

    /// Whether this source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Opaque immutable identity for this source version.
    fn identity(&self) -> &SourceIdentity;

    /// Reads bytes beginning at `offset` into `output`.
    async fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize>;
}

/// Async range reader for ZIP, 7z, and ISO 9660.
#[derive(Debug)]
pub struct AsyncRangeArchiveReader<S: AsyncRangeSource> {
    source: S,
    reader: SeekArchiveReader<DemandReader>,
    demand: DemandReader,
    identity: SourceIdentity,
    length: u64,
    metrics: RangeMetrics,
    event_data: Vec<u8>,
}

impl<S: AsyncRangeSource> AsyncRangeArchiveReader<S> {
    /// Opens a range-backed archive with safe default limits.
    pub async fn new(source: S) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::default()).await
    }

    /// Opens a range-backed archive with explicit limits.
    pub async fn with_limits(mut source: S, limits: Limits) -> Result<Self, StreamError> {
        let identity = source.identity().clone();
        let length = source.len();
        let demand = DemandReader::new(length, limits);
        let mut metrics = RangeMetrics::default();
        let reader = loop {
            match SeekArchiveReader::with_limits(demand.clone(), limits) {
                Ok(reader) => break reader,
                Err(error) if is_demand(&error) => {
                    fulfill(&mut source, &demand, &identity, length, &mut metrics).await?;
                },
                Err(error) => return Err(error),
            }
        };
        demand.clear_cache()?;
        validate_source(&source, &identity, length)?;
        Ok(Self {
            source,
            reader,
            demand,
            identity,
            length,
            metrics,
            event_data: Vec::with_capacity(BUFFER),
        })
    }

    /// Opens an encrypted archive with explicit limits and password.
    pub async fn with_limits_and_password(
        mut source: S,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        let identity = source.identity().clone();
        let length = source.len();
        let demand = DemandReader::new(length, limits);
        let mut metrics = RangeMetrics::default();
        let reader = loop {
            match SeekArchiveReader::with_limits_and_password(
                demand.clone(),
                limits,
                password.clone(),
            ) {
                Ok(reader) => break reader,
                Err(error) if is_demand(&error) => {
                    fulfill(&mut source, &demand, &identity, length, &mut metrics).await?;
                },
                Err(error) => return Err(error),
            }
        };
        demand.clear_cache()?;
        validate_source(&source, &identity, length)?;
        Ok(Self {
            source,
            reader,
            demand,
            identity,
            length,
            metrics,
            event_data: Vec::with_capacity(BUFFER),
        })
    }

    /// Opens an encrypted archive with safe default limits.
    pub async fn with_password(source: S, password: SecretBytes) -> Result<Self, StreamError> {
        Self::with_limits_and_password(source, Limits::default(), password).await
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

        validate_source(&self.source, &self.identity, self.length)?;
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
                    fulfill(
                        &mut self.source,
                        &self.demand,
                        &self.identity,
                        self.length,
                        &mut self.metrics,
                    )
                    .await?;
                    continue;
                },
                Err(error) => return Err(error),
            };
            self.demand.clear_cache()?;
            validate_source(&self.source, &self.identity, self.length)?;
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
        validate_source(&self.source, &self.identity, self.length)?;
        loop {
            match self.reader.skip_entry() {
                Ok(()) => {
                    self.demand.clear_cache()?;
                    validate_source(&self.source, &self.identity, self.length)?;
                    return Ok(());
                },
                Err(error) if is_demand(&error) => {
                    fulfill(
                        &mut self.source,
                        &self.demand,
                        &self.identity,
                        self.length,
                        &mut self.metrics,
                    )
                    .await?;
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

    /// Captured immutable source identity.
    #[must_use]
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    /// Exact provider I/O metrics.
    #[must_use]
    pub const fn metrics(&self) -> RangeMetrics {
        self.metrics
    }

    /// Returns the asynchronous range source.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.source
    }
}

fn validate_source<S: AsyncRangeSource>(
    source: &S,
    identity: &SourceIdentity,
    length: u64,
) -> Result<(), StreamError> {
    if source.identity() != identity {
        return Err(StreamError::io(range_error(
            RangeReadError::IdentityChanged,
        )));
    }
    if source.len() != length {
        return Err(StreamError::io(range_error(RangeReadError::LengthChanged)));
    }
    Ok(())
}

async fn fulfill<S: AsyncRangeSource>(
    source: &mut S,
    demand: &DemandReader,
    identity: &SourceIdentity,
    length: u64,
    metrics: &mut RangeMetrics,
) -> Result<(), StreamError> {
    let (offset, fetch_length) = demand.take_fetch_request()?;
    validate_source(source, identity, length)?;
    let end = offset
        .checked_add(fetch_length as u64)
        .ok_or_else(|| StreamError::io(range_error(RangeReadError::OffsetOverflow)))?;
    if end > length {
        return Err(StreamError::io(range_error(
            RangeReadError::OffsetOutOfBounds,
        )));
    }

    let mut bytes = vec![0; fetch_length];
    let mut filled = 0;
    while filled != fetch_length {
        validate_source(source, identity, length)?;
        let request_offset = offset
            .checked_add(filled as u64)
            .ok_or_else(|| StreamError::io(range_error(RangeReadError::OffsetOverflow)))?;
        metrics
            .record_request()
            .map_err(|error| StreamError::io(range_error(error)))?;
        let read = match source
            .read_range(request_offset, &mut bytes[filled..])
            .await
        {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(StreamError::io(range_error(RangeReadError::ShortRead)));
            },
            Err(error) => return Err(StreamError::io(error)),
            Ok(read) => read,
        };
        if read > fetch_length - filled {
            return Err(StreamError::io(range_error(
                RangeReadError::InvalidReadCount,
            )));
        }
        if read == 0 {
            return Err(StreamError::io(range_error(RangeReadError::NoProgress)));
        }
        metrics
            .record_bytes(read)
            .map_err(|error| StreamError::io(range_error(error)))?;
        filled += read;
        validate_source(source, identity, length)?;
    }
    demand.insert(offset, bytes)
}
