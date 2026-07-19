// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable random-access sources for seek-required archive formats.
//!
//! A [`RangeSource`] can be backed by an object store, an HTTP range endpoint,
//! or application-owned storage. The adapter presents it to the existing
//! [`SeekArchiveReader`] state machine, so remote inputs do not have a separate
//! archive parser.

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use libarchive_oxide_core::{FormatId, Limits};

use crate::{ReaderEvent, SecretBytes, SeekArchiveReader, StreamError};

const DEFAULT_READ_AHEAD: usize = 128 * 1024;

/// Opaque identity for one immutable source version.
///
/// Providers should use a strong version identifier such as a generation,
/// version ID, or `ETag` that cannot be reused for different bytes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SourceIdentity(Vec<u8>);

impl SourceIdentity {
    /// Creates an opaque identity from provider-owned bytes.
    #[must_use]
    pub fn new(identity: impl Into<Vec<u8>>) -> Self {
        Self(identity.into())
    }

    /// Returns the opaque identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceIdentity")
            .field("bytes", &format_args!("<redacted; {} bytes>", self.0.len()))
            .finish()
    }
}

/// Exact I/O accounting for range-backed archive reads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RangeMetrics {
    requests: u64,
    transferred_bytes: u64,
}

impl RangeMetrics {
    /// Number of provider `read_range` calls.
    #[must_use]
    pub const fn requests(self) -> u64 {
        self.requests
    }

    /// Bytes successfully returned by the provider.
    #[must_use]
    pub const fn transferred_bytes(self) -> u64 {
        self.transferred_bytes
    }

    #[cfg(feature = "async")]
    pub(crate) fn record_request(&mut self) -> Result<(), RangeReadError> {
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or(RangeReadError::MetricsOverflow)?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub(crate) fn record_bytes(&mut self, bytes: usize) -> Result<(), RangeReadError> {
        self.transferred_bytes = self
            .transferred_bytes
            .checked_add(bytes as u64)
            .ok_or(RangeReadError::MetricsOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct MetricTracker {
    requests: Arc<AtomicU64>,
    transferred_bytes: Arc<AtomicU64>,
}

impl MetricTracker {
    fn snapshot(&self) -> RangeMetrics {
        RangeMetrics {
            requests: self.requests.load(Ordering::Relaxed),
            transferred_bytes: self.transferred_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_request(&self) -> io::Result<()> {
        self.requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map(|_| ())
            .map_err(|_| range_error(RangeReadError::MetricsOverflow))
    }

    fn record_bytes(&self, bytes: usize) -> io::Result<()> {
        self.transferred_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(bytes as u64)
            })
            .map(|_| ())
            .map_err(|_| range_error(RangeReadError::MetricsOverflow))
    }
}

/// Protocol failures detected while adapting a range source.
///
/// The error is stored inside [`io::Error`] and can be recovered with
/// [`io::Error::get_ref`] followed by `downcast_ref::<RangeReadError>()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RangeReadError {
    /// The provider identity changed during the session.
    IdentityChanged,
    /// The provider-reported length changed during the session.
    LengthChanged,
    /// A seek or read addressed bytes outside the declared source.
    OffsetOutOfBounds,
    /// Offset arithmetic exceeded `u64` or the platform address space.
    OffsetOverflow,
    /// The provider returned zero before the requested range was complete.
    NoProgress,
    /// The source ended before its declared length.
    ShortRead,
    /// The provider claimed to return more bytes than the supplied buffer.
    InvalidReadCount,
    /// Exact request or transferred-byte accounting overflowed.
    MetricsOverflow,
    /// A parser request exceeded the configured cache budget.
    CacheBudgetExceeded,
}

impl fmt::Display for RangeReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityChanged => "range source identity changed",
            Self::LengthChanged => "range source length changed",
            Self::OffsetOutOfBounds => "range source offset is out of bounds",
            Self::OffsetOverflow => "range source offset arithmetic overflowed",
            Self::NoProgress => "range source made no progress",
            Self::ShortRead => "range source ended before its declared length",
            Self::InvalidReadCount => "range source returned an invalid byte count",
            Self::MetricsOverflow => "range source metrics overflowed",
            Self::CacheBudgetExceeded => "range request exceeds the configured cache budget",
        })
    }
}

impl Error for RangeReadError {}

/// Immutable, random-access byte source.
///
/// Implementations may return short chunks. Returning zero before the end of
/// the declared object is treated as a truncated or non-progressing source.
pub trait RangeSource {
    /// Declared byte length for this source version.
    fn len(&self) -> u64;

    /// Whether this source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Opaque immutable identity for this source version.
    fn identity(&self) -> &SourceIdentity;

    /// Reads bytes beginning at `offset` into `output`.
    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize>;
}

/// `Read + Seek` adapter over an immutable [`RangeSource`].
#[derive(Debug)]
pub struct RangeReader<S> {
    source: S,
    identity: SourceIdentity,
    length: u64,
    position: u64,
    cache_offset: u64,
    cache: Vec<u8>,
    cache_limit: Option<usize>,
    read_ahead: usize,
    metrics: MetricTracker,
}

impl<S: RangeSource> RangeReader<S> {
    /// Creates an adapter with safe default resource limits.
    #[must_use]
    pub fn new(source: S) -> Self {
        Self::with_limits(source, Limits::default())
    }

    /// Creates an adapter with explicit cache and read-ahead limits.
    #[must_use]
    pub fn with_limits(source: S, limits: Limits) -> Self {
        let identity = source.identity().clone();
        let length = source.len();
        let cache_limit = limits.metadata_bytes();
        let read_ahead = limits
            .in_flight_bytes()
            .map_or(DEFAULT_READ_AHEAD, |limit| limit.min(DEFAULT_READ_AHEAD))
            .max(1);
        Self {
            source,
            identity,
            length,
            position: 0,
            cache_offset: 0,
            cache: Vec::new(),
            cache_limit,
            read_ahead,
            metrics: MetricTracker::default(),
        }
    }

    /// Captured immutable identity.
    #[must_use]
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    /// Captured source length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Whether the captured source is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Exact provider I/O metrics.
    #[must_use]
    pub fn metrics(&self) -> RangeMetrics {
        self.metrics.snapshot()
    }

    /// Returns the source.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.source
    }

    fn validate_source(&self) -> io::Result<()> {
        if self.source.identity() != &self.identity {
            return Err(range_error(RangeReadError::IdentityChanged));
        }
        if self.source.len() != self.length {
            return Err(range_error(RangeReadError::LengthChanged));
        }
        Ok(())
    }

    fn fill_cache(&mut self, requested: usize) -> io::Result<()> {
        self.validate_source()?;
        if self.position >= self.length {
            return Err(range_error(RangeReadError::OffsetOutOfBounds));
        }
        if self.cache_limit.is_some_and(|limit| requested > limit) {
            return Err(range_error(RangeReadError::CacheBudgetExceeded));
        }
        let remaining = usize::try_from(self.length - self.position).unwrap_or(usize::MAX);
        let desired = requested.max(self.read_ahead).min(remaining);
        let length = self
            .cache_limit
            .map_or(desired, |limit| desired.min(limit.max(requested)));
        self.cache.clear();
        self.cache.resize(length, 0);
        self.cache_offset = self.position;

        let mut filled = 0;
        while filled != length {
            self.validate_source()?;
            let offset = self
                .cache_offset
                .checked_add(filled as u64)
                .ok_or_else(|| range_error(RangeReadError::OffsetOverflow))?;
            self.metrics.record_request()?;
            let read = match self.source.read_range(offset, &mut self.cache[filled..]) {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(range_error(RangeReadError::ShortRead));
                },
                result => result?,
            };
            if read > length - filled {
                return Err(range_error(RangeReadError::InvalidReadCount));
            }
            if read == 0 {
                return Err(range_error(RangeReadError::NoProgress));
            }
            self.metrics.record_bytes(read)?;
            filled += read;
            self.validate_source()?;
        }
        Ok(())
    }
}

impl<S: RangeSource> Read for RangeReader<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.validate_source()?;
        if self.position == self.length {
            return Ok(0);
        }
        if self.position > self.length {
            return Err(range_error(RangeReadError::OffsetOutOfBounds));
        }
        let available = usize::try_from((self.length - self.position).min(output.len() as u64))
            .unwrap_or(output.len());
        let cached = self
            .position
            .checked_sub(self.cache_offset)
            .and_then(|relative| {
                let relative = usize::try_from(relative).ok()?;
                let end = relative.checked_add(available)?;
                (end <= self.cache.len()).then_some(relative)
            });
        let relative = if let Some(relative) = cached {
            relative
        } else {
            self.fill_cache(available)?;
            0
        };
        output[..available].copy_from_slice(&self.cache[relative..relative + available]);
        self.position = self
            .position
            .checked_add(available as u64)
            .ok_or_else(|| range_error(RangeReadError::OffsetOverflow))?;
        Ok(available)
    }
}

impl<S: RangeSource> Seek for RangeReader<S> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.validate_source()?;
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
        }
        .ok_or_else(|| range_error(RangeReadError::OffsetOverflow))?;
        if next > self.length {
            return Err(range_error(RangeReadError::OffsetOutOfBounds));
        }
        self.position = next;
        Ok(next)
    }
}

/// Seek-format archive reader backed by an immutable range source.
#[derive(Debug)]
pub struct RangeArchiveReader<S: RangeSource> {
    reader: SeekArchiveReader<RangeReader<S>>,
    identity: SourceIdentity,
    metrics: MetricTracker,
}

impl<S: RangeSource> RangeArchiveReader<S> {
    /// Opens a range-backed archive with safe default limits.
    pub fn new(source: S) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::default())
    }

    /// Opens a range-backed archive with explicit limits.
    pub fn with_limits(source: S, limits: Limits) -> Result<Self, StreamError> {
        let input = RangeReader::with_limits(source, limits);
        let identity = input.identity().clone();
        let metrics = input.metrics.clone();
        Ok(Self {
            reader: SeekArchiveReader::with_limits(input, limits)?,
            identity,
            metrics,
        })
    }

    /// Opens an encrypted archive with a zeroizing password.
    pub fn with_password(source: S, password: SecretBytes) -> Result<Self, StreamError> {
        Self::with_limits_and_password(source, Limits::default(), password)
    }

    /// Opens an encrypted archive with explicit limits and password.
    pub fn with_limits_and_password(
        source: S,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        let input = RangeReader::with_limits(source, limits);
        let identity = input.identity().clone();
        let metrics = input.metrics.clone();
        Ok(Self {
            reader: SeekArchiveReader::with_limits_and_password(input, limits, password)?,
            identity,
            metrics,
        })
    }

    /// Produces the next archive event using the shared seek parser.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.validate_source()?;
        self.reader.next_event()
    }

    /// Skips the current payload.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.validate_source()?;
        self.reader.skip_entry()
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
    pub fn metrics(&self) -> RangeMetrics {
        self.metrics.snapshot()
    }

    /// Returns the range source.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.reader.into_inner().into_inner()
    }

    fn validate_source(&self) -> Result<(), StreamError> {
        self.reader
            .source_ref()
            .validate_source()
            .map_err(StreamError::io)
    }
}

pub(crate) fn range_error(error: RangeReadError) -> io::Error {
    let kind = match error {
        RangeReadError::OffsetOutOfBounds | RangeReadError::OffsetOverflow => {
            io::ErrorKind::InvalidInput
        },
        RangeReadError::ShortRead | RangeReadError::NoProgress => io::ErrorKind::UnexpectedEof,
        RangeReadError::IdentityChanged | RangeReadError::LengthChanged => {
            io::ErrorKind::InvalidData
        },
        RangeReadError::InvalidReadCount
        | RangeReadError::MetricsOverflow
        | RangeReadError::CacheBudgetExceeded => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}
