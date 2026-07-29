// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable random-access sources for seek-required archive formats.
//!
//! A [`ReadAt`] source can be backed by an object store, an HTTP range endpoint,
//! or application-owned storage. The adapter presents it to the existing
//! [`SeekArchiveReader`] state machine, so remote inputs do not have a separate
//! archive parser or an implicit whole-input spool.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use libarchive_oxide_core::{ArchiveError, FormatId, Limits};

use crate::{ReaderEvent, SecretBytes, SeekArchiveReader, StreamError};

const DEFAULT_READ_AHEAD: usize = 128 * 1024;
const DEFAULT_MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_VOLUMES: u32 = 256;
const DEFAULT_MAX_VOLUME_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const MAX_SOURCE_IDENTITY_BYTES: usize = 1024;
static NEXT_FILE_IDENTITY: AtomicU64 = AtomicU64::new(1);

/// Opaque identity for one immutable source version.
///
/// Providers should use a strong version identifier such as a generation,
/// version ID, or `ETag` that cannot be reused for different bytes.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SourceIdentity(Vec<u8>);

impl SourceIdentity {
    /// Validates an opaque identity from provider-owned bytes.
    ///
    /// Empty identities cannot prove immutability. The finite byte cap also
    /// prevents an untrusted transport header from becoming an unbounded clone
    /// at every source-validation boundary.
    pub fn try_new(identity: impl Into<Vec<u8>>) -> Result<Self, SourceIdentityError> {
        let identity = identity.into();
        match identity.len() {
            0 => Err(SourceIdentityError::Empty),
            length if length > MAX_SOURCE_IDENTITY_BYTES => Err(SourceIdentityError::TooLong {
                length,
                maximum: MAX_SOURCE_IDENTITY_BYTES,
            }),
            _ => Ok(Self(identity)),
        }
    }

    /// Returns the opaque identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Heap bytes retained by this cloned identity inside composite readers.
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.0.capacity()
    }
}

impl TryFrom<Vec<u8>> for SourceIdentity {
    type Error = SourceIdentityError;

    fn try_from(identity: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(identity)
    }
}

/// Validation failure for an immutable source identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceIdentityError {
    /// The identity was empty.
    Empty,
    /// The identity exceeded the fixed allocation cap.
    TooLong {
        /// Supplied identity length.
        length: usize,
        /// Maximum accepted identity length.
        maximum: usize,
    },
}

impl fmt::Display for SourceIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("source identity must not be empty"),
            Self::TooLong { length, maximum } => write!(
                formatter,
                "source identity is {length} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl Error for SourceIdentityError {}

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
    /// Number of provider `read_at` calls.
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
            .ok_or_else(|| RangeReadError::new(RangeReadErrorKind::MetricsOverflow))?;
        Ok(())
    }

    #[cfg(feature = "async")]
    pub(crate) fn record_bytes(&mut self, bytes: usize) -> Result<(), RangeReadError> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| RangeReadError::new(RangeReadErrorKind::MetricsOverflow))?;
        self.transferred_bytes = self
            .transferred_bytes
            .checked_add(bytes)
            .ok_or_else(|| RangeReadError::new(RangeReadErrorKind::MetricsOverflow))?;
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
            .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::MetricsOverflow)))
    }

    fn record_bytes(&self, bytes: usize) -> io::Result<()> {
        let bytes = usize_to_u64(bytes)?;
        self.transferred_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(bytes)
            })
            .map(|_| ())
            .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::MetricsOverflow)))
    }
}

/// Stable classification for failures detected at a random-access boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RangeReadErrorKind {
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
    /// A source exceeded its configured encoded-size budget.
    SourceSizeExceeded,
    /// More distinct volumes were requested than the configured budget.
    VolumeCountExceeded,
    /// The sum of resolved volume lengths exceeded the configured budget.
    VolumeBytesExceeded,
    /// A required volume was not supplied by the resolver.
    MissingVolume,
    /// A synchronized seek adapter could no longer access its reader.
    SourceUnavailable,
}

/// Protocol failure with stable offset, volume, and limit context.
///
/// The error is stored inside [`io::Error`] and can be recovered with
/// [`io::Error::get_ref`] followed by `downcast_ref::<RangeReadError>()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeReadError {
    kind: RangeReadErrorKind,
    offset: Option<u64>,
    requested: Option<u64>,
    volume: Option<VolumeId>,
    declared: Option<u64>,
    limit: Option<u64>,
}

impl RangeReadError {
    pub(crate) const fn new(kind: RangeReadErrorKind) -> Self {
        Self {
            kind,
            offset: None,
            requested: None,
            volume: None,
            declared: None,
            limit: None,
        }
    }

    const fn at(mut self, offset: u64, requested: u64) -> Self {
        self.offset = Some(offset);
        self.requested = Some(requested);
        self
    }

    const fn for_volume(mut self, volume: VolumeId) -> Self {
        self.volume = Some(volume);
        self
    }

    const fn with_budget(mut self, declared: u64, limit: u64) -> Self {
        self.declared = Some(declared);
        self.limit = Some(limit);
        self
    }

    /// Stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RangeReadErrorKind {
        self.kind
    }

    /// Byte offset and requested length, when the failure addressed a range.
    #[must_use]
    pub const fn range(self) -> Option<(u64, u64)> {
        match (self.offset, self.requested) {
            (Some(offset), Some(requested)) => Some((offset, requested)),
            _ => None,
        }
    }

    /// Logical volume associated with the failure.
    #[must_use]
    pub const fn volume(self) -> Option<VolumeId> {
        self.volume
    }

    /// Observed value and configured maximum for a limit failure.
    #[must_use]
    pub const fn budget(self) -> Option<(u64, u64)> {
        match (self.declared, self.limit) {
            (Some(declared), Some(limit)) => Some((declared, limit)),
            _ => None,
        }
    }
}

impl fmt::Display for RangeReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RangeReadErrorKind::IdentityChanged => "random-access source identity changed",
            RangeReadErrorKind::LengthChanged => "random-access source length changed",
            RangeReadErrorKind::OffsetOutOfBounds => "random-access source offset is out of bounds",
            RangeReadErrorKind::OffsetOverflow => {
                "random-access source offset arithmetic overflowed"
            },
            RangeReadErrorKind::NoProgress => "random-access source made no progress",
            RangeReadErrorKind::ShortRead => {
                "random-access source ended before its declared length"
            },
            RangeReadErrorKind::InvalidReadCount => {
                "random-access source returned an invalid byte count"
            },
            RangeReadErrorKind::MetricsOverflow => "random-access source metrics overflowed",
            RangeReadErrorKind::CacheBudgetExceeded => {
                "random-access request exceeds the configured cache budget"
            },
            RangeReadErrorKind::SourceSizeExceeded => {
                "random-access source exceeds the configured size budget"
            },
            RangeReadErrorKind::VolumeCountExceeded => {
                "multi-volume source exceeds the configured volume-count budget"
            },
            RangeReadErrorKind::VolumeBytesExceeded => {
                "multi-volume source exceeds the configured total-byte budget"
            },
            RangeReadErrorKind::MissingVolume => "required archive volume is unavailable",
            RangeReadErrorKind::SourceUnavailable => "random-access source is no longer available",
        })?;
        if let Some(volume) = self.volume {
            write!(formatter, " (volume {})", volume.get())?;
        }
        if let Some((offset, requested)) = self.range() {
            write!(formatter, " (offset {offset}, requested {requested} bytes)")?;
        }
        if let Some((declared, limit)) = self.budget() {
            write!(formatter, " (observed {declared}, limit {limit})")?;
        }
        Ok(())
    }
}

impl Error for RangeReadError {}

/// Finite-by-default budgets for encoded random-access sources and volumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLimits {
    source_bytes: Option<u64>,
    volumes: Option<u32>,
    volume_bytes: Option<u64>,
}

impl SourceLimits {
    /// Safe defaults: 64 GiB per source, 256 volumes, and 256 GiB total.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            source_bytes: Some(DEFAULT_MAX_SOURCE_BYTES),
            volumes: Some(DEFAULT_MAX_VOLUMES),
            volume_bytes: Some(DEFAULT_MAX_VOLUME_BYTES),
        }
    }

    /// Removes configurable budgets. Arithmetic and protocol checks remain.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            source_bytes: None,
            volumes: None,
            volume_bytes: None,
        }
    }

    /// Maximum declared length of one encoded source.
    #[must_use]
    pub const fn source_bytes(self) -> Option<u64> {
        self.source_bytes
    }

    /// Maximum number of distinct logical volumes, including volume zero.
    #[must_use]
    pub const fn volumes(self) -> Option<u32> {
        self.volumes
    }

    /// Maximum sum of declared lengths for all resolved volumes.
    #[must_use]
    pub const fn volume_bytes(self) -> Option<u64> {
        self.volume_bytes
    }

    /// Replaces the per-source encoded-size budget.
    #[must_use]
    pub const fn with_source_bytes(mut self, value: Option<u64>) -> Self {
        self.source_bytes = value;
        self
    }

    /// Replaces the distinct-volume budget.
    #[must_use]
    pub const fn with_volumes(mut self, value: Option<u32>) -> Self {
        self.volumes = value;
        self
    }

    /// Replaces the total encoded bytes across resolved volumes.
    #[must_use]
    pub const fn with_volume_bytes(mut self, value: Option<u64>) -> Self {
        self.volume_bytes = value;
        self
    }
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self::safe()
    }
}

/// Immutable, thread-safe random-access byte source.
///
/// Implementations may return short chunks. Returning zero before the end of
/// the declared object is treated as a truncated or non-progressing source.
///
/// The trait is object-safe so applications can use `Arc<dyn ReadAt>` without
/// exposing a source-specific type in their archive integration.
pub trait ReadAt: Send + Sync {
    /// Declared byte length for this source version.
    fn len(&self) -> u64;

    /// Whether this source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Opaque immutable identity for this source version.
    fn identity(&self) -> &SourceIdentity;

    /// Reads bytes beginning at `offset` into `output`.
    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize>;

    /// Fills `output` from an exact range with overflow and progress checks.
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let requested = u64::try_from(output.len())
            .map_err(|_| range_error_at(RangeReadErrorKind::OffsetOverflow, offset, u64::MAX))?;
        let end = offset
            .checked_add(requested)
            .ok_or_else(|| range_error_at(RangeReadErrorKind::OffsetOverflow, offset, requested))?;
        if end > self.len() {
            return Err(range_error_at(
                RangeReadErrorKind::OffsetOutOfBounds,
                offset,
                requested,
            ));
        }

        let mut filled = 0_usize;
        while filled != output.len() {
            let filled_u64 = usize_to_u64(filled)?;
            let remaining = usize_to_u64(output.len() - filled)?;
            let read_offset = offset.checked_add(filled_u64).ok_or_else(|| {
                range_error_at(RangeReadErrorKind::OffsetOverflow, offset, requested)
            })?;
            let read = match self.read_at(read_offset, &mut output[filled..]) {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(range_error_at(
                        RangeReadErrorKind::ShortRead,
                        read_offset,
                        remaining,
                    ));
                },
                result => result?,
            };
            if read > output.len() - filled {
                return Err(range_error_at(
                    RangeReadErrorKind::InvalidReadCount,
                    read_offset,
                    remaining,
                ));
            }
            if read == 0 {
                return Err(range_error_at(
                    RangeReadErrorKind::NoProgress,
                    read_offset,
                    remaining,
                ));
            }
            filled += read;
        }
        Ok(())
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Arc<T> {
    fn len(&self) -> u64 {
        T::len(self)
    }

    fn identity(&self) -> &SourceIdentity {
        T::identity(self)
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        T::read_at(self, offset, output)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn len(&self) -> u64 {
        T::len(self)
    }

    fn identity(&self) -> &SourceIdentity {
        T::identity(self)
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        T::read_at(self, offset, output)
    }
}

/// Immutable in-memory [`ReadAt`] adapter.
#[derive(Clone, Debug)]
pub struct MemoryReadAt {
    bytes: Arc<[u8]>,
    identity: SourceIdentity,
}

impl MemoryReadAt {
    /// Copies bytes into an immutable source with a caller-owned identity.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>, identity: SourceIdentity) -> Self {
        Self {
            bytes: Arc::from(bytes.into()),
            identity,
        }
    }

    /// Wraps already shared immutable bytes without another byte copy.
    #[must_use]
    pub fn from_arc(bytes: Arc<[u8]>, identity: SourceIdentity) -> Self {
        Self { bytes, identity }
    }

    /// Returns the immutable bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReadAt for MemoryReadAt {
    fn len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let requested = usize_to_u64(output.len())?;
        let start = usize::try_from(offset)
            .map_err(|_| range_error_at(RangeReadErrorKind::OffsetOverflow, offset, requested))?;
        let available = self.bytes.get(start..).ok_or_else(|| {
            range_error_at(RangeReadErrorKind::OffsetOutOfBounds, offset, requested)
        })?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// Thread-safe positional adapter for a standard `Read + Seek` source.
#[derive(Debug)]
pub struct SeekReadAt<R> {
    source: Mutex<R>,
    identity: SourceIdentity,
    length: u64,
}

impl<R: Read + Seek> SeekReadAt<R> {
    /// Captures the current length and restores the source's original position.
    pub fn new(mut source: R, identity: SourceIdentity) -> io::Result<Self> {
        let position = source.stream_position()?;
        let length = source.seek(SeekFrom::End(0))?;
        source.seek(SeekFrom::Start(position))?;
        Ok(Self {
            source: Mutex::new(source),
            identity,
            length,
        })
    }

    /// Returns the wrapped reader when its lock is healthy.
    pub fn into_inner(self) -> io::Result<R> {
        self.source
            .into_inner()
            .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::SourceUnavailable)))
    }
}

impl<R: Read + Seek + Send> ReadAt for SeekReadAt<R> {
    fn len(&self) -> u64 {
        self.length
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let requested = usize_to_u64(output.len())?;
        if offset > self.length {
            return Err(range_error_at(
                RangeReadErrorKind::OffsetOutOfBounds,
                offset,
                requested,
            ));
        }
        let mut source = self
            .source
            .lock()
            .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::SourceUnavailable)))?;
        source.seek(SeekFrom::Start(offset))?;
        source.read(output)
    }
}

/// Positional [`File`] adapter with length and modification-time revalidation.
#[derive(Debug)]
pub struct FileReadAt {
    source: SeekReadAt<File>,
    metadata_handle: File,
    modified: Option<SystemTime>,
}

impl FileReadAt {
    /// Opens a file and captures a stable session identity plus metadata snapshot.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let sequence = NEXT_FILE_IDENTITY.fetch_add(1, Ordering::Relaxed);
        let identity = SourceIdentity::try_new(
            format!(
                "file-session-{sequence}:{}:{:?}",
                metadata.len(),
                metadata.modified().ok()
            )
            .into_bytes(),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Self::new(file, identity)
    }

    /// Wraps an open file with a transport- or application-owned identity.
    pub fn new(file: File, identity: SourceIdentity) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let metadata_handle = file.try_clone()?;
        Ok(Self {
            source: SeekReadAt::new(file, identity)?,
            metadata_handle,
            modified: metadata.modified().ok(),
        })
    }

    /// Returns the wrapped file.
    pub fn into_inner(self) -> io::Result<File> {
        self.source.into_inner()
    }

    fn validate_metadata(&self) -> io::Result<()> {
        let metadata = self.metadata_handle.metadata()?;
        if metadata.len() != self.source.len() {
            return Err(range_error(RangeReadError::new(
                RangeReadErrorKind::LengthChanged,
            )));
        }
        if metadata.modified().ok() != self.modified {
            return Err(range_error(RangeReadError::new(
                RangeReadErrorKind::IdentityChanged,
            )));
        }
        Ok(())
    }
}

impl ReadAt for FileReadAt {
    fn len(&self) -> u64 {
        self.source.len()
    }

    fn identity(&self) -> &SourceIdentity {
        self.source.identity()
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        self.validate_metadata()?;
        let read = self.source.read_at(offset, output)?;
        self.validate_metadata()?;
        Ok(read)
    }
}

/// Zero-based logical volume identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VolumeId(u32);

impl VolumeId {
    /// Creates a logical volume identifier. Volume zero is the primary source.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the zero-based logical index.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Application-owned resolver for additional archive volumes.
///
/// Resolver implementations perform no parsing. They map a format provider's
/// logical volume request to an immutable random-access source.
pub trait VolumeResolver: Send + Sync {
    /// Resolves an additional volume, or returns `None` when it is unavailable.
    fn resolve(&self, volume: VolumeId) -> io::Result<Option<Arc<dyn ReadAt>>>;
}

#[derive(Default)]
struct VolumeState {
    resolved: BTreeMap<VolumeId, Option<Arc<dyn ReadAt>>>,
    total_bytes: u64,
}

/// Validated, bounded source set supplied to a multi-volume format provider.
pub struct VolumeSet {
    primary: Arc<dyn ReadAt>,
    resolver: Arc<dyn VolumeResolver>,
    limits: SourceLimits,
    state: Mutex<VolumeState>,
}

impl fmt::Debug for VolumeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let resolved = self.state.lock().map_or(0, |state| state.resolved.len());
        formatter
            .debug_struct("VolumeSet")
            .field("primary_identity", self.primary.identity())
            .field("limits", &self.limits)
            .field("resolved", &resolved)
            .finish_non_exhaustive()
    }
}

impl VolumeSet {
    /// Creates a bounded volume set. Volume zero always resolves to `primary`.
    pub fn new(
        primary: Arc<dyn ReadAt>,
        resolver: Arc<dyn VolumeResolver>,
        limits: SourceLimits,
    ) -> io::Result<Self> {
        validate_source_length(primary.len(), limits, Some(VolumeId::new(0)))?;
        if limits.volumes().is_some_and(|limit| limit == 0) {
            return Err(range_error(
                RangeReadError::new(RangeReadErrorKind::VolumeCountExceeded).with_budget(1, 0),
            ));
        }
        if limits
            .volume_bytes()
            .is_some_and(|limit| primary.len() > limit)
        {
            return Err(range_error(
                RangeReadError::new(RangeReadErrorKind::VolumeBytesExceeded)
                    .for_volume(VolumeId::new(0))
                    .with_budget(primary.len(), limits.volume_bytes().unwrap_or(0)),
            ));
        }
        Ok(Self {
            primary,
            resolver,
            limits,
            state: Mutex::new(VolumeState {
                resolved: BTreeMap::new(),
                total_bytes: 0,
            }),
        })
    }

    /// Returns the primary volume.
    #[must_use]
    pub fn primary(&self) -> Arc<dyn ReadAt> {
        Arc::clone(&self.primary)
    }

    /// Resolves and caches a logical volume while enforcing all source budgets.
    pub fn resolve(&self, volume: VolumeId) -> io::Result<Option<Arc<dyn ReadAt>>> {
        if volume.get() == 0 {
            return Ok(Some(self.primary()));
        }

        {
            let state = self.lock_state()?;
            if let Some(cached) = state.resolved.get(&volume) {
                return Ok(cached.clone());
            }
            let observed = u32::try_from(state.resolved.len())
                .unwrap_or(u32::MAX)
                .saturating_add(2);
            if self.limits.volumes().is_some_and(|limit| observed > limit) {
                return Err(range_error(
                    RangeReadError::new(RangeReadErrorKind::VolumeCountExceeded)
                        .for_volume(volume)
                        .with_budget(
                            u64::from(observed),
                            u64::from(self.limits.volumes().unwrap_or(0)),
                        ),
                ));
            }
        }

        let resolved = self.resolver.resolve(volume)?;
        let resolved_length = resolved.as_ref().map(ReadAt::len);
        if let Some(length) = resolved_length {
            validate_source_length(length, self.limits, Some(volume))?;
        }

        let mut state = self.lock_state()?;
        if let Some(cached) = state.resolved.get(&volume) {
            return Ok(cached.clone());
        }
        let observed = u32::try_from(state.resolved.len())
            .unwrap_or(u32::MAX)
            .saturating_add(2);
        if self.limits.volumes().is_some_and(|limit| observed > limit) {
            return Err(range_error(
                RangeReadError::new(RangeReadErrorKind::VolumeCountExceeded)
                    .for_volume(volume)
                    .with_budget(
                        u64::from(observed),
                        u64::from(self.limits.volumes().unwrap_or(0)),
                    ),
            ));
        }
        if let Some(length) = resolved_length {
            let total = self
                .primary
                .len()
                .checked_add(state.total_bytes)
                .and_then(|value| value.checked_add(length))
                .ok_or_else(|| {
                    range_error(
                        RangeReadError::new(RangeReadErrorKind::VolumeBytesExceeded)
                            .for_volume(volume),
                    )
                })?;
            if self
                .limits
                .volume_bytes()
                .is_some_and(|limit| total > limit)
            {
                return Err(range_error(
                    RangeReadError::new(RangeReadErrorKind::VolumeBytesExceeded)
                        .for_volume(volume)
                        .with_budget(total, self.limits.volume_bytes().unwrap_or(0)),
                ));
            }
            state.total_bytes = state.total_bytes.checked_add(length).ok_or_else(|| {
                range_error(
                    RangeReadError::new(RangeReadErrorKind::VolumeBytesExceeded).for_volume(volume),
                )
            })?;
        }
        state.resolved.insert(volume, resolved.clone());
        Ok(resolved)
    }

    /// Resolves a required volume and preserves its identifier in typed context.
    pub fn resolve_required(&self, volume: VolumeId) -> io::Result<Arc<dyn ReadAt>> {
        self.resolve(volume)?.ok_or_else(|| {
            range_error(RangeReadError::new(RangeReadErrorKind::MissingVolume).for_volume(volume))
        })
    }

    fn lock_state(&self) -> io::Result<std::sync::MutexGuard<'_, VolumeState>> {
        self.state
            .lock()
            .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::SourceUnavailable)))
    }
}

/// `Read + Seek` adapter over an immutable [`ReadAt`].
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

impl<S: ReadAt> RangeReader<S> {
    /// Creates an adapter with safe default resource limits.
    pub fn new(source: S) -> io::Result<Self> {
        Self::with_limits(source, Limits::default())
    }

    /// Creates an adapter with explicit cache and read-ahead limits.
    pub fn with_limits(source: S, limits: Limits) -> io::Result<Self> {
        Self::with_source_limits(source, limits, SourceLimits::default())
    }

    /// Creates an adapter with explicit archive and encoded-source limits.
    pub fn with_source_limits(
        source: S,
        limits: Limits,
        source_limits: SourceLimits,
    ) -> io::Result<Self> {
        let identity = source.identity().clone();
        let length = source.len();
        validate_source_length(length, source_limits, None)?;
        let cache_limit = limits.metadata_bytes();
        let read_ahead = limits
            .in_flight_bytes()
            .map_or(DEFAULT_READ_AHEAD, |limit| limit.min(DEFAULT_READ_AHEAD))
            .max(1);
        Ok(Self {
            source,
            identity,
            length,
            position: 0,
            cache_offset: 0,
            cache: Vec::new(),
            cache_limit,
            read_ahead,
            metrics: MetricTracker::default(),
        })
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
        validate_read_at_snapshot(&self.source, &self.identity, self.length)
    }

    fn fill_cache(&mut self, requested: usize) -> io::Result<()> {
        let requested_u64 = usize_to_u64(requested)?;
        self.validate_source()?;
        if self.position >= self.length {
            return Err(range_error_at(
                RangeReadErrorKind::OffsetOutOfBounds,
                self.position,
                requested_u64,
            ));
        }
        if self.cache_limit.is_some_and(|limit| requested > limit) {
            return Err(range_error(
                RangeReadError::new(RangeReadErrorKind::CacheBudgetExceeded)
                    .at(self.position, requested_u64)
                    .with_budget(requested_u64, usize_to_u64(self.cache_limit.unwrap_or(0))?),
            ));
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
            let filled_u64 = usize_to_u64(filled)?;
            let remaining_u64 = usize_to_u64(length - filled)?;
            self.validate_source()?;
            let offset = self.cache_offset.checked_add(filled_u64).ok_or_else(|| {
                range_error_at(
                    RangeReadErrorKind::OffsetOverflow,
                    self.cache_offset,
                    filled_u64,
                )
            })?;
            self.metrics.record_request()?;
            let read = match self.source.read_at(offset, &mut self.cache[filled..]) {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(range_error_at(
                        RangeReadErrorKind::ShortRead,
                        offset,
                        remaining_u64,
                    ));
                },
                result => result?,
            };
            if read > length - filled {
                return Err(range_error_at(
                    RangeReadErrorKind::InvalidReadCount,
                    offset,
                    remaining_u64,
                ));
            }
            if read == 0 {
                return Err(range_error_at(
                    RangeReadErrorKind::NoProgress,
                    offset,
                    remaining_u64,
                ));
            }
            self.metrics.record_bytes(read)?;
            filled += read;
            self.validate_source()?;
        }
        Ok(())
    }
}

impl<S: ReadAt> Read for RangeReader<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let requested = usize_to_u64(output.len())?;
        if output.is_empty() {
            return Ok(0);
        }
        self.validate_source()?;
        if self.position == self.length {
            return Ok(0);
        }
        if self.position > self.length {
            return Err(range_error_at(
                RangeReadErrorKind::OffsetOutOfBounds,
                self.position,
                requested,
            ));
        }
        let available =
            usize::try_from((self.length - self.position).min(requested)).unwrap_or(output.len());
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
        let available_u64 = usize_to_u64(available)?;
        self.position = self.position.checked_add(available_u64).ok_or_else(|| {
            range_error_at(
                RangeReadErrorKind::OffsetOverflow,
                self.position,
                available_u64,
            )
        })?;
        Ok(available)
    }
}

impl<S: ReadAt> Seek for RangeReader<S> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.validate_source()?;
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
        }
        .ok_or_else(|| range_error_at(RangeReadErrorKind::OffsetOverflow, self.position, 0))?;
        if next > self.length {
            return Err(range_error_at(
                RangeReadErrorKind::OffsetOutOfBounds,
                next,
                0,
            ));
        }
        self.position = next;
        Ok(next)
    }
}

/// Seek-format archive reader backed by an immutable range source.
#[derive(Debug)]
pub struct RangeArchiveReader<S: ReadAt> {
    reader: SeekArchiveReader<RangeReader<S>>,
    identity: SourceIdentity,
    metrics: MetricTracker,
}

impl<S: ReadAt> RangeArchiveReader<S> {
    /// Opens a range-backed archive with safe default limits.
    pub fn new(source: S) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::default())
    }

    /// Opens a range-backed archive with explicit limits.
    pub fn with_limits(source: S, limits: Limits) -> Result<Self, StreamError> {
        let input = RangeReader::with_limits(source, limits).map_err(StreamError::io)?;
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
        let input = RangeReader::with_limits(source, limits).map_err(StreamError::io)?;
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

    /// Returns the range source when ownership is recoverable.
    ///
    /// # Errors
    ///
    /// Returns a protocol error if a seek decoder lost its source while
    /// switching an incremental decode graph.
    pub fn into_inner(self) -> Result<S, ArchiveError> {
        Ok(self.reader.into_inner()?.into_inner())
    }

    fn validate_source(&self) -> Result<(), StreamError> {
        self.reader
            .with_source(RangeReader::validate_source)
            .map_err(StreamError::archive)?
            .map_err(StreamError::io)
    }
}

pub(crate) fn validate_source_length(
    length: u64,
    limits: SourceLimits,
    volume: Option<VolumeId>,
) -> io::Result<()> {
    let Some(limit) = limits.source_bytes() else {
        return Ok(());
    };
    if length <= limit {
        return Ok(());
    }
    let mut error =
        RangeReadError::new(RangeReadErrorKind::SourceSizeExceeded).with_budget(length, limit);
    if let Some(volume) = volume {
        error = error.for_volume(volume);
    }
    Err(range_error(error))
}

/// Confirms that a caller-held immutable-source snapshot still identifies the
/// same bytes and declared extent. Composite format adapters use this at every
/// lazy read boundary just as [`RangeReader`] does for a single source.
pub(crate) fn validate_read_at_snapshot(
    source: &dyn ReadAt,
    identity: &SourceIdentity,
    length: u64,
) -> io::Result<()> {
    if source.identity() != identity {
        return Err(range_error(RangeReadError::new(
            RangeReadErrorKind::IdentityChanged,
        )));
    }
    if source.len() != length {
        return Err(range_error(RangeReadError::new(
            RangeReadErrorKind::LengthChanged,
        )));
    }
    Ok(())
}

fn range_error_at(kind: RangeReadErrorKind, offset: u64, requested: u64) -> io::Error {
    range_error(RangeReadError::new(kind).at(offset, requested))
}

pub(crate) fn usize_to_u64(value: usize) -> io::Result<u64> {
    u64::try_from(value)
        .map_err(|_| range_error(RangeReadError::new(RangeReadErrorKind::OffsetOverflow)))
}

pub(crate) fn range_error(error: RangeReadError) -> io::Error {
    let kind = match error.kind() {
        RangeReadErrorKind::OffsetOutOfBounds | RangeReadErrorKind::OffsetOverflow => {
            io::ErrorKind::InvalidInput
        },
        RangeReadErrorKind::ShortRead | RangeReadErrorKind::NoProgress => {
            io::ErrorKind::UnexpectedEof
        },
        RangeReadErrorKind::IdentityChanged | RangeReadErrorKind::LengthChanged => {
            io::ErrorKind::InvalidData
        },
        RangeReadErrorKind::MissingVolume => io::ErrorKind::NotFound,
        RangeReadErrorKind::SourceSizeExceeded
        | RangeReadErrorKind::VolumeCountExceeded
        | RangeReadErrorKind::VolumeBytesExceeded => io::ErrorKind::FileTooLarge,
        RangeReadErrorKind::InvalidReadCount
        | RangeReadErrorKind::MetricsOverflow
        | RangeReadErrorKind::CacheBudgetExceeded
        | RangeReadErrorKind::SourceUnavailable => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}
