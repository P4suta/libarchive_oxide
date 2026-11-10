// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lazy seek view over application-owned split 7z volumes.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use libarchive_oxide_core::{AccessMode, ArchiveError, DirectionSet, ErrorKind, FormatId, Limits};

use crate::provider::FormatCapabilities;
use crate::range_source::{ReadAt, SourceIdentity, VolumeId, VolumeSet, validate_read_at_snapshot};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
use crate::{OpenOptions, ReaderEvent, SeekArchiveReader, StreamError};

const SIGNATURE: &[u8; 6] = b"7z\xbc\xaf'\x1c";

/// Built-in provider for byte-split 7z volume sets.
///
/// `VolumeId(0)` is the first physical segment and subsequent identifiers are concatenated in order until the resolver returns `None`.
/// Source-count and aggregate-byte limits are enforced by `VolumeSet`.
/// The provider performs no filename, filesystem, network, or registry discovery.
#[derive(Debug, Default)]
pub struct SevenZipVolumeProvider;

impl SevenZipVolumeProvider {
    /// Creates the stateless split-7z provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomAccessFormatProvider for SevenZipVolumeProvider {
    type Decoder = SevenZipVolumeReader;

    fn format(&self) -> FormatId {
        FormatId::SevenZip
    }

    fn name(&self) -> &'static str {
        "7z-volume"
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Seek)
    }

    fn probe(&self, source: &VolumeSet, _limits: Limits) -> Result<bool, StreamError> {
        let primary = source.primary();
        if primary.len() < u64::try_from(SIGNATURE.len()).unwrap_or(u64::MAX) {
            return Ok(false);
        }
        let mut signature = [0_u8; SIGNATURE.len()];
        primary.read_exact_at(0, &mut signature)?;
        Ok(&signature == SIGNATURE)
    }

    fn open(&self, source: Arc<VolumeSet>, limits: Limits) -> Result<Self::Decoder, StreamError> {
        SevenZipVolumeReader::with_limits(source.as_ref(), limits)
    }

    fn open_with_options(
        &self,
        source: Arc<VolumeSet>,
        options: &OpenOptions,
    ) -> Result<Self::Decoder, StreamError> {
        SevenZipVolumeReader::from_options(source.as_ref(), options)
    }
}

/// Seek-native reader over physical chunks of one byte-split 7z archive.
///
/// Opening resolves only source handles and builds a bounded extent table.
/// Payload and headers remain in the original immutable `ReadAt` sources and are fetched lazily as the ordinary 7z reader seeks across them.
pub struct SevenZipVolumeReader {
    inner: SeekArchiveReader<JoinedVolumeInput>,
}

impl fmt::Debug for SevenZipVolumeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SevenZipVolumeReader")
            .field("inner", &self.inner)
            .finish()
    }
}

impl SevenZipVolumeReader {
    /// Opens split 7z volumes with finite safe defaults.
    pub fn new(source: &VolumeSet) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::safe())
    }

    /// Opens split 7z volumes with explicit archive limits.
    pub fn with_limits(source: &VolumeSet, limits: Limits) -> Result<Self, StreamError> {
        let input = JoinedVolumeInput::new(source, limits)?;
        Ok(Self {
            inner: SeekArchiveReader::with_limits(input, limits)?,
        })
    }

    /// Opens the volume set and password provider carried by common options.
    pub fn with_options(options: &OpenOptions) -> Result<Self, StreamError> {
        let source = options.volumes().ok_or_else(|| {
            ArchiveError::new(ErrorKind::Capability)
                .with_format("7z")
                .with_context("SevenZipVolumeReader requires OpenOptions containing VolumeSet")
        })?;
        if options.adjacent_volume_discovery() {
            return Err(split_error(
                ErrorKind::Capability,
                "adjacent volume discovery is available only for path-based opens",
            ));
        }
        if options.filter().is_some() {
            return Err(split_error(
                ErrorKind::Capability,
                "outer filters are not supported around split 7z archives",
            ));
        }
        if options.source_limits() != source.limits() {
            return Err(split_error(
                ErrorKind::Capability,
                "OpenOptions source limits must match the limits already enforced by VolumeSet",
            ));
        }
        Self::from_options(source, options)
    }

    fn from_options(source: &VolumeSet, options: &OpenOptions) -> Result<Self, StreamError> {
        let input = JoinedVolumeInput::new(source, options.limits())?;
        let options = options.without_volumes();
        Ok(Self {
            inner: SeekArchiveReader::with_options(input, &options)?,
        })
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.inner.next_event()
    }

    /// Skips the current payload while preserving folder decoder state.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.inner.skip_entry()
    }
}

impl RandomAccessArchiveDecoder for SevenZipVolumeReader {
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        Self::next_event(self)
    }

    fn skip_entry(&mut self) -> Result<(), StreamError> {
        Self::skip_entry(self)
    }
}

struct CapturedSource {
    source: Arc<dyn ReadAt>,
    identity: SourceIdentity,
    start: u64,
    length: u64,
}

struct JoinedVolumeInput {
    sources: Vec<CapturedSource>,
    position: u64,
    length: u64,
}

impl fmt::Debug for JoinedVolumeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinedVolumeInput")
            .field("sources", &self.sources.len())
            .field("position", &self.position)
            .field("length", &self.length)
            .finish()
    }
}

impl JoinedVolumeInput {
    fn new(volumes: &VolumeSet, limits: Limits) -> Result<Self, StreamError> {
        let mut sources = Vec::<CapturedSource>::new();
        let mut length = 0_u64;
        let mut index = 0_u32;
        loop {
            let id = VolumeId::new(index);
            let source = if index == 0 {
                Some(volumes.primary())
            } else {
                volumes.resolve(id)?
            };
            let Some(source) = source else {
                break;
            };
            let source_length = source.len();
            if source_length == 0 {
                return Err(split_error(
                    ErrorKind::Malformed,
                    "split 7z contains an empty physical volume",
                ));
            }
            let identity = source.identity().clone();
            validate_read_at_snapshot(source.as_ref(), &identity, source_length)?;
            if sources.iter().any(|captured| captured.identity == identity) {
                return Err(split_error(
                    ErrorKind::Malformed,
                    "split 7z resolver returned a duplicate or cyclic source",
                ));
            }
            let metadata = sources
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(std::mem::size_of::<CapturedSource>()))
                .ok_or_else(|| {
                    split_error(ErrorKind::Limit, "split 7z extent metadata overflow")
                })?;
            if limits
                .metadata_bytes()
                .is_some_and(|maximum| metadata > maximum)
            {
                return Err(split_error(
                    ErrorKind::Limit,
                    "split 7z extent metadata exceeds configured limit",
                ));
            }
            sources
                .try_reserve(1)
                .map_err(|_| split_error(ErrorKind::Limit, "split 7z extent allocation failed"))?;
            sources.push(CapturedSource {
                source,
                identity,
                start: length,
                length: source_length,
            });
            length = length.checked_add(source_length).ok_or_else(|| {
                split_error(ErrorKind::Limit, "split 7z aggregate length overflow")
            })?;
            index = index.checked_add(1).ok_or_else(|| {
                split_error(ErrorKind::Limit, "split 7z volume identifier overflow")
            })?;
        }
        if sources.is_empty() {
            return Err(split_error(
                ErrorKind::Malformed,
                "split 7z has no primary volume",
            ));
        }
        Ok(Self {
            sources,
            position: 0,
            length,
        })
    }
}

impl Read for JoinedVolumeInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let mut written = 0_usize;
        while written < output.len() && self.position < self.length {
            let source_index = self
                .sources
                .partition_point(|source| source.start <= self.position)
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("split 7z virtual extent has a gap"))?;
            let captured = self
                .sources
                .get(source_index)
                .ok_or_else(|| io::Error::other("split 7z source disappeared"))?;
            let end = captured
                .start
                .checked_add(captured.length)
                .ok_or_else(|| io::Error::other("split 7z source extent overflow"))?;
            if self.position >= end {
                return Err(io::Error::other("split 7z virtual extent has a gap"));
            }
            let available = usize::try_from(end - self.position)
                .map_err(|_| io::Error::other("split 7z range exceeds address space"))?;
            let count = available.min(output.len() - written);
            let source_offset = self.position - captured.start;
            validate_read_at_snapshot(
                captured.source.as_ref(),
                &captured.identity,
                captured.length,
            )?;
            captured
                .source
                .read_exact_at(source_offset, &mut output[written..written + count])?;
            validate_read_at_snapshot(
                captured.source.as_ref(),
                &captured.identity,
                captured.length,
            )?;
            let count = u64::try_from(count)
                .map_err(|_| io::Error::other("split 7z read count exceeds u64"))?;
            self.position = self
                .position
                .checked_add(count)
                .ok_or_else(|| io::Error::other("split 7z read position overflow"))?;
            written += usize::try_from(count)
                .map_err(|_| io::Error::other("split 7z read count exceeds address space"))?;
        }
        Ok(written)
    }
}

impl Seek for JoinedVolumeInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let requested = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if !(0..=i128::from(u64::MAX)).contains(&requested) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "split 7z seek target is outside the u64 domain",
            ));
        }
        self.position = u64::try_from(requested).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "split 7z seek target exceeds the u64 domain",
            )
        })?;
        Ok(self.position)
    }
}

fn split_error(kind: ErrorKind, context: &'static str) -> StreamError {
    ArchiveError::new(kind)
        .with_format("7z")
        .with_context(context)
        .into()
}
