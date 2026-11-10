// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disk-aware seek view over application-owned split ZIP volumes.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use libarchive_oxide_core::{AccessMode, ArchiveError, DirectionSet, ErrorKind, FormatId, Limits};

use crate::provider::FormatCapabilities;
use crate::range_source::{ReadAt, SourceIdentity, VolumeId, VolumeSet, validate_read_at_snapshot};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
use crate::{OpenOptions, ReaderEvent, SeekArchiveReader, StreamError};

const EOCD_MIN: usize = 22;
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;
const ZIP64_LOCATOR: usize = 20;
const ZIP64_LOCATOR_U64: u64 = 20;

pub(crate) fn terminal_disk_number(source: &dyn ReadAt) -> Result<u32, StreamError> {
    let end = source.len();
    let tail_length = end.min(EOCD_SEARCH);
    let tail_size = usize::try_from(tail_length).map_err(|_| {
        split_error(
            ErrorKind::Limit,
            "split ZIP EOCD search range exceeds address space",
        )
    })?;
    let mut tail = vec![0_u8; tail_size];
    source.read_exact_at(end - tail_length, &mut tail)?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or_else(|| {
            split_error(
                ErrorKind::Malformed,
                "split ZIP terminal file has no end-of-central-directory record",
            )
        })?;
    let fixed = tail.get(eocd..eocd + EOCD_MIN).ok_or_else(|| {
        split_error(
            ErrorKind::Malformed,
            "split ZIP terminal end-of-central-directory record is truncated",
        )
    })?;
    let disk = u16::from_le_bytes([fixed[4], fixed[5]]);
    if disk != u16::MAX {
        return Ok(u32::from(disk));
    }
    let absolute = end - tail_length + eocd as u64;
    let locator_offset = absolute.checked_sub(ZIP64_LOCATOR_U64).ok_or_else(|| {
        split_error(
            ErrorKind::Malformed,
            "split ZIP64 terminal locator is missing",
        )
    })?;
    let mut locator = [0_u8; ZIP64_LOCATOR];
    source.read_exact_at(locator_offset, &mut locator)?;
    if &locator[..4] != b"PK\x06\x07" {
        return Err(split_error(
            ErrorKind::Malformed,
            "split ZIP64 terminal locator has a bad signature",
        ));
    }
    let total = u32::from_le_bytes([locator[16], locator[17], locator[18], locator[19]]);
    total.checked_sub(1).ok_or_else(|| {
        split_error(
            ErrorKind::Malformed,
            "split ZIP64 terminal locator declares zero disks",
        )
    })
}

/// Built-in provider for standard multi-disk ZIP archives.
///
/// `VolumeId(0)` is the first ZIP disk, not the terminal `.zip` file.
/// The provider consumes disk-number and disk-relative offset fields from the ZIP central directory; it does not treat the sources as an ordinary byte split.
#[derive(Debug, Default)]
pub struct ZipVolumeProvider;

impl ZipVolumeProvider {
    /// Creates the stateless split-ZIP provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomAccessFormatProvider for ZipVolumeProvider {
    type Decoder = ZipVolumeReader;

    fn format(&self) -> FormatId {
        FormatId::Zip
    }

    fn name(&self) -> &'static str {
        "zip-volume"
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Seek)
    }

    fn probe(&self, source: &VolumeSet, _limits: Limits) -> Result<bool, StreamError> {
        let primary = source.primary();
        if primary.len() < 4 {
            return Ok(false);
        }
        let mut signature = [0_u8; 4];
        primary.read_exact_at(0, &mut signature)?;
        Ok(matches!(
            &signature,
            b"PK\x07\x08" | b"PK\x03\x04" | b"PK\x05\x06"
        ))
    }

    fn open(&self, source: Arc<VolumeSet>, limits: Limits) -> Result<Self::Decoder, StreamError> {
        ZipVolumeReader::with_limits(source.as_ref(), limits)
    }

    fn open_with_options(
        &self,
        source: Arc<VolumeSet>,
        options: &OpenOptions,
    ) -> Result<Self::Decoder, StreamError> {
        ZipVolumeReader::from_options(source.as_ref(), options)
    }
}

/// Seek-native reader for standard split ZIP archives.
pub struct ZipVolumeReader {
    inner: SeekArchiveReader<ZipVolumeInput>,
}

impl fmt::Debug for ZipVolumeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZipVolumeReader")
            .field("inner", &self.inner)
            .finish()
    }
}

impl ZipVolumeReader {
    /// Opens split ZIP volumes with finite safe defaults.
    pub fn new(source: &VolumeSet) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::safe())
    }

    /// Opens split ZIP volumes with explicit archive limits.
    pub fn with_limits(source: &VolumeSet, limits: Limits) -> Result<Self, StreamError> {
        let input = ZipVolumeInput::new(source, limits)?;
        let disk_starts = input.disk_starts();
        Ok(Self {
            inner: SeekArchiveReader::with_split_zip(
                input,
                &disk_starts,
                &OpenOptions::new()
                    .with_format(Some(FormatId::Zip))
                    .with_limits(limits),
            )?,
        })
    }

    /// Opens the volume set and password provider carried by common options.
    pub fn with_options(options: &OpenOptions) -> Result<Self, StreamError> {
        let source = options.volumes().ok_or_else(|| {
            ArchiveError::new(ErrorKind::Capability)
                .with_format("zip")
                .with_context("ZipVolumeReader requires OpenOptions containing VolumeSet")
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
                "outer filters are not supported around split ZIP archives",
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

    pub(crate) fn from_options(
        source: &VolumeSet,
        options: &OpenOptions,
    ) -> Result<Self, StreamError> {
        let input = ZipVolumeInput::new(source, options.limits())?;
        let disk_starts = input.disk_starts();
        let options = options.without_volumes();
        Ok(Self {
            inner: SeekArchiveReader::with_split_zip(input, &disk_starts, &options)?,
        })
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.inner.next_event()
    }

    /// Skips the current payload.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.inner.skip_entry()
    }
}

impl RandomAccessArchiveDecoder for ZipVolumeReader {
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

struct ZipVolumeInput {
    sources: Vec<CapturedSource>,
    position: u64,
    length: u64,
}

impl fmt::Debug for ZipVolumeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZipVolumeInput")
            .field("sources", &self.sources.len())
            .field("position", &self.position)
            .field("length", &self.length)
            .finish()
    }
}

impl ZipVolumeInput {
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
                    "split ZIP contains an empty physical volume",
                ));
            }
            let identity = source.identity().clone();
            validate_read_at_snapshot(source.as_ref(), &identity, source_length)?;
            if sources.iter().any(|captured| captured.identity == identity) {
                return Err(split_error(
                    ErrorKind::Malformed,
                    "split ZIP resolver returned a duplicate or cyclic source",
                ));
            }
            let metadata = sources
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(std::mem::size_of::<CapturedSource>()))
                .ok_or_else(|| {
                    split_error(ErrorKind::Limit, "split ZIP extent metadata overflow")
                })?;
            if limits
                .metadata_bytes()
                .is_some_and(|maximum| metadata > maximum)
            {
                return Err(split_error(
                    ErrorKind::Limit,
                    "split ZIP extent metadata exceeds configured limit",
                ));
            }
            sources
                .try_reserve(1)
                .map_err(|_| split_error(ErrorKind::Limit, "split ZIP extent allocation failed"))?;
            sources.push(CapturedSource {
                source,
                identity,
                start: length,
                length: source_length,
            });
            length = length.checked_add(source_length).ok_or_else(|| {
                split_error(ErrorKind::Limit, "split ZIP aggregate length overflow")
            })?;
            index = index.checked_add(1).ok_or_else(|| {
                split_error(ErrorKind::Limit, "split ZIP volume identifier overflow")
            })?;
        }
        if sources.is_empty() {
            return Err(split_error(
                ErrorKind::Malformed,
                "split ZIP has no primary volume",
            ));
        }
        Ok(Self {
            sources,
            position: 0,
            length,
        })
    }

    fn disk_starts(&self) -> Vec<u64> {
        self.sources.iter().map(|source| source.start).collect()
    }
}

impl Read for ZipVolumeInput {
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
                .ok_or_else(|| io::Error::other("split ZIP virtual extent has a gap"))?;
            let captured = self
                .sources
                .get(source_index)
                .ok_or_else(|| io::Error::other("split ZIP source disappeared"))?;
            let end = captured
                .start
                .checked_add(captured.length)
                .ok_or_else(|| io::Error::other("split ZIP source extent overflow"))?;
            if self.position >= end {
                return Err(io::Error::other("split ZIP virtual extent has a gap"));
            }
            let available = usize::try_from(end - self.position)
                .map_err(|_| io::Error::other("split ZIP range exceeds address space"))?;
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
            let count_u64 = u64::try_from(count)
                .map_err(|_| io::Error::other("split ZIP read count exceeds u64"))?;
            self.position = self
                .position
                .checked_add(count_u64)
                .ok_or_else(|| io::Error::other("split ZIP read position overflow"))?;
            written += count;
        }
        Ok(written)
    }
}

impl Seek for ZipVolumeInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let requested = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if !(0..=i128::from(u64::MAX)).contains(&requested) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "split ZIP seek target is outside the u64 domain",
            ));
        }
        self.position = u64::try_from(requested).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "split ZIP seek target exceeds the u64 domain",
            )
        })?;
        Ok(self.position)
    }
}

fn split_error(kind: ErrorKind, context: &'static str) -> StreamError {
    ArchiveError::new(kind)
        .with_format("zip")
        .with_context(context)
        .into()
}
