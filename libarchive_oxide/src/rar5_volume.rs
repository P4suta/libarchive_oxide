// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded sequencing of complete and split entries across physical RAR5 volumes.

use std::fmt;
use std::sync::Arc;

use libarchive_oxide_core::{
    AccessMode, ArchiveError, ArchiveMetadata, Checksum, DirectionSet, EntryMetadata, ErrorKind,
    Extension, FormatId, Limits, ProbeResult, Rar5CompressionInfo, Rar5SplitVerifier,
};
#[cfg(feature = "rar")]
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput};

#[cfg(feature = "rar")]
use crate::provider::{
    BuiltinPayloadDecoder, builtin_solid_split_rar5_decoder, builtin_split_rar5_decoder,
};
use crate::provider::{
    BuiltinRar5Decoder, FormatCapabilities, FormatProvider, FormatProviderNode, NoArchiveEncoder,
    NoCodecProviders, NoFormatProviders, ProviderSet, builtin_rar5_decoder,
};
use crate::range_source::{RangeReader, ReadAt, SourceLimits, VolumeId, VolumeSet};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
use crate::{ArchiveReader, OpenOptions, ReaderEvent, StreamError};

const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const ARCHIVE_VOLUME: u64 = 0x01;
const ARCHIVE_SOLID: u64 = 0x04;
#[cfg(feature = "rar")]
const COMPRESSED_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
struct Rar5PhysicalProvider;

impl FormatProvider for Rar5PhysicalProvider {
    type Decoder = BuiltinRar5Decoder;
    type Encoder = NoArchiveEncoder;

    fn format(&self) -> FormatId {
        FormatId::Rar5
    }

    fn name(&self) -> &'static str {
        "rar5-physical-volume"
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() < SIGNATURE.len() {
            ProbeResult::NeedMore {
                minimum: SIGNATURE.len(),
            }
        } else if prefix.starts_with(SIGNATURE) {
            ProbeResult::Match(())
        } else {
            ProbeResult::NoMatch
        }
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Sequential)
    }

    fn decoder(&self, limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(builtin_rar5_decoder(limits, true, Vec::new()))
    }

    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Err(rar5_volume_error(
            ErrorKind::Unsupported,
            "RAR writing is license-excluded",
        ))
    }
}

type PhysicalProviders = FormatProviderNode<Rar5PhysicalProvider, NoFormatProviders>;
type PhysicalReader =
    ArchiveReader<RangeReader<Arc<dyn ReadAt>>, PhysicalProviders, NoCodecProviders>;

/// Built-in provider for RAR5 physical volume sets.
///
/// The provider follows an end header's next-volume declaration through the application-owned [`VolumeSet`].
/// Split Store file parts are checksum-verified directly; generation-0 LZ members retain one bounded concrete decoder across both member and volume boundaries.
/// Both are exposed as one logical entry.
/// Split compressed service data remains a typed unsupported path.
/// Since RAR stores the logical checksum in the final part, a split entry's initial [`ReaderEvent::Entry`] has no typed checksum; validation still completes before its single [`ReaderEvent::EndEntry`].
#[derive(Debug, Default)]
pub struct Rar5VolumeProvider;

impl Rar5VolumeProvider {
    /// Creates the stateless RAR5 volume provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomAccessFormatProvider for Rar5VolumeProvider {
    type Decoder = Rar5VolumeReader;

    fn format(&self) -> FormatId {
        FormatId::Rar5
    }

    fn name(&self) -> &'static str {
        "rar5-volume"
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
        Rar5VolumeReader::with_limits(source, limits)
    }

    fn open_with_options(
        &self,
        source: Arc<VolumeSet>,
        options: &OpenOptions,
    ) -> Result<Self::Decoder, StreamError> {
        if options.has_password_provider() {
            return Err(rar5_volume_error(
                ErrorKind::Unsupported,
                "RAR5 volume encryption is not implemented",
            )
            .into());
        }
        Rar5VolumeReader::from_options(source, options)
    }
}

/// Event reader over a caller-owned sequence of physical RAR5 volumes.
pub struct Rar5VolumeReader {
    volumes: Arc<VolumeSet>,
    limits: Limits,
    source_limits: SourceLimits,
    reader: Option<PhysicalReader>,
    volume: u32,
    physical_metadata_seen: bool,
    next_volume: Option<bool>,
    archive_solid: Option<bool>,
    logical_entries: u64,
    consumed_entries: u64,
    consumed_decoded: u64,
    entry_open: bool,
    logical_entry: Option<LogicalEntry>,
    #[cfg(feature = "rar")]
    compressed_payload: CompressedPayloadState,
    #[cfg(feature = "rar")]
    retained_payload: Option<BuiltinPayloadDecoder>,
    #[cfg(feature = "rar")]
    compressed_data: Vec<u8>,
    #[cfg(feature = "rar")]
    compressed_offset: usize,
    done: bool,
    event_data: Vec<u8>,
}

impl fmt::Debug for Rar5VolumeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rar5VolumeReader")
            .field("volume", &self.volume)
            .field("entry_open", &self.entry_open)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Rar5VolumeReader {
    /// Opens a RAR5 volume set with finite safe defaults.
    pub fn new(source: Arc<VolumeSet>) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::safe())
    }

    /// Opens a RAR5 volume set with explicit archive limits.
    pub fn with_limits(source: Arc<VolumeSet>, limits: Limits) -> Result<Self, StreamError> {
        let source_limits = source.limits();
        Self::open(source, limits, source_limits)
    }

    /// Opens the volume set carried by common options.
    pub fn with_options(options: &OpenOptions) -> Result<Self, StreamError> {
        let source = options.volumes().ok_or_else(|| {
            rar5_volume_error(
                ErrorKind::Capability,
                "Rar5VolumeReader requires OpenOptions containing VolumeSet",
            )
        })?;
        if options.adjacent_volume_discovery() {
            return Err(rar5_volume_error(
                ErrorKind::Capability,
                "adjacent volume discovery is available only for path-based opens",
            )
            .into());
        }
        if options.filter().is_some() {
            return Err(rar5_volume_error(
                ErrorKind::Capability,
                "outer filters are not supported around RAR5 volume sets",
            )
            .into());
        }
        if options.has_password_provider() {
            return Err(rar5_volume_error(
                ErrorKind::Unsupported,
                "RAR5 volume encryption is not implemented",
            )
            .into());
        }
        if options.source_limits() != source.limits() {
            return Err(rar5_volume_error(
                ErrorKind::Capability,
                "OpenOptions source limits must match the limits enforced by VolumeSet",
            )
            .into());
        }
        Self::from_options(Arc::clone(source), options)
    }

    fn from_options(source: Arc<VolumeSet>, options: &OpenOptions) -> Result<Self, StreamError> {
        Self::open(source, options.limits(), options.source_limits())
    }

    fn open(
        volumes: Arc<VolumeSet>,
        limits: Limits,
        source_limits: SourceLimits,
    ) -> Result<Self, StreamError> {
        let reader = open_physical(volumes.primary(), limits, source_limits)?;
        Ok(Self {
            volumes,
            limits,
            source_limits,
            reader: Some(reader),
            volume: 0,
            physical_metadata_seen: false,
            next_volume: None,
            archive_solid: None,
            logical_entries: 0,
            consumed_entries: 0,
            consumed_decoded: 0,
            entry_open: false,
            logical_entry: None,
            #[cfg(feature = "rar")]
            compressed_payload: CompressedPayloadState::Idle,
            #[cfg(feature = "rar")]
            retained_payload: None,
            #[cfg(feature = "rar")]
            compressed_data: Vec::new(),
            #[cfg(feature = "rar")]
            compressed_offset: 0,
            done: false,
            event_data: Vec::new(),
        })
    }

    /// Produces the next logical archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        if self.done {
            return Ok(ReaderEvent::Done);
        }
        loop {
            #[cfg(feature = "rar")]
            match self.drive_compressed_payload()? {
                CompressedPayloadProgress::Data => return Ok(ReaderEvent::Data(&self.event_data)),
                CompressedPayloadProgress::Finished => {
                    self.compressed_payload = CompressedPayloadState::Idle;
                    if self.finish_logical_entry()? {
                        return Ok(ReaderEvent::EndEntry);
                    }
                },
                CompressedPayloadProgress::Idle => {},
            }
            let event = self.next_physical_event()?;
            match event {
                PhysicalEvent::Metadata(metadata) => {
                    if let Some(end) = physical_end(&metadata)? {
                        self.consume_physical_budget(end)?;
                        self.next_volume = Some(end.next);
                        continue;
                    }
                    let first = !self.physical_metadata_seen;
                    if first {
                        let solid = validate_main_metadata(&metadata, self.volume)?;
                        if self.archive_solid.is_some_and(|expected| expected != solid) {
                            return Err(rar5_volume_error(
                                ErrorKind::Malformed,
                                "RAR5 physical volumes disagree on the solid archive flag",
                            )
                            .into());
                        }
                        self.archive_solid = Some(solid);
                        self.physical_metadata_seen = true;
                        if self.volume != 0 {
                            continue;
                        }
                    }
                    return Ok(ReaderEvent::ArchiveMetadata(metadata));
                },
                PhysicalEvent::Entry(metadata) => {
                    if let Some(metadata) = self.begin_physical_entry(*metadata)? {
                        return Ok(ReaderEvent::Entry(metadata));
                    }
                },
                PhysicalEvent::Data => {
                    self.observe_physical_data()?;
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                #[cfg(feature = "rar")]
                PhysicalEvent::CompressedData => {},
                PhysicalEvent::EndEntry => {
                    if self.end_physical_entry()? {
                        return Ok(ReaderEvent::EndEntry);
                    }
                },
                PhysicalEvent::Done => {
                    if self.advance_physical_volume()? {
                        return Ok(ReaderEvent::Done);
                    }
                },
            }
        }
    }

    fn next_physical_event(&mut self) -> Result<PhysicalEvent, StreamError> {
        let reader = self.reader.as_mut().ok_or_else(|| {
            rar5_volume_error(ErrorKind::Protocol, "RAR5 physical reader is missing")
        })?;
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(metadata) => Ok(PhysicalEvent::Metadata(metadata)),
            ReaderEvent::Entry(metadata) => Ok(PhysicalEvent::Entry(Box::new(metadata))),
            ReaderEvent::Data(data) => {
                #[cfg(feature = "rar")]
                if matches!(self.compressed_payload, CompressedPayloadState::Decoding(_)) {
                    self.compressed_data.clear();
                    self.compressed_data.try_reserve(data.len()).map_err(|_| {
                        rar5_volume_error(
                            ErrorKind::Limit,
                            "RAR5 compressed volume event allocation failed",
                        )
                    })?;
                    self.compressed_data.extend_from_slice(data);
                    self.compressed_offset = 0;
                    return Ok(PhysicalEvent::CompressedData);
                }

                self.event_data.clear();
                self.event_data.try_reserve(data.len()).map_err(|_| {
                    rar5_volume_error(ErrorKind::Limit, "RAR5 volume event allocation failed")
                })?;
                self.event_data.extend_from_slice(data);
                Ok(PhysicalEvent::Data)
            },
            ReaderEvent::EndEntry => Ok(PhysicalEvent::EndEntry),
            ReaderEvent::Done => Ok(PhysicalEvent::Done),
        }
    }

    fn begin_physical_entry(
        &mut self,
        metadata: EntryMetadata,
    ) -> Result<Option<EntryMetadata>, StreamError> {
        let split = entry_split(&metadata)?;
        if let Some(logical) = &mut self.logical_entry {
            let split = split.ok_or_else(|| {
                rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 split entry is not continued in the next physical file",
                )
            })?;
            if !split.before {
                return Err(rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 split continuation omits the previous-volume flag",
                )
                .into());
            }
            validate_continuation(&logical.metadata, &metadata)?;
            if let Some(size) = metadata.size() {
                if logical
                    .logical_size
                    .is_some_and(|expected| expected != size)
                {
                    return Err(rar5_volume_error(
                        ErrorKind::Malformed,
                        "RAR5 split continuation changes its logical size",
                    )
                    .into());
                }
                logical.logical_size = Some(size);
            }
            logical.part_after = split.after;
            logical.final_checksum = (!split.after)
                .then(|| metadata.checksum().cloned())
                .flatten();
            logical.final_crc = if split.after {
                None
            } else {
                entry_crc32(&metadata)?
            };
            return Ok(None);
        }
        if split.is_some_and(|flags| flags.before) {
            return Err(rar5_volume_error(
                ErrorKind::Malformed,
                "RAR5 first logical file part has a previous-volume flag",
            )
            .into());
        }
        let compression = entry_compression(&metadata)?;
        if compression.solid() && self.logical_entries == 0 {
            return Err(rar5_volume_error(
                ErrorKind::Malformed,
                "RAR5 solid entry has no preceding logical member",
            )
            .into());
        }
        self.logical_entries = self.logical_entries.checked_add(1).ok_or_else(|| {
            rar5_volume_error(ErrorKind::Limit, "RAR5 logical entry count overflow")
        })?;
        self.entry_open = true;
        #[cfg(feature = "rar")]
        let compressed = self.start_compressed_payload(&metadata, compression)?;
        #[cfg(not(feature = "rar"))]
        let compressed = Self::start_compressed_payload(&metadata, compression)?;
        let part_after = split.is_some_and(|flags| flags.after);
        if compressed || part_after {
            self.logical_entry = Some(LogicalEntry {
                metadata: metadata.clone(),
                verifier: Rar5SplitVerifier::new(),
                decoded: 0,
                logical_size: metadata.size(),
                part_after,
                compressed,
                final_checksum: (!part_after)
                    .then(|| metadata.checksum().cloned())
                    .flatten(),
                final_crc: if part_after {
                    None
                } else {
                    entry_crc32(&metadata)?
                },
            });
        }
        Ok(Some(metadata))
    }

    #[cfg(feature = "rar")]
    fn start_compressed_payload(
        &mut self,
        metadata: &EntryMetadata,
        compression: Rar5CompressionInfo,
    ) -> Result<bool, StreamError> {
        let compressed = compression.method() != 0 && !metadata.is_encrypted();
        if !compressed {
            return Ok(false);
        }
        let unpacked_size = metadata.size().ok_or_else(|| {
            rar5_volume_error(
                ErrorKind::Malformed,
                "compressed RAR5 entry has no logical size",
            )
        })?;
        let decoder = if compression.solid() {
            let previous = self.retained_payload.take().ok_or_else(|| {
                rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 solid entry has no reusable decoder state",
                )
            })?;
            builtin_solid_split_rar5_decoder(previous, compression, unpacked_size, self.limits)
        } else {
            self.retained_payload = None;
            builtin_split_rar5_decoder(compression, unpacked_size, self.limits)
        }
        .map_err(StreamError::archive)?;
        self.compressed_payload = CompressedPayloadState::Decoding(decoder);
        self.compressed_data.clear();
        self.compressed_offset = 0;
        Ok(true)
    }

    #[cfg(not(feature = "rar"))]
    fn start_compressed_payload(
        metadata: &EntryMetadata,
        compression: Rar5CompressionInfo,
    ) -> Result<bool, StreamError> {
        if compression.method() == 0 || metadata.is_encrypted() {
            return Ok(false);
        }
        Err(rar5_volume_error(
            ErrorKind::Unsupported,
            "compressed RAR5 volume entry requires the rar feature",
        )
        .into())
    }

    fn observe_physical_data(&mut self) -> Result<(), StreamError> {
        let Some(logical) = &mut self.logical_entry else {
            return Ok(());
        };
        logical.verifier.update(&self.event_data);
        logical.decoded = logical
            .decoded
            .checked_add(self.event_data.len() as u64)
            .ok_or_else(|| {
                rar5_volume_error(ErrorKind::Limit, "RAR5 logical entry size overflow")
            })?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| logical.decoded > maximum)
        {
            return Err(rar5_volume_error(
                ErrorKind::Limit,
                "RAR5 logical entry exceeds the configured entry-byte budget",
            )
            .into());
        }
        if logical
            .logical_size
            .is_some_and(|declared| logical.decoded > declared)
        {
            return Err(rar5_volume_error(
                ErrorKind::Malformed,
                "RAR5 logical payload exceeds its declared size",
            )
            .into());
        }
        Ok(())
    }

    fn end_physical_entry(&mut self) -> Result<bool, StreamError> {
        if self
            .logical_entry
            .as_ref()
            .is_some_and(|split| split.part_after)
        {
            return Ok(false);
        }
        #[cfg(feature = "rar")]
        if matches!(self.compressed_payload, CompressedPayloadState::Decoding(_)) {
            let CompressedPayloadState::Decoding(codec) =
                core::mem::replace(&mut self.compressed_payload, CompressedPayloadState::Idle)
            else {
                return Err(rar5_volume_error(
                    ErrorKind::Protocol,
                    "RAR5 compressed payload state changed during finalization",
                )
                .into());
            };
            self.compressed_payload = CompressedPayloadState::Finishing(codec);
            return Ok(false);
        }
        self.finish_logical_entry()
    }

    fn finish_logical_entry(&mut self) -> Result<bool, StreamError> {
        if let Some(logical) = self.logical_entry.take() {
            if logical
                .logical_size
                .is_some_and(|declared| logical.decoded != declared)
            {
                return Err(rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 logical payload does not match its declared size",
                )
                .into());
            }
            if logical
                .final_checksum
                .as_ref()
                .is_some_and(|checksum| !logical.verifier.verifies(checksum))
            {
                return Err(rar5_volume_error(
                    ErrorKind::Integrity,
                    "RAR5 logical entry checksum does not match its payload",
                )
                .into());
            }
            if logical
                .final_crc
                .is_some_and(|expected| !logical.verifier.verifies_crc32(expected))
            {
                return Err(rar5_volume_error(
                    ErrorKind::Integrity,
                    "RAR5 logical entry CRC-32 does not match its payload",
                )
                .into());
            }
            if logical.compressed {
                self.consumed_decoded = self
                    .consumed_decoded
                    .checked_add(logical.decoded)
                    .ok_or_else(|| {
                        rar5_volume_error(ErrorKind::Limit, "RAR5 decoded size overflow")
                    })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|maximum| self.consumed_decoded > maximum)
                {
                    return Err(rar5_volume_error(
                        ErrorKind::Limit,
                        "RAR5 volumes exceed the logical decoded-byte budget",
                    )
                    .into());
                }
            }
        }
        self.entry_open = false;
        Ok(true)
    }

    #[cfg(feature = "rar")]
    fn drive_compressed_payload(&mut self) -> Result<CompressedPayloadProgress, StreamError> {
        let finishing = matches!(
            self.compressed_payload,
            CompressedPayloadState::Finishing(_)
        );
        let codec = match &mut self.compressed_payload {
            CompressedPayloadState::Idle => return Ok(CompressedPayloadProgress::Idle),
            CompressedPayloadState::Decoding(codec) | CompressedPayloadState::Finishing(codec) => {
                codec
            },
            CompressedPayloadState::Finished => return Ok(CompressedPayloadProgress::Finished),
        };
        if self.compressed_offset > self.compressed_data.len() {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 compressed codec input offset exceeds its buffer",
            )
            .into());
        }
        let input = &self.compressed_data[self.compressed_offset..];
        let end = if finishing && input.is_empty() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        self.event_data.clear();
        self.event_data
            .try_reserve(COMPRESSED_OUTPUT_BYTES)
            .map_err(|_| {
                rar5_volume_error(
                    ErrorKind::Limit,
                    "RAR5 compressed codec output allocation failed",
                )
            })?;
        self.event_data.resize(COMPRESSED_OUTPUT_BYTES, 0);
        let step = codec
            .process(input, &mut self.event_data, end)
            .map_err(StreamError::archive)?
            .validate(input.len(), self.event_data.len())
            .map_err(StreamError::archive)?;
        self.compressed_offset = self
            .compressed_offset
            .checked_add(step.consumed)
            .ok_or_else(|| {
                rar5_volume_error(
                    ErrorKind::Limit,
                    "RAR5 compressed codec input offset overflow",
                )
            })?;
        self.event_data.truncate(step.produced);

        if matches!(step.status, CodecStatus::Done) {
            if !finishing {
                return Err(rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 compressed codec ended before the final volume part",
                )
                .into());
            }
            if self.compressed_offset != self.compressed_data.len() {
                return Err(rar5_volume_error(
                    ErrorKind::Malformed,
                    "RAR5 compressed codec left trailing packed data",
                )
                .into());
            }
            self.retain_completed_payload()?;
        } else if step.consumed == 0 && step.produced == 0 && !input.is_empty() {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 compressed codec made no progress with available input",
            )
            .into());
        } else if matches!(step.status, CodecStatus::NeedOutput) && step.produced == 0 {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 compressed codec requested output without producing data",
            )
            .into());
        }

        if self.compressed_offset == self.compressed_data.len() {
            self.compressed_data.clear();
            self.compressed_offset = 0;
        }
        if !self.event_data.is_empty() {
            self.observe_physical_data()?;
            return Ok(CompressedPayloadProgress::Data);
        }
        if matches!(self.compressed_payload, CompressedPayloadState::Finished) {
            Ok(CompressedPayloadProgress::Finished)
        } else {
            Ok(CompressedPayloadProgress::Idle)
        }
    }

    #[cfg(feature = "rar")]
    fn retain_completed_payload(&mut self) -> Result<(), StreamError> {
        let completed = core::mem::replace(
            &mut self.compressed_payload,
            CompressedPayloadState::Finished,
        );
        let CompressedPayloadState::Finishing(completed) = completed else {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 payload state changed while retaining a completed decoder",
            )
            .into());
        };
        self.retained_payload = (self.archive_solid == Some(true)).then_some(completed);
        Ok(())
    }

    fn advance_physical_volume(&mut self) -> Result<bool, StreamError> {
        if (self.entry_open && self.logical_entry.is_none()) || !self.physical_metadata_seen {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 physical volume ended in an invalid state",
            )
            .into());
        }
        let next = self.next_volume.ok_or_else(|| {
            rar5_volume_error(
                ErrorKind::Protocol,
                "RAR5 physical volume omitted its end marker",
            )
        })?;
        if self.logical_entry.is_some() && !next {
            return Err(rar5_volume_error(
                ErrorKind::Malformed,
                "RAR5 volume set ends before its split entry is complete",
            )
            .into());
        }
        if !next {
            self.done = true;
            return Ok(true);
        }
        let volume = self
            .volume
            .checked_add(1)
            .ok_or_else(|| rar5_volume_error(ErrorKind::Limit, "RAR5 volume index overflow"))?;
        let source = self
            .volumes
            .resolve_required(VolumeId::new(volume))
            .map_err(StreamError::io)?;
        self.reader = Some(open_physical(
            source,
            self.remaining_limits()?,
            self.source_limits,
        )?);
        self.volume = volume;
        self.physical_metadata_seen = false;
        self.next_volume = None;
        Ok(false)
    }

    fn consume_physical_budget(&mut self, end: PhysicalEnd) -> Result<(), StreamError> {
        self.consumed_entries = self
            .consumed_entries
            .checked_add(end.entries)
            .ok_or_else(|| rar5_volume_error(ErrorKind::Limit, "RAR5 entry count overflow"))?;
        self.consumed_decoded = self
            .consumed_decoded
            .checked_add(end.decoded)
            .ok_or_else(|| rar5_volume_error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.consumed_entries > maximum)
            || self
                .limits
                .decoded_total()
                .is_some_and(|maximum| self.consumed_decoded > maximum)
        {
            return Err(rar5_volume_error(
                ErrorKind::Limit,
                "RAR5 physical volumes exceed the logical archive budget",
            )
            .into());
        }
        Ok(())
    }

    fn remaining_limits(&self) -> Result<Limits, StreamError> {
        let entries = match self.limits.entries() {
            Some(maximum) => Some(maximum.checked_sub(self.consumed_entries).ok_or_else(|| {
                rar5_volume_error(ErrorKind::Limit, "RAR5 entry budget underflow")
            })?),
            None => None,
        };
        let decoded = match self.limits.decoded_total() {
            Some(maximum) => Some(maximum.checked_sub(self.consumed_decoded).ok_or_else(|| {
                rar5_volume_error(ErrorKind::Limit, "RAR5 decoded budget underflow")
            })?),
            None => None,
        };
        Ok(self
            .limits
            .with_entries(entries)
            .with_decoded_total(decoded))
    }

    /// Skips the currently open entry while preserving volume sequencing.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        if !self.entry_open {
            return Err(rar5_volume_error(
                ErrorKind::Protocol,
                "skip_entry called without an open RAR5 entry",
            )
            .into());
        }
        loop {
            match self.next_event()? {
                ReaderEvent::Data(_) => {},
                ReaderEvent::EndEntry => return Ok(()),
                _ => {
                    return Err(rar5_volume_error(
                        ErrorKind::Protocol,
                        "RAR5 entry ended without an end-entry event",
                    )
                    .into());
                },
            }
        }
    }
}

impl RandomAccessArchiveDecoder for Rar5VolumeReader {
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        Self::next_event(self)
    }

    fn skip_entry(&mut self) -> Result<(), StreamError> {
        Self::skip_entry(self)
    }
}

enum PhysicalEvent {
    Metadata(ArchiveMetadata),
    Entry(Box<EntryMetadata>),
    Data,
    #[cfg(feature = "rar")]
    CompressedData,
    EndEntry,
    Done,
}

#[cfg(feature = "rar")]
enum CompressedPayloadProgress {
    Idle,
    Data,
    Finished,
}

#[cfg(feature = "rar")]
enum CompressedPayloadState {
    Idle,
    Decoding(BuiltinPayloadDecoder),
    Finishing(BuiltinPayloadDecoder),
    Finished,
}

struct LogicalEntry {
    metadata: EntryMetadata,
    verifier: Rar5SplitVerifier,
    decoded: u64,
    logical_size: Option<u64>,
    part_after: bool,
    compressed: bool,
    final_checksum: Option<Checksum>,
    final_crc: Option<u32>,
}

#[derive(Clone, Copy)]
struct PhysicalSplit {
    before: bool,
    after: bool,
}

#[derive(Clone, Copy)]
struct PhysicalEnd {
    next: bool,
    entries: u64,
    decoded: u64,
}

fn open_physical(
    source: Arc<dyn ReadAt>,
    limits: Limits,
    source_limits: SourceLimits,
) -> Result<PhysicalReader, StreamError> {
    let input = RangeReader::with_source_limits(source, limits, source_limits)
        .map_err(StreamError::io_or_archive)?;
    let providers = ProviderSet::empty().with_format_provider(Rar5PhysicalProvider);
    ArchiveReader::with_providers_and_format(input, FormatId::Rar5, limits, providers)
        .map_err(StreamError::archive)
}

fn validate_main_metadata(metadata: &ArchiveMetadata, volume: u32) -> Result<bool, StreamError> {
    let flags = extension_u64(metadata, b"archive-flags")?.ok_or_else(|| {
        rar5_volume_error(
            ErrorKind::Malformed,
            "RAR5 physical volume omitted its archive flags",
        )
    })?;
    if flags & ARCHIVE_VOLUME == 0 {
        return Err(rar5_volume_error(
            ErrorKind::Malformed,
            "RAR5 physical source is not marked as a volume archive",
        )
        .into());
    }
    if let Some(number) = extension_u64(metadata, b"volume-number")?
        && number != u64::from(volume)
    {
        return Err(rar5_volume_error(
            ErrorKind::Malformed,
            "RAR5 physical volume number is out of sequence",
        )
        .into());
    }
    Ok(flags & ARCHIVE_SOLID != 0)
}

fn physical_end(metadata: &ArchiveMetadata) -> Result<Option<PhysicalEnd>, StreamError> {
    let Some(value) = extension(metadata, b"physical-volume-end") else {
        return Ok(None);
    };
    if value.len() != 17 || !matches!(value[0], 0 | 1) {
        return Err(rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 physical end marker has an invalid provider value",
        )
        .into());
    }
    let entries = u64::from_le_bytes(value[1..9].try_into().map_err(|_| {
        rar5_volume_error(ErrorKind::Protocol, "RAR5 physical entry count is invalid")
    })?);
    let decoded = u64::from_le_bytes(value[9..17].try_into().map_err(|_| {
        rar5_volume_error(ErrorKind::Protocol, "RAR5 physical decoded size is invalid")
    })?);
    Ok(Some(PhysicalEnd {
        next: value[0] == 1,
        entries,
        decoded,
    }))
}

fn extension_u64(metadata: &ArchiveMetadata, key: &[u8]) -> Result<Option<u64>, StreamError> {
    let Some(value) = extension(metadata, key) else {
        return Ok(None);
    };
    let value: [u8; 8] = value.try_into().map_err(|_| {
        rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 provider metadata has an invalid integer width",
        )
    })?;
    Ok(Some(u64::from_le_bytes(value)))
}

fn extension<'a>(metadata: &'a ArchiveMetadata, key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .extensions()
        .iter()
        .rev()
        .find(|extension| extension.namespace() == "rar5" && extension.key() == key)
        .map(libarchive_oxide_core::Extension::value)
}

fn entry_split(metadata: &EntryMetadata) -> Result<Option<PhysicalSplit>, StreamError> {
    let Some(value) = entry_extension(metadata, b"split") else {
        return Ok(None);
    };
    if value.len() != 2 || !matches!(value[0], 0 | 1) || !matches!(value[1], 0 | 1) {
        return Err(rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 split metadata has an invalid provider value",
        )
        .into());
    }
    let split = PhysicalSplit {
        before: value[0] == 1,
        after: value[1] == 1,
    };
    if !split.before && !split.after {
        return Err(rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 split metadata carries no split direction",
        )
        .into());
    }
    Ok(Some(split))
}

fn entry_crc32(metadata: &EntryMetadata) -> Result<Option<u32>, StreamError> {
    let Some(value) = entry_extension(metadata, b"data-crc32") else {
        return Ok(None);
    };
    let value: [u8; 4] = value.try_into().map_err(|_| {
        rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 split CRC-32 metadata has an invalid width",
        )
    })?;
    Ok(Some(u32::from_be_bytes(value)))
}

fn entry_compression(metadata: &EntryMetadata) -> Result<Rar5CompressionInfo, StreamError> {
    let value = entry_extension(metadata, b"compression-info").ok_or_else(|| {
        rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 entry omitted its compression information",
        )
    })?;
    let value: [u8; 8] = value.try_into().map_err(|_| {
        rar5_volume_error(
            ErrorKind::Protocol,
            "RAR5 compression information has an invalid width",
        )
    })?;
    Rar5CompressionInfo::from_raw(u64::from_le_bytes(value)).map_err(StreamError::archive)
}

fn validate_continuation(first: &EntryMetadata, next: &EntryMetadata) -> Result<(), StreamError> {
    let size_matches =
        first.size().is_none() || next.size().is_none() || first.size() == next.size();
    let stable_extensions_match = [
        b"compression-info".as_slice(),
        b"solid".as_slice(),
        b"file-version".as_slice(),
        b"windows-attributes".as_slice(),
    ]
    .into_iter()
    .all(|key| entry_extension(first, key) == entry_extension(next, key));
    if first.kind() != next.kind()
        || first.path() != next.path()
        || !size_matches
        || first.link_target() != next.link_target()
        || first.mode() != next.mode()
        || first.owner() != next.owner()
        || first.times() != next.times()
        || first.inode() != next.inode()
        || first.links() != next.links()
        || first.device() != next.device()
        || first.referenced_device() != next.referenced_device()
        || first.sparse_extents() != next.sparse_extents()
        || first.xattrs() != next.xattrs()
        || first.acl() != next.acl()
        || first.file_flags() != next.file_flags()
        || first.is_encrypted() != next.is_encrypted()
        || first.comment() != next.comment()
        || !stable_extensions_match
    {
        return Err(rar5_volume_error(
            ErrorKind::Malformed,
            "RAR5 split continuation metadata does not match its first part",
        )
        .into());
    }
    Ok(())
}

fn entry_extension<'a>(metadata: &'a EntryMetadata, key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .extensions()
        .iter()
        .rev()
        .find(|extension| extension.namespace() == "rar5" && extension.key() == key)
        .map(Extension::value)
}

fn rar5_volume_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("rar5")
        .with_context(context)
}
