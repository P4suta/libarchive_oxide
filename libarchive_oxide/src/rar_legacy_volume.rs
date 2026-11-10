// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded sequencing of complete and split entries across physical RAR 3.x/4.x volumes.

use std::fmt;
use std::sync::Arc;

use libarchive_oxide_core::{
    AccessMode, ArchiveError, ArchiveMetadata, ChecksumAlgorithm, DirectionSet, EntryMetadata,
    ErrorKind, Extension, FormatId, Limits, ProbeResult,
};
#[cfg(feature = "rar")]
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput};

use crate::filter::Crc32;
#[cfg(feature = "rar")]
use crate::provider::{BuiltinPayloadDecoder, builtin_split_rar3_decoder};
use crate::provider::{
    BuiltinRarLegacyDecoder, FormatCapabilities, FormatProvider, FormatProviderNode,
    NoArchiveEncoder, NoCodecProviders, NoFormatProviders, ProviderSet, builtin_rar_legacy_decoder,
};
use crate::range_source::{RangeReader, ReadAt, SourceLimits, VolumeId, VolumeSet};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
use crate::{ArchiveReader, OpenOptions, ReaderEvent, StreamError};

const SIGNATURE: &[u8; 7] = b"Rar!\x1a\x07\x00";
const MHD_VOLUME: u16 = 0x0001;
const MHD_FIRSTVOLUME: u16 = 0x0100;
#[cfg(feature = "rar")]
const SPLIT_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
struct RarLegacyPhysicalProvider;

impl FormatProvider for RarLegacyPhysicalProvider {
    type Decoder = BuiltinRarLegacyDecoder;
    type Encoder = NoArchiveEncoder;

    fn format(&self) -> FormatId {
        FormatId::RarLegacy
    }

    fn name(&self) -> &'static str {
        "rar-legacy-physical-volume"
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
        Ok(builtin_rar_legacy_decoder(limits, true, Vec::new()))
    }

    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Err(rar_volume_error(
            ErrorKind::Unsupported,
            "RAR writing is license-excluded",
        ))
    }
}

type PhysicalProviders = FormatProviderNode<RarLegacyPhysicalProvider, NoFormatProviders>;
type PhysicalReader =
    ArchiveReader<RangeReader<Arc<dyn ReadAt>>, PhysicalProviders, NoCodecProviders>;

/// Built-in provider for physical RAR 3.x/4.x sets.
///
/// Split Store parts stream directly.
/// Non-solid RAR3 LZ parts are collected within explicit whole-payload limits and decoded through the static codec provider.
/// Both are checksum-verified and exposed as one logical entry.
/// Since the logical CRC is stored in the final part, the initial [`ReaderEvent::Entry`] has no typed checksum; validation completes before the single [`ReaderEvent::EndEntry`].
/// `PPMd`, solid compression, and encryption remain typed unsupported paths.
#[derive(Debug, Default)]
pub struct RarLegacyVolumeProvider;

impl RarLegacyVolumeProvider {
    /// Creates the stateless legacy RAR volume provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomAccessFormatProvider for RarLegacyVolumeProvider {
    type Decoder = RarLegacyVolumeReader;

    fn format(&self) -> FormatId {
        FormatId::RarLegacy
    }

    fn name(&self) -> &'static str {
        "rar-legacy-volume"
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
        RarLegacyVolumeReader::with_limits(source, limits)
    }

    fn open_with_options(
        &self,
        source: Arc<VolumeSet>,
        options: &OpenOptions,
    ) -> Result<Self::Decoder, StreamError> {
        if options.has_password_provider() {
            return Err(rar_volume_error(
                ErrorKind::Unsupported,
                "RAR volume encryption is not implemented",
            )
            .into());
        }
        RarLegacyVolumeReader::from_options(source, options)
    }
}

/// Event reader over a caller-owned sequence of physical RAR 3.x/4.x volumes.
pub struct RarLegacyVolumeReader {
    volumes: Arc<VolumeSet>,
    limits: Limits,
    source_limits: SourceLimits,
    reader: Option<PhysicalReader>,
    volume: u32,
    physical_metadata_seen: bool,
    next_volume: Option<bool>,
    consumed_entries: u64,
    consumed_decoded: u64,
    entry_open: bool,
    split_entry: Option<SplitEntry>,
    #[cfg(feature = "rar")]
    split_payload: SplitPayloadState,
    #[cfg(feature = "rar")]
    packed_data: Vec<u8>,
    #[cfg(feature = "rar")]
    packed_offset: usize,
    done: bool,
    event_data: Vec<u8>,
}

impl fmt::Debug for RarLegacyVolumeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RarLegacyVolumeReader")
            .field("volume", &self.volume)
            .field("entry_open", &self.entry_open)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl RarLegacyVolumeReader {
    /// Opens a legacy RAR volume set with finite safe defaults.
    pub fn new(source: Arc<VolumeSet>) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::safe())
    }

    /// Opens a legacy RAR volume set with explicit archive limits.
    pub fn with_limits(source: Arc<VolumeSet>, limits: Limits) -> Result<Self, StreamError> {
        let source_limits = source.limits();
        Self::open(source, limits, source_limits)
    }

    /// Opens the volume set carried by common options.
    pub fn with_options(options: &OpenOptions) -> Result<Self, StreamError> {
        let source = options.volumes().ok_or_else(|| {
            rar_volume_error(
                ErrorKind::Capability,
                "RarLegacyVolumeReader requires OpenOptions containing VolumeSet",
            )
        })?;
        if options.adjacent_volume_discovery() {
            return Err(rar_volume_error(
                ErrorKind::Capability,
                "adjacent volume discovery is available only for path-based opens",
            )
            .into());
        }
        if options.filter().is_some() {
            return Err(rar_volume_error(
                ErrorKind::Capability,
                "outer filters are not supported around RAR volume sets",
            )
            .into());
        }
        if options.has_password_provider() {
            return Err(rar_volume_error(
                ErrorKind::Unsupported,
                "RAR volume encryption is not implemented",
            )
            .into());
        }
        if options.source_limits() != source.limits() {
            return Err(rar_volume_error(
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
            consumed_entries: 0,
            consumed_decoded: 0,
            entry_open: false,
            split_entry: None,
            #[cfg(feature = "rar")]
            split_payload: SplitPayloadState::Idle,
            #[cfg(feature = "rar")]
            packed_data: Vec::new(),
            #[cfg(feature = "rar")]
            packed_offset: 0,
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
            match self.drive_split_payload()? {
                SplitPayloadProgress::Data => return Ok(ReaderEvent::Data(&self.event_data)),
                SplitPayloadProgress::Finished => {
                    self.split_payload = SplitPayloadState::Idle;
                    if self.finish_logical_entry()? {
                        return Ok(ReaderEvent::EndEntry);
                    }
                },
                SplitPayloadProgress::Idle => {},
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
                        validate_main_metadata(&metadata, self.volume)?;
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
                PhysicalEvent::CompressedData => self.append_packed_data()?,
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
            rar_volume_error(ErrorKind::Protocol, "RAR physical reader is missing")
        })?;
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(metadata) => Ok(PhysicalEvent::Metadata(metadata)),
            ReaderEvent::Entry(metadata) => Ok(PhysicalEvent::Entry(Box::new(metadata))),
            ReaderEvent::Data(data) => {
                self.event_data.clear();
                self.event_data.try_reserve(data.len()).map_err(|_| {
                    rar_volume_error(ErrorKind::Limit, "RAR volume event allocation failed")
                })?;
                self.event_data.extend_from_slice(data);
                #[cfg(feature = "rar")]
                if matches!(self.split_payload, SplitPayloadState::Collecting) {
                    return Ok(PhysicalEvent::CompressedData);
                }
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
        if let Some(logical) = &mut self.split_entry {
            let split = split.ok_or_else(|| {
                rar_volume_error(
                    ErrorKind::Malformed,
                    "RAR split entry is not continued in the next physical file",
                )
            })?;
            if !split.before {
                return Err(rar_volume_error(
                    ErrorKind::Malformed,
                    "RAR split continuation omits the previous-volume flag",
                )
                .into());
            }
            validate_continuation(&logical.metadata, &metadata)?;
            if logical.logical_size != metadata.size() {
                return Err(rar_volume_error(
                    ErrorKind::Malformed,
                    "RAR split continuation changes its logical size",
                )
                .into());
            }
            logical.part_after = split.after;
            logical.final_crc = if split.after {
                None
            } else {
                entry_crc32(&metadata)?
            };
            return Ok(None);
        }
        if split.is_some_and(|flags| flags.before) {
            return Err(rar_volume_error(
                ErrorKind::Malformed,
                "RAR first logical file part has a previous-volume flag",
            )
            .into());
        }
        self.entry_open = true;
        if split.is_some_and(|flags| flags.after) {
            let (method, version) = entry_compression(&metadata)?;
            #[cfg(not(feature = "rar"))]
            let _ = version;
            let compressed = method != 0x30 && !metadata.is_encrypted();
            #[cfg(feature = "rar")]
            if compressed {
                self.split_payload = SplitPayloadState::Collecting;
                self.packed_data.clear();
                self.packed_offset = 0;
            }
            #[cfg(not(feature = "rar"))]
            if compressed {
                return Err(rar_volume_error(
                    ErrorKind::Unsupported,
                    "split compressed RAR entry requires the rar feature",
                )
                .into());
            }
            self.split_entry = Some(SplitEntry {
                logical_size: metadata.size(),
                metadata: metadata.clone(),
                crc: Crc32::new(),
                decoded: 0,
                part_after: true,
                compressed,
                #[cfg(feature = "rar")]
                method,
                #[cfg(feature = "rar")]
                version,
                final_crc: None,
            });
        }
        Ok(Some(metadata))
    }

    #[cfg(feature = "rar")]
    fn append_packed_data(&mut self) -> Result<(), StreamError> {
        let unpacked = self
            .split_entry
            .as_ref()
            .and_then(|split| split.logical_size)
            .ok_or_else(|| {
                rar_volume_error(
                    ErrorKind::Malformed,
                    "split compressed RAR entry has no logical size",
                )
            })?;
        let new_len = self
            .packed_data
            .len()
            .checked_add(self.event_data.len())
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "split RAR packed size overflow"))?;
        let retained_peak = u64::try_from(new_len)
            .ok()
            .and_then(|packed| packed.checked_mul(2))
            .and_then(|packed| packed.checked_add(unpacked))
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "split RAR memory size overflow"))?;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|maximum| retained_peak > maximum as u64)
        {
            return Err(rar_volume_error(
                ErrorKind::Limit,
                "split RAR packed and decoded buffers exceed the in-flight budget",
            )
            .into());
        }
        self.packed_data
            .try_reserve(self.event_data.len())
            .map_err(|_| {
                rar_volume_error(ErrorKind::Limit, "split RAR packed allocation failed")
            })?;
        self.packed_data.extend_from_slice(&self.event_data);
        Ok(())
    }

    fn observe_physical_data(&mut self) -> Result<(), StreamError> {
        let Some(split) = &mut self.split_entry else {
            return Ok(());
        };
        split.crc.update(&self.event_data);
        split.decoded = split
            .decoded
            .checked_add(self.event_data.len() as u64)
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "RAR split entry size overflow"))?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| split.decoded > maximum)
        {
            return Err(rar_volume_error(
                ErrorKind::Limit,
                "RAR split entry exceeds the configured entry-byte budget",
            )
            .into());
        }
        if split
            .logical_size
            .is_some_and(|declared| split.decoded > declared)
        {
            return Err(rar_volume_error(
                ErrorKind::Malformed,
                "RAR split data exceeds its declared logical size",
            )
            .into());
        }
        Ok(())
    }

    fn end_physical_entry(&mut self) -> Result<bool, StreamError> {
        if self
            .split_entry
            .as_ref()
            .is_some_and(|split| split.part_after)
        {
            return Ok(false);
        }
        #[cfg(feature = "rar")]
        if self
            .split_entry
            .as_ref()
            .is_some_and(|split| split.compressed)
            && matches!(self.split_payload, SplitPayloadState::Collecting)
        {
            let split = self.split_entry.as_ref().ok_or_else(|| {
                rar_volume_error(ErrorKind::Protocol, "split RAR entry state is missing")
            })?;
            let unpacked_size = split.logical_size.ok_or_else(|| {
                rar_volume_error(
                    ErrorKind::Malformed,
                    "split compressed RAR entry has no logical size",
                )
            })?;
            let packed_size = u64::try_from(self.packed_data.len()).map_err(|_| {
                rar_volume_error(ErrorKind::Limit, "split RAR packed size exceeds u64")
            })?;
            let decoder = builtin_split_rar3_decoder(
                split.method,
                split.version,
                packed_size,
                unpacked_size,
                self.packed_data.len(),
                self.remaining_limits()?,
            )
            .map_err(StreamError::archive)?;
            self.split_payload = SplitPayloadState::Decoding(decoder);
            self.packed_offset = 0;
            return Ok(false);
        }
        self.finish_logical_entry()
    }

    fn finish_logical_entry(&mut self) -> Result<bool, StreamError> {
        if let Some(split) = self.split_entry.take() {
            if split
                .logical_size
                .is_some_and(|declared| split.decoded != declared)
            {
                return Err(rar_volume_error(
                    ErrorKind::Malformed,
                    "RAR split data does not match its declared logical size",
                )
                .into());
            }
            if split
                .final_crc
                .is_some_and(|expected| split.crc.finalize() != expected)
            {
                return Err(rar_volume_error(
                    ErrorKind::Integrity,
                    "RAR split entry CRC32 does not match its logical payload",
                )
                .into());
            }
            if split.compressed {
                self.consumed_decoded = self
                    .consumed_decoded
                    .checked_add(split.decoded)
                    .ok_or_else(|| {
                        rar_volume_error(ErrorKind::Limit, "RAR decoded size overflow")
                    })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|maximum| self.consumed_decoded > maximum)
                {
                    return Err(rar_volume_error(
                        ErrorKind::Limit,
                        "RAR volumes exceed the logical decoded-byte budget",
                    )
                    .into());
                }
            }
        }
        self.entry_open = false;
        Ok(true)
    }

    #[cfg(feature = "rar")]
    fn drive_split_payload(&mut self) -> Result<SplitPayloadProgress, StreamError> {
        let codec = match &mut self.split_payload {
            SplitPayloadState::Idle | SplitPayloadState::Collecting => {
                return Ok(SplitPayloadProgress::Idle);
            },
            SplitPayloadState::Decoding(codec) => codec,
            SplitPayloadState::Finished => return Ok(SplitPayloadProgress::Finished),
        };
        if self.packed_offset > self.packed_data.len() {
            return Err(rar_volume_error(
                ErrorKind::Protocol,
                "split RAR codec input offset exceeds its buffer",
            )
            .into());
        }
        let input = &self.packed_data[self.packed_offset..];
        self.event_data.clear();
        self.event_data
            .try_reserve(SPLIT_OUTPUT_BYTES)
            .map_err(|_| {
                rar_volume_error(ErrorKind::Limit, "split RAR codec output allocation failed")
            })?;
        self.event_data.resize(SPLIT_OUTPUT_BYTES, 0);
        let step = codec
            .process(input, &mut self.event_data, EndOfInput::End)
            .map_err(StreamError::archive)?
            .validate(input.len(), self.event_data.len())
            .map_err(StreamError::archive)?;
        self.packed_offset = self
            .packed_offset
            .checked_add(step.consumed)
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "split RAR input offset overflow"))?;
        self.event_data.truncate(step.produced);

        if matches!(step.status, CodecStatus::Done) {
            if self.packed_offset != self.packed_data.len() {
                return Err(rar_volume_error(
                    ErrorKind::Malformed,
                    "split RAR codec left trailing packed data",
                )
                .into());
            }
            self.split_payload = SplitPayloadState::Finished;
        } else if step.consumed == 0 && step.produced == 0 {
            return Err(
                rar_volume_error(ErrorKind::Protocol, "split RAR codec made no progress").into(),
            );
        }

        if self.packed_offset == self.packed_data.len() {
            self.packed_data = Vec::new();
            self.packed_offset = 0;
        }
        if !self.event_data.is_empty() {
            self.observe_physical_data()?;
            return Ok(SplitPayloadProgress::Data);
        }
        if matches!(self.split_payload, SplitPayloadState::Finished) {
            Ok(SplitPayloadProgress::Finished)
        } else {
            Ok(SplitPayloadProgress::Idle)
        }
    }

    fn advance_physical_volume(&mut self) -> Result<bool, StreamError> {
        if (self.entry_open && self.split_entry.is_none()) || !self.physical_metadata_seen {
            return Err(rar_volume_error(
                ErrorKind::Protocol,
                "RAR physical volume ended in an invalid state",
            )
            .into());
        }
        let next = self.next_volume.ok_or_else(|| {
            rar_volume_error(
                ErrorKind::Protocol,
                "RAR physical volume omitted its end marker",
            )
        })?;
        if self.split_entry.is_some() && !next {
            return Err(rar_volume_error(
                ErrorKind::Malformed,
                "RAR volume set ends before its split entry is complete",
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
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "RAR volume index overflow"))?;
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
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "RAR entry count overflow"))?;
        self.consumed_decoded = self
            .consumed_decoded
            .checked_add(end.decoded)
            .ok_or_else(|| rar_volume_error(ErrorKind::Limit, "RAR decoded size overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.consumed_entries > maximum)
            || self
                .limits
                .decoded_total()
                .is_some_and(|maximum| self.consumed_decoded > maximum)
        {
            return Err(rar_volume_error(
                ErrorKind::Limit,
                "RAR physical volumes exceed the logical archive budget",
            )
            .into());
        }
        Ok(())
    }

    fn remaining_limits(&self) -> Result<Limits, StreamError> {
        let entries = match self.limits.entries() {
            Some(maximum) => {
                Some(maximum.checked_sub(self.consumed_entries).ok_or_else(|| {
                    rar_volume_error(ErrorKind::Limit, "RAR entry budget underflow")
                })?)
            },
            None => None,
        };
        let decoded = match self.limits.decoded_total() {
            Some(maximum) => Some(maximum.checked_sub(self.consumed_decoded).ok_or_else(|| {
                rar_volume_error(ErrorKind::Limit, "RAR decoded budget underflow")
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
            return Err(rar_volume_error(
                ErrorKind::Protocol,
                "skip_entry called without an open RAR entry",
            )
            .into());
        }
        loop {
            match self.next_event()? {
                ReaderEvent::Data(_) => {},
                ReaderEvent::EndEntry => return Ok(()),
                _ => {
                    return Err(rar_volume_error(
                        ErrorKind::Protocol,
                        "RAR entry ended without an end-entry event",
                    )
                    .into());
                },
            }
        }
    }
}

impl RandomAccessArchiveDecoder for RarLegacyVolumeReader {
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
enum SplitPayloadProgress {
    Idle,
    Data,
    Finished,
}

#[cfg(feature = "rar")]
// The decoder is fixed-size and input-independent.
// Keeping it inline preserves the closed state machine and static dispatch without heap indirection.
#[allow(clippy::large_enum_variant)]
enum SplitPayloadState {
    Idle,
    Collecting,
    Decoding(BuiltinPayloadDecoder),
    Finished,
}

struct SplitEntry {
    metadata: EntryMetadata,
    crc: Crc32,
    decoded: u64,
    logical_size: Option<u64>,
    part_after: bool,
    compressed: bool,
    #[cfg(feature = "rar")]
    method: u8,
    #[cfg(feature = "rar")]
    version: u8,
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
    let providers = ProviderSet::empty().with_format_provider(RarLegacyPhysicalProvider);
    ArchiveReader::with_providers_and_format(input, FormatId::RarLegacy, limits, providers)
        .map_err(StreamError::archive)
}

fn validate_main_metadata(metadata: &ArchiveMetadata, volume: u32) -> Result<(), StreamError> {
    let flags = extension_u16(metadata, b"main-flags")?.ok_or_else(|| {
        rar_volume_error(
            ErrorKind::Malformed,
            "RAR physical volume omitted its main flags",
        )
    })?;
    if flags & MHD_VOLUME == 0 {
        return Err(rar_volume_error(
            ErrorKind::Malformed,
            "RAR physical source is not marked as a volume archive",
        )
        .into());
    }
    if volume != 0 && flags & MHD_FIRSTVOLUME != 0 {
        return Err(rar_volume_error(
            ErrorKind::Malformed,
            "RAR continuation is incorrectly marked as the first volume",
        )
        .into());
    }
    Ok(())
}

fn physical_end(metadata: &ArchiveMetadata) -> Result<Option<PhysicalEnd>, StreamError> {
    let Some(value) = extension(metadata, b"physical-volume-end") else {
        return Ok(None);
    };
    if value.len() != 17 || !matches!(value[0], 0 | 1) {
        return Err(rar_volume_error(
            ErrorKind::Protocol,
            "RAR physical end marker has an invalid provider value",
        )
        .into());
    }
    let entries = u64::from_le_bytes(value[1..9].try_into().map_err(|_| {
        rar_volume_error(ErrorKind::Protocol, "RAR physical entry count is invalid")
    })?);
    let decoded = u64::from_le_bytes(value[9..17].try_into().map_err(|_| {
        rar_volume_error(ErrorKind::Protocol, "RAR physical decoded size is invalid")
    })?);
    Ok(Some(PhysicalEnd {
        next: value[0] == 1,
        entries,
        decoded,
    }))
}

fn extension_u16(metadata: &ArchiveMetadata, key: &[u8]) -> Result<Option<u16>, StreamError> {
    let Some(value) = extension(metadata, key) else {
        return Ok(None);
    };
    let value: [u8; 2] = value.try_into().map_err(|_| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR provider metadata has an invalid integer width",
        )
    })?;
    Ok(Some(u16::from_le_bytes(value)))
}

fn extension<'a>(metadata: &'a ArchiveMetadata, key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .extensions()
        .iter()
        .rev()
        .find(|extension| extension.namespace() == "rar-legacy" && extension.key() == key)
        .map(libarchive_oxide_core::Extension::value)
}

fn entry_split(metadata: &EntryMetadata) -> Result<Option<PhysicalSplit>, StreamError> {
    let flags = entry_extension_u16(metadata, b"file-flags")?.ok_or_else(|| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR physical entry omitted its file flags",
        )
    })?;
    let split = PhysicalSplit {
        before: flags & 0x0001 != 0,
        after: flags & 0x0002 != 0,
    };
    Ok((split.before || split.after).then_some(split))
}

fn entry_crc32(metadata: &EntryMetadata) -> Result<Option<u32>, StreamError> {
    let Some(checksum) = metadata.checksum() else {
        return Ok(None);
    };
    if checksum.algorithm() != ChecksumAlgorithm::Crc32 {
        return Err(rar_volume_error(
            ErrorKind::Protocol,
            "RAR physical entry carries an unexpected checksum algorithm",
        )
        .into());
    }
    let value: [u8; 4] = checksum.as_bytes().try_into().map_err(|_| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR physical CRC32 metadata has an invalid width",
        )
    })?;
    Ok(Some(u32::from_be_bytes(value)))
}

fn entry_compression(metadata: &EntryMetadata) -> Result<(u8, u8), StreamError> {
    let method = entry_extension(metadata, b"compression-method")
        .and_then(|value| value.first())
        .copied()
        .ok_or_else(|| {
            rar_volume_error(
                ErrorKind::Protocol,
                "RAR entry omitted its compression method",
            )
        })?;
    let version = entry_extension(metadata, b"unpack-version")
        .and_then(|value| value.first())
        .copied()
        .ok_or_else(|| {
            rar_volume_error(ErrorKind::Protocol, "RAR entry omitted its unpack version")
        })?;
    Ok((method, version))
}

fn validate_continuation(first: &EntryMetadata, next: &EntryMetadata) -> Result<(), StreamError> {
    let first_flags = entry_extension_u16(first, b"file-flags")?.ok_or_else(|| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR first split part omitted its file flags",
        )
    })?;
    let next_flags = entry_extension_u16(next, b"file-flags")?.ok_or_else(|| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR split continuation omitted its file flags",
        )
    })?;
    let stable_extensions_match = [
        b"host-os".as_slice(),
        b"file-attributes".as_slice(),
        b"unpack-version".as_slice(),
        b"file-optional".as_slice(),
    ]
    .into_iter()
    .all(|key| entry_extension(first, key) == entry_extension(next, key));
    if first.kind() != next.kind()
        || first.path() != next.path()
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
        || first_flags & !0x0003 != next_flags & !0x0003
        || !stable_extensions_match
    {
        return Err(rar_volume_error(
            ErrorKind::Malformed,
            "RAR split continuation metadata does not match its first part",
        )
        .into());
    }
    Ok(())
}

fn entry_extension_u16(metadata: &EntryMetadata, key: &[u8]) -> Result<Option<u16>, StreamError> {
    let Some(value) = entry_extension(metadata, key) else {
        return Ok(None);
    };
    let value: [u8; 2] = value.try_into().map_err(|_| {
        rar_volume_error(
            ErrorKind::Protocol,
            "RAR entry metadata has an invalid integer width",
        )
    })?;
    Ok(Some(u16::from_le_bytes(value)))
}

fn entry_extension<'a>(metadata: &'a EntryMetadata, key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .extensions()
        .iter()
        .rev()
        .find(|extension| extension.namespace() == "rar-legacy" && extension.key() == key)
        .map(Extension::value)
}

fn rar_volume_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("rar-legacy")
        .with_context(context)
}
