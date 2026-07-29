// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only UDF 1.02 through 2.60 support for 2048-byte optical images,
//! including bounded Metadata, Sparable, and Virtual Partition/VAT translation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Extension, Limits, Owner, PathEncoding, SparseExtent, Timestamp,
};

use crate::{ReaderEvent, StreamError};

const BLOCK_SIZE: u64 = 2048;
const BLOCK_SIZE_U32: u32 = 2048;
const BLOCK_SIZE_USIZE: usize = 2048;
const VRS_START: u64 = 16;
const VRS_MAX_DESCRIPTORS: u64 = 64;
const TAG_SIZE: usize = 16;
const TAG_PRIMARY_VOLUME: u16 = 1;
const TAG_ANCHOR: u16 = 2;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL_VOLUME: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_IDENTIFIER: u16 = 257;
const TAG_ALLOCATION_EXTENT: u16 = 258;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_ATTRIBUTE_HEADER: u16 = 262;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;
const FILE_TYPE_VAT: u8 = 248;
const FILE_TYPE_METADATA: u8 = 250;
const FILE_TYPE_METADATA_MIRROR: u8 = 251;
const FILE_TYPE_METADATA_BITMAP: u8 = 252;
const TAG_SPACE_BITMAP: u16 = 264;
const FILE_TYPE_STREAM_DIRECTORY: u8 = 13;
const ICB_FLAG_SETUID: u16 = 1 << 6;
const ICB_FLAG_SETGID: u16 = 1 << 7;
const ICB_FLAG_STICKY: u16 = 1 << 8;
const ICB_FLAG_TRANSFORMED: u16 = 1 << 11;
const ICB_FLAG_MULTI_VERSION: u16 = 1 << 12;
const ICB_FLAG_STREAM: u16 = 1 << 13;
const ICB_FLAG_RESERVED: u16 = 0xc000;
const FID_CHARACTERISTIC_DIRECTORY: u8 = 0x02;
const FID_CHARACTERISTIC_DELETED: u8 = 0x04;
const FID_CHARACTERISTIC_PARENT: u8 = 0x08;
const FID_CHARACTERISTIC_METADATA: u8 = 0x10;
const FID_CHARACTERISTIC_RESERVED: u8 = 0xe0;
const LONG_AD_FLAG_ERASED: u16 = 0x0001;
const LONG_AD_FLAG_RESERVED: u16 = !LONG_AD_FLAG_ERASED;
const BUFFER: usize = 64 * 1024;
const MAX_FID_SIZE: usize = BLOCK_SIZE_USIZE;
const MAX_FSD_EXTENTS: usize = 64;
const MAX_VAT_DISCOVERY_BLOCKS: u32 = 4096;
const MAX_VAT_HISTORY_DEPTH: usize = 64;
const MAX_SPARING_TABLES: usize = 4;
const SPARING_TABLE_HEADER_SIZE: usize = 56;
const SPARING_TABLE_HEADER_SIZE_U32: u32 = 56;
const SPARING_ENTRY_SIZE: usize = 8;
const SPARING_ENTRY_DEFECTIVE: u32 = 0xffff_fff0;
const SPARING_ENTRY_AVAILABLE: u32 = u32::MAX;
const UDF_STREAM_PATH_PREFIX: &[u8] = b".libarchive-oxide-udf-streams/";

/// Returns whether the Volume Recognition Sequence selects UDF.
///
/// ISO/UDF bridge images can place ISO descriptors before the ECMA-167
/// `BEA01`/`NSR0x` records, so this deliberately scans the bounded VRS rather
/// than checking only sectors 16 and 17.
pub(crate) fn probe_vrs<R: Read + Seek>(input: &mut R) -> Result<bool, StreamError> {
    let saved = input.stream_position().map_err(StreamError::io)?;
    let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
    let blocks = image_length / BLOCK_SIZE;
    let mut saw_bea = false;
    let mut matched = false;
    for block in VRS_START..VRS_START.saturating_add(VRS_MAX_DESCRIPTORS).min(blocks) {
        let offset = block
            .checked_mul(BLOCK_SIZE)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "VRS offset overflow"))?;
        input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut identifier = [0_u8; 5];
        input.read_exact(&mut identifier).map_err(StreamError::io)?;
        match &identifier {
            b"BEA01" => saw_bea = true,
            b"NSR02" | b"NSR03" if saw_bea => {
                matched = true;
                break;
            },
            b"TEA01" if saw_bea => break,
            _ => {},
        }
    }
    input
        .seek(SeekFrom::Start(saved))
        .map_err(StreamError::io)?;
    Ok(matched)
}

#[derive(Debug, Clone)]
struct UdfIndex {
    metadata: EntryMetadata,
    payload: UdfPayload,
}

#[derive(Debug, Clone)]
enum UdfPayload {
    None,
    Inline { data: Vec<u8>, tag_location: u32 },
    Extents(Vec<UdfExtent>),
}

#[derive(Debug, Clone)]
struct UdfExtent {
    source_offset: Option<u64>,
    length: u64,
    logical_block: u32,
}

#[derive(Debug)]
enum UdfBody {
    Idle,
    Data(UdfDataCursor),
    EndEntry,
    Done,
}

/// Seek-native, read-only UDF archive reader.
#[derive(Debug)]
pub(crate) struct UdfSeekReader<R> {
    input: R,
    limits: Limits,
    archive_metadata: Option<ArchiveMetadata>,
    entries: Vec<UdfIndex>,
    next_entry: usize,
    body: UdfBody,
    event_data: Vec<u8>,
    event_chunk: usize,
    decoded_total: u64,
}

impl<R: Read + Seek> UdfSeekReader<R> {
    pub(crate) fn new(mut input: R, limits: Limits) -> Result<Self, StreamError> {
        if !probe_vrs(&mut input)? {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF Volume Recognition Sequence is missing",
            ));
        }
        let (archive_metadata, entries, decoded_total) =
            UdfParser::new(&mut input, limits)?.parse()?;
        let event_chunk = limits.in_flight_bytes().unwrap_or(BUFFER).min(BUFFER);
        Ok(Self {
            input,
            limits,
            archive_metadata: Some(archive_metadata),
            entries,
            next_entry: 0,
            body: UdfBody::Idle,
            event_data: Vec::with_capacity(event_chunk),
            event_chunk,
            decoded_total,
        })
    }

    pub(crate) fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        if let Some(metadata) = self.archive_metadata.take() {
            return Ok(ReaderEvent::ArchiveMetadata(metadata));
        }
        loop {
            match &mut self.body {
                UdfBody::Idle => {
                    let Some(entry) = self.entries.get(self.next_entry).cloned() else {
                        self.body = UdfBody::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    self.next_entry += 1;
                    self.body = match entry.payload {
                        UdfPayload::None => UdfBody::EndEntry,
                        payload => UdfBody::Data(UdfDataCursor::new(
                            payload,
                            entry.metadata.size().unwrap_or(0),
                        )?),
                    };
                    return Ok(ReaderEvent::Entry(entry.metadata));
                },
                UdfBody::Data(cursor) => {
                    if cursor.remaining == 0 {
                        self.body = UdfBody::EndEntry;
                        continue;
                    }
                    if self.event_chunk == 0 {
                        return Err(udf_error(
                            ErrorKind::Limit,
                            "UDF payload cannot progress under a zero in-flight byte limit",
                        ));
                    }
                    let count = usize::try_from(cursor.remaining.min(self.event_chunk as u64))
                        .map_err(|_| {
                            udf_error(ErrorKind::Limit, "UDF extent read exceeds address space")
                        })?;
                    self.event_data.resize(count, 0);
                    cursor.read_exact(&mut self.input, &mut self.event_data)?;
                    self.decoded_total = self
                        .decoded_total
                        .checked_add(count as u64)
                        .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF decoded total overflow"))?;
                    if self
                        .limits
                        .decoded_total()
                        .is_some_and(|maximum| self.decoded_total > maximum)
                    {
                        return Err(udf_error(
                            ErrorKind::Limit,
                            "UDF decoded total exceeds configured limit",
                        ));
                    }
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                UdfBody::EndEntry => {
                    self.body = UdfBody::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                UdfBody::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> Result<(), StreamError> {
        match self.body {
            UdfBody::Data(_) | UdfBody::EndEntry => {
                self.body = UdfBody::EndEntry;
                Ok(())
            },
            _ => Err(udf_error(
                ErrorKind::Protocol,
                "skip_entry called without an open UDF payload",
            )),
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.input
    }

    pub(crate) const fn source_ref(&self) -> &R {
        &self.input
    }
}

#[derive(Debug)]
struct UdfDataCursor {
    payload: UdfPayload,
    extent_index: usize,
    extent_offset: u64,
    inline_offset: usize,
    position: u64,
    remaining: u64,
}

impl UdfDataCursor {
    fn new(payload: UdfPayload, length: u64) -> Result<Self, StreamError> {
        let available = payload_length(&payload)?;
        if available < length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF allocation descriptors do not cover information length",
            ));
        }
        Ok(Self {
            payload,
            extent_index: 0,
            extent_offset: 0,
            inline_offset: 0,
            position: 0,
            remaining: length,
        })
    }

    fn advance_exhausted_extents(&mut self) -> Result<(), StreamError> {
        let UdfPayload::Extents(extents) = &self.payload else {
            return Ok(());
        };
        loop {
            let Some(extent) = extents.get(self.extent_index) else {
                return Ok(());
            };
            if self.extent_offset > extent.length {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF extent cursor advanced past its extent",
                ));
            }
            if self.extent_offset != extent.length {
                return Ok(());
            }
            self.extent_index += 1;
            self.extent_offset = 0;
        }
    }

    fn tag_location(&mut self) -> Result<u32, StreamError> {
        self.advance_exhausted_extents()?;
        match &self.payload {
            UdfPayload::None => Err(udf_error(
                ErrorKind::Malformed,
                "empty UDF payload has no tag location",
            )),
            UdfPayload::Inline { tag_location, .. } => Ok(*tag_location),
            UdfPayload::Extents(extents) => {
                let extent = extents.get(self.extent_index).ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF extent cursor is outside payload")
                })?;
                let block_delta = u32::try_from(self.extent_offset / BLOCK_SIZE)
                    .map_err(|_| udf_error(ErrorKind::Malformed, "UDF tag location exceeds u32"))?;
                extent
                    .logical_block
                    .checked_add(block_delta)
                    .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF tag location overflow"))
            },
        }
    }

    fn read_exact<R: Read + Seek>(
        &mut self,
        input: &mut R,
        mut output: &mut [u8],
    ) -> Result<(), StreamError> {
        if output.len() as u64 > self.remaining {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF payload read exceeds information length",
            ));
        }
        while !output.is_empty() {
            match &self.payload {
                UdfPayload::None => {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF payload ended before declared length",
                    ));
                },
                UdfPayload::Inline { data, .. } => {
                    let available = data.len().saturating_sub(self.inline_offset);
                    let count = available.min(output.len());
                    if count == 0 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "embedded UDF payload is truncated",
                        ));
                    }
                    output[..count].copy_from_slice(
                        &data[self.inline_offset..self.inline_offset.saturating_add(count)],
                    );
                    self.inline_offset += count;
                    self.position = self.position.checked_add(count as u64).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF payload position overflow")
                    })?;
                    self.remaining -= count as u64;
                    output = &mut output[count..];
                },
                UdfPayload::Extents(extents) => {
                    let Some(extent) = extents.get(self.extent_index) else {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF extents end before information length",
                        ));
                    };
                    let available = extent.length.saturating_sub(self.extent_offset);
                    if available == 0 {
                        self.extent_index += 1;
                        self.extent_offset = 0;
                        continue;
                    }
                    let count =
                        usize::try_from(available.min(output.len() as u64)).map_err(|_| {
                            udf_error(ErrorKind::Limit, "UDF extent chunk exceeds address space")
                        })?;
                    if let Some(source) = extent.source_offset {
                        let offset = source.checked_add(self.extent_offset).ok_or_else(|| {
                            udf_error(ErrorKind::Malformed, "UDF source offset overflow")
                        })?;
                        input
                            .seek(SeekFrom::Start(offset))
                            .map_err(StreamError::io)?;
                        input
                            .read_exact(&mut output[..count])
                            .map_err(StreamError::io)?;
                    } else {
                        output[..count].fill(0);
                    }
                    self.extent_offset += count as u64;
                    self.position = self.position.checked_add(count as u64).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF payload position overflow")
                    })?;
                    self.remaining -= count as u64;
                    output = &mut output[count..];
                },
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct UdfDirectoryFid {
    characteristics: u8,
    icb: IcbAddress,
    unique_id: u32,
    identifier: Vec<u8>,
}

#[derive(Debug)]
struct UdfDirectoryCursor {
    data: UdfDataCursor,
    fid_buffer: Vec<u8>,
    expected_parent: IcbAddress,
    expected_parent_unique_id: Option<u32>,
    saw_parent: bool,
}

impl UdfDirectoryCursor {
    fn new(
        payload: UdfPayload,
        length: u64,
        expected_parent: IcbAddress,
        expected_parent_unique_id: Option<u32>,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        let fid_buffer_size = limits
            .in_flight_bytes()
            .map_or(MAX_FID_SIZE, |maximum| {
                maximum.saturating_sub(u8::MAX as usize)
            })
            .min(MAX_FID_SIZE);
        Ok(Self {
            data: UdfDataCursor::new(payload, length)?,
            fid_buffer: vec![0_u8; fid_buffer_size],
            expected_parent,
            expected_parent_unique_id,
            saw_parent: false,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn next<R: Read + Seek>(
        &mut self,
        input: &mut R,
    ) -> Result<Option<UdfDirectoryFid>, StreamError> {
        loop {
            if self.data.remaining == 0 {
                if !self.saw_parent {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF directory is missing its parent FID",
                    ));
                }
                return Ok(None);
            }
            if self.data.remaining < TAG_SIZE as u64 {
                let count = usize::try_from(self.data.remaining).map_err(|_| {
                    udf_error(ErrorKind::Limit, "UDF directory tail exceeds address space")
                })?;
                let mut tail = [0_u8; TAG_SIZE];
                self.data.read_exact(input, &mut tail[..count])?;
                if tail[..count].iter().any(|byte| *byte != 0) {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "truncated UDF File Identifier Descriptor",
                    ));
                }
                continue;
            }
            let tag_location = self.data.tag_location()?;
            let record_position = self.data.position;
            let mut head = [0_u8; 38];
            self.data.read_exact(input, &mut head[..TAG_SIZE])?;
            if head[..TAG_SIZE].iter().all(|byte| *byte == 0) {
                let within_block = (record_position + TAG_SIZE as u64) % BLOCK_SIZE;
                let block_tail = (if within_block == 0 {
                    0
                } else {
                    BLOCK_SIZE - within_block
                })
                .min(self.data.remaining);
                if block_tail != 0 {
                    let count = usize::try_from(block_tail).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF directory padding exceeds address space",
                        )
                    })?;
                    let mut padding = [0_u8; BLOCK_SIZE_USIZE];
                    let mut left = count;
                    while left != 0 {
                        let chunk = left.min(padding.len());
                        self.data.read_exact(input, &mut padding[..chunk])?;
                        if padding[..chunk].iter().any(|byte| *byte != 0) {
                            return Err(udf_error(
                                ErrorKind::Malformed,
                                "non-zero bytes in UDF directory padding",
                            ));
                        }
                        left -= chunk;
                    }
                }
                continue;
            }
            if self.data.remaining < (head.len() - TAG_SIZE) as u64 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "truncated UDF File Identifier Descriptor header",
                ));
            }
            self.data.read_exact(input, &mut head[TAG_SIZE..])?;
            if le_u16(&head, 16)? != 1 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID file version number is not one",
                ));
            }
            let implementation_length = usize::from(le_u16(&head, 36)?);
            let identifier_length = usize::from(head[19]);
            if !implementation_length.is_multiple_of(4) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID implementation-use length is not 4-byte aligned",
                ));
            }
            if implementation_length != 0 && implementation_length < 32 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID implementation-use field is shorter than its entity identifier",
                ));
            }
            let record_length = align4(
                head.len()
                    .checked_add(implementation_length)
                    .and_then(|value| value.checked_add(identifier_length))
                    .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF FID length overflow"))?,
            )?;
            if record_length > BLOCK_SIZE_USIZE {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID exceeds one logical block",
                ));
            }
            if record_length > self.fid_buffer.len() {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF FID exceeds the fixed in-flight buffer limit",
                ));
            }
            let record = &mut self.fid_buffer[..record_length];
            record.fill(0);
            record[..head.len()].copy_from_slice(&head);
            self.data.read_exact(input, &mut record[head.len()..])?;
            validate_descriptor_tag(record, Some(TAG_FILE_IDENTIFIER), tag_location)?;
            let implementation_start = 38_usize;
            let identifier_start = implementation_start
                .checked_add(implementation_length)
                .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF FID offset overflow"))?;
            let identifier_end = identifier_start
                .checked_add(identifier_length)
                .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF FID name overflow"))?;
            require_verified_range(record, identifier_end, "UDF File Identifier Descriptor")?;
            if record[identifier_end..record_length]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID padding is non-zero",
                ));
            }
            let characteristics = record[18];
            if characteristics & FID_CHARACTERISTIC_RESERVED != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID characteristics contain reserved bits",
                ));
            }
            let ad_flags = le_u16(record, 30)?;
            if ad_flags & LONG_AD_FLAG_RESERVED != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID ICB long allocation descriptor has reserved flags",
                ));
            }
            if ad_flags & LONG_AD_FLAG_ERASED != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID references an erased ICB extent",
                ));
            }
            let icb = parse_long_ad(record, 20)?;
            let unique_id = le_u32(record, 32)?;
            let is_parent = characteristics & FID_CHARACTERISTIC_PARENT != 0;
            if !self.saw_parent && !is_parent {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF directory parent FID is not first",
                ));
            }
            if characteristics & FID_CHARACTERISTIC_DELETED != 0 {
                continue;
            }
            if is_parent {
                if characteristics & FID_CHARACTERISTIC_DIRECTORY == 0
                    || identifier_length != 0
                    || self.saw_parent
                    || icb != self.expected_parent
                    || self
                        .expected_parent_unique_id
                        .is_some_and(|expected| unique_id != expected)
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF directory has an invalid parent FID",
                    ));
                }
                self.saw_parent = true;
                continue;
            }
            let identifier = record
                .get(identifier_start..identifier_end)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF FID identifier is outside its descriptor",
                    )
                })?
                .to_vec();
            return Ok(Some(UdfDirectoryFid {
                characteristics,
                icb,
                unique_id,
                identifier,
            }));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IcbAddress {
    partition_ref: u16,
    logical_block: u32,
    length: u32,
}

#[derive(Debug, Clone, Copy)]
struct ExtentAd {
    length: u32,
    location: u32,
}

#[derive(Debug, Clone)]
struct Partition {
    blocks: u32,
    mapping: PartitionMapping,
}

#[derive(Debug, Clone)]
enum PartitionMapping {
    Physical { start: u32 },
    Metadata(MetadataPartition),
    Sparable(SparablePartition),
    Virtual(VirtualPartition),
}

#[derive(Debug, Clone)]
struct MetadataPartition {
    primary: MetadataFile,
    mirror: Option<MetadataFile>,
    using_mirror: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataFile {
    blocks: u32,
    extents: Vec<MetadataFileExtent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataFileExtent {
    logical_offset: u64,
    length: u64,
    source_offset: Option<u64>,
}

#[derive(Debug, Clone)]
struct VirtualPartition {
    physical_start: u32,
    entries: Vec<Option<u32>>,
}

#[derive(Debug, Clone)]
struct SparablePartition {
    physical_start: u32,
    packet_blocks: u32,
    mapped_packets: BTreeMap<u32, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SparingEntry {
    original_packet: u32,
    mapped_packet: u32,
}

#[derive(Debug)]
struct ParsedSparingTable {
    sequence: u32,
    entries: Vec<SparingEntry>,
    retained_bytes: usize,
}

#[derive(Debug, Clone)]
struct PhysicalPartition {
    start: u32,
    blocks: u32,
    access_type: u32,
}

#[derive(Debug, Clone)]
struct VolumeSet {
    logical_volume_id: Vec<u8>,
    revision: u16,
    partitions: Vec<Partition>,
    file_set: IcbAddress,
    pvd_volume_id: Vec<u8>,
}

#[derive(Debug)]
struct RawVolumeSet {
    primary: Option<DescriptorCandidate>,
    partitions: BTreeMap<u16, DescriptorCandidate>,
    logical: Option<DescriptorCandidate>,
}

#[derive(Debug)]
struct DescriptorCandidate {
    sequence: u32,
    descriptor: Vec<u8>,
}

#[derive(Debug)]
struct RawLogicalVolume {
    logical_volume_id: Vec<u8>,
    revision: u16,
    maps: Vec<RawPartitionMap>,
    file_set: IcbAddress,
}

#[derive(Debug)]
enum RawPartitionMap {
    Physical {
        volume_sequence: u16,
        partition_number: u16,
    },
    Metadata(RawMetadataPartitionMap),
    Sparable(RawSparablePartitionMap),
    Virtual {
        volume_sequence: u16,
        partition_number: u16,
    },
}

#[derive(Debug)]
struct RawSparablePartitionMap {
    volume_sequence: u16,
    partition_number: u16,
    packet_blocks: u32,
    table_size: u32,
    table_locations: Vec<u32>,
}

#[derive(Debug)]
struct RawMetadataPartitionMap {
    volume_sequence: u16,
    partition_number: u16,
    metadata_file_location: u32,
    metadata_mirror_file_location: Option<u32>,
    metadata_bitmap_file_location: Option<u32>,
    allocation_unit_blocks: u32,
    alignment_unit_blocks: u16,
    duplicate: bool,
}

#[derive(Debug)]
struct ParsedVat {
    entries: Vec<Option<u32>>,
    previous_icb: Option<u32>,
    occupied_ranges: Vec<(u64, u64)>,
}

#[derive(Debug)]
struct DirectoryTask {
    prefix: Vec<u8>,
    payload: UdfPayload,
    length: u64,
    depth: usize,
    directory_icb: IcbAddress,
    parent_icb: IcbAddress,
}

#[derive(Debug)]
struct StreamTask {
    owner_path: Option<Vec<u8>>,
    owner_icb: IcbAddress,
    owner_unique_id: Option<u64>,
    owner_information_length: Option<u64>,
    owner_object_size: Option<u64>,
    owner_metadata: Option<StreamOwnerMetadata>,
    stream_directory: IcbAddress,
    depth: usize,
}

#[derive(Debug, Clone)]
struct StreamOwnerMetadata {
    mode: u32,
    owner: Owner,
}

#[derive(Debug)]
struct ParsedFileSet {
    file_set_number: u32,
    descriptor_number: u32,
    root: IcbAddress,
    next_extent: Option<IcbAddress>,
    system_stream_directory: Option<IcbAddress>,
    descriptor: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileEntryRole {
    Main,
    StreamDirectory,
    NamedStream,
    ExternalAttributes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocationPartitionConstraint {
    Any,
    Physical,
}

#[derive(Debug)]
struct FileRecord {
    kind: EntryKind,
    size: u64,
    object_size: u64,
    mode: u32,
    owner: Owner,
    times: EntryTimes,
    inode: u64,
    links: u64,
    payload: UdfPayload,
    sparse: Vec<SparseExtent>,
    extensions: Vec<Extension>,
    link_target: Option<ArchivePath>,
    stream_directory: Option<IcbAddress>,
}

impl FileRecord {
    fn metadata(&self, path: ArchivePath) -> EntryMetadata {
        let mut builder = EntryMetadata::builder(self.kind, path)
            .size(Some(if self.kind == EntryKind::Dir {
                0
            } else {
                self.size
            }))
            .mode(Some(self.mode))
            .owner(self.owner.clone())
            .times(self.times)
            .inode_and_links(Some(self.inode), Some(self.links))
            .link_target(self.link_target.clone());
        for extent in &self.sparse {
            builder = builder.sparse_extent(*extent);
        }
        for extension in &self.extensions {
            builder = builder.extension(extension.clone());
        }
        builder.build()
    }
}

struct UdfParser<'a, R> {
    input: &'a mut R,
    limits: Limits,
    image_length: u64,
    revision: u16,
    partitions: Vec<Partition>,
    metadata_used: usize,
    decoded_total: u64,
    seen_paths: BTreeSet<Vec<u8>>,
    seen_icbs: BTreeMap<(u16, u32), ArchivePath>,
    seen_stream_directories: BTreeSet<(u16, u32)>,
    seen_stream_icbs: BTreeSet<(u16, u32)>,
    entries: Vec<UdfIndex>,
}

impl<'a, R: Read + Seek> UdfParser<'a, R> {
    fn new(input: &'a mut R, limits: Limits) -> Result<Self, StreamError> {
        let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
        if image_length % BLOCK_SIZE != 0 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF reader requires a 2048-byte-sector optical image",
            ));
        }
        if image_length / BLOCK_SIZE <= 256 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF image is too short to contain an anchor",
            ));
        }
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| maximum < BLOCK_SIZE_USIZE)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF descriptor block exceeds the configured in-flight byte limit",
            ));
        }
        Ok(Self {
            input,
            limits,
            image_length,
            revision: 0,
            partitions: Vec::new(),
            metadata_used: 0,
            decoded_total: 0,
            seen_paths: BTreeSet::new(),
            seen_icbs: BTreeMap::new(),
            seen_stream_directories: BTreeSet::new(),
            seen_stream_icbs: BTreeSet::new(),
            entries: Vec::new(),
        })
    }

    fn parse(mut self) -> Result<(ArchiveMetadata, Vec<UdfIndex>, u64), StreamError> {
        let volume = self.find_volume_set()?;
        self.partitions.clone_from(&volume.partitions);
        self.revision = volume.revision;
        match self.parse_volume_contents(&volume) {
            Ok(parsed) => Ok(parsed),
            Err(error)
                if can_fallback_to_reserve(&error)
                    && self.activate_metadata_mirror(volume.file_set.partition_ref) =>
            {
                self.reset_volume_contents();
                self.parse_volume_contents(&volume)
            },
            Err(error) => Err(error),
        }
    }

    fn parse_volume_contents(
        &mut self,
        volume: &VolumeSet,
    ) -> Result<(ArchiveMetadata, Vec<UdfIndex>, u64), StreamError> {
        let volume_name = if volume.logical_volume_id.is_empty() {
            &volume.pvd_volume_id
        } else {
            &volume.logical_volume_id
        };
        let mut archive_metadata = ArchiveMetadata::new().with_extension(Extension::new(
            "udf-volume",
            b"revision".to_vec(),
            volume.revision.to_le_bytes().to_vec(),
        ));
        if !volume_name.is_empty() {
            archive_metadata = archive_metadata.with_volume_name(ArchivePath::try_from_encoded(
                volume_name.clone(),
                PathEncoding::Utf8,
            )?);
        }
        self.metadata_used = archive_metadata_size(&archive_metadata);
        self.enforce_metadata_limit()?;

        let file_set = self.parse_file_set_sequence(volume.file_set, volume.revision)?;
        let root = file_set.root;
        self.validate_icb_address(root)?;
        let root_record = self.parse_file_entry(root)?;
        if root_record.kind != EntryKind::Dir {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF root ICB is not a directory",
            ));
        }
        if root_record.inode != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF root ICB Unique ID is not zero",
            ));
        }
        self.seen_icbs.insert(
            (root.partition_ref, root.logical_block),
            ArchivePath::from_utf8("/"),
        );
        self.metadata_used = self
            .metadata_used
            .checked_add(1)
            .and_then(|value| value.checked_add(core::mem::size_of::<((u16, u32), ArchivePath)>()))
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.enforce_metadata_limit()?;
        let root_stream_directory = root_record.stream_directory;
        let root_inode = root_record.inode;
        let root_stream_metadata = StreamOwnerMetadata {
            mode: root_record.mode,
            owner: root_record.owner.clone(),
        };
        let root_task = DirectoryTask {
            prefix: Vec::new(),
            payload: root_record.payload,
            length: root_record.size,
            depth: 0,
            directory_icb: root,
            parent_icb: root,
        };
        self.account_directory_task(&root_task)?;
        let mut stack = vec![root_task];
        let mut stream_tasks = Vec::new();
        if let Some(stream_directory) = root_stream_directory {
            let task = StreamTask {
                owner_path: Some(Vec::new()),
                owner_icb: root,
                owner_unique_id: Some(root_inode),
                owner_information_length: Some(root_record.size),
                owner_object_size: Some(root_record.object_size),
                owner_metadata: Some(root_stream_metadata),
                stream_directory,
                depth: 1,
            };
            self.account_stream_task(&task)?;
            stream_tasks.push(task);
        }
        if let Some(stream_directory) = file_set.system_stream_directory {
            let task = StreamTask {
                owner_path: None,
                owner_icb: stream_directory,
                owner_unique_id: None,
                owner_information_length: None,
                owner_object_size: None,
                owner_metadata: None,
                stream_directory,
                depth: 1,
            };
            self.account_stream_task(&task)?;
            stream_tasks.push(task);
        }
        while let Some(task) = stack.pop() {
            self.parse_directory(task, &mut stack, &mut stream_tasks)?;
        }
        while let Some(task) = stream_tasks.pop() {
            self.parse_stream_directory(&task)?;
        }
        Ok((
            archive_metadata,
            core::mem::take(&mut self.entries),
            self.decoded_total,
        ))
    }

    fn activate_metadata_mirror(&mut self, partition_ref: u16) -> bool {
        let Some(partition) = self.partitions.get_mut(usize::from(partition_ref)) else {
            return false;
        };
        let PartitionMapping::Metadata(metadata) = &mut partition.mapping else {
            return false;
        };
        if metadata.using_mirror || metadata.mirror.is_none() {
            return false;
        }
        metadata.using_mirror = true;
        true
    }

    fn reset_volume_contents(&mut self) {
        self.metadata_used = 0;
        self.decoded_total = 0;
        self.seen_paths.clear();
        self.seen_icbs.clear();
        self.seen_stream_directories.clear();
        self.seen_stream_icbs.clear();
        self.entries.clear();
    }

    #[allow(clippy::too_many_lines)]
    fn parse_file_set_sequence(
        &mut self,
        first_extent: IcbAddress,
        revision: u16,
    ) -> Result<ParsedFileSet, StreamError> {
        let mut next_extent = Some(first_extent);
        let mut seen_extents = BTreeSet::new();
        let mut candidates = BTreeMap::<u32, ParsedFileSet>::new();
        let mut descriptor_bytes = 0_usize;
        let mut candidate_overhead = 0_usize;
        let mut extent_count = 0_usize;

        while let Some(extent) = next_extent.take() {
            if extent_count >= MAX_FSD_EXTENTS
                || self
                    .limits
                    .nesting()
                    .is_some_and(|maximum| extent_count > maximum)
            {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF File Set Descriptor continuation depth exceeds configured limit",
                ));
            }
            extent_count = extent_count.checked_add(1).ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF File Set Descriptor continuation depth overflow",
                )
            })?;
            self.validate_icb_address(extent)?;
            let extent_length = extent.length & 0x3fff_ffff;
            if !extent_length.is_multiple_of(BLOCK_SIZE_U32) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF File Set Descriptor extent is not block-aligned",
                ));
            }
            if !seen_extents.insert((extent.partition_ref, extent.logical_block)) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "cycle in UDF File Set Descriptor continuations",
                ));
            }

            let blocks = extent_length / BLOCK_SIZE_U32;
            let mut continuation = None;
            for index in 0..blocks {
                let logical_block = extent.logical_block.checked_add(index).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF File Set Descriptor block overflow",
                    )
                })?;
                let descriptor = self.read_partition_block(extent.partition_ref, logical_block)?;
                if descriptor.iter().all(|byte| *byte == 0) {
                    break;
                }
                validate_descriptor_tag(&descriptor, None, logical_block)?;
                match le_u16(&descriptor, 0)? {
                    TAG_FILE_SET => {
                        let parsed = self.parse_file_set_descriptor(descriptor, revision)?;
                        descriptor_bytes = descriptor_bytes
                            .checked_add(parsed.descriptor.capacity())
                            .ok_or_else(|| {
                                udf_error(
                                    ErrorKind::Limit,
                                    "UDF File Set Descriptor metadata accounting overflow",
                                )
                            })?;
                        continuation = parsed.next_extent;
                        let key = parsed.descriptor_number;
                        if let Some(previous) = candidates.get(&key) {
                            if !vds_descriptors_identical(&previous.descriptor, &parsed.descriptor)?
                            {
                                return Err(udf_error(
                                    ErrorKind::Malformed,
                                    "conflicting UDF File Set Descriptors have the same numbers",
                                ));
                            }
                        } else {
                            candidate_overhead = candidate_overhead
                                .checked_add(core::mem::size_of::<(u32, ParsedFileSet)>())
                                .and_then(|value| {
                                    value.checked_add(core::mem::size_of::<usize>() * 4)
                                })
                                .ok_or_else(|| {
                                    udf_error(
                                        ErrorKind::Limit,
                                        "UDF File Set candidate accounting overflow",
                                    )
                                })?;
                            candidates.insert(key, parsed);
                        }
                        let file_set_bytes = descriptor_bytes
                            .checked_add(candidate_overhead)
                            .ok_or_else(|| {
                                udf_error(
                                    ErrorKind::Limit,
                                    "UDF File Set Descriptor metadata accounting overflow",
                                )
                            })?;
                        if self.limits.metadata_bytes().is_some_and(|maximum| {
                            self.metadata_used
                                .checked_add(file_set_bytes)
                                .is_none_or(|total| total > maximum)
                        }) {
                            return Err(udf_error(
                                ErrorKind::Limit,
                                "UDF File Set Descriptor sequence exceeds metadata limit",
                            ));
                        }
                        if continuation.is_some() {
                            break;
                        }
                    },
                    TAG_TERMINATING => {
                        if descriptor[TAG_SIZE..].iter().any(|byte| *byte != 0) {
                            return Err(udf_error(
                                ErrorKind::Malformed,
                                "UDF File Set terminating descriptor reserved bytes are non-zero",
                            ));
                        }
                        break;
                    },
                    tag => {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            format!(
                                "unexpected descriptor tag {tag} in UDF File Set Descriptor sequence"
                            ),
                        ));
                    },
                }
            }
            next_extent = continuation;
        }

        if !candidates
            .values()
            .any(|descriptor| descriptor.file_set_number == 0)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF File Set Descriptor sequence has no file set zero",
            ));
        }
        let selected_key = candidates
            .iter()
            .filter(|(_, descriptor)| descriptor.file_set_number == 0)
            .map(|(number, _)| *number)
            .max()
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF File Set Descriptor sequence has no prevailing descriptor",
                )
            })?;
        let mut selected = candidates.remove(&selected_key).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF prevailing File Set Descriptor disappeared",
            )
        })?;
        self.metadata_used = self
            .metadata_used
            .checked_add(descriptor_bytes)
            .and_then(|value| value.checked_add(candidate_overhead))
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF File Set Descriptor metadata accounting overflow",
                )
            })?;
        self.enforce_metadata_limit()?;
        selected.descriptor = Vec::new();
        Ok(selected)
    }

    fn parse_file_set_descriptor(
        &self,
        mut descriptor: Vec<u8>,
        revision: u16,
    ) -> Result<ParsedFileSet, StreamError> {
        require_verified_range(&descriptor, 512, "UDF File Set Descriptor")?;
        validate_osta_charspec(&descriptor[48..112], "File Set logical volume")?;
        validate_osta_charspec(&descriptor[240..304], "File Set")?;
        let file_set_revision = parse_udf_domain_revision(&descriptor[416..448])?;
        if file_set_revision != revision {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF File Set and Logical Volume revisions disagree",
            ));
        }
        let root = parse_long_ad(&descriptor, 400)?;
        let next_extent =
            parse_optional_long_ad(&descriptor, 448, "File Set Descriptor continuation")?;
        let system_stream_directory = if revision >= 0x0200 {
            if descriptor[480..512].iter().any(|byte| *byte != 0) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF File Set Descriptor reserved bytes are non-zero",
                ));
            }
            parse_optional_long_ad(&descriptor, 464, "system-stream directory")?
        } else {
            if descriptor[464..512].iter().any(|byte| *byte != 0) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "pre-2.00 UDF File Set Descriptor stream-directory reserved bytes are non-zero",
                ));
            }
            None
        };
        if let Some(address) = next_extent {
            self.validate_icb_address(address)?;
        }
        if let Some(address) = system_stream_directory {
            self.validate_icb_address(address)?;
        }
        let used = descriptor_verified_end(&descriptor)?;
        descriptor.truncate(used);
        descriptor.shrink_to_fit();
        Ok(ParsedFileSet {
            file_set_number: le_u32(&descriptor, 40)?,
            descriptor_number: le_u32(&descriptor, 44)?,
            root,
            next_extent,
            system_stream_directory,
            descriptor,
        })
    }

    fn find_volume_set(&mut self) -> Result<VolumeSet, StreamError> {
        let last = self
            .image_length
            .checked_div(BLOCK_SIZE)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF block count underflow"))?;
        let mut candidates = Vec::new();
        for candidate in [256, last.saturating_sub(256), last] {
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
        let mut last_error = None;
        for block in candidates {
            let anchor = match self.read_descriptor_block(block, block, Some(TAG_ANCHOR)) {
                Ok(anchor) => anchor,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                },
            };
            require_verified_range(&anchor, 32, "UDF anchor extents")?;
            let main = parse_extent_ad(&anchor, 16)?;
            let reserve = parse_extent_ad(&anchor, 24)?;
            match self.parse_volume_sequence(main) {
                Ok(volume) => return Ok(volume),
                Err(error) if can_fallback_to_reserve(&error) => {},
                Err(error) => return Err(error),
            }
            match self.parse_volume_sequence(reserve) {
                Ok(volume) => return Ok(volume),
                Err(error) if can_fallback_to_reserve(&error) => {
                    last_error = Some(error);
                },
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "no valid UDF anchor or volume descriptor sequence was found",
            )
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn parse_volume_sequence(&mut self, extent: ExtentAd) -> Result<VolumeSet, StreamError> {
        let mut raw = RawVolumeSet {
            primary: None,
            partitions: BTreeMap::new(),
            logical: None,
        };
        let mut saw_terminator = false;
        let mut next_extent = Some(extent);
        let mut seen_extents = BTreeSet::new();
        let mut descriptors_by_sequence = BTreeMap::new();
        let mut descriptor_bytes = 0_usize;
        while let Some(current) = next_extent.take() {
            if current.length == 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF volume descriptor extent is empty",
                ));
            }
            if !current.length.is_multiple_of(BLOCK_SIZE_U32) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF volume descriptor extent is not block-aligned",
                ));
            }
            if !seen_extents.insert((current.location, current.length)) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "cycle in UDF Volume Descriptor Pointer continuations",
                ));
            }
            let end = u64::from(current.location)
                .checked_mul(BLOCK_SIZE)
                .and_then(|offset| offset.checked_add(u64::from(current.length)))
                .ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF volume descriptor range overflow")
                })?;
            if end > self.image_length {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF volume descriptor sequence is outside the image",
                ));
            }
            descriptor_bytes = descriptor_bytes
                .checked_add(current.length as usize)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Limit,
                        "UDF volume descriptor accounting overflow",
                    )
                })?;
            if self
                .limits
                .metadata_bytes()
                .is_some_and(|maximum| descriptor_bytes > maximum)
            {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF volume descriptor sequence exceeds metadata limit",
                ));
            }

            let blocks = u64::from(current.length) / BLOCK_SIZE;
            let mut extent_ended = false;
            for index in 0..blocks {
                let block = u64::from(current.location)
                    .checked_add(index)
                    .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF VDS block overflow"))?;
                let descriptor = self.read_descriptor_block(block, block, None)?;
                let tag = le_u16(&descriptor, 0)?;
                if matches!(tag, 1 | 3 | 4 | 5 | 6 | 7) {
                    validate_vds_sequence_identity(&mut descriptors_by_sequence, &descriptor)?;
                }
                match tag {
                    TAG_PRIMARY_VOLUME => {
                        consider_descriptor(&mut raw.primary, descriptor)?;
                    },
                    TAG_PARTITION => {
                        let number = le_u16(&descriptor, 22)?;
                        let candidate =
                            raw.partitions
                                .entry(number)
                                .or_insert_with(|| DescriptorCandidate {
                                    sequence: 0,
                                    descriptor: Vec::new(),
                                });
                        consider_descriptor_candidate(candidate, descriptor)?;
                    },
                    TAG_LOGICAL_VOLUME => {
                        consider_descriptor(&mut raw.logical, descriptor)?;
                    },
                    TAG_TERMINATING => {
                        saw_terminator = true;
                        extent_ended = true;
                        break;
                    },
                    3 => {
                        require_verified_range(&descriptor, 28, "UDF Volume Descriptor Pointer")?;
                        next_extent = Some(parse_extent_ad(&descriptor, 20)?);
                        extent_ended = true;
                        break;
                    },
                    4 | 7 | 9 => {},
                    tag => {
                        return Err(udf_error(
                            ErrorKind::Unsupported,
                            format!("unsupported UDF volume descriptor tag {tag}"),
                        ));
                    },
                }
            }
            if !extent_ended {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF volume descriptor extent lacks a terminator or continuation",
                ));
            }
            if saw_terminator {
                break;
            }
        }
        if !saw_terminator {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF volume descriptor terminator is missing",
            ));
        }
        let primary = raw.primary.ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF Primary Volume Descriptor is missing",
            )
        })?;
        require_verified_range(&primary.descriptor, 264, "UDF Primary Volume Descriptor")?;
        validate_osta_charspec(&primary.descriptor[200..264], "Primary Volume")?;
        let pvd_volume_id = decode_dstring(&primary.descriptor[24..56])?;

        let mut physical_partitions = BTreeMap::new();
        for (number, candidate) in raw.partitions {
            let descriptor = candidate.descriptor;
            let contents = descriptor.get(25..48).ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "partition contents identifier truncated",
                )
            })?;
            if !contents.starts_with(b"+NSR02") && !contents.starts_with(b"+NSR03") {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    "UDF partition contents are not a physical NSR partition",
                ));
            }
            if contents[6..].iter().any(|byte| *byte != 0) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF partition contents identifier padding is non-zero",
                ));
            }
            require_verified_range(&descriptor, 196, "UDF Partition Descriptor")?;
            let access_type = le_u32(&descriptor, 184)?;
            let start = le_u32(&descriptor, 188)?;
            let length = le_u32(&descriptor, 192)?;
            self.validate_partition_range(start, length)?;
            physical_partitions.insert(
                number,
                PhysicalPartition {
                    start,
                    blocks: length,
                    access_type,
                },
            );
        }

        let logical = raw.logical.ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF Logical Volume Descriptor is missing",
            )
        })?;
        let logical = parse_logical_volume(&logical.descriptor)?;
        if !matches!(
            logical.revision,
            0x0102 | 0x0150 | 0x0200 | 0x0201 | 0x0250 | 0x0260
        ) {
            return Err(udf_error(
                ErrorKind::Unsupported,
                format!(
                    "unsupported UDF revision {:x}.{:02x}",
                    logical.revision >> 8,
                    logical.revision & 0xff
                ),
            ));
        }
        let volume_sequence = le_u16(&primary.descriptor, 56)?;
        let mut physical_map_counts = BTreeMap::<u16, usize>::new();
        let mut physical_map_references = BTreeMap::<u16, u16>::new();
        let mut sparable_map_counts = BTreeMap::<u16, usize>::new();
        let mut metadata_map_numbers = BTreeSet::new();
        let mut sparable_map_numbers = BTreeSet::new();
        let mut virtual_map_numbers = BTreeSet::new();
        for (reference, map) in logical.maps.iter().enumerate() {
            match map {
                RawPartitionMap::Physical {
                    partition_number, ..
                } => {
                    let count = physical_map_counts.entry(*partition_number).or_default();
                    *count = count.checked_add(1).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF partition map count overflow")
                    })?;
                    let reference = u16::try_from(reference).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF physical partition reference exceeds address space",
                        )
                    })?;
                    physical_map_references
                        .entry(*partition_number)
                        .or_insert(reference);
                },
                RawPartitionMap::Metadata(map) => {
                    metadata_map_numbers.insert(map.partition_number);
                },
                RawPartitionMap::Sparable(map) => {
                    let count = sparable_map_counts.entry(map.partition_number).or_default();
                    *count = count.checked_add(1).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF partition map count overflow")
                    })?;
                    sparable_map_numbers.insert(map.partition_number);
                },
                RawPartitionMap::Virtual {
                    partition_number, ..
                } => {
                    virtual_map_numbers.insert(*partition_number);
                },
            }
        }
        if sparable_map_numbers
            .iter()
            .any(|number| physical_map_counts.contains_key(number))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Type 1 and Sparable Partition Maps reference the same physical partition",
            ));
        }
        if metadata_map_numbers
            .iter()
            .any(|number| virtual_map_numbers.contains(number))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata and Virtual Partition Maps reference the same physical partition",
            ));
        }
        if sparable_map_numbers
            .iter()
            .any(|number| virtual_map_numbers.contains(number))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Sparable and Virtual Partition Maps reference the same physical partition",
            ));
        }
        let mut sparable_partitions = BTreeMap::new();
        for map in &logical.maps {
            let RawPartitionMap::Sparable(map) = map else {
                continue;
            };
            if map.volume_sequence != volume_sequence {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparable Partition Map references a different volume sequence",
                ));
            }
            if sparable_map_counts
                .get(&map.partition_number)
                .copied()
                .unwrap_or(0)
                != 1
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "duplicate UDF Sparable Partition Map for one partition",
                ));
            }
            let physical = physical_partitions
                .get(&map.partition_number)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Sparable Partition Map references a missing partition descriptor",
                    )
                })?;
            if physical.access_type != 3 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparable Partition Map requires a rewritable physical partition",
                ));
            }
            if !physical.start.is_multiple_of(map.packet_blocks)
                || !physical.blocks.is_multiple_of(map.packet_blocks)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparable Partition does not begin and end on packet boundaries",
                ));
            }
            let partition = self.load_sparable_partition(physical, map, logical.revision)?;
            sparable_partitions.insert(map.partition_number, partition);
        }
        let mut partitions = Vec::with_capacity(logical.maps.len());
        let mut metadata_numbers = BTreeSet::new();
        let mut sparable_numbers = BTreeSet::new();
        let mut virtual_numbers = BTreeSet::new();
        for map in logical.maps {
            match map {
                RawPartitionMap::Physical {
                    volume_sequence: map_volume,
                    partition_number,
                } => {
                    if map_volume != volume_sequence {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Type 1 map references a different volume sequence",
                        ));
                    }
                    let physical = physical_partitions.get(&partition_number).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Malformed,
                            "UDF Type 1 map references a missing partition descriptor",
                        )
                    })?;
                    partitions.push(Partition {
                        blocks: physical.blocks,
                        mapping: PartitionMapping::Physical {
                            start: physical.start,
                        },
                    });
                },
                RawPartitionMap::Metadata(map) => {
                    if map.volume_sequence != volume_sequence {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition Map references a different volume sequence",
                        ));
                    }
                    if !metadata_numbers.insert(map.partition_number) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "duplicate UDF Metadata Partition Map for one partition",
                        ));
                    }
                    let physical_maps = physical_map_counts
                        .get(&map.partition_number)
                        .copied()
                        .unwrap_or(0);
                    let sparable_maps = sparable_map_counts
                        .get(&map.partition_number)
                        .copied()
                        .unwrap_or(0);
                    if physical_maps
                        .checked_add(sparable_maps)
                        .is_none_or(|matching_maps| matching_maps != 1)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition Map requires exactly one physical or Sparable base map",
                        ));
                    }
                    let physical = physical_partitions
                        .get(&map.partition_number)
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Malformed,
                                "UDF Metadata Partition Map references a missing partition descriptor",
                            )
                        })?
                        .clone();
                    let base = if physical_maps == 1 {
                        if !matches!(physical.access_type, 0 | 1 | 4) {
                            return Err(udf_error(
                                ErrorKind::Malformed,
                                "UDF Metadata Partition Map has an invalid physical-partition access type",
                            ));
                        }
                        Partition {
                            blocks: physical.blocks,
                            mapping: PartitionMapping::Physical {
                                start: physical.start,
                            },
                        }
                    } else {
                        sparable_partitions
                            .get(&map.partition_number)
                            .cloned()
                            .ok_or_else(|| {
                                udf_error(
                                    ErrorKind::Malformed,
                                    "UDF Metadata Partition Map has no Sparable base partition",
                                )
                            })?
                    };
                    partitions.push(self.load_metadata_partition(&base, &map)?);
                },
                RawPartitionMap::Sparable(map) => {
                    if !sparable_numbers.insert(map.partition_number) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "duplicate UDF Sparable Partition Map for one partition",
                        ));
                    }
                    partitions.push(
                        sparable_partitions
                            .get(&map.partition_number)
                            .cloned()
                            .ok_or_else(|| {
                                udf_error(
                                    ErrorKind::Malformed,
                                    "UDF Sparable Partition was not loaded",
                                )
                            })?,
                    );
                },
                RawPartitionMap::Virtual {
                    volume_sequence: map_volume,
                    partition_number,
                } => {
                    if map_volume != volume_sequence {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map references a different volume sequence",
                        ));
                    }
                    if !virtual_numbers.insert(partition_number) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "duplicate UDF Virtual Partition Map for one partition",
                        ));
                    }
                    let matching_maps = physical_map_counts
                        .get(&partition_number)
                        .copied()
                        .unwrap_or(0);
                    if matching_maps != 1 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map requires exactly one matching physical map",
                        ));
                    }
                    let physical = physical_partitions.get(&partition_number).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map references a missing partition descriptor",
                        )
                    })?;
                    if physical.access_type != 2 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map requires a write-once physical partition",
                        ));
                    }
                    let physical_reference = *physical_map_references
                        .get(&partition_number)
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Malformed,
                                "UDF Virtual Partition Map has no physical partition reference",
                            )
                        })?;
                    partitions.push(self.load_virtual_partition(
                        physical,
                        physical_reference,
                        logical.revision,
                    )?);
                },
            }
        }
        let volume = VolumeSet {
            logical_volume_id: logical.logical_volume_id,
            revision: logical.revision,
            partitions,
            file_set: logical.file_set,
            pvd_volume_id,
        };
        Self::validate_icb_with_partitions(volume.file_set, &volume.partitions)?;
        Ok(volume)
    }

    #[allow(clippy::too_many_lines)]
    fn load_sparable_partition(
        &mut self,
        physical: &PhysicalPartition,
        map: &RawSparablePartitionMap,
        revision: u16,
    ) -> Result<Partition, StreamError> {
        let table_size = usize::try_from(map.table_size).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF sparing-table size exceeds address space",
            )
        })?;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|maximum| table_size > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing table exceeds the configured in-flight byte limit",
            ));
        }
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| table_size > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing table exceeds the configured metadata limit",
            ));
        }

        let table_blocks = u64::from(map.table_size).div_ceil(BLOCK_SIZE);
        let image_blocks = self.image_length / BLOCK_SIZE;
        let mut table_ranges = Vec::new();
        table_ranges
            .try_reserve(map.table_locations.len())
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table range allocation failed",
                )
            })?;
        for (index, &location) in map.table_locations.iter().enumerate() {
            if map.table_locations[..index].contains(&location) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "duplicate UDF sparing-table location",
                ));
            }
            let start = u64::from(location);
            let end = start.checked_add(table_blocks).ok_or_else(|| {
                udf_error(ErrorKind::Malformed, "UDF sparing-table range overflow")
            })?;
            if end > image_blocks {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF sparing table is outside the image",
                ));
            }
            if table_ranges
                .iter()
                .any(|range| ranges_overlap(*range, (start, end)))
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF sparing-table copies overlap",
                ));
            }
            table_ranges.push((start, end));
        }
        let packet_blocks = u64::from(map.packet_blocks);
        let mut table_packet_ranges = Vec::new();
        table_packet_ranges
            .try_reserve(table_ranges.len())
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table packet-range allocation failed",
                )
            })?;
        for &(start, end) in &table_ranges {
            let packet_start = start / packet_blocks * packet_blocks;
            let packet_end = end
                .div_ceil(packet_blocks)
                .checked_mul(packet_blocks)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF sparing-table packet range overflow",
                    )
                })?;
            let packet_range = (packet_start, packet_end);
            if table_packet_ranges
                .iter()
                .any(|range| ranges_overlap(*range, packet_range))
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF sparing-table copies occupy the same sparing packet",
                ));
            }
            table_packet_ranges.push(packet_range);
        }

        let mut parsed_tables = Vec::new();
        parsed_tables
            .try_reserve(map.table_locations.len())
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table candidate allocation failed",
                )
            })?;
        let base_metadata_bytes = [
            capacity_bytes::<u32>(
                map.table_locations.capacity(),
                "UDF sparing-table location metadata accounting overflow",
            )?,
            capacity_bytes::<(u64, u64)>(
                table_ranges.capacity(),
                "UDF sparing-table range metadata accounting overflow",
            )?,
            capacity_bytes::<(u64, u64)>(
                table_packet_ranges.capacity(),
                "UDF sparing-table packet-range metadata accounting overflow",
            )?,
            capacity_bytes::<ParsedSparingTable>(
                parsed_tables.capacity(),
                "UDF sparing-table candidate metadata accounting overflow",
            )?,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or_else(|| {
            udf_error(
                ErrorKind::Limit,
                "UDF sparing-table bookkeeping metadata accounting overflow",
            )
        })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| base_metadata_bytes > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table bookkeeping exceeds the configured metadata limit",
            ));
        }
        let mut first_error = None;
        let mut retained_copy_bytes = 0_usize;
        for &location in &map.table_locations {
            match self.parse_sparing_table(
                location,
                table_size,
                map.packet_blocks,
                physical.blocks,
                revision,
                &table_ranges,
                base_metadata_bytes,
                retained_copy_bytes,
            ) {
                Ok(table) => {
                    retained_copy_bytes = retained_copy_bytes
                        .checked_add(table.retained_bytes)
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF sparing-table copy metadata accounting overflow",
                            )
                        })?;
                    parsed_tables.push(table);
                },
                Err(error) if can_fallback_to_reserve(&error) => {
                    first_error.get_or_insert(error);
                },
                Err(error) => return Err(error),
            }
        }
        let highest_sequence = parsed_tables
            .iter()
            .map(|table| table.sequence)
            .max()
            .ok_or_else(|| {
                first_error.unwrap_or_else(|| {
                    udf_error(ErrorKind::Malformed, "no valid UDF sparing table was found")
                })
            })?;
        let mut selected = parsed_tables
            .iter()
            .filter(|table| table.sequence == highest_sequence);
        let prevailing = selected.next().ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "prevailing UDF sparing table disappeared",
            )
        })?;
        if selected.any(|candidate| candidate.entries != prevailing.entries) {
            return Err(udf_error(
                ErrorKind::Integrity,
                "conflicting UDF sparing tables have the same sequence number",
            ));
        }

        let active_count = prevailing
            .entries
            .iter()
            .take_while(|entry| entry.original_packet < SPARING_ENTRY_DEFECTIVE)
            .count();
        let retained = core::mem::size_of::<SparablePartition>()
            .checked_add(
                active_count
                    .checked_mul(core::mem::size_of::<(u32, u32)>() * 4)
                    .ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF sparing-map metadata accounting overflow",
                        )
                    })?,
            )
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-map metadata accounting overflow",
                )
            })?;
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(retained))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing map exceeds the configured metadata limit",
            ));
        }
        let mut mapped_packets = BTreeMap::new();
        for entry in prevailing.entries.iter().take(active_count) {
            mapped_packets.insert(entry.original_packet, entry.mapped_packet);
        }
        Ok(Partition {
            blocks: physical.blocks,
            mapping: PartitionMapping::Sparable(SparablePartition {
                physical_start: physical.start,
                packet_blocks: map.packet_blocks,
                mapped_packets,
            }),
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn parse_sparing_table(
        &mut self,
        location: u32,
        table_size: usize,
        packet_blocks: u32,
        partition_blocks: u32,
        revision: u16,
        table_ranges: &[(u64, u64)],
        base_metadata_bytes: usize,
        retained_copy_bytes: usize,
    ) -> Result<ParsedSparingTable, StreamError> {
        let offset = u64::from(location)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF sparing-table offset overflow"))?;
        let mut descriptor = Vec::new();
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(table_size))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table copies exceed the configured metadata limit",
            ));
        }
        descriptor.try_reserve_exact(table_size).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF sparing-table buffer allocation failed",
            )
        })?;
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(descriptor.capacity()))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table copies exceed the configured metadata limit",
            ));
        }
        descriptor.resize(table_size, 0);
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        self.input
            .read_exact(&mut descriptor)
            .map_err(StreamError::io)?;
        validate_descriptor_tag(&descriptor, Some(0), location)?;
        require_verified_range(&descriptor, SPARING_TABLE_HEADER_SIZE, "UDF Sparing Table")?;
        validate_udf_entity_identifier(
            &descriptor[16..48],
            b"*UDF Sparing Table",
            revision,
            "UDF Sparing Table",
        )?;
        if descriptor[50..52].iter().any(|byte| *byte != 0) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Sparing Table reserved bytes are non-zero",
            ));
        }
        let entry_count = usize::from(le_u16(&descriptor, 48)?);
        let used = SPARING_TABLE_HEADER_SIZE
            .checked_add(entry_count.checked_mul(SPARING_ENTRY_SIZE).ok_or_else(|| {
                udf_error(ErrorKind::Limit, "UDF sparing-table entry length overflow")
            })?)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table descriptor length overflow",
                )
            })?;
        if used > table_size {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Sparing Table entries exceed the allocated table size",
            ));
        }
        let required_crc_length = used.saturating_sub(TAG_SIZE).min(usize::from(u16::MAX));
        let required_verified_end = TAG_SIZE.checked_add(required_crc_length).ok_or_else(|| {
            udf_error(
                ErrorKind::Limit,
                "UDF Sparing Table CRC range accounting overflow",
            )
        })?;
        if descriptor_verified_end(&descriptor)? != required_verified_end {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Sparing Table descriptor CRC length is not profile-conforming",
            ));
        }
        let entry_bytes = entry_count
            .checked_mul(core::mem::size_of::<SparingEntry>())
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table metadata accounting overflow",
                )
            })?;
        let mapped_range_bytes = entry_count
            .checked_mul(core::mem::size_of::<(u64, u64)>())
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF sparing-table range metadata accounting overflow",
                )
            })?;
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(descriptor.capacity()))
                .and_then(|peak| peak.checked_add(entry_bytes))
                .and_then(|peak| peak.checked_add(mapped_range_bytes))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table copies exceed the configured metadata limit",
            ));
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(entry_count).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF sparing-table entry allocation failed",
            )
        })?;
        let entry_capacity_bytes = capacity_bytes::<SparingEntry>(
            entries.capacity(),
            "UDF sparing-table entry metadata accounting overflow",
        )?;
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(descriptor.capacity()))
                .and_then(|peak| peak.checked_add(entry_capacity_bytes))
                .and_then(|peak| peak.checked_add(mapped_range_bytes))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table copies exceed the configured metadata limit",
            ));
        }
        let image_blocks = self.image_length / BLOCK_SIZE;
        let mut mapped_ranges = Vec::new();
        mapped_ranges.try_reserve(entry_count).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF sparing-table mapped-range allocation failed",
            )
        })?;
        let mapped_range_capacity_bytes = capacity_bytes::<(u64, u64)>(
            mapped_ranges.capacity(),
            "UDF sparing-table mapped-range metadata accounting overflow",
        )?;
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            base_metadata_bytes
                .checked_add(retained_copy_bytes)
                .and_then(|peak| peak.checked_add(descriptor.capacity()))
                .and_then(|peak| peak.checked_add(entry_capacity_bytes))
                .and_then(|peak| peak.checked_add(mapped_range_capacity_bytes))
                .is_none_or(|peak| peak > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF sparing-table copies exceed the configured metadata limit",
            ));
        }
        let mut previous_original = None;
        for raw in descriptor[SPARING_TABLE_HEADER_SIZE..used].chunks_exact(SPARING_ENTRY_SIZE) {
            let original_packet = le_u32(raw, 0)?;
            let mapped_packet = le_u32(raw, 4)?;
            if previous_original.is_some_and(|previous| {
                original_packet < previous
                    || (original_packet < SPARING_ENTRY_DEFECTIVE && original_packet == previous)
            }) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparing Table entries are not sorted with unique original packets",
                ));
            }
            previous_original = Some(original_packet);
            if original_packet < SPARING_ENTRY_DEFECTIVE {
                if !original_packet.is_multiple_of(packet_blocks)
                    || u64::from(original_packet)
                        .checked_add(u64::from(packet_blocks))
                        .is_none_or(|end| end > u64::from(partition_blocks))
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Sparing Table original packet is unaligned or outside its partition",
                    ));
                }
            } else if !matches!(
                original_packet,
                SPARING_ENTRY_DEFECTIVE | SPARING_ENTRY_AVAILABLE
            ) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparing Table contains a reserved original-location value",
                ));
            }
            let mapped_start = u64::from(mapped_packet);
            let mapped_end = mapped_start
                .checked_add(u64::from(packet_blocks))
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF sparing-table mapped packet range overflow",
                    )
                })?;
            let mapped_range = (mapped_start, mapped_end);
            if mapped_end > image_blocks {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparing Table mapped packet is outside the image",
                ));
            }
            if table_ranges
                .iter()
                .any(|table_range| ranges_overlap(*table_range, mapped_range))
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparing Table mapped packet overlaps a sparing-table copy",
                ));
            }
            if mapped_ranges
                .iter()
                .any(|range| ranges_overlap(*range, mapped_range))
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Sparing Table mapped packet ranges overlap",
                ));
            }
            mapped_ranges.push(mapped_range);
            entries.push(SparingEntry {
                original_packet,
                mapped_packet,
            });
        }
        Ok(ParsedSparingTable {
            sequence: le_u32(&descriptor, 52)?,
            entries,
            retained_bytes: entry_capacity_bytes,
        })
    }

    fn load_virtual_partition(
        &mut self,
        physical: &PhysicalPartition,
        physical_reference: u16,
        revision: u16,
    ) -> Result<Partition, StreamError> {
        let mut budget = core::mem::size_of::<VirtualPartition>()
            .checked_add(core::mem::size_of::<ParsedVat>())
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT metadata accounting overflow"))?;
        self.enforce_vat_budget(budget)?;

        let latest_location = self.discover_latest_vat(physical, revision, &mut budget)?;
        let mut latest = self.parse_vat(
            physical,
            physical_reference,
            latest_location,
            revision,
            &mut budget,
        )?;
        let entries = core::mem::take(&mut latest.entries);
        let mut occupied_ranges = latest.occupied_ranges;
        let mut previous = latest.previous_icb;
        let mut newer_location = latest_location;
        let mut seen = BTreeSet::new();
        seen.insert(latest_location);
        self.account_vat_budget(&mut budget, core::mem::size_of::<u32>() * 4)?;
        let mut depth = 0_usize;
        while let Some(location) = previous {
            if !seen.insert(location) {
                return Err(udf_error(ErrorKind::Malformed, "cycle in UDF VAT history"));
            }
            if location >= newer_location {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT history does not point to an earlier physical block",
                ));
            }
            depth = depth
                .checked_add(1)
                .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT history depth overflow"))?;
            if depth > MAX_VAT_HISTORY_DEPTH
                || self.limits.nesting().is_some_and(|maximum| depth > maximum)
            {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF VAT history depth exceeds configured limit",
                ));
            }
            self.account_vat_budget(&mut budget, core::mem::size_of::<u32>() * 4)?;
            let historical = self.parse_vat(
                physical,
                physical_reference,
                location,
                revision,
                &mut budget,
            )?;
            previous = historical.previous_icb;
            newer_location = location;
            occupied_ranges
                .try_reserve(historical.occupied_ranges.len())
                .map_err(|_| {
                    udf_error(ErrorKind::Limit, "UDF VAT history range allocation failed")
                })?;
            occupied_ranges.extend(historical.occupied_ranges);
        }
        Self::validate_vat_entry_ranges(physical, &entries, &occupied_ranges)?;
        let blocks = u32::try_from(entries.len()).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF Virtual Partition block count exceeds address space",
            )
        })?;
        if blocks == 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT contains no virtual block entries",
            ));
        }
        Ok(Partition {
            blocks,
            mapping: PartitionMapping::Virtual(VirtualPartition {
                physical_start: physical.start,
                entries,
            }),
        })
    }

    fn discover_latest_vat(
        &mut self,
        physical: &PhysicalPartition,
        revision: u16,
        budget: &mut usize,
    ) -> Result<u32, StreamError> {
        if physical.blocks == 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Virtual Partition references an empty physical partition",
            ));
        }
        let expected_file_type = if revision == 0x0150 { 0 } else { FILE_TYPE_VAT };
        let scan_blocks = physical.blocks.min(MAX_VAT_DISCOVERY_BLOCKS);
        for distance in 0..scan_blocks {
            let location = physical
                .blocks
                .checked_sub(distance)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF VAT discovery block underflow")
                })?;
            let descriptor = self.read_physical_partition_block(physical, location)?;
            self.account_vat_budget(budget, descriptor.capacity())?;
            if matches!(
                le_u16(&descriptor, 0)?,
                TAG_FILE_ENTRY | TAG_EXTENDED_FILE_ENTRY
            ) && descriptor.get(27).copied() == Some(expected_file_type)
            {
                return Ok(location);
            }
        }
        if scan_blocks < physical.blocks {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF VAT discovery exceeds the bounded reverse-scan window",
            ));
        }
        Err(udf_error(
            ErrorKind::Malformed,
            "UDF Virtual Partition has no discoverable VAT ICB",
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn parse_vat(
        &mut self,
        physical: &PhysicalPartition,
        physical_reference: u16,
        location: u32,
        revision: u16,
        budget: &mut usize,
    ) -> Result<ParsedVat, StreamError> {
        let descriptor =
            self.read_physical_partition_descriptor(physical, location, None, "UDF VAT ICB")?;
        self.account_vat_budget(budget, descriptor.capacity())?;
        let tag = le_u16(&descriptor, 0)?;
        let (
            object_size_offset,
            logical_blocks_offset,
            external_attributes_offset,
            extended_length_offset,
            allocation_length_offset,
            allocation_start,
        ): (Option<usize>, usize, usize, usize, usize, usize) = match tag {
            TAG_FILE_ENTRY => (None, 64, 112, 168, 172, 176),
            TAG_EXTENDED_FILE_ENTRY => (Some(64), 72, 136, 208, 212, 216),
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT ICB does not reference a File Entry",
                ));
            },
        };
        if le_u16(&descriptor, 20)? != 4 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF VAT ICB strategy type is not 4",
            ));
        }
        let expected_file_type = if revision == 0x0150 { 0 } else { FILE_TYPE_VAT };
        if descriptor.get(27).copied() != Some(expected_file_type) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT ICB has the wrong file type",
            ));
        }
        let flags = le_u16(&descriptor, 34)?;
        let allocation_type = flags & 0x0007;
        if flags
            & (ICB_FLAG_RESERVED | ICB_FLAG_TRANSFORMED | ICB_FLAG_MULTI_VERSION | ICB_FLAG_STREAM)
            != 0
            || !matches!(allocation_type, 0 | 1 | 3)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT ICB has invalid flags or allocation descriptors",
            ));
        }
        if le_u16(&descriptor, 48)? != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT ICB has a non-zero File Link Count",
            ));
        }
        if parse_optional_long_ad(
            &descriptor,
            external_attributes_offset,
            "VAT external extended attributes",
        )?
        .is_some()
            || (tag == TAG_EXTENDED_FILE_ENTRY
                && parse_optional_long_ad(&descriptor, 152, "VAT stream directory")?.is_some())
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT ICB has an auxiliary ICB",
            ));
        }
        let extended_length = usize::try_from(le_u32(&descriptor, extended_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF VAT extended attributes exceed address space",
                )
            })?;
        if extended_length != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT ICB has embedded extended attributes",
            ));
        }
        let information_length = le_u64(&descriptor, 56)?;
        if information_length == 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT Information Length is zero",
            ));
        }
        if object_size_offset
            .map(|offset| le_u64(&descriptor, offset))
            .transpose()?
            .is_some_and(|object_size| object_size != information_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT Object Size differs from Information Length",
            ));
        }
        let body_length = usize::try_from(information_length)
            .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT exceeds address space"))?;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|maximum| body_length > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF VAT exceeds the configured in-flight byte limit",
            ));
        }
        self.account_vat_budget(budget, body_length)?;
        let allocation_length = usize::try_from(le_u32(&descriptor, allocation_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF VAT allocation descriptors exceed address space",
                )
            })?;
        let allocation_end = allocation_start
            .checked_add(allocation_length)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF VAT allocation length overflow"))?;
        require_verified_range(
            &descriptor,
            allocation_end,
            "UDF VAT allocation descriptors",
        )?;
        let allocation = descriptor
            .get(allocation_start..allocation_end)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT allocation descriptors are truncated",
                )
            })?;
        let mut occupied_ranges = vec![physical_block_range(physical, location, 1)?];
        self.account_vat_budget(budget, core::mem::size_of::<(u64, u64)>())?;
        let expected_recorded = le_u64(&descriptor, logical_blocks_offset)?;
        let (payload, recorded_blocks) = if allocation_type == 3 {
            if allocation_length != body_length {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "embedded UDF VAT length differs from Information Length",
                ));
            }
            (
                UdfPayload::Inline {
                    data: allocation.to_vec(),
                    tag_location: location,
                },
                0,
            )
        } else {
            self.parse_vat_allocations(
                physical,
                physical_reference,
                allocation,
                allocation_type,
                information_length,
                &mut occupied_ranges,
                budget,
            )?
        };
        if expected_recorded != recorded_blocks {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT Logical Blocks Recorded does not match its allocations",
            ));
        }
        let body = match payload {
            UdfPayload::Inline { data, .. } => data,
            external => {
                let mut body = Vec::new();
                body.try_reserve_exact(body_length)
                    .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT body allocation failed"))?;
                body.resize(body_length, 0);
                UdfDataCursor::new(external, information_length)?
                    .read_exact(self.input, &mut body)?;
                body
            },
        };
        let (entries, previous_icb) = self.parse_vat_contents(&body, revision, budget)?;
        self.validate_vat_entries(physical, &entries, &occupied_ranges, budget)?;
        Ok(ParsedVat {
            entries,
            previous_icb,
            occupied_ranges,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn parse_vat_allocations(
        &mut self,
        physical: &PhysicalPartition,
        physical_reference: u16,
        initial: &[u8],
        allocation_type: u16,
        information_length: u64,
        occupied_ranges: &mut Vec<(u64, u64)>,
        budget: &mut usize,
    ) -> Result<(UdfPayload, u64), StreamError> {
        let width = match allocation_type {
            0 => 8,
            1 => 16,
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT uses an invalid allocation descriptor type",
                ));
            },
        };
        let mut descriptors = initial.to_vec();
        self.account_vat_budget(budget, descriptors.capacity())?;
        let mut extents = Vec::new();
        let mut logical_offset = 0_u64;
        let mut recorded_blocks = 0_u64;
        let mut chains = BTreeSet::new();
        let mut depth = 0_usize;
        let mut previous_allocation_extent = 0_u32;
        loop {
            if !descriptors.len().is_multiple_of(width) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT allocation descriptor array is truncated",
                ));
            }
            let mut continuation = None;
            for (descriptor_index, descriptor) in descriptors.chunks_exact(width).enumerate() {
                let raw_length = le_u32(descriptor, 0)?;
                let extent_type = raw_length >> 30;
                let extent_length = raw_length & 0x3fff_ffff;
                let logical_block = le_u32(descriptor, 4)?;
                let referenced_partition = if allocation_type == 1 {
                    le_u16(descriptor, 8)?
                } else {
                    physical_reference
                };
                if allocation_type == 1
                    && (le_u16(descriptor, 10)? != 0
                        || descriptor[12..16].iter().any(|byte| *byte != 0))
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT long allocation descriptor implementation use is non-zero",
                    ));
                }
                if extent_length == 0 {
                    if extent_type != 0
                        || logical_block != 0
                        || (allocation_type == 1 && referenced_partition != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "zero-length UDF VAT allocation has non-zero fields",
                        ));
                    }
                    let trailing = (descriptor_index + 1).checked_mul(width).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF VAT allocation offset overflow")
                    })?;
                    if descriptors[trailing..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "non-zero UDF VAT allocation follows a terminator",
                        ));
                    }
                    break;
                }
                if referenced_partition != physical_reference {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT allocation references a non-physical partition map",
                    ));
                }
                if extent_type == 3 {
                    let trailing = (descriptor_index + 1).checked_mul(width).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF VAT allocation offset overflow")
                    })?;
                    if descriptors[trailing..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF VAT allocation follows a continuation",
                        ));
                    }
                    if extent_length > BLOCK_SIZE_U32 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "oversized continuation in UDF VAT allocations",
                        ));
                    }
                    if !chains.insert(logical_block) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "cycle in UDF VAT allocations",
                        ));
                    }
                    self.account_vat_budget(budget, core::mem::size_of::<u32>() * 4)?;
                    depth = depth.checked_add(1).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF VAT allocation depth overflow")
                    })?;
                    if depth > MAX_VAT_HISTORY_DEPTH
                        || self.limits.nesting().is_some_and(|maximum| depth > maximum)
                    {
                        return Err(udf_error(
                            ErrorKind::Limit,
                            "UDF VAT allocation depth exceeds configured limit",
                        ));
                    }
                    let range = physical_block_range(physical, logical_block, 1)?;
                    Self::insert_vat_range(occupied_ranges, range)?;
                    self.account_vat_budget(budget, core::mem::size_of::<(u64, u64)>())?;
                    continuation = Some((logical_block, extent_length));
                    break;
                }
                if extent_type != 0 {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT contains an unrecorded allocation",
                    ));
                }
                let next = logical_offset
                    .checked_add(u64::from(extent_length))
                    .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT length overflow"))?;
                if next > information_length
                    || (next < information_length && !extent_length.is_multiple_of(BLOCK_SIZE_U32))
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT allocation lengths disagree with Information Length",
                    ));
                }
                let blocks = extent_length.div_ceil(BLOCK_SIZE_U32);
                let range = physical_block_range(physical, logical_block, blocks)?;
                Self::insert_vat_range(occupied_ranges, range)?;
                self.account_vat_budget(
                    budget,
                    core::mem::size_of::<(u64, u64)>()
                        .checked_add(core::mem::size_of::<UdfExtent>())
                        .ok_or_else(|| {
                            udf_error(ErrorKind::Limit, "UDF VAT extent accounting overflow")
                        })?,
                )?;
                extents
                    .try_reserve(1)
                    .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT extent allocation failed"))?;
                extents.push(UdfExtent {
                    source_offset: Some(range.0.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF VAT source offset overflow")
                    })?),
                    length: u64::from(extent_length),
                    logical_block,
                });
                logical_offset = next;
                recorded_blocks =
                    recorded_blocks
                        .checked_add(u64::from(blocks))
                        .ok_or_else(|| {
                            udf_error(ErrorKind::Limit, "UDF VAT recorded-block count overflow")
                        })?;
            }
            let Some((location, declared_length)) = continuation else {
                break;
            };
            let chained = self.read_physical_partition_descriptor(
                physical,
                location,
                Some(TAG_ALLOCATION_EXTENT),
                "UDF VAT Allocation Extent Descriptor",
            )?;
            self.account_vat_budget(budget, chained.capacity())?;
            let used = TAG_SIZE
                .checked_add(usize::from(le_u16(&chained, 10)?))
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT Allocation Extent length overflow",
                    )
                })?;
            if used > usize::try_from(declared_length).unwrap_or(usize::MAX)
                || le_u32(&chained, 16)? != previous_allocation_extent
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT Allocation Extent has invalid bounds or back pointer",
                ));
            }
            previous_allocation_extent = location;
            let descriptors_length = usize::try_from(le_u32(&chained, 20)?).map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF VAT continuation descriptors exceed address space",
                )
            })?;
            let end = 24_usize.checked_add(descriptors_length).ok_or_else(|| {
                udf_error(ErrorKind::Malformed, "UDF VAT continuation length overflow")
            })?;
            require_verified_range(&chained, end, "UDF VAT Allocation Extent Descriptor")?;
            descriptors = chained
                .get(24..end)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF VAT continuation descriptors are truncated",
                    )
                })?
                .to_vec();
            self.account_vat_budget(budget, descriptors.capacity())?;
        }
        if logical_offset != information_length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT allocations do not equal Information Length",
            ));
        }
        Ok((UdfPayload::Extents(extents), recorded_blocks))
    }

    fn parse_vat_contents(
        &self,
        body: &[u8],
        revision: u16,
        budget: &mut usize,
    ) -> Result<(Vec<Option<u32>>, Option<u32>), StreamError> {
        let (entry_bytes, previous_icb) = if revision == 0x0150 {
            Self::parse_vat_150_contents(body, revision)?
        } else {
            Self::parse_vat_200_contents(body, revision)?
        };
        let entry_count = entry_bytes.len() / 4;
        self.account_vat_budget(
            budget,
            entry_count
                .checked_mul(core::mem::size_of::<Option<u32>>())
                .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT entry accounting overflow"))?,
        )?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(entry_count)
            .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT entry allocation failed"))?;
        for entry in entry_bytes.chunks_exact(4) {
            entries.push(optional_u32(le_u32(entry, 0)?));
        }
        Ok((entries, previous_icb))
    }

    fn parse_vat_150_contents(
        body: &[u8],
        revision: u16,
    ) -> Result<(&[u8], Option<u32>), StreamError> {
        if body.len() < 36 || !(body.len() - 36).is_multiple_of(4) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF 1.50 VAT body is truncated or misaligned",
            ));
        }
        let entries_end = body.len() - 36;
        validate_udf_entity_identifier(
            &body[entries_end..entries_end + 32],
            b"*UDF Virtual Alloc Tbl",
            revision,
            "UDF VAT",
        )?;
        Ok((
            &body[..entries_end],
            optional_u32(le_u32(body, entries_end + 32)?),
        ))
    }

    fn parse_vat_200_contents(
        body: &[u8],
        revision: u16,
    ) -> Result<(&[u8], Option<u32>), StreamError> {
        if body.len() < 152 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF 2.00+ VAT header is truncated",
            ));
        }
        let header_length = usize::from(le_u16(body, 0)?);
        let implementation_length = usize::from(le_u16(body, 2)?);
        let expected_header = 152_usize
            .checked_add(implementation_length)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT header length overflow"))?;
        if header_length != expected_header
            || header_length > body.len()
            || !(body.len() - header_length).is_multiple_of(4)
            || (implementation_length != 0
                && (implementation_length < 32 || !implementation_length.is_multiple_of(4)))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT header or entry table has invalid lengths",
            ));
        }
        if body[150..152].iter().any(|byte| *byte != 0) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT header reserved bytes are non-zero",
            ));
        }
        if decode_dstring(&body[4..132])?.is_empty() {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT Logical Volume Identifier is empty",
            ));
        }
        let minimum_read = le_u16(body, 144)?;
        if !matches!(
            minimum_read,
            0x0102 | 0x0150 | 0x0200 | 0x0201 | 0x0250 | 0x0260
        ) {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF VAT requires an unsupported minimum read revision",
            ));
        }
        if minimum_read > revision {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF VAT minimum read revision exceeds the logical-volume revision",
            ));
        }
        if implementation_length != 0 {
            let implementation = &body[152..header_length];
            if implementation[0] != 0 || implementation[28..32].iter().any(|byte| *byte != 0) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT implementation-use EntityID is malformed",
                ));
            }
        }
        Ok((&body[header_length..], optional_u32(le_u32(body, 132)?)))
    }

    fn validate_vat_entries(
        &self,
        physical: &PhysicalPartition,
        entries: &[Option<u32>],
        occupied_ranges: &[(u64, u64)],
        budget: &mut usize,
    ) -> Result<(), StreamError> {
        let mapped_count = entries.iter().flatten().count();
        self.account_vat_budget(
            budget,
            mapped_count
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or_else(|| {
                    udf_error(ErrorKind::Limit, "UDF VAT mapping accounting overflow")
                })?,
        )?;
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(mapped_count)
            .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT mapping allocation failed"))?;
        mapped.extend(entries.iter().flatten().copied());
        mapped.sort_unstable();
        if mapped.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "overlapping UDF VAT entries map multiple virtual blocks to one physical block",
            ));
        }
        Self::validate_vat_entry_ranges(physical, entries, occupied_ranges)
    }

    fn validate_vat_entry_ranges(
        physical: &PhysicalPartition,
        entries: &[Option<u32>],
        occupied_ranges: &[(u64, u64)],
    ) -> Result<(), StreamError> {
        for location in entries.iter().flatten().copied() {
            let range = physical_block_range(physical, location, 1)?;
            if occupied_ranges
                .iter()
                .any(|occupied| ranges_overlap(*occupied, range))
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF VAT entry overlaps VAT metadata",
                ));
            }
        }
        Ok(())
    }

    fn insert_vat_range(
        ranges: &mut Vec<(u64, u64)>,
        candidate: (u64, u64),
    ) -> Result<(), StreamError> {
        if ranges.iter().any(|range| ranges_overlap(*range, candidate)) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "overlapping UDF VAT physical allocations",
            ));
        }
        ranges
            .try_reserve(1)
            .map_err(|_| udf_error(ErrorKind::Limit, "UDF VAT physical-range allocation failed"))?;
        ranges.push(candidate);
        Ok(())
    }

    fn enforce_vat_budget(&self, used: usize) -> Result<(), StreamError> {
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| used > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF VAT metadata exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn account_vat_budget(&self, used: &mut usize, additional: usize) -> Result<(), StreamError> {
        *used = used
            .checked_add(additional)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF VAT metadata accounting overflow"))?;
        self.enforce_vat_budget(*used)
    }

    fn load_metadata_partition(
        &mut self,
        base: &Partition,
        map: &RawMetadataPartitionMap,
    ) -> Result<Partition, StreamError> {
        let mut budget = core::mem::size_of::<MetadataPartition>()
            .checked_add(core::mem::size_of::<MetadataFile>() * 2)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata-map accounting overflow"))?;
        self.enforce_local_metadata_budget(budget)?;

        let primary_result = self.parse_metadata_file(
            base,
            map.metadata_file_location,
            FILE_TYPE_METADATA,
            map.allocation_unit_blocks,
            map.alignment_unit_blocks,
            &mut budget,
        );
        let mirror_result = map.metadata_mirror_file_location.map(|location| {
            self.parse_metadata_file(
                base,
                location,
                FILE_TYPE_METADATA_MIRROR,
                map.allocation_unit_blocks,
                map.alignment_unit_blocks,
                &mut budget,
            )
        });

        let (primary, mirror) = match primary_result {
            Ok(primary) => {
                let mirror = match mirror_result {
                    Some(Ok(mirror)) => Some(mirror),
                    Some(Err(error)) if can_fallback_to_reserve(&error) => None,
                    Some(Err(error)) => return Err(error),
                    None => None,
                };
                (primary, mirror)
            },
            Err(primary_error) if can_fallback_to_reserve(&primary_error) => match mirror_result {
                Some(Ok(mirror)) => (mirror, None),
                Some(Err(error)) if can_fallback_to_reserve(&error) => {
                    return Err(primary_error);
                },
                Some(Err(error)) => return Err(error),
                None => return Err(primary_error),
            },
            Err(error) => return Err(error),
        };

        let mirror = if let Some(mirror) = mirror {
            if primary.blocks != mirror.blocks {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File and mirror have different information lengths",
                ));
            }
            if map.duplicate {
                if metadata_files_overlap(&primary, &mirror)? {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "duplicated UDF Metadata File allocations overlap their mirror",
                    ));
                }
                Some(mirror)
            } else {
                if primary != mirror {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "shared UDF Metadata File and mirror allocations differ",
                    ));
                }
                None
            }
        } else {
            None
        };

        if let Some(location) = map.metadata_bitmap_file_location {
            if location == map.metadata_file_location
                || map.metadata_mirror_file_location == Some(location)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap File ICB overlaps a metadata-file ICB",
                ));
            }
            self.validate_metadata_bitmap(base, location, primary.blocks, &mut budget)?;
        }

        Ok(Partition {
            blocks: primary.blocks,
            mapping: PartitionMapping::Metadata(MetadataPartition {
                primary,
                mirror,
                using_mirror: false,
            }),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_metadata_file(
        &mut self,
        base: &Partition,
        location: u32,
        expected_file_type: u8,
        allocation_unit_blocks: u32,
        alignment_unit_blocks: u16,
        budget: &mut usize,
    ) -> Result<MetadataFile, StreamError> {
        let descriptor =
            self.read_base_partition_descriptor(base, location, None, "UDF Metadata File ICB")?;
        self.account_local_metadata_budget(budget, descriptor.capacity())?;
        let tag = le_u16(&descriptor, 0)?;
        let (
            information_offset,
            object_size_offset,
            logical_blocks_offset,
            external_attributes_offset,
            extended_length_offset,
            allocation_length_offset,
            allocation_start,
            unique_offset,
        ): (
            usize,
            Option<usize>,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
        ) = match tag {
            TAG_FILE_ENTRY => (56, None, 64, 112, 168, 172, 176, 160),
            TAG_EXTENDED_FILE_ENTRY => (56, Some(64), 72, 136, 208, 212, 216, 200),
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File ICB does not reference a File Entry",
                ));
            },
        };
        if le_u16(&descriptor, 20)? != 4 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF Metadata File ICB strategy type is not 4",
            ));
        }
        if descriptor.get(27).copied() != Some(expected_file_type) {
            return Err(udf_error(
                ErrorKind::Malformed,
                format!(
                    "UDF metadata auxiliary ICB has file type {}, expected {expected_file_type}",
                    descriptor.get(27).copied().unwrap_or_default()
                ),
            ));
        }
        let flags = le_u16(&descriptor, 34)?;
        if flags
            & (ICB_FLAG_RESERVED | ICB_FLAG_TRANSFORMED | ICB_FLAG_MULTI_VERSION | ICB_FLAG_STREAM)
            != 0
            || flags & 0x0007 != 0
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File must use untransformed short allocation descriptors",
            ));
        }
        if le_u16(&descriptor, 48)? != 0 || le_u64(&descriptor, unique_offset)? != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File link count and Unique ID must be zero",
            ));
        }
        if parse_optional_long_ad(
            &descriptor,
            external_attributes_offset,
            "Metadata File external extended attributes",
        )?
        .is_some()
            || (tag == TAG_EXTENDED_FILE_ENTRY
                && parse_optional_long_ad(&descriptor, 152, "Metadata File stream directory")?
                    .is_some())
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File has an auxiliary ICB",
            ));
        }
        let extended_length = usize::try_from(le_u32(&descriptor, extended_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata File extended attributes exceed address space",
                )
            })?;
        if extended_length != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File has embedded extended attributes",
            ));
        }
        let allocation_length = usize::try_from(le_u32(&descriptor, allocation_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata File allocation descriptors exceed address space",
                )
            })?;
        let allocation_end = allocation_start
            .checked_add(allocation_length)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File allocation length overflow",
                )
            })?;
        require_verified_range(
            &descriptor,
            allocation_end,
            "UDF Metadata File allocation descriptors",
        )?;
        let information_length = le_u64(&descriptor, information_offset)?;
        if information_length == 0 || !information_length.is_multiple_of(BLOCK_SIZE) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File information length is not a non-zero block multiple",
            ));
        }
        if object_size_offset
            .map(|offset| le_u64(&descriptor, offset))
            .transpose()?
            .is_some_and(|object_size| object_size != information_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File Object Size differs from Information Length",
            ));
        }
        let blocks = u32::try_from(information_length / BLOCK_SIZE).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF Metadata Partition block count exceeds address space",
            )
        })?;
        let expected_recorded = le_u64(&descriptor, logical_blocks_offset)?;
        let allocation = descriptor
            .get(allocation_start..allocation_end)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File allocation descriptors are truncated",
                )
            })?;
        self.account_local_metadata_budget(budget, core::mem::size_of::<(u64, u64)>())?;
        let mut physical_ranges = self.base_partition_block_ranges(base, location, BLOCK_SIZE)?;
        self.account_local_metadata_budget(
            budget,
            physical_ranges
                .len()
                .checked_mul(core::mem::size_of::<(u64, u64)>())
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Limit,
                        "UDF Metadata File range accounting overflow",
                    )
                })?,
        )?;
        let (extents, recorded_blocks) = self.parse_metadata_file_allocations(
            base,
            allocation,
            information_length,
            allocation_unit_blocks,
            alignment_unit_blocks,
            &mut physical_ranges,
            budget,
        )?;
        if recorded_blocks != expected_recorded {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File Logical Blocks Recorded does not match its allocations",
            ));
        }
        Ok(MetadataFile { blocks, extents })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn parse_metadata_file_allocations(
        &mut self,
        base: &Partition,
        initial: &[u8],
        information_length: u64,
        allocation_unit_blocks: u32,
        alignment_unit_blocks: u16,
        physical_ranges: &mut Vec<(u64, u64)>,
        budget: &mut usize,
    ) -> Result<(Vec<MetadataFileExtent>, u64), StreamError> {
        if !initial.len().is_multiple_of(8) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File short allocation descriptor array is truncated",
            ));
        }
        let allocation_unit_bytes = u64::from(allocation_unit_blocks)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata Partition allocation unit overflows",
                )
            })?;
        let mut descriptors = initial.to_vec();
        self.account_local_metadata_budget(budget, descriptors.capacity())?;
        let mut extents = Vec::new();
        let mut chains = BTreeSet::new();
        let mut logical_offset = 0_u64;
        let mut recorded_blocks = 0_u64;
        let mut depth = 0_usize;
        loop {
            let mut continuation = None;
            for (descriptor_index, descriptor) in descriptors.chunks_exact(8).enumerate() {
                let raw_length = le_u32(descriptor, 0)?;
                let extent_type = raw_length >> 30;
                let extent_length = u64::from(raw_length & 0x3fff_ffff);
                let logical_block = le_u32(descriptor, 4)?;
                if extent_length == 0 {
                    if extent_type != 0 || logical_block != 0 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "zero-length UDF Metadata File allocation has non-zero fields",
                        ));
                    }
                    let trailing = (descriptor_index + 1).checked_mul(8).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File allocation offset overflow",
                        )
                    })?;
                    if descriptors[trailing..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "non-zero UDF Metadata File allocation follows a terminator",
                        ));
                    }
                    break;
                }
                if extent_type == 3 {
                    let trailing = (descriptor_index + 1).checked_mul(8).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File allocation offset overflow",
                        )
                    })?;
                    if descriptors[trailing..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata File allocation follows a continuation",
                        ));
                    }
                    if extent_length > BLOCK_SIZE {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata File allocation continuation exceeds one block",
                        ));
                    }
                    if !chains.insert(logical_block) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "cycle in UDF Metadata File allocation descriptors",
                        ));
                    }
                    self.account_local_metadata_budget(budget, core::mem::size_of::<u32>() * 4)?;
                    depth = depth.checked_add(1).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File allocation depth overflow",
                        )
                    })?;
                    if self.limits.nesting().is_some_and(|maximum| depth > maximum) {
                        return Err(udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File allocation depth exceeds configured limit",
                        ));
                    }
                    let ranges =
                        self.base_partition_block_ranges(base, logical_block, BLOCK_SIZE)?;
                    for range in ranges {
                        self.account_local_metadata_budget(
                            budget,
                            core::mem::size_of::<(u64, u64)>(),
                        )?;
                        insert_nonoverlapping_range(physical_ranges, range)?;
                    }
                    continuation = Some((
                        logical_block,
                        u32::try_from(extent_length).map_err(|_| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF Metadata File continuation length exceeds address space",
                            )
                        })?,
                    ));
                    break;
                }
                if !matches!(extent_type, 0 | 2) {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata File contains a not-recorded-but-allocated extent",
                    ));
                }
                if !extent_length.is_multiple_of(allocation_unit_bytes) {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata File extent is not allocation-unit aligned",
                    ));
                }
                let next = logical_offset.checked_add(extent_length).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Limit,
                        "UDF Metadata File logical length overflow",
                    )
                })?;
                if next > information_length {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata File allocations exceed Information Length",
                    ));
                }
                if extent_type == 0 {
                    if !logical_block.is_multiple_of(u32::from(alignment_unit_blocks)) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata File extent start is not alignment-unit aligned",
                        ));
                    }
                    let block_count = extent_length / BLOCK_SIZE;
                    let block_count = u32::try_from(block_count).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File extent block count exceeds address space",
                        )
                    })?;
                    let translated =
                        self.base_partition_extents(base, logical_block, extent_length)?;
                    let translated_ranges = udf_extent_block_ranges(&translated)?;
                    for range in translated_ranges {
                        self.account_local_metadata_budget(
                            budget,
                            core::mem::size_of::<(u64, u64)>(),
                        )?;
                        insert_nonoverlapping_range(physical_ranges, range)?;
                    }
                    recorded_blocks = recorded_blocks
                        .checked_add(u64::from(block_count))
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF Metadata File recorded-block count overflow",
                            )
                        })?;
                    let mut translated_offset = logical_offset;
                    for translated_extent in translated {
                        self.account_local_metadata_budget(
                            budget,
                            core::mem::size_of::<MetadataFileExtent>(),
                        )?;
                        extents.try_reserve(1).map_err(|_| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF Metadata File extent allocation failed",
                            )
                        })?;
                        extents.push(MetadataFileExtent {
                            logical_offset: translated_offset,
                            length: translated_extent.length,
                            source_offset: translated_extent.source_offset,
                        });
                        translated_offset = translated_offset
                            .checked_add(translated_extent.length)
                            .ok_or_else(|| {
                                udf_error(
                                    ErrorKind::Limit,
                                    "UDF Metadata File translated offset overflow",
                                )
                            })?;
                    }
                    if translated_offset != next {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata File base translation changed its extent length",
                        ));
                    }
                } else {
                    if logical_block != 0 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "unallocated UDF Metadata File extent has a non-zero location",
                        ));
                    }
                    self.account_local_metadata_budget(
                        budget,
                        core::mem::size_of::<MetadataFileExtent>(),
                    )?;
                    extents.try_reserve(1).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata File extent allocation failed",
                        )
                    })?;
                    extents.push(MetadataFileExtent {
                        logical_offset,
                        length: extent_length,
                        source_offset: None,
                    });
                }
                logical_offset = next;
            }
            let Some((location, extent_length)) = continuation else {
                break;
            };
            let chained = self.read_base_partition_descriptor(
                base,
                location,
                Some(TAG_ALLOCATION_EXTENT),
                "UDF Metadata File Allocation Extent Descriptor",
            )?;
            let declared_extent_length = usize::try_from(extent_length).map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata File continuation length exceeds address space",
                )
            })?;
            if TAG_SIZE
                .checked_add(usize::from(le_u16(&chained, 10)?))
                .is_none_or(|used| used > declared_extent_length)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File Allocation Extent exceeds its declared extent",
                ));
            }
            let descriptors_length = usize::try_from(le_u32(&chained, 20)?).map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata File continuation descriptors exceed address space",
                )
            })?;
            let end = 24_usize.checked_add(descriptors_length).ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File continuation length overflow",
                )
            })?;
            require_verified_range(
                &chained,
                end,
                "UDF Metadata File Allocation Extent Descriptor",
            )?;
            if !descriptors_length.is_multiple_of(8) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata File continuation short ADs are truncated",
                ));
            }
            descriptors = chained
                .get(24..end)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata File continuation descriptors are truncated",
                    )
                })?
                .to_vec();
            self.account_local_metadata_budget(budget, descriptors.capacity())?;
        }
        if logical_offset != information_length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File allocations do not equal Information Length",
            ));
        }
        Ok((extents, recorded_blocks))
    }

    #[allow(clippy::too_many_lines)]
    fn validate_metadata_bitmap(
        &mut self,
        base: &Partition,
        location: u32,
        metadata_blocks: u32,
        budget: &mut usize,
    ) -> Result<(), StreamError> {
        let descriptor = self.read_base_partition_descriptor(
            base,
            location,
            None,
            "UDF Metadata Bitmap File ICB",
        )?;
        self.account_local_metadata_budget(budget, descriptor.capacity())?;
        let tag = le_u16(&descriptor, 0)?;
        let (
            information_offset,
            object_size_offset,
            logical_blocks_offset,
            external_attributes_offset,
            extended_length_offset,
            allocation_length_offset,
            data_offset,
            unique_offset,
        ): (
            usize,
            Option<usize>,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
        ) = match tag {
            TAG_FILE_ENTRY => (56, None, 64, 112, 168, 172, 176, 160),
            TAG_EXTENDED_FILE_ENTRY => (56, Some(64), 72, 136, 208, 212, 216, 200),
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap File ICB does not reference a File Entry",
                ));
            },
        };
        if le_u16(&descriptor, 20)? != 4
            || descriptor.get(27).copied() != Some(FILE_TYPE_METADATA_BITMAP)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File has an invalid strategy or file type",
            ));
        }
        let flags = le_u16(&descriptor, 34)?;
        let allocation_type = flags & 0x0007;
        if flags
            & (ICB_FLAG_RESERVED | ICB_FLAG_TRANSFORMED | ICB_FLAG_MULTI_VERSION | ICB_FLAG_STREAM)
            != 0
            || !matches!(allocation_type, 0 | 3)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File has invalid ICB flags",
            ));
        }
        if le_u16(&descriptor, 48)? != 0 || le_u64(&descriptor, unique_offset)? != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File link count and Unique ID must be zero",
            ));
        }
        if parse_optional_long_ad(
            &descriptor,
            external_attributes_offset,
            "Metadata Bitmap File external extended attributes",
        )?
        .is_some()
            || (tag == TAG_EXTENDED_FILE_ENTRY
                && parse_optional_long_ad(
                    &descriptor,
                    152,
                    "Metadata Bitmap File stream directory",
                )?
                .is_some())
            || le_u32(&descriptor, extended_length_offset)? != 0
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File has auxiliary metadata",
            ));
        }
        let information_length = le_u64(&descriptor, information_offset)?;
        if information_length < 24 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File is shorter than its Space Bitmap Descriptor",
            ));
        }
        if object_size_offset
            .map(|offset| le_u64(&descriptor, offset))
            .transpose()?
            .is_some_and(|object_size| object_size != information_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap File Object Size differs from Information Length",
            ));
        }
        let allocation_length = usize::try_from(le_u32(&descriptor, allocation_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata Bitmap allocations exceed address space",
                )
            })?;
        let allocation_end = data_offset.checked_add(allocation_length).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap allocation length overflow",
            )
        })?;
        require_verified_range(
            &descriptor,
            allocation_end,
            "UDF Metadata Bitmap allocation descriptors",
        )?;
        let allocation = descriptor.get(data_offset..allocation_end).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap allocation descriptors are truncated",
            )
        })?;
        let mut header = [0_u8; 24];
        let tag_location = if allocation_type == 3 {
            let length = usize::try_from(information_length).map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata Bitmap inline length exceeds address space",
                )
            })?;
            if allocation.len() < length || allocation.len() < header.len() {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "inline UDF Metadata Bitmap is truncated",
                ));
            }
            let header_length = header.len();
            header.copy_from_slice(&allocation[..header_length]);
            if le_u64(&descriptor, logical_blocks_offset)? != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "inline UDF Metadata Bitmap records physical blocks",
                ));
            }
            location
        } else {
            if !allocation.len().is_multiple_of(8) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap short AD array is truncated",
                ));
            }
            let mut total = 0_u64;
            let mut recorded_blocks = 0_u64;
            let mut copied = 0_usize;
            let mut first_location = None;
            let mut ranges = self.base_partition_block_ranges(base, location, BLOCK_SIZE)?;
            self.account_local_metadata_budget(
                budget,
                ranges
                    .len()
                    .checked_mul(core::mem::size_of::<(u64, u64)>())
                    .ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata Bitmap range accounting overflow",
                        )
                    })?,
            )?;
            for descriptor in allocation.chunks_exact(8) {
                let raw_length = le_u32(descriptor, 0)?;
                let extent_type = raw_length >> 30;
                let extent_length = u64::from(raw_length & 0x3fff_ffff);
                let logical_block = le_u32(descriptor, 4)?;
                if extent_length == 0 {
                    if extent_type != 0 || logical_block != 0 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "zero-length UDF Metadata Bitmap allocation has non-zero fields",
                        ));
                    }
                    break;
                }
                if extent_type != 0 {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Bitmap has an unrecorded allocation",
                    ));
                }
                let block_count =
                    u32::try_from(extent_length.div_ceil(BLOCK_SIZE)).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata Bitmap extent exceeds address space",
                        )
                    })?;
                let allocated_length =
                    u64::from(block_count)
                        .checked_mul(BLOCK_SIZE)
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF Metadata Bitmap allocated length overflow",
                            )
                        })?;
                let translated =
                    self.base_partition_extents(base, logical_block, allocated_length)?;
                for range in udf_extent_block_ranges(&translated)? {
                    self.account_local_metadata_budget(budget, core::mem::size_of::<(u64, u64)>())?;
                    insert_nonoverlapping_range(&mut ranges, range)?;
                }
                first_location.get_or_insert(logical_block);
                recorded_blocks = recorded_blocks
                    .checked_add(u64::from(block_count))
                    .ok_or_else(|| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF Metadata Bitmap recorded-block count overflow",
                        )
                    })?;
                let mut data_remaining = extent_length;
                for translated_extent in translated {
                    if data_remaining == 0 || copied == header.len() {
                        break;
                    }
                    let available = translated_extent.length.min(data_remaining);
                    let count =
                        (header.len() - copied).min(usize::try_from(available).map_err(|_| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF Metadata Bitmap extent length exceeds address space",
                            )
                        })?);
                    let offset = translated_extent.source_offset.ok_or_else(|| {
                        udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Bitmap recorded extent is unallocated",
                        )
                    })?;
                    self.input
                        .seek(SeekFrom::Start(offset))
                        .map_err(StreamError::io)?;
                    self.input
                        .read_exact(&mut header[copied..copied + count])
                        .map_err(StreamError::io)?;
                    copied += count;
                    data_remaining -= available;
                }
                total = total.checked_add(extent_length).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Limit,
                        "UDF Metadata Bitmap information length overflow",
                    )
                })?;
            }
            if total != information_length || copied != header.len() {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap allocations do not equal Information Length",
                ));
            }
            if recorded_blocks != le_u64(&descriptor, logical_blocks_offset)? {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap Logical Blocks Recorded is inconsistent",
                ));
            }
            first_location.ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Bitmap has no recorded allocation",
                )
            })?
        };
        validate_descriptor_tag(&header, Some(TAG_SPACE_BITMAP), tag_location)?;
        let crc_length = le_u16(&header, 10)?;
        if !matches!(crc_length, 0 | 8) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap descriptor CRC length is not zero or eight",
            ));
        }
        let bits = le_u32(&header, 16)?;
        let bytes = le_u32(&header, 20)?;
        let required_bytes = bits.div_ceil(8);
        if bits != metadata_blocks || bytes < required_bytes {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap size does not describe its Metadata Partition",
            ));
        }
        if u64::from(bytes)
            .checked_add(24)
            .is_none_or(|length| length != information_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Bitmap Information Length is inconsistent",
            ));
        }
        Ok(())
    }

    fn base_partition_extents(
        &self,
        base: &Partition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        if !matches!(
            base.mapping,
            PartitionMapping::Physical { .. } | PartitionMapping::Sparable(_)
        ) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Metadata Partition base is not physical or Sparable",
            ));
        }
        self.partition_extents(base, logical_block, length)
    }

    fn base_partition_block_ranges(
        &self,
        base: &Partition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<(u64, u64)>, StreamError> {
        let extents = self.base_partition_extents(base, logical_block, length)?;
        udf_extent_block_ranges(&extents)
    }

    fn read_base_partition_descriptor(
        &mut self,
        base: &Partition,
        logical_block: u32,
        expected_tag: Option<u16>,
        context: &'static str,
    ) -> Result<Vec<u8>, StreamError> {
        let descriptor = self.read_base_partition_block(base, logical_block)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Err(udf_error(
                ErrorKind::Malformed,
                format!("{context} is missing"),
            ));
        }
        validate_descriptor_tag(&descriptor, expected_tag, logical_block)?;
        Ok(descriptor)
    }

    fn read_base_partition_block(
        &mut self,
        base: &Partition,
        logical_block: u32,
    ) -> Result<Vec<u8>, StreamError> {
        let extents = self.base_partition_extents(base, logical_block, BLOCK_SIZE)?;
        let extent = extents.first().ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF base-partition block has no physical mapping",
            )
        })?;
        if extents.len() != 1 || extent.length != BLOCK_SIZE {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF base-partition block crosses an invalid mapping boundary",
            ));
        }
        let offset = extent.source_offset.ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF base-partition block is unallocated",
            )
        })?;
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut block = vec![0_u8; BLOCK_SIZE_USIZE];
        self.input.read_exact(&mut block).map_err(StreamError::io)?;
        Ok(block)
    }

    fn read_physical_partition_descriptor(
        &mut self,
        partition: &PhysicalPartition,
        logical_block: u32,
        expected_tag: Option<u16>,
        context: &'static str,
    ) -> Result<Vec<u8>, StreamError> {
        let range = physical_block_range(partition, logical_block, 1)?;
        let offset = range
            .0
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor offset overflow"))?;
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut descriptor = vec![0_u8; BLOCK_SIZE_USIZE];
        self.input
            .read_exact(&mut descriptor)
            .map_err(StreamError::io)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Err(udf_error(
                ErrorKind::Malformed,
                format!("{context} is missing"),
            ));
        }
        validate_descriptor_tag(&descriptor, expected_tag, logical_block)?;
        Ok(descriptor)
    }

    fn read_physical_partition_block(
        &mut self,
        partition: &PhysicalPartition,
        logical_block: u32,
    ) -> Result<Vec<u8>, StreamError> {
        let range = physical_block_range(partition, logical_block, 1)?;
        let offset = range
            .0
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF physical block offset overflow"))?;
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut block = vec![0_u8; BLOCK_SIZE_USIZE];
        self.input.read_exact(&mut block).map_err(StreamError::io)?;
        Ok(block)
    }

    fn enforce_local_metadata_budget(&self, used: usize) -> Result<(), StreamError> {
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| used > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF Metadata Partition metadata exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn account_local_metadata_budget(
        &self,
        used: &mut usize,
        additional: usize,
    ) -> Result<(), StreamError> {
        *used = used.checked_add(additional).ok_or_else(|| {
            udf_error(
                ErrorKind::Limit,
                "UDF Metadata Partition metadata accounting overflow",
            )
        })?;
        self.enforce_local_metadata_budget(*used)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_directory(
        &mut self,
        task: DirectoryTask,
        stack: &mut Vec<DirectoryTask>,
        stream_tasks: &mut Vec<StreamTask>,
    ) -> Result<(), StreamError> {
        if self
            .limits
            .nesting()
            .is_some_and(|maximum| task.depth > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF directory nesting exceeds configured limit",
            ));
        }
        self.account_decoded(
            task.length,
            "UDF directory data exceeds the configured decoded-total limit",
        )?;
        let mut cursor = UdfDirectoryCursor::new(
            task.payload,
            task.length,
            task.parent_icb,
            None,
            self.limits,
        )?;
        while let Some(fid) = cursor.next(self.input)? {
            let icb = fid.icb;
            self.validate_icb_address(icb)?;
            let name = decode_compressed_unicode(&fid.identifier)?;
            if name.is_empty() {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID has an empty identifier",
                ));
            }
            let file = self.parse_file_entry(icb)?;
            if (fid.characteristics & FID_CHARACTERISTIC_DIRECTORY != 0)
                != (file.kind == EntryKind::Dir)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID directory characteristic disagrees with its ICB",
                ));
            }
            let mut path = task.prefix.clone();
            path.extend_from_slice(&name);
            if file.kind == EntryKind::Dir {
                path.push(b'/');
            }
            if self
                .limits
                .path_bytes()
                .is_some_and(|maximum| path.len() > maximum)
            {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF path exceeds configured limit",
                ));
            }
            if !self.seen_paths.insert(path.clone()) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "duplicate UDF archive path",
                ));
            }
            let path_value = ArchivePath::try_from_encoded(path.clone(), PathEncoding::Utf8)?;
            let key = (icb.partition_ref, icb.logical_block);
            let (metadata, payload, directory_task, stream_task) =
                if let Some(target) = self.seen_icbs.get(&key).cloned() {
                    (
                        EntryMetadata::builder(EntryKind::Hardlink, path_value)
                            .size(Some(0))
                            .mode(Some(file.mode))
                            .owner(file.owner)
                            .times(file.times)
                            .inode_and_links(Some(file.inode), Some(file.links))
                            .link_target(Some(target))
                            .build(),
                        UdfPayload::None,
                        None,
                        None,
                    )
                } else {
                    if fid.unique_id != udf_fid_unique_id(file.inode) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "first UDF FID Unique ID differs from its File Entry",
                        ));
                    }
                    self.seen_icbs.insert(key, path_value.clone());
                    let metadata = file.metadata(path_value);
                    let child_depth = task.depth.checked_add(1).ok_or_else(|| {
                        udf_error(ErrorKind::Limit, "UDF directory nesting overflow")
                    })?;
                    let directory_task = (file.kind == EntryKind::Dir).then(|| DirectoryTask {
                        prefix: path.clone(),
                        payload: file.payload.clone(),
                        length: file.size,
                        depth: child_depth,
                        directory_icb: icb,
                        parent_icb: task.directory_icb,
                    });
                    let stream_task = file.stream_directory.map(|stream_directory| StreamTask {
                        owner_path: Some(path),
                        owner_icb: icb,
                        owner_unique_id: Some(file.inode),
                        owner_information_length: Some(file.size),
                        owner_object_size: Some(file.object_size),
                        owner_metadata: Some(StreamOwnerMetadata {
                            mode: file.mode,
                            owner: file.owner.clone(),
                        }),
                        stream_directory,
                        depth: child_depth,
                    });
                    let payload = if matches!(file.kind, EntryKind::File) {
                        file.payload
                    } else {
                        UdfPayload::None
                    };
                    (metadata, payload, directory_task, stream_task)
                };
            self.account_entry(&metadata, &payload)?;
            self.entries.push(UdfIndex { metadata, payload });
            if let Some(directory) = directory_task {
                self.account_directory_task(&directory)?;
                stack.push(directory);
            }
            if let Some(stream) = stream_task {
                self.account_stream_task(&stream)?;
                stream_tasks.push(stream);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn parse_stream_directory(&mut self, task: &StreamTask) -> Result<(), StreamError> {
        if self
            .limits
            .nesting()
            .is_some_and(|maximum| task.depth > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF stream-directory nesting exceeds configured limit",
            ));
        }
        let directory_key = (
            task.stream_directory.partition_ref,
            task.stream_directory.logical_block,
        );
        if self.seen_icbs.contains_key(&directory_key)
            || self.seen_stream_icbs.contains(&directory_key)
            || self.seen_stream_directories.contains(&directory_key)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Stream Directory ICB is referenced more than once",
            ));
        }
        self.seen_stream_directories.insert(directory_key);
        self.account_stream_identity()?;
        let directory =
            self.parse_file_entry_for_role(task.stream_directory, FileEntryRole::StreamDirectory)?;
        if task.owner_path.is_none() && directory.inode != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF System Stream Directory Unique ID is not zero",
            ));
        }
        let owner_unique_id = task.owner_unique_id.unwrap_or(directory.inode);
        if directory.inode != owner_unique_id {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Stream Directory Unique ID differs from its main stream",
            ));
        }
        self.account_decoded(
            directory.size,
            "UDF stream-directory data exceeds the configured decoded-total limit",
        )?;
        let mut cursor = UdfDirectoryCursor::new(
            directory.payload,
            directory.size,
            task.owner_icb,
            Some(udf_fid_unique_id(owner_unique_id)),
            self.limits,
        )?;
        let mut object_size = task.owner_information_length;
        while let Some(fid) = cursor.next(self.input)? {
            if fid.characteristics & FID_CHARACTERISTIC_DIRECTORY != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream FID has the directory characteristic",
                ));
            }
            self.validate_icb_address(fid.icb)?;
            let name = decode_compressed_unicode(&fid.identifier)?;
            if name.is_empty() {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream has an empty identifier",
                ));
            }
            let is_metadata = fid.characteristics & FID_CHARACTERISTIC_METADATA != 0;
            if task.owner_path.is_none() && !is_metadata {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF system stream is missing the metadata characteristic",
                ));
            }
            if udf_defined_stream_metadata(&name).is_some_and(|expected| is_metadata != expected) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF-defined named stream has the wrong metadata characteristic",
                ));
            }
            if fid.unique_id != udf_fid_unique_id(owner_unique_id) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF stream FID Unique ID differs from its main stream",
                ));
            }
            let stream_key = (fid.icb.partition_ref, fid.icb.logical_block);
            if self.seen_icbs.contains_key(&stream_key)
                || self.seen_stream_directories.contains(&stream_key)
                || self.seen_stream_icbs.contains(&stream_key)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream ICB is referenced more than once",
                ));
            }
            self.seen_stream_icbs.insert(stream_key);
            self.account_stream_identity()?;
            let mut file = self.parse_file_entry_for_role(fid.icb, FileEntryRole::NamedStream)?;
            if file.links != 1 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream link count is not one",
                ));
            }
            if file.inode != owner_unique_id {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream Unique ID differs from its main stream",
                ));
            }
            if let Some(total) = &mut object_size {
                *total = total.checked_add(file.size).ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF Object Size calculation overflow")
                })?;
            }
            if let Some(owner) = &task.owner_metadata {
                file.mode = owner.mode;
                file.owner.clone_from(&owner.owner);
            }
            let path = udf_stream_archive_path(task.owner_path.as_deref(), &name)?;
            if self
                .limits
                .path_bytes()
                .is_some_and(|maximum| path.len() > maximum)
            {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "synthetic UDF stream path exceeds configured limit",
                ));
            }
            if !self.seen_paths.insert(path.clone()) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "duplicate synthetic UDF stream archive path",
                ));
            }
            file.extensions.push(Extension::new(
                "udf-stream",
                b"kind".to_vec(),
                if task.owner_path.is_some() {
                    b"named".to_vec()
                } else {
                    b"system".to_vec()
                },
            ));
            file.extensions.push(Extension::new(
                "udf-stream",
                b"owner".to_vec(),
                task.owner_path
                    .as_deref()
                    .filter(|owner| !owner.is_empty())
                    .unwrap_or(b"/")
                    .to_vec(),
            ));
            file.extensions.push(Extension::new(
                "udf-stream",
                b"metadata".to_vec(),
                vec![u8::from(is_metadata)],
            ));
            let path = ArchivePath::try_from_encoded(path, PathEncoding::Utf8)?;
            let metadata = file.metadata(path);
            let payload = file.payload;
            self.account_entry(&metadata, &payload)?;
            self.entries.push(UdfIndex { metadata, payload });
        }
        if let (Some(actual), Some(expected)) = (object_size, task.owner_object_size)
            && actual != expected
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Extended File Entry Object Size does not include its named streams",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn parse_file_entry(&mut self, icb: IcbAddress) -> Result<FileRecord, StreamError> {
        self.parse_file_entry_for_role(icb, FileEntryRole::Main)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_file_entry_for_role(
        &mut self,
        icb: IcbAddress,
        role: FileEntryRole,
    ) -> Result<FileRecord, StreamError> {
        let descriptor = self.read_icb_descriptor_any(icb)?;
        let tag = le_u16(&descriptor, 0)?;
        let (
            information_offset,
            object_size_offset,
            logical_blocks_offset,
            access_offset,
            modified_offset,
        ) = match tag {
            TAG_FILE_ENTRY => (56, None, 64, 72, 84),
            TAG_EXTENDED_FILE_ENTRY => (56, Some(64), 72, 80, 92),
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF ICB does not reference a File Entry",
                ));
            },
        };
        if matches!(
            role,
            FileEntryRole::StreamDirectory | FileEntryRole::NamedStream
        ) && tag != TAG_EXTENDED_FILE_ENTRY
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF named streams and stream directories require Extended File Entries",
            ));
        }
        if le_u16(&descriptor, 20)? != 4 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF ICB strategy type is not 4",
            ));
        }
        let file_type = descriptor
            .get(27)
            .copied()
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF ICB tag is truncated"))?;
        let kind = match (role, file_type) {
            (FileEntryRole::Main, 4)
            | (FileEntryRole::StreamDirectory, FILE_TYPE_STREAM_DIRECTORY) => EntryKind::Dir,
            (FileEntryRole::Main | FileEntryRole::NamedStream, 5)
            | (FileEntryRole::ExternalAttributes, 8) => EntryKind::File,
            (FileEntryRole::Main, 12) => EntryKind::Symlink,
            (FileEntryRole::Main, _) => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    format!("unsupported UDF ICB file type {file_type}"),
                ));
            },
            (FileEntryRole::StreamDirectory, _) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Stream Directory ICB does not have file type 13",
                ));
            },
            (FileEntryRole::NamedStream, _) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream ICB does not have file type 5",
                ));
            },
            (FileEntryRole::ExternalAttributes, _) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF external extended-attribute ICB does not have file type 8",
                ));
            },
        };
        let flags = le_u16(&descriptor, 34)?;
        if flags & ICB_FLAG_RESERVED != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF ICB flags contain reserved bits",
            ));
        }
        if flags & ICB_FLAG_TRANSFORMED != 0 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "transformed UDF file data is not supported",
            ));
        }
        if flags & ICB_FLAG_MULTI_VERSION != 0 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "multi-version UDF ICBs are not supported",
            ));
        }
        let is_stream = flags & ICB_FLAG_STREAM != 0;
        match (role, is_stream) {
            (FileEntryRole::Main, true) => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    "UDF stream ICB is referenced from a normal directory",
                ));
            },
            (FileEntryRole::StreamDirectory, true) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Stream Directory ICB has the named-stream flag",
                ));
            },
            (FileEntryRole::NamedStream, false) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF named stream ICB is missing the stream flag",
                ));
            },
            (FileEntryRole::ExternalAttributes, true) => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF external extended-attribute ICB has the named-stream flag",
                ));
            },
            _ => {},
        }
        let allocation_type = flags & 0x0007;
        let icb_mapping = &self.partition(icb.partition_ref)?.mapping;
        let icb_is_metadata = matches!(icb_mapping, PartitionMapping::Metadata(_));
        let icb_is_virtual = matches!(icb_mapping, PartitionMapping::Virtual(_));
        if icb_is_metadata {
            let valid_allocation = match kind {
                EntryKind::Dir => matches!(allocation_type, 0 | 3),
                _ => matches!(allocation_type, 1 | 3),
            };
            if !valid_allocation {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Partition ICB uses an allocation descriptor type forbidden for its file type",
                ));
            }
        }
        if icb_is_virtual && !matches!(allocation_type, 1 | 3) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Virtual Partition ICB must use long or immediate allocation descriptors",
            ));
        }
        let information_length = le_u64(&descriptor, information_offset)?;
        let object_size = object_size_offset
            .map_or(Ok(information_length), |offset| le_u64(&descriptor, offset))?;
        let logical_blocks_recorded = le_u64(&descriptor, logical_blocks_offset)?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| information_length > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF entry exceeds configured size limit",
            ));
        }
        let (
            unique_offset,
            external_attributes_offset,
            extended_length_offset,
            allocation_length_offset,
            data_offset,
        ): (usize, usize, usize, usize, usize) = if tag == TAG_FILE_ENTRY {
            (160, 112, 168, 172, 176)
        } else {
            (200, 136, 208, 212, 216)
        };
        let optional_icb_end = if tag == TAG_FILE_ENTRY { 128 } else { 168 };
        require_verified_range(&descriptor, optional_icb_end, "UDF File Entry fixed fields")?;
        let stream_directory = if tag == TAG_EXTENDED_FILE_ENTRY {
            parse_optional_long_ad(&descriptor, 152, "stream directory")?
        } else {
            None
        };
        if stream_directory.is_some() && self.revision < 0x0200 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "pre-2.00 UDF Extended File Entry has a stream directory",
            ));
        }
        if role != FileEntryRole::Main && stream_directory.is_some() {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF stream ICB has a nested stream directory",
            ));
        }
        if (role != FileEntryRole::Main || stream_directory.is_none())
            && object_size != information_length
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Extended File Entry Object Size disagrees with Information Length",
            ));
        }
        if object_size < information_length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Extended File Entry Object Size is smaller than Information Length",
            ));
        }
        if let Some(address) = stream_directory {
            self.validate_icb_address(address)?;
        }
        let external_attributes = parse_optional_long_ad(
            &descriptor,
            external_attributes_offset,
            "external extended-attribute ICB",
        )?;
        if let Some(address) = external_attributes {
            self.validate_icb_address(address)?;
        }
        if external_attributes.is_some() && role != FileEntryRole::Main {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF auxiliary ICB cannot itself have external extended attributes",
            ));
        }
        let extended_length = usize::try_from(le_u32(&descriptor, extended_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF extended attributes exceed address space",
                )
            })?;
        if !extended_length.is_multiple_of(4) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute area is not 4-byte aligned",
            ));
        }
        if role != FileEntryRole::Main && extended_length != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF auxiliary ICB cannot itself have embedded extended attributes",
            ));
        }
        let allocation_length = usize::try_from(le_u32(&descriptor, allocation_length_offset)?)
            .map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF allocation descriptors exceed address space",
                )
            })?;
        let allocation_start = data_offset
            .checked_add(extended_length)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF allocation offset overflow"))?;
        let allocation_end = allocation_start
            .checked_add(allocation_length)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF allocation length overflow"))?;
        let crc_end = TAG_SIZE
            .checked_add(usize::from(le_u16(&descriptor, 10)?))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor CRC length overflow"))?;
        if allocation_end > crc_end || allocation_end > descriptor.len() {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF File Entry variable fields exceed descriptor",
            ));
        }
        let mut extensions = Vec::new();
        if extended_length != 0 {
            let value = descriptor
                .get(data_offset..allocation_start)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF extended attributes are truncated",
                    )
                })?;
            validate_extended_attributes(value, icb.logical_block)?;
            extensions.push(Extension::new(
                "udf-extended-attributes",
                b"raw".to_vec(),
                value.to_vec(),
            ));
        }
        let allocation = &descriptor[allocation_start..allocation_end];
        let (mut payload, sparse, calculated_blocks_recorded) = match allocation_type {
            0..=2 => self.parse_allocation_descriptors(
                allocation,
                allocation_type,
                icb.partition_ref,
                information_length,
                if icb_is_virtual {
                    AllocationPartitionConstraint::Physical
                } else {
                    AllocationPartitionConstraint::Any
                },
            )?,
            3 => {
                let length = usize::try_from(information_length).map_err(|_| {
                    udf_error(
                        ErrorKind::Limit,
                        "embedded UDF payload exceeds address space",
                    )
                })?;
                let data = allocation.get(..length).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "embedded UDF payload is shorter than information length",
                    )
                })?;
                (
                    UdfPayload::Inline {
                        data: data.to_vec(),
                        tag_location: icb.logical_block,
                    },
                    Vec::new(),
                    0,
                )
            },
            _ => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    "unknown UDF allocation descriptor type",
                ));
            },
        };
        if logical_blocks_recorded != calculated_blocks_recorded {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF Logical Blocks Recorded does not match allocation descriptors",
            ));
        }
        if let Some(address) = external_attributes {
            let value = self.read_external_extended_attributes(address)?;
            extensions.push(Extension::new(
                "udf-extended-attributes",
                b"external-raw".to_vec(),
                value,
            ));
        }
        let mut link_target = None;
        if kind == EntryKind::Symlink {
            let target = self.read_symlink(&payload, information_length)?;
            link_target = Some(ArchivePath::try_from_encoded(target, PathEncoding::Utf8)?);
            payload = UdfPayload::None;
        }
        let uid = le_u32(&descriptor, 36)?;
        let gid = le_u32(&descriptor, 40)?;
        let permissions = le_u32(&descriptor, 44)?;
        let links = u64::from(le_u16(&descriptor, 48)?);
        if role == FileEntryRole::Main && stream_directory.is_some() && links < 2 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF main stream link count omits its Stream Directory parent FID",
            ));
        }
        Ok(FileRecord {
            kind,
            size: information_length,
            object_size,
            mode: udf_permissions(permissions) | udf_special_permissions(flags),
            owner: Owner {
                uid: (uid != u32::MAX).then_some(u64::from(uid)),
                gid: (gid != u32::MAX).then_some(u64::from(gid)),
                ..Owner::default()
            },
            times: EntryTimes {
                accessed: parse_udf_timestamp(descriptor.get(access_offset..access_offset + 12)),
                modified: parse_udf_timestamp(
                    descriptor.get(modified_offset..modified_offset + 12),
                ),
                changed: if tag == TAG_EXTENDED_FILE_ENTRY {
                    parse_udf_timestamp(descriptor.get(116..128))
                } else {
                    parse_udf_timestamp(descriptor.get(96..108))
                },
                created: if tag == TAG_EXTENDED_FILE_ENTRY {
                    parse_udf_timestamp(descriptor.get(104..116))
                } else {
                    None
                },
            },
            inode: le_u64(&descriptor, unique_offset)?,
            links,
            payload,
            sparse,
            extensions,
            link_target,
            stream_directory,
        })
    }

    fn read_external_extended_attributes(
        &mut self,
        address: IcbAddress,
    ) -> Result<Vec<u8>, StreamError> {
        let file = self.parse_file_entry_for_role(address, FileEntryRole::ExternalAttributes)?;
        if file.links != 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF external extended-attribute file has a non-zero File Link Count",
            ));
        }
        let length = usize::try_from(file.size).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF external extended-attribute space exceeds address space",
            )
        })?;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|maximum| length > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF external extended-attribute space exceeds the in-flight buffer limit",
            ));
        }
        if self.limits.metadata_bytes().is_some_and(|maximum| {
            self.metadata_used
                .checked_add(length)
                .is_none_or(|used| used > maximum)
        }) {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF external extended-attribute space exceeds the metadata limit",
            ));
        }
        let mut cursor = UdfDataCursor::new(file.payload, file.size)?;
        let tag_location = cursor.tag_location()?;
        let mut value = vec![0_u8; length];
        cursor.read_exact(self.input, &mut value)?;
        validate_extended_attributes(&value, tag_location)?;
        Ok(value)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_allocation_descriptors(
        &mut self,
        allocation: &[u8],
        allocation_type: u16,
        default_partition: u16,
        information_length: u64,
        partition_constraint: AllocationPartitionConstraint,
    ) -> Result<(UdfPayload, Vec<SparseExtent>, u64), StreamError> {
        let mut extents = Vec::new();
        let mut sparse = Vec::new();
        let mut logical_offset = 0_u64;
        let mut recorded_blocks = 0_u64;
        let mut pending = vec![(allocation.to_vec(), default_partition)];
        let mut chains = BTreeSet::new();
        while let Some((descriptors, partition_ref)) = pending.pop() {
            let width = match allocation_type {
                0 => 8,
                1 => 16,
                2 => 20,
                _ => {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "invalid UDF allocation descriptor type",
                    ));
                },
            };
            if descriptors.len() % width != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF allocation descriptor array is truncated",
                ));
            }
            for (descriptor_index, descriptor) in descriptors.chunks_exact(width).enumerate() {
                let raw_length = le_u32(descriptor, 0)?;
                let extent_type = raw_length >> 30;
                let extent_length = raw_length & 0x3fff_ffff;
                let (
                    recorded_length,
                    extent_information_length,
                    logical_block,
                    referenced_partition,
                ) = match allocation_type {
                    0 => (
                        if extent_type == 0 { extent_length } else { 0 },
                        extent_length,
                        le_u32(descriptor, 4)?,
                        partition_ref,
                    ),
                    1 => (
                        if extent_type == 0 { extent_length } else { 0 },
                        extent_length,
                        le_u32(descriptor, 4)?,
                        le_u16(descriptor, 8)?,
                    ),
                    2 => {
                        let recorded = le_u32(descriptor, 4)?;
                        if recorded & 0xc000_0000 != 0 {
                            return Err(udf_error(
                                ErrorKind::Malformed,
                                "UDF extended allocation descriptor Recorded Length has reserved bits",
                            ));
                        }
                        (
                            recorded,
                            le_u32(descriptor, 8)?,
                            le_u32(descriptor, 12)?,
                            le_u16(descriptor, 16)?,
                        )
                    },
                    _ => {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "invalid UDF allocation descriptor type",
                        ));
                    },
                };
                if extent_length == 0 {
                    if extent_type != 0
                        || recorded_length != 0
                        || extent_information_length != 0
                        || logical_block != 0
                        || (allocation_type != 0 && referenced_partition != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "zero-length UDF allocation descriptor has non-zero reserved fields",
                        ));
                    }
                    let trailing_start =
                        (descriptor_index + 1).checked_mul(width).ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF allocation descriptor offset overflow",
                            )
                        })?;
                    if descriptors[trailing_start..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "non-zero UDF allocation descriptor follows a terminator",
                        ));
                    }
                    break;
                }
                if partition_constraint == AllocationPartitionConstraint::Physical
                    && !matches!(
                        self.partition(referenced_partition)?.mapping,
                        PartitionMapping::Physical { .. }
                    )
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF Virtual Partition ICB allocation does not reference a physical partition map",
                    ));
                }
                if extent_type == 3 {
                    let trailing_start =
                        (descriptor_index + 1).checked_mul(width).ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF allocation descriptor offset overflow",
                            )
                        })?;
                    if descriptors[trailing_start..].iter().any(|byte| *byte != 0) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF allocation descriptor follows a continuation",
                        ));
                    }
                    let key = (referenced_partition, logical_block);
                    if !chains.insert(key) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "cycle in UDF allocation-extent chain",
                        ));
                    }
                    let address = IcbAddress {
                        partition_ref: referenced_partition,
                        logical_block,
                        length: extent_length,
                    };
                    let chained = self.read_icb_descriptor(address, TAG_ALLOCATION_EXTENT)?;
                    let descriptors_length =
                        usize::try_from(le_u32(&chained, 20)?).map_err(|_| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF allocation extent exceeds address space",
                            )
                        })?;
                    let end = 24_usize.checked_add(descriptors_length).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Malformed,
                            "UDF allocation extent length overflow",
                        )
                    })?;
                    require_verified_range(&chained, end, "UDF Allocation Extent Descriptor")?;
                    let values = chained.get(24..end).ok_or_else(|| {
                        udf_error(
                            ErrorKind::Malformed,
                            "UDF allocation extent descriptors are truncated",
                        )
                    })?;
                    self.metadata_used =
                        self.metadata_used
                            .checked_add(values.len())
                            .ok_or_else(|| {
                                udf_error(ErrorKind::Limit, "UDF metadata accounting overflow")
                            })?;
                    self.enforce_metadata_limit()?;
                    pending.push((values.to_vec(), referenced_partition));
                    break;
                }
                let partition = self.partition(referenced_partition)?;
                if allocation_type == 2 && recorded_length > extent_length {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF extended allocation descriptor records more bytes than its extent",
                    ));
                }
                if allocation_type == 2 {
                    match extent_type {
                        0 if recorded_length != extent_information_length => {
                            return Err(udf_error(
                                ErrorKind::Unsupported,
                                "transformed UDF extended allocation extent is not supported",
                            ));
                        },
                        1 | 2 if recorded_length != 0 => {
                            return Err(udf_error(
                                ErrorKind::Malformed,
                                "unrecorded UDF extended allocation extent has a Recorded Length",
                            ));
                        },
                        _ => {},
                    }
                }
                let logical_length = if allocation_type == 2 {
                    extent_information_length
                } else {
                    extent_length
                };
                let mapped_extents = match extent_type {
                    0 => {
                        self.partition_extents(partition, logical_block, u64::from(logical_length))?
                    },
                    1 => {
                        Self::validate_partition_extent(
                            partition,
                            logical_block,
                            u64::from(extent_length),
                        )?;
                        vec![UdfExtent {
                            source_offset: None,
                            length: u64::from(logical_length),
                            logical_block,
                        }]
                    },
                    2 if logical_block == 0
                        && (allocation_type == 0 || referenced_partition == 0) =>
                    {
                        vec![UdfExtent {
                            source_offset: None,
                            length: u64::from(logical_length),
                            logical_block,
                        }]
                    },
                    2 => {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "unallocated UDF extent has a non-zero location",
                        ));
                    },
                    _ => {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "invalid UDF allocation extent type",
                        ));
                    },
                };
                let next_logical_offset = logical_offset
                    .checked_add(u64::from(logical_length))
                    .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF allocation length overflow"))?;
                if logical_offset >= information_length {
                    if extent_type != 1
                        || !extent_length.is_multiple_of(BLOCK_SIZE_U32)
                        || (allocation_type == 2 && logical_length != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF File Tail extent is not block-aligned unrecorded allocation",
                        ));
                    }
                    continue;
                }
                if next_logical_offset > information_length {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF file-body extent exceeds information length",
                    ));
                }
                if next_logical_offset < information_length
                    && !extent_length.is_multiple_of(BLOCK_SIZE_U32)
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "non-final UDF file-body extent is not block-aligned",
                    ));
                }
                if extent_type != 0 {
                    sparse.push(SparseExtent::new(
                        logical_offset,
                        u64::from(logical_length)
                            .min(information_length.saturating_sub(logical_offset)),
                    )?);
                } else {
                    recorded_blocks = recorded_blocks
                        .checked_add(u64::from(recorded_length).div_ceil(BLOCK_SIZE))
                        .ok_or_else(|| {
                            udf_error(ErrorKind::Limit, "UDF recorded-block count overflow")
                        })?;
                }
                extents.extend(mapped_extents);
                logical_offset = next_logical_offset;
            }
        }
        if logical_offset < information_length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF allocation descriptors do not cover information length",
            ));
        }
        Ok((UdfPayload::Extents(extents), sparse, recorded_blocks))
    }

    fn read_symlink(&mut self, payload: &UdfPayload, length: u64) -> Result<Vec<u8>, StreamError> {
        let maximum = self.limits.path_bytes().unwrap_or(usize::MAX);
        let length = usize::try_from(length).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF symbolic-link target exceeds address space",
            )
        })?;
        if length > maximum {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF symbolic-link target exceeds path limit",
            ));
        }
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|maximum| length > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF symbolic-link target exceeds the in-flight buffer limit",
            ));
        }
        self.account_decoded(
            length as u64,
            "UDF symbolic-link data exceeds the configured decoded-total limit",
        )?;
        let mut encoded = vec![0; length];
        UdfDataCursor::new(payload.clone(), length as u64)?.read_exact(self.input, &mut encoded)?;
        decode_symlink_components(&encoded, maximum)
    }

    fn read_descriptor_block(
        &mut self,
        physical_block: u64,
        tag_location: u64,
        expected_tag: Option<u16>,
    ) -> Result<Vec<u8>, StreamError> {
        let offset = physical_block
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor offset overflow"))?;
        if offset
            .checked_add(BLOCK_SIZE)
            .is_none_or(|end| end > self.image_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF descriptor is outside the image",
            ));
        }
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut descriptor = vec![0; BLOCK_SIZE_USIZE];
        self.input
            .read_exact(&mut descriptor)
            .map_err(StreamError::io)?;
        let location = u32::try_from(tag_location)
            .map_err(|_| udf_error(ErrorKind::Malformed, "UDF tag location exceeds u32"))?;
        validate_descriptor_tag(&descriptor, expected_tag, location)?;
        Ok(descriptor)
    }

    fn read_partition_block(
        &mut self,
        partition_ref: u16,
        logical_block: u32,
    ) -> Result<Vec<u8>, StreamError> {
        let partition = self.partition(partition_ref)?.clone();
        let extents = self.partition_extents(&partition, logical_block, BLOCK_SIZE)?;
        let extent = extents.first().ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF partition block has no physical mapping",
            )
        })?;
        if extents.len() != 1 || extent.length != BLOCK_SIZE {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF partition block crosses an invalid mapping boundary",
            ));
        }
        let offset = extent.source_offset.ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "referenced UDF Metadata Partition block is unallocated",
            )
        })?;
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut descriptor = vec![0; BLOCK_SIZE_USIZE];
        self.input
            .read_exact(&mut descriptor)
            .map_err(StreamError::io)?;
        Ok(descriptor)
    }

    fn read_icb_descriptor(
        &mut self,
        address: IcbAddress,
        expected_tag: u16,
    ) -> Result<Vec<u8>, StreamError> {
        let descriptor = self.read_icb_descriptor_any(address)?;
        if le_u16(&descriptor, 0)? != expected_tag {
            return Err(udf_error(
                ErrorKind::Malformed,
                format!("UDF ICB tag is not expected descriptor {expected_tag}"),
            ));
        }
        Ok(descriptor)
    }

    fn read_icb_descriptor_any(&mut self, address: IcbAddress) -> Result<Vec<u8>, StreamError> {
        self.validate_icb_address(address)?;
        let descriptor = self.read_partition_block(address.partition_ref, address.logical_block)?;
        validate_descriptor_tag(&descriptor, None, address.logical_block)?;
        let used = TAG_SIZE
            .checked_add(usize::from(le_u16(&descriptor, 10)?))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor length overflow"))?;
        if used > usize::try_from(address.length & 0x3fff_ffff).unwrap_or(usize::MAX) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF descriptor exceeds its declared ICB extent",
            ));
        }
        Ok(descriptor)
    }

    fn validate_icb_address(&self, address: IcbAddress) -> Result<(), StreamError> {
        Self::validate_icb_with_partitions(address, &self.partitions)
    }

    fn validate_icb_with_partitions(
        address: IcbAddress,
        partitions: &[Partition],
    ) -> Result<(), StreamError> {
        let recorded_length = address.length & 0x3fff_ffff;
        if address.length >> 30 != 0 || recorded_length == 0 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF ICB extent is not recorded and allocated",
            ));
        }
        let partition = partitions
            .get(usize::from(address.partition_ref))
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF ICB references an unknown partition map",
                )
            })?;
        let blocks = u64::from(recorded_length).div_ceil(BLOCK_SIZE);
        if u64::from(address.logical_block)
            .checked_add(blocks)
            .is_none_or(|end| end > u64::from(partition.blocks))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF ICB is outside its partition",
            ));
        }
        Ok(())
    }

    fn partition(&self, reference: u16) -> Result<&Partition, StreamError> {
        self.partitions.get(usize::from(reference)).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF allocation descriptor references an unknown partition map",
            )
        })
    }

    fn validate_partition_extent(
        partition: &Partition,
        logical_block: u32,
        length: u64,
    ) -> Result<(), StreamError> {
        let blocks = length.div_ceil(BLOCK_SIZE);
        if u64::from(logical_block)
            .checked_add(blocks)
            .is_none_or(|end| end > u64::from(partition.blocks))
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF data extent is outside its partition",
            ));
        }
        Ok(())
    }

    fn partition_extents(
        &self,
        partition: &Partition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        Self::validate_partition_extent(partition, logical_block, length)?;
        match &partition.mapping {
            PartitionMapping::Physical { start } => {
                self.physical_partition_extent(*start, logical_block, length)
            },
            PartitionMapping::Metadata(metadata) => {
                Self::metadata_partition_extents(metadata, logical_block, length)
            },
            PartitionMapping::Sparable(sparable) => {
                self.sparable_partition_extents(sparable, logical_block, length)
            },
            PartitionMapping::Virtual(virtual_partition) => {
                self.virtual_partition_extents(virtual_partition, logical_block, length)
            },
        }
    }

    fn physical_partition_extent(
        &self,
        start: u32,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        let physical_block = u64::from(start)
            .checked_add(u64::from(logical_block))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF data block overflow"))?;
        let offset = physical_block
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF data offset overflow"))?;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.image_length)
        {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF data extent is outside the image",
            ));
        }
        Ok(vec![UdfExtent {
            source_offset: Some(offset),
            length,
            logical_block,
        }])
    }

    fn sparable_partition_extents(
        &self,
        sparable: &SparablePartition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        let mut result = Vec::new();
        let mut current_block = logical_block;
        let mut remaining = length;
        while remaining != 0 {
            let packet_offset = current_block % sparable.packet_blocks;
            let packet_start = current_block.checked_sub(packet_offset).ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF sparable packet calculation underflow",
                )
            })?;
            let blocks_left = sparable
                .packet_blocks
                .checked_sub(packet_offset)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF sparable packet calculation underflow",
                    )
                })?;
            let count = remaining.min(u64::from(blocks_left).checked_mul(BLOCK_SIZE).ok_or_else(
                || udf_error(ErrorKind::Malformed, "UDF sparable packet length overflow"),
            )?);
            let physical_block =
                if let Some(mapped) = sparable.mapped_packets.get(&packet_start).copied() {
                    u64::from(mapped)
                        .checked_add(u64::from(packet_offset))
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Malformed,
                                "UDF sparable replacement block overflow",
                            )
                        })?
                } else {
                    u64::from(sparable.physical_start)
                        .checked_add(u64::from(current_block))
                        .ok_or_else(|| {
                            udf_error(ErrorKind::Malformed, "UDF sparable physical block overflow")
                        })?
                };
            let source_offset = physical_block.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                udf_error(ErrorKind::Malformed, "UDF sparable source offset overflow")
            })?;
            if source_offset
                .checked_add(count)
                .is_none_or(|end| end > self.image_length)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF sparable mapping is outside the image",
                ));
            }
            result.try_reserve(1).map_err(|_| {
                udf_error(ErrorKind::Limit, "UDF sparable extent allocation failed")
            })?;
            result.push(UdfExtent {
                source_offset: Some(source_offset),
                length: count,
                logical_block: current_block,
            });
            remaining -= count;
            let consumed_blocks = count.div_ceil(BLOCK_SIZE);
            current_block = current_block
                .checked_add(u32::try_from(consumed_blocks).map_err(|_| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF sparable block request exceeds address space",
                    )
                })?)
                .ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF sparable block request overflows")
                })?;
        }
        Ok(result)
    }

    fn virtual_partition_extents(
        &self,
        virtual_partition: &VirtualPartition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        let mut result = Vec::new();
        let mut current_block = logical_block;
        let mut remaining = length;
        while remaining != 0 {
            let mapped = virtual_partition
                .entries
                .get(usize::try_from(current_block).map_err(|_| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF virtual block exceeds address space",
                    )
                })?)
                .copied()
                .flatten()
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "referenced UDF virtual block is unallocated",
                    )
                })?;
            let physical_block = u64::from(virtual_partition.physical_start)
                .checked_add(u64::from(mapped))
                .ok_or_else(|| {
                    udf_error(ErrorKind::Malformed, "UDF virtual block mapping overflows")
                })?;
            let source_offset = physical_block.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                udf_error(ErrorKind::Malformed, "UDF virtual block offset overflows")
            })?;
            if source_offset
                .checked_add(BLOCK_SIZE)
                .is_none_or(|end| end > self.image_length)
            {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF virtual block mapping is outside the image",
                ));
            }
            let count = remaining.min(BLOCK_SIZE);
            result
                .try_reserve(1)
                .map_err(|_| udf_error(ErrorKind::Limit, "UDF virtual extent allocation failed"))?;
            result.push(UdfExtent {
                source_offset: Some(source_offset),
                length: count,
                logical_block: current_block,
            });
            remaining -= count;
            current_block = current_block.checked_add(1).ok_or_else(|| {
                udf_error(ErrorKind::Malformed, "UDF virtual block request overflows")
            })?;
        }
        Ok(result)
    }

    fn metadata_partition_extents(
        metadata: &MetadataPartition,
        logical_block: u32,
        length: u64,
    ) -> Result<Vec<UdfExtent>, StreamError> {
        let file = if metadata.using_mirror {
            metadata.mirror.as_ref().ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Partition mirror is unavailable",
                )
            })?
        } else {
            &metadata.primary
        };
        let mut result = Vec::new();
        let mut requested_offset = u64::from(logical_block)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Partition offset overflow",
                )
            })?;
        let mut remaining = length;
        while remaining != 0 {
            let mapping = file
                .extents
                .iter()
                .find(|extent| {
                    requested_offset >= extent.logical_offset
                        && requested_offset < extent.logical_offset.saturating_add(extent.length)
                })
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Partition block has no file allocation",
                    )
                })?;
            let within = requested_offset
                .checked_sub(mapping.logical_offset)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Partition mapping underflow",
                    )
                })?;
            let available = mapping.length.checked_sub(within).ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Partition mapping underflow",
                )
            })?;
            let count = remaining.min(available);
            let block_delta =
                u32::try_from(requested_offset.checked_div(BLOCK_SIZE).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Partition block calculation failed",
                    )
                })?)
                .map_err(|_| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Partition logical block exceeds address space",
                    )
                })?;
            result.try_reserve(1).map_err(|_| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF Metadata Partition extent allocation failed",
                )
            })?;
            let source_offset = match mapping.source_offset {
                Some(source) => Some(source.checked_add(within).ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Partition source offset overflow",
                    )
                })?),
                None => None,
            };
            result.push(UdfExtent {
                source_offset,
                length: count,
                logical_block: block_delta,
            });
            requested_offset = requested_offset.checked_add(count).ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Metadata Partition request overflow",
                )
            })?;
            remaining -= count;
        }
        Ok(result)
    }

    fn validate_partition_range(&self, start: u32, blocks: u32) -> Result<(), StreamError> {
        let end = u64::from(start)
            .checked_add(u64::from(blocks))
            .and_then(|value| value.checked_mul(BLOCK_SIZE))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF partition range overflow"))?;
        if end > self.image_length {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF partition is outside the image",
            ));
        }
        Ok(())
    }

    fn account_entry(
        &mut self,
        metadata: &EntryMetadata,
        payload: &UdfPayload,
    ) -> Result<(), StreamError> {
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.entries.len() as u64 >= maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF entry count exceeds configured limit",
            ));
        }
        let payload_bytes = match payload {
            UdfPayload::Extents(extents) => extents
                .len()
                .checked_mul(core::mem::size_of::<UdfExtent>())
                .ok_or_else(|| {
                    udf_error(ErrorKind::Limit, "UDF extent metadata accounting overflow")
                })?,
            UdfPayload::Inline { data, .. } => data.len(),
            UdfPayload::None => 0,
        };
        let extension_bytes = metadata
            .extensions()
            .iter()
            .try_fold(0_usize, |total, extension| {
                total
                    .checked_add(extension.namespace().len())
                    .and_then(|value| value.checked_add(extension.key().len()))
                    .and_then(|value| value.checked_add(extension.value().len()))
            })
            .ok_or_else(|| {
                udf_error(
                    ErrorKind::Limit,
                    "UDF extension metadata accounting overflow",
                )
            })?;
        let path_bytes = metadata
            .path()
            .as_bytes()
            .len()
            .checked_mul(3)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF path accounting overflow"))?;
        let accounted = path_bytes
            .checked_add(payload_bytes)
            .and_then(|value| value.checked_add(extension_bytes))
            .and_then(|value| value.checked_add(core::mem::size_of::<UdfIndex>()))
            .and_then(|value| value.checked_add(core::mem::size_of::<Vec<u8>>()))
            .and_then(|value| value.checked_add(core::mem::size_of::<((u16, u32), ArchivePath)>()))
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounted)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.enforce_metadata_limit()
    }

    fn account_directory_task(&mut self, task: &DirectoryTask) -> Result<(), StreamError> {
        let payload_bytes = match &task.payload {
            UdfPayload::Extents(extents) => extents
                .len()
                .checked_mul(core::mem::size_of::<UdfExtent>())
                .ok_or_else(|| {
                    udf_error(ErrorKind::Limit, "UDF directory extent accounting overflow")
                })?,
            UdfPayload::Inline { data, .. } => data.len(),
            UdfPayload::None => 0,
        };
        let accounted = task
            .prefix
            .len()
            .checked_add(payload_bytes)
            .and_then(|value| value.checked_add(core::mem::size_of::<DirectoryTask>()))
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounted)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.enforce_metadata_limit()
    }

    fn account_stream_task(&mut self, task: &StreamTask) -> Result<(), StreamError> {
        let owner_bytes = task.owner_path.as_ref().map_or(0, Vec::len);
        let accounted = owner_bytes
            .checked_add(core::mem::size_of::<StreamTask>())
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounted)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.enforce_metadata_limit()
    }

    fn account_stream_identity(&mut self) -> Result<(), StreamError> {
        let accounted = core::mem::size_of::<(u16, u32)>()
            .checked_mul(4)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounted)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF metadata accounting overflow"))?;
        self.enforce_metadata_limit()
    }

    fn account_decoded(&mut self, count: u64, context: &'static str) -> Result<(), StreamError> {
        self.decoded_total = self
            .decoded_total
            .checked_add(count)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF decoded-total accounting overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| self.decoded_total > maximum)
        {
            return Err(udf_error(ErrorKind::Limit, context));
        }
        Ok(())
    }

    fn enforce_metadata_limit(&self) -> Result<(), StreamError> {
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| self.metadata_used > maximum)
        {
            return Err(udf_error(
                ErrorKind::Limit,
                "UDF metadata exceeds configured limit",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn parse_logical_volume(descriptor: &[u8]) -> Result<RawLogicalVolume, StreamError> {
    validate_osta_charspec(
        descriptor
            .get(20..84)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF LVD character set is truncated"))?,
        "Logical Volume",
    )?;
    if le_u32(descriptor, 212)? != BLOCK_SIZE_U32 {
        return Err(udf_error(
            ErrorKind::Unsupported,
            "UDF logical block size is not 2048",
        ));
    }
    let logical_volume_id = decode_dstring(
        descriptor
            .get(84..212)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF LVD identifier is truncated"))?,
    )?;
    let domain = descriptor
        .get(216..248)
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF domain identifier is truncated"))?;
    let revision = parse_udf_domain_revision(domain)?;
    let file_set = parse_long_ad(descriptor, 248)?;
    let map_length = usize::try_from(le_u32(descriptor, 264)?)
        .map_err(|_| udf_error(ErrorKind::Limit, "UDF partition maps exceed address space"))?;
    let map_count = usize::try_from(le_u32(descriptor, 268)?).map_err(|_| {
        udf_error(
            ErrorKind::Limit,
            "UDF partition map count exceeds address space",
        )
    })?;
    let maps_end = 440_usize
        .checked_add(map_length)
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF partition map length overflow"))?;
    require_verified_range(descriptor, maps_end, "UDF Logical Volume Descriptor")?;
    let maps = descriptor
        .get(440..maps_end)
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF partition map table is truncated"))?;
    let mut cursor = 0;
    let mut partition_maps = Vec::new();
    for _ in 0..map_count {
        let kind = maps.get(cursor).copied().ok_or_else(|| {
            udf_error(ErrorKind::Malformed, "UDF partition map table ended early")
        })?;
        let length = usize::from(*maps.get(cursor + 1).ok_or_else(|| {
            udf_error(ErrorKind::Malformed, "UDF partition map length is missing")
        })?);
        if length < 2 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF partition map has an invalid length",
            ));
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF partition map overflow"))?;
        let map = maps
            .get(cursor..end)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF partition map is truncated"))?;
        match kind {
            1 if length == 6 => partition_maps.push(RawPartitionMap::Physical {
                volume_sequence: le_u16(map, 2)?,
                partition_number: le_u16(map, 4)?,
            }),
            1 => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Type 1 partition map length is not 6",
                ));
            },
            2 => {
                let identifier = map.get(5..28).unwrap_or_default();
                if identifier.starts_with(b"*UDF Metadata Partition") {
                    if length != 64 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition Map length is not 64",
                        ));
                    }
                    if revision < 0x0250 {
                        return Err(udf_error(
                            ErrorKind::Unsupported,
                            "UDF Metadata Partition Map requires revision 2.50 or newer",
                        ));
                    }
                    validate_metadata_partition_identifier(&map[4..36], revision)?;
                    if map[2..4].iter().any(|byte| *byte != 0)
                        || map[59..64].iter().any(|byte| *byte != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition Map reserved bytes are non-zero",
                        ));
                    }
                    let allocation_unit_blocks = le_u32(map, 52)?;
                    if allocation_unit_blocks < 32 || !allocation_unit_blocks.is_multiple_of(32) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition allocation unit is not a multiple of 32 blocks",
                        ));
                    }
                    let alignment_unit_blocks = le_u16(map, 56)?;
                    if alignment_unit_blocks == 0 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Metadata Partition alignment unit is zero",
                        ));
                    }
                    partition_maps.push(RawPartitionMap::Metadata(RawMetadataPartitionMap {
                        volume_sequence: le_u16(map, 36)?,
                        partition_number: le_u16(map, 38)?,
                        metadata_file_location: le_u32(map, 40)?,
                        metadata_mirror_file_location: match le_u32(map, 44)? {
                            u32::MAX => None,
                            location => Some(location),
                        },
                        metadata_bitmap_file_location: match le_u32(map, 48)? {
                            u32::MAX => None,
                            location => Some(location),
                        },
                        allocation_unit_blocks,
                        alignment_unit_blocks,
                        // Bits 1-7 are reserved but explicitly ignored on read by UDF 2.60.
                        duplicate: map[58] & 1 != 0,
                    }));
                } else if identifier.starts_with(b"*UDF Sparable Partition") {
                    if length != 64 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Sparable Partition Map length is not 64",
                        ));
                    }
                    if revision < 0x0150 {
                        return Err(udf_error(
                            ErrorKind::Unsupported,
                            "UDF Sparable Partition Map requires revision 1.50 or newer",
                        ));
                    }
                    validate_udf_entity_identifier(
                        &map[4..36],
                        b"*UDF Sparable Partition",
                        revision,
                        "UDF Sparable Partition Map",
                    )?;
                    let table_count = usize::from(map[42]);
                    if !(1..=MAX_SPARING_TABLES).contains(&table_count) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Sparable Partition Map table count is not between one and four",
                        ));
                    }
                    let locations_end = 48_usize
                        .checked_add(table_count.checked_mul(4).ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF sparing-table location count overflow",
                            )
                        })?)
                        .ok_or_else(|| {
                            udf_error(
                                ErrorKind::Limit,
                                "UDF sparing-table location range overflow",
                            )
                        })?;
                    if map[2..4].iter().any(|byte| *byte != 0)
                        || map[43] != 0
                        || map[locations_end..64].iter().any(|byte| *byte != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Sparable Partition Map reserved bytes are non-zero",
                        ));
                    }
                    let packet_blocks = u32::from(le_u16(map, 40)?);
                    if !matches!(packet_blocks, 16 | 32) {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Sparable Partition packet length is neither 16 nor 32 blocks",
                        ));
                    }
                    let table_size = le_u32(map, 44)?;
                    if table_size < SPARING_TABLE_HEADER_SIZE_U32 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Sparable Partition table size is shorter than its header",
                        ));
                    }
                    let mut table_locations = Vec::new();
                    table_locations.try_reserve(table_count).map_err(|_| {
                        udf_error(
                            ErrorKind::Limit,
                            "UDF sparing-table location allocation failed",
                        )
                    })?;
                    for offset in (48..locations_end).step_by(4) {
                        table_locations.push(le_u32(map, offset)?);
                    }
                    partition_maps.push(RawPartitionMap::Sparable(RawSparablePartitionMap {
                        volume_sequence: le_u16(map, 36)?,
                        partition_number: le_u16(map, 38)?,
                        packet_blocks,
                        table_size,
                        table_locations,
                    }));
                } else if identifier.starts_with(b"*UDF Virtual Partition") {
                    if length != 64 {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map length is not 64",
                        ));
                    }
                    if revision < 0x0150 {
                        return Err(udf_error(
                            ErrorKind::Unsupported,
                            "UDF Virtual Partition Map requires revision 1.50 or newer",
                        ));
                    }
                    validate_udf_entity_identifier(
                        &map[4..36],
                        b"*UDF Virtual Partition",
                        revision,
                        "UDF Virtual Partition Map",
                    )?;
                    if map[2..4].iter().any(|byte| *byte != 0)
                        || map[40..64].iter().any(|byte| *byte != 0)
                    {
                        return Err(udf_error(
                            ErrorKind::Malformed,
                            "UDF Virtual Partition Map reserved bytes are non-zero",
                        ));
                    }
                    partition_maps.push(RawPartitionMap::Virtual {
                        volume_sequence: le_u16(map, 36)?,
                        partition_number: le_u16(map, 38)?,
                    });
                } else {
                    return Err(udf_error(
                        ErrorKind::Unsupported,
                        "UDF Type 2 partition maps are not supported",
                    ));
                }
            },
            _ => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    "unknown UDF partition map type",
                ));
            },
        }
        cursor = end;
    }
    if cursor != maps.len()
        || !partition_maps.iter().any(|map| {
            matches!(
                map,
                RawPartitionMap::Physical { .. } | RawPartitionMap::Sparable(_)
            )
        })
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF partition map table length/count mismatch",
        ));
    }
    Ok(RawLogicalVolume {
        logical_volume_id,
        revision,
        maps: partition_maps,
        file_set,
    })
}

fn consider_descriptor(
    slot: &mut Option<DescriptorCandidate>,
    descriptor: Vec<u8>,
) -> Result<(), StreamError> {
    let sequence = le_u32(&descriptor, 16)?;
    if let Some(candidate) = slot {
        consider_descriptor_candidate(candidate, descriptor)
    } else {
        *slot = Some(DescriptorCandidate {
            sequence,
            descriptor,
        });
        Ok(())
    }
}

fn consider_descriptor_candidate(
    candidate: &mut DescriptorCandidate,
    descriptor: Vec<u8>,
) -> Result<(), StreamError> {
    let sequence = le_u32(&descriptor, 16)?;
    if candidate.descriptor.is_empty() || sequence > candidate.sequence {
        *candidate = DescriptorCandidate {
            sequence,
            descriptor,
        };
    } else if sequence == candidate.sequence
        && !vds_descriptors_identical(&candidate.descriptor, &descriptor)?
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "conflicting UDF descriptors have the same sequence number",
        ));
    }
    Ok(())
}

fn validate_vds_sequence_identity(
    descriptors: &mut BTreeMap<u32, Vec<u8>>,
    descriptor: &[u8],
) -> Result<(), StreamError> {
    let sequence = le_u32(descriptor, 16)?;
    if let Some(previous) = descriptors.get(&sequence) {
        if !vds_descriptors_identical(previous, descriptor)? {
            return Err(udf_error(
                ErrorKind::Malformed,
                "different UDF volume descriptors share a sequence number",
            ));
        }
    } else {
        descriptors.insert(sequence, descriptor.to_vec());
    }
    Ok(())
}

fn vds_descriptors_identical(left: &[u8], right: &[u8]) -> Result<bool, StreamError> {
    let left_end = descriptor_verified_end(left)?;
    let right_end = descriptor_verified_end(right)?;
    if left_end != right_end {
        return Ok(false);
    }
    Ok((0..left_end)
        .all(|index| matches!(index, 4 | 8..=15) || left.get(index) == right.get(index)))
}

fn parse_extent_ad(bytes: &[u8], offset: usize) -> Result<ExtentAd, StreamError> {
    Ok(ExtentAd {
        length: le_u32(bytes, offset)?,
        location: le_u32(bytes, offset + 4)?,
    })
}

fn parse_long_ad(bytes: &[u8], offset: usize) -> Result<IcbAddress, StreamError> {
    Ok(IcbAddress {
        length: le_u32(bytes, offset)?,
        logical_block: le_u32(bytes, offset + 4)?,
        partition_ref: le_u16(bytes, offset + 8)?,
    })
}

fn parse_optional_long_ad(
    bytes: &[u8],
    offset: usize,
    context: &str,
) -> Result<Option<IcbAddress>, StreamError> {
    let raw_length = le_u32(bytes, offset)?;
    if raw_length >> 30 != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("UDF {context} has non-zero extent type"),
        ));
    }
    if raw_length & 0x3fff_ffff != 0 {
        return Ok(Some(parse_long_ad(bytes, offset)?));
    }
    if le_u32(bytes, offset + 4)? != 0 || le_u16(bytes, offset + 8)? != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("empty UDF {context} has a non-zero extent location"),
        ));
    }
    Ok(None)
}

fn validate_descriptor_tag(
    descriptor: &[u8],
    expected_tag: Option<u16>,
    expected_location: u32,
) -> Result<(), StreamError> {
    if descriptor.len() < TAG_SIZE {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF descriptor tag is truncated",
        ));
    }
    let tag = le_u16(descriptor, 0)?;
    if expected_tag.is_some_and(|expected| tag != expected) {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("unexpected UDF descriptor tag {tag}"),
        ));
    }
    if !matches!(le_u16(descriptor, 2)?, 2 | 3) {
        return Err(udf_error(
            ErrorKind::Unsupported,
            "unsupported ECMA-167 descriptor version",
        ));
    }
    let checksum = descriptor[..TAG_SIZE]
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .fold(0_u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    if checksum != descriptor[4] {
        return Err(udf_error(
            ErrorKind::Integrity,
            "UDF descriptor tag checksum mismatch",
        ));
    }
    if le_u32(descriptor, 12)? != expected_location {
        return Err(udf_error(
            ErrorKind::Integrity,
            "UDF descriptor tag location mismatch",
        ));
    }
    let crc_length = usize::from(le_u16(descriptor, 10)?);
    let crc_end = TAG_SIZE
        .checked_add(crc_length)
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor CRC length overflow"))?;
    let body = descriptor.get(TAG_SIZE..crc_end).ok_or_else(|| {
        udf_error(
            ErrorKind::Malformed,
            "UDF descriptor CRC range is truncated",
        )
    })?;
    if crc16(body) != le_u16(descriptor, 8)? {
        return Err(udf_error(
            ErrorKind::Integrity,
            "UDF descriptor CRC16 mismatch",
        ));
    }
    Ok(())
}

fn descriptor_verified_end(descriptor: &[u8]) -> Result<usize, StreamError> {
    let end = TAG_SIZE
        .checked_add(usize::from(le_u16(descriptor, 10)?))
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF descriptor CRC length overflow"))?;
    if end > descriptor.len() {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF descriptor CRC range is truncated",
        ));
    }
    Ok(end)
}

fn require_verified_range(
    descriptor: &[u8],
    required_end: usize,
    context: &'static str,
) -> Result<(), StreamError> {
    if descriptor_verified_end(descriptor)? < required_end {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} fields are outside the descriptor CRC"),
        ));
    }
    Ok(())
}

fn validate_osta_charspec(raw: &[u8], context: &'static str) -> Result<(), StreamError> {
    const OSTA_COMPRESSED_UNICODE: &[u8] = b"OSTA Compressed Unicode";
    if raw.len() != 64 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} character set is truncated"),
        ));
    }
    if raw[0] != 0 || !raw[1..].starts_with(OSTA_COMPRESSED_UNICODE) {
        return Err(udf_error(
            ErrorKind::Unsupported,
            format!("{context} character set is not OSTA Compressed Unicode"),
        ));
    }
    if raw[1 + OSTA_COMPRESSED_UNICODE.len()..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} character-set padding is non-zero"),
        ));
    }
    Ok(())
}

fn parse_udf_domain_revision(raw: &[u8]) -> Result<u16, StreamError> {
    const OSTA_DOMAIN: &[u8] = b"*OSTA UDF Compliant";
    if raw.len() != 32 {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF domain identifier is truncated",
        ));
    }
    if !raw[1..24].starts_with(OSTA_DOMAIN) {
        return Err(udf_error(
            ErrorKind::Unsupported,
            "UDF domain identifier is not OSTA UDF",
        ));
    }
    if raw[1 + OSTA_DOMAIN.len()..24].iter().any(|byte| *byte != 0)
        || raw[27..].iter().any(|byte| *byte != 0)
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF domain identifier padding is non-zero",
        ));
    }
    le_u16(raw, 24)
}

fn validate_extended_attributes(raw: &[u8], tag_location: u32) -> Result<(), StreamError> {
    if raw.len() < 24 {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF extended-attribute area is shorter than its header",
        ));
    }
    validate_descriptor_tag(raw, Some(TAG_EXTENDED_ATTRIBUTE_HEADER), tag_location)?;
    let implementation_location = usize::try_from(le_u32(raw, 16)?).map_err(|_| {
        udf_error(
            ErrorKind::Limit,
            "UDF implementation-use attribute offset exceeds address space",
        )
    })?;
    let application_location = usize::try_from(le_u32(raw, 20)?).map_err(|_| {
        udf_error(
            ErrorKind::Limit,
            "UDF application-use attribute offset exceeds address space",
        )
    })?;
    let implementation_location =
        (implementation_location < raw.len()).then_some(implementation_location);
    let application_location = (application_location < raw.len()).then_some(application_location);
    if implementation_location.is_some_and(|location| location < 24)
        || application_location.is_some_and(|location| location < 24)
        || matches!(
            (implementation_location, application_location),
            (Some(implementation), Some(application)) if implementation > application
        )
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF extended-attribute header offsets are invalid",
        ));
    }

    let mut boundaries = BTreeSet::new();
    boundaries.insert(24);
    let mut cursor = 24;
    while cursor < raw.len() {
        if raw[cursor..].iter().all(|byte| *byte == 0) {
            cursor = raw.len();
            boundaries.insert(cursor);
            break;
        }
        let header = raw.get(cursor..cursor + 12).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute record is truncated",
            )
        })?;
        if header[5..8].iter().any(|byte| *byte != 0) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute reserved bytes are non-zero",
            ));
        }
        let length = usize::try_from(le_u32(header, 8)?).map_err(|_| {
            udf_error(
                ErrorKind::Limit,
                "UDF extended-attribute length exceeds address space",
            )
        })?;
        if length < 12 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute record has an invalid length",
            ));
        }
        cursor = cursor.checked_add(length).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute range overflow",
            )
        })?;
        if cursor > raw.len() {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF extended-attribute record exceeds its area",
            ));
        }
        boundaries.insert(cursor);
    }
    if cursor != raw.len()
        || implementation_location.is_some_and(|location| !boundaries.contains(&location))
        || application_location.is_some_and(|location| !boundaries.contains(&location))
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF extended-attribute header points inside an attribute",
        ));
    }
    Ok(())
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn decode_dstring(field: &[u8]) -> Result<Vec<u8>, StreamError> {
    let Some(&length) = field.last() else {
        return Ok(Vec::new());
    };
    let length = usize::from(length);
    if length == 0 {
        return Ok(Vec::new());
    }
    if length > field.len().saturating_sub(1) {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF dstring length exceeds its field",
        ));
    }
    if field[length..field.len() - 1].iter().any(|byte| *byte != 0) {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF dstring padding is non-zero",
        ));
    }
    decode_compressed_unicode(&field[..length])
}

fn decode_compressed_unicode(value: &[u8]) -> Result<Vec<u8>, StreamError> {
    let Some((&compression, encoded)) = value.split_first() else {
        return Ok(Vec::new());
    };
    let mut decoded = String::new();
    match compression {
        8 => {
            for byte in encoded {
                decoded.push(char::from(*byte));
            }
        },
        16 => {
            if !encoded.len().is_multiple_of(2) {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "16-bit OSTA Compressed Unicode has an odd length",
                ));
            }
            let units = encoded
                .chunks_exact(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
            for character in char::decode_utf16(units) {
                decoded.push(character.map_err(|_| {
                    udf_error(
                        ErrorKind::Malformed,
                        "invalid UTF-16 in OSTA Compressed Unicode",
                    )
                })?);
            }
        },
        _ => {
            return Err(udf_error(
                ErrorKind::Malformed,
                "unsupported OSTA Compressed Unicode compression ID",
            ));
        },
    }
    Ok(decoded.into_bytes())
}

fn decode_symlink_components(encoded: &[u8], maximum: usize) -> Result<Vec<u8>, StreamError> {
    if encoded.is_empty() {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF symbolic-link pathname is empty",
        ));
    }
    let mut cursor = 0;
    let mut output = Vec::new();
    while cursor < encoded.len() {
        let header = encoded.get(cursor..cursor + 4).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "truncated UDF symbolic-link component",
            )
        })?;
        let kind = header[0];
        let length = usize::from(header[1]);
        cursor = cursor
            .checked_add(4)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF symlink offset overflow"))?;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF symlink length overflow"))?;
        let identifier = encoded.get(cursor..end).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF symbolic-link component is truncated",
            )
        })?;
        cursor = end;
        match kind {
            1 => {
                if !identifier.is_empty() {
                    return Err(udf_error(
                        ErrorKind::Unsupported,
                        "named UDF filesystem-root symlink components are not supported",
                    ));
                }
                output.clear();
                output.push(b'/');
            },
            2 => {
                if !identifier.is_empty() {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF hierarchy-root symlink component has an identifier",
                    ));
                }
                output.clear();
                output.push(b'/');
            },
            3 => {
                if !identifier.is_empty() {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF parent symlink component has an identifier",
                    ));
                }
                append_path_component(&mut output, b"..");
            },
            4 => {
                if !identifier.is_empty() {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF current-directory symlink component has an identifier",
                    ));
                }
                append_path_component(&mut output, b".");
            },
            5 => {
                if identifier.is_empty() {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF named symlink component is empty",
                    ));
                }
                let name = decode_compressed_unicode(identifier)?;
                append_path_component(&mut output, &name);
            },
            _ => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    "unsupported UDF symbolic-link component type",
                ));
            },
        }
        if output.len() > maximum {
            return Err(udf_error(
                ErrorKind::Limit,
                "decoded UDF symbolic-link target exceeds path limit",
            ));
        }
    }
    Ok(output)
}

fn append_path_component(output: &mut Vec<u8>, component: &[u8]) {
    if !output.is_empty() && !output.ends_with(b"/") {
        output.push(b'/');
    }
    output.extend_from_slice(component);
}

fn udf_fid_unique_id(unique_id: u64) -> u32 {
    let bytes = unique_id.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn udf_defined_stream_metadata(name: &[u8]) -> Option<bool> {
    match name {
        b"*UDF Macintosh Resource Fork" | b"*UDF OS/2 EA" | b"*UDF NT ACL" | b"*UDF UNIX ACL" => {
            Some(false)
        },
        value if value.starts_with(b"*UDF") => Some(true),
        _ => None,
    }
}

fn udf_stream_archive_path(owner: Option<&[u8]>, name: &[u8]) -> Result<Vec<u8>, StreamError> {
    let owner_bytes = owner.map_or(Ok(0), |value| {
        value
            .len()
            .checked_mul(3)
            .ok_or_else(|| udf_error(ErrorKind::Limit, "synthetic UDF stream owner overflow"))
    })?;
    let name_bytes = name
        .len()
        .checked_mul(3)
        .ok_or_else(|| udf_error(ErrorKind::Limit, "synthetic UDF stream name overflow"))?;
    let maximum = UDF_STREAM_PATH_PREFIX
        .len()
        .checked_add(owner_bytes)
        .and_then(|value| value.checked_add(name_bytes))
        .and_then(|value| value.checked_add(32))
        .ok_or_else(|| udf_error(ErrorKind::Limit, "synthetic UDF stream path overflow"))?;
    let mut path = Vec::new();
    path.try_reserve(maximum).map_err(|_| {
        udf_error(
            ErrorKind::Limit,
            "synthetic UDF stream path allocation failed",
        )
    })?;
    path.extend_from_slice(UDF_STREAM_PATH_PREFIX);
    match owner {
        Some(owner) => {
            path.extend_from_slice(b"named/o-");
            if owner.is_empty() {
                path.extend_from_slice(b"root");
            } else {
                path.extend_from_slice(b"path-");
                append_percent_encoded(&mut path, owner);
            }
            path.extend_from_slice(b"/s-");
        },
        None => path.extend_from_slice(b"system/s-"),
    }
    append_percent_encoded(&mut path, name);
    Ok(path)
}

fn append_percent_encoded(output: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_') {
            output.push(*byte);
        } else {
            output.extend_from_slice(&[
                b'%',
                HEX[usize::from(*byte >> 4)],
                HEX[usize::from(*byte & 0x0f)],
            ]);
        }
    }
}

fn udf_permissions(value: u32) -> u32 {
    u32::from(value & 0x1000 != 0) << 8
        | u32::from(value & 0x0800 != 0) << 7
        | u32::from(value & 0x0400 != 0) << 6
        | u32::from(value & 0x0080 != 0) << 5
        | u32::from(value & 0x0040 != 0) << 4
        | u32::from(value & 0x0020 != 0) << 3
        | u32::from(value & 0x0004 != 0) << 2
        | u32::from(value & 0x0002 != 0) << 1
        | u32::from(value & 0x0001 != 0)
}

fn udf_special_permissions(flags: u16) -> u32 {
    u32::from(flags & ICB_FLAG_SETUID != 0) << 11
        | u32::from(flags & ICB_FLAG_SETGID != 0) << 10
        | u32::from(flags & ICB_FLAG_STICKY != 0) << 9
}

fn parse_udf_timestamp(raw: Option<&[u8]>) -> Option<Timestamp> {
    let raw = raw?;
    if raw.len() != 12 {
        return None;
    }
    let type_and_zone = u16::from_le_bytes([raw[0], raw[1]]);
    let year = i32::from(u16::from_le_bytes([raw[2], raw[3]]));
    let month = u32::from(raw[4]);
    let day = u32::from(raw[5]);
    let hour = u32::from(raw[6]);
    let minute = u32::from(raw[7]);
    let second = u32::from(raw[8]);
    let timestamp_type = type_and_zone >> 12;
    if timestamp_type > 2
        || !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)?).contains(&day)
        || hour > 23
        || minute > 59
        || second > if timestamp_type == 2 { 60 } else { 59 }
        || raw[9..12].iter().any(|value| *value > 99)
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let mut secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour * 3600 + minute * 60 + second))?;
    let zone = type_and_zone & 0x0fff;
    if zone != 0x0801 {
        let signed = if zone & 0x0800 != 0 {
            i32::from(zone) - 0x1000
        } else {
            i32::from(zone)
        };
        if !(-1440..=1440).contains(&signed) {
            return None;
        }
        secs = secs.checked_sub(i64::from(signed) * 60)?;
    }
    let nanos =
        u32::from(raw[9]) * 10_000_000 + u32::from(raw[10]) * 100_000 + u32::from(raw[11]) * 1_000;
    Timestamp::new(secs, nanos).ok()
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i32::try_from(month).ok()? + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i32::try_from(day).ok()?.checked_sub(1)?;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(i64::from(era * 146_097 + day_of_era - 719_468))
}

fn payload_length(payload: &UdfPayload) -> Result<u64, StreamError> {
    match payload {
        UdfPayload::None => Ok(0),
        UdfPayload::Inline { data, .. } => Ok(data.len() as u64),
        UdfPayload::Extents(extents) => extents.iter().try_fold(0_u64, |total, extent| {
            total
                .checked_add(extent.length)
                .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF payload extent length overflow"))
        }),
    }
}

fn archive_metadata_size(metadata: &ArchiveMetadata) -> usize {
    metadata
        .volume_name()
        .map_or(0, |value| value.as_bytes().len())
        + metadata.comment().map_or(0, <[u8]>::len)
        + metadata
            .extensions()
            .iter()
            .map(|extension| {
                extension.namespace().len() + extension.key().len() + extension.value().len()
            })
            .sum::<usize>()
}

fn validate_metadata_partition_identifier(
    raw: &[u8],
    logical_volume_revision: u16,
) -> Result<(), StreamError> {
    const IDENTIFIER: &[u8] = b"*UDF Metadata Partition";
    if raw.len() != 32 {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF Metadata Partition identifier is truncated",
        ));
    }
    if raw[0] != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF Metadata Partition identifier flags are non-zero",
        ));
    }
    if !raw[1..24].starts_with(IDENTIFIER) {
        return Err(udf_error(
            ErrorKind::Unsupported,
            "UDF Type 2 map is not a Metadata Partition Map",
        ));
    }
    if raw[1 + IDENTIFIER.len()..24].iter().any(|byte| *byte != 0)
        || raw[28..].iter().any(|byte| *byte != 0)
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF Metadata Partition identifier padding is non-zero",
        ));
    }
    if le_u16(raw, 24)? != logical_volume_revision {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF Metadata Partition identifier revision disagrees with the logical volume",
        ));
    }
    Ok(())
}

fn validate_udf_entity_identifier(
    raw: &[u8],
    identifier: &[u8],
    logical_volume_revision: u16,
    context: &'static str,
) -> Result<(), StreamError> {
    if raw.len() != 32 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} identifier is truncated"),
        ));
    }
    if raw[0] != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} identifier flags are non-zero"),
        ));
    }
    if identifier.len() > 23 || !raw[1..24].starts_with(identifier) {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} identifier is invalid"),
        ));
    }
    if raw[1 + identifier.len()..24].iter().any(|byte| *byte != 0)
        || raw[28..].iter().any(|byte| *byte != 0)
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} identifier padding is non-zero"),
        ));
    }
    if le_u16(raw, 24)? != logical_volume_revision {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("{context} identifier revision disagrees with the logical volume"),
        ));
    }
    Ok(())
}

const fn optional_u32(value: u32) -> Option<u32> {
    if value == u32::MAX { None } else { Some(value) }
}

const fn ranges_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn capacity_bytes<T>(capacity: usize, context: &'static str) -> Result<usize, StreamError> {
    capacity
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| udf_error(ErrorKind::Limit, context))
}

fn udf_extent_block_ranges(extents: &[UdfExtent]) -> Result<Vec<(u64, u64)>, StreamError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve(extents.len())
        .map_err(|_| udf_error(ErrorKind::Limit, "UDF physical-range allocation failed"))?;
    for extent in extents {
        let source_offset = extent.source_offset.ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF recorded base-partition extent is unallocated",
            )
        })?;
        if !source_offset.is_multiple_of(BLOCK_SIZE) || !extent.length.is_multiple_of(BLOCK_SIZE) {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF base-partition extent is not block-aligned",
            ));
        }
        let start = source_offset / BLOCK_SIZE;
        let end = start
            .checked_add(extent.length / BLOCK_SIZE)
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF physical range overflow"))?;
        ranges.push((start, end));
    }
    Ok(ranges)
}

fn physical_block_range(
    partition: &PhysicalPartition,
    logical_block: u32,
    blocks: u32,
) -> Result<(u64, u64), StreamError> {
    if blocks == 0
        || u64::from(logical_block)
            .checked_add(u64::from(blocks))
            .is_none_or(|end| end > u64::from(partition.blocks))
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF metadata auxiliary extent is outside its physical partition",
        ));
    }
    let start = u64::from(partition.start)
        .checked_add(u64::from(logical_block))
        .ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF metadata auxiliary block overflow",
            )
        })?;
    let end = start.checked_add(u64::from(blocks)).ok_or_else(|| {
        udf_error(
            ErrorKind::Malformed,
            "UDF metadata auxiliary extent overflow",
        )
    })?;
    Ok((start, end))
}

fn insert_nonoverlapping_range(
    ranges: &mut Vec<(u64, u64)>,
    candidate: (u64, u64),
) -> Result<(), StreamError> {
    if ranges
        .iter()
        .any(|range| candidate.0 < range.1 && range.0 < candidate.1)
    {
        return Err(udf_error(
            ErrorKind::Malformed,
            "overlapping UDF Metadata File physical allocations",
        ));
    }
    ranges.try_reserve(1).map_err(|_| {
        udf_error(
            ErrorKind::Limit,
            "UDF Metadata File range allocation failed",
        )
    })?;
    ranges.push(candidate);
    Ok(())
}

fn metadata_files_overlap(
    first: &MetadataFile,
    second: &MetadataFile,
) -> Result<bool, StreamError> {
    for first_extent in first
        .extents
        .iter()
        .filter_map(|extent| extent.source_offset.map(|source| (source, extent.length)))
    {
        let first_end = first_extent.0.checked_add(first_extent.1).ok_or_else(|| {
            udf_error(
                ErrorKind::Malformed,
                "UDF Metadata File physical range overflow",
            )
        })?;
        for second_extent in second
            .extents
            .iter()
            .filter_map(|extent| extent.source_offset.map(|source| (source, extent.length)))
        {
            let second_end = second_extent
                .0
                .checked_add(second_extent.1)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF Metadata Mirror File physical range overflow",
                    )
                })?;
            if first_extent.0 < second_end && second_extent.0 < first_end {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn align4(value: usize) -> Result<usize, StreamError> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF alignment overflow"))
}

fn can_fallback_to_reserve(error: &StreamError) -> bool {
    error.archive_error().is_some_and(|archive| {
        matches!(archive.kind(), ErrorKind::Malformed | ErrorKind::Integrity)
    })
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, StreamError> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "truncated UDF u16 field"))?;
    Ok(u16::from_le_bytes(value))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, StreamError> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "truncated UDF u32 field"))?;
    Ok(u32::from_le_bytes(value))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, StreamError> {
    let value: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| udf_error(ErrorKind::Malformed, "truncated UDF u64 field"))?;
    Ok(u64::from_le_bytes(value))
}

fn udf_error(kind: ErrorKind, context: impl Into<String>) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("udf")
            .with_context(context),
    )
}
