// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only UDF 1.02/1.50/2.01 support for 2048-byte optical images.

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
const ICB_FLAG_SETUID: u16 = 1 << 6;
const ICB_FLAG_SETGID: u16 = 1 << 7;
const ICB_FLAG_STICKY: u16 = 1 << 8;
const ICB_FLAG_TRANSFORMED: u16 = 1 << 11;
const ICB_FLAG_MULTI_VERSION: u16 = 1 << 12;
const ICB_FLAG_STREAM: u16 = 1 << 13;
const ICB_FLAG_RESERVED: u16 = 0xc000;
const BUFFER: usize = 64 * 1024;
const MAX_FID_SIZE: usize = 38 + u16::MAX as usize + u8::MAX as usize;

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
    start: u32,
    blocks: u32,
}

#[derive(Debug)]
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
    maps: Vec<u16>,
    file_set: IcbAddress,
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
struct FileRecord {
    kind: EntryKind,
    size: u64,
    mode: u32,
    owner: Owner,
    times: EntryTimes,
    inode: u64,
    links: u64,
    payload: UdfPayload,
    sparse: Vec<SparseExtent>,
    extensions: Vec<Extension>,
    link_target: Option<ArchivePath>,
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
    partitions: Vec<Partition>,
    metadata_used: usize,
    decoded_total: u64,
    seen_paths: BTreeSet<Vec<u8>>,
    seen_icbs: BTreeMap<(u16, u32), ArchivePath>,
    entries: Vec<UdfIndex>,
}

impl<'a, R: Read + Seek> UdfParser<'a, R> {
    fn new(input: &'a mut R, limits: Limits) -> Result<Self, StreamError> {
        let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
        if image_length % BLOCK_SIZE != 0 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF Phase 1 requires a 2048-byte-sector optical image",
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
            partitions: Vec::new(),
            metadata_used: 0,
            decoded_total: 0,
            seen_paths: BTreeSet::new(),
            seen_icbs: BTreeMap::new(),
            entries: Vec::new(),
        })
    }

    fn parse(mut self) -> Result<(ArchiveMetadata, Vec<UdfIndex>, u64), StreamError> {
        let volume = self.find_volume_set()?;
        self.partitions.clone_from(&volume.partitions);
        let volume_name = if volume.logical_volume_id.is_empty() {
            volume.pvd_volume_id
        } else {
            volume.logical_volume_id
        };
        let mut archive_metadata = ArchiveMetadata::new().with_extension(Extension::new(
            "udf-volume",
            b"revision".to_vec(),
            volume.revision.to_le_bytes().to_vec(),
        ));
        if !volume_name.is_empty() {
            archive_metadata = archive_metadata
                .with_volume_name(ArchivePath::from_encoded(volume_name, PathEncoding::Utf8));
        }
        self.metadata_used = archive_metadata_size(&archive_metadata);
        self.enforce_metadata_limit()?;

        let file_set = self.read_icb_descriptor(volume.file_set, TAG_FILE_SET)?;
        if file_set.len() < 416 {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF File Set Descriptor is truncated",
            ));
        }
        require_verified_range(&file_set, 480, "UDF File Set Descriptor")?;
        validate_osta_charspec(&file_set[48..112], "File Set logical volume")?;
        validate_osta_charspec(&file_set[240..304], "File Set")?;
        let file_set_revision = parse_udf_domain_revision(&file_set[416..448])?;
        if file_set_revision != volume.revision {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF File Set and Logical Volume revisions disagree",
            ));
        }
        if optional_long_ad_present(&file_set, 448, "File Set Descriptor continuation")? {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "continued UDF File Set Descriptor sequences are not supported",
            ));
        }
        if optional_long_ad_present(&file_set, 464, "system-stream directory")? {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF system-stream directories are not supported",
            ));
        }
        let root = parse_long_ad(&file_set, 400)?;
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
        while let Some(task) = stack.pop() {
            self.parse_directory(task, &mut stack)?;
        }
        Ok((archive_metadata, self.entries, self.decoded_total))
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
            let start = le_u32(&descriptor, 188)?;
            let length = le_u32(&descriptor, 192)?;
            self.validate_partition_range(start, length)?;
            physical_partitions.insert(
                number,
                Partition {
                    start,
                    blocks: length,
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
        if !matches!(logical.revision, 0x0102 | 0x0150 | 0x0201) {
            return Err(udf_error(
                ErrorKind::Unsupported,
                format!(
                    "UDF revision {:x}.{:02x} is outside Phase 1",
                    logical.revision >> 8,
                    logical.revision & 0xff
                ),
            ));
        }
        let mut partitions = Vec::with_capacity(logical.maps.len());
        for number in logical.maps {
            partitions.push(physical_partitions.get(&number).cloned().ok_or_else(|| {
                udf_error(
                    ErrorKind::Malformed,
                    "UDF Type 1 map references a missing partition descriptor",
                )
            })?);
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
    fn parse_directory(
        &mut self,
        task: DirectoryTask,
        stack: &mut Vec<DirectoryTask>,
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
        let mut saw_parent = false;
        let fid_buffer_size = self
            .limits
            .in_flight_bytes()
            .unwrap_or(MAX_FID_SIZE)
            .min(MAX_FID_SIZE);
        let mut fid_buffer = vec![0_u8; fid_buffer_size];
        let mut cursor = UdfDataCursor::new(task.payload, task.length)?;
        while cursor.remaining != 0 {
            if cursor.remaining < TAG_SIZE as u64 {
                let count = usize::try_from(cursor.remaining).map_err(|_| {
                    udf_error(ErrorKind::Limit, "UDF directory tail exceeds address space")
                })?;
                let mut tail = [0_u8; TAG_SIZE];
                cursor.read_exact(self.input, &mut tail[..count])?;
                if tail[..count].iter().any(|byte| *byte != 0) {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "truncated UDF File Identifier Descriptor",
                    ));
                }
                break;
            }
            let tag_location = cursor.tag_location()?;
            let record_position = cursor.position;
            let mut head = [0_u8; 38];
            cursor.read_exact(self.input, &mut head[..TAG_SIZE])?;
            if head[..TAG_SIZE].iter().all(|byte| *byte == 0) {
                let within_block = (record_position + TAG_SIZE as u64) % BLOCK_SIZE;
                let block_tail = (if within_block == 0 {
                    0
                } else {
                    BLOCK_SIZE - within_block
                })
                .min(cursor.remaining);
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
                        cursor.read_exact(self.input, &mut padding[..chunk])?;
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
            if cursor.remaining < (head.len() - TAG_SIZE) as u64 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "truncated UDF File Identifier Descriptor header",
                ));
            }
            cursor.read_exact(self.input, &mut head[TAG_SIZE..])?;
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
            if record_length > fid_buffer.len() {
                return Err(udf_error(
                    ErrorKind::Limit,
                    "UDF FID exceeds the fixed in-flight buffer limit",
                ));
            }
            let record = &mut fid_buffer[..record_length];
            record.fill(0);
            record[..head.len()].copy_from_slice(&head);
            cursor.read_exact(self.input, &mut record[head.len()..])?;
            validate_descriptor_tag(record, Some(TAG_FILE_IDENTIFIER), tag_location)?;
            let implementation_start = 38_usize;
            let identifier_start = implementation_start
                .checked_add(implementation_length)
                .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF FID offset overflow"))?;
            let identifier_end = identifier_start
                .checked_add(identifier_length)
                .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF FID name overflow"))?;
            require_verified_range(record, identifier_end, "UDF File Identifier Descriptor")?;
            let identifier = record
                .get(identifier_start..identifier_end)
                .ok_or_else(|| {
                    udf_error(
                        ErrorKind::Malformed,
                        "UDF FID identifier is outside its descriptor",
                    )
                })?;
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
            if characteristics & 0x04 != 0 {
                continue;
            }
            let icb = parse_long_ad(record, 20)?;
            self.validate_icb_address(icb)?;
            if characteristics & 0x08 != 0 {
                if characteristics & 0x02 == 0
                    || identifier_length != 0
                    || saw_parent
                    || icb.partition_ref != task.parent_icb.partition_ref
                    || icb.logical_block != task.parent_icb.logical_block
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "UDF directory has an invalid parent FID",
                    ));
                }
                saw_parent = true;
                continue;
            }
            let name = decode_compressed_unicode(identifier)?;
            if name.is_empty() {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF FID has an empty identifier",
                ));
            }
            let file = self.parse_file_entry(icb)?;
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
            let path_value = ArchivePath::from_encoded(path.clone(), PathEncoding::Utf8);
            let key = (icb.partition_ref, icb.logical_block);
            let (metadata, payload, schedule) =
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
                    )
                } else {
                    self.seen_icbs.insert(key, path_value.clone());
                    let metadata = file.metadata(path_value);
                    let schedule = (file.kind == EntryKind::Dir).then(|| DirectoryTask {
                        prefix: path,
                        payload: file.payload.clone(),
                        length: file.size,
                        depth: task.depth.saturating_add(1),
                        directory_icb: icb,
                        parent_icb: task.directory_icb,
                    });
                    let payload = if matches!(file.kind, EntryKind::File) {
                        file.payload
                    } else {
                        UdfPayload::None
                    };
                    (metadata, payload, schedule)
                };
            self.account_entry(&metadata, &payload)?;
            self.entries.push(UdfIndex { metadata, payload });
            if let Some(directory) = schedule {
                self.account_directory_task(&directory)?;
                stack.push(directory);
            }
        }
        if !saw_parent {
            return Err(udf_error(
                ErrorKind::Malformed,
                "UDF directory is missing its parent FID",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn parse_file_entry(&mut self, icb: IcbAddress) -> Result<FileRecord, StreamError> {
        let descriptor = self.read_icb_descriptor_any(icb)?;
        let tag = le_u16(&descriptor, 0)?;
        let (information_offset, logical_blocks_offset, access_offset, modified_offset) = match tag
        {
            TAG_FILE_ENTRY => (56, 64, 72, 84),
            TAG_EXTENDED_FILE_ENTRY => (56, 72, 80, 92),
            _ => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF ICB does not reference a File Entry",
                ));
            },
        };
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
        let kind = match file_type {
            4 => EntryKind::Dir,
            5 => EntryKind::File,
            12 => EntryKind::Symlink,
            _ => {
                return Err(udf_error(
                    ErrorKind::Unsupported,
                    format!("unsupported UDF ICB file type {file_type}"),
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
        if flags & ICB_FLAG_STREAM != 0 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF stream ICBs are not supported",
            ));
        }
        let allocation_type = flags & 0x0007;
        if allocation_type == 2 {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF extended allocation descriptors are not supported",
            ));
        }
        let information_length = le_u64(&descriptor, information_offset)?;
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
        if tag == TAG_EXTENDED_FILE_ENTRY
            && optional_long_ad_present(&descriptor, 152, "stream directory")?
        {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "UDF named streams are not supported",
            ));
        }
        if optional_long_ad_present(
            &descriptor,
            external_attributes_offset,
            "external extended-attribute ICB",
        )? {
            return Err(udf_error(
                ErrorKind::Unsupported,
                "external UDF extended-attribute ICBs are not supported",
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
            0 | 1 => self.parse_allocation_descriptors(
                allocation,
                allocation_type,
                icb.partition_ref,
                information_length,
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
        let mut link_target = None;
        if kind == EntryKind::Symlink {
            let target = self.read_symlink(&payload, information_length)?;
            link_target = Some(ArchivePath::from_encoded(target, PathEncoding::Utf8));
            payload = UdfPayload::None;
        }
        let uid = le_u32(&descriptor, 36)?;
        let gid = le_u32(&descriptor, 40)?;
        let permissions = le_u32(&descriptor, 44)?;
        Ok(FileRecord {
            kind,
            size: information_length,
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
            links: u64::from(le_u16(&descriptor, 48)?),
            payload,
            sparse,
            extensions,
            link_target,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_allocation_descriptors(
        &mut self,
        allocation: &[u8],
        allocation_type: u16,
        default_partition: u16,
        information_length: u64,
    ) -> Result<(UdfPayload, Vec<SparseExtent>, u64), StreamError> {
        let mut extents = Vec::new();
        let mut sparse = Vec::new();
        let mut logical_offset = 0_u64;
        let mut recorded_blocks = 0_u64;
        let mut pending = vec![(allocation.to_vec(), default_partition)];
        let mut chains = BTreeSet::new();
        while let Some((descriptors, partition_ref)) = pending.pop() {
            let width = if allocation_type == 0 { 8 } else { 16 };
            if descriptors.len() % width != 0 {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF allocation descriptor array is truncated",
                ));
            }
            for (descriptor_index, descriptor) in descriptors.chunks_exact(width).enumerate() {
                let raw_length = le_u32(descriptor, 0)?;
                let extent_type = raw_length >> 30;
                let length = raw_length & 0x3fff_ffff;
                let (logical_block, referenced_partition) = if allocation_type == 0 {
                    (le_u32(descriptor, 4)?, partition_ref)
                } else {
                    (le_u32(descriptor, 4)?, le_u16(descriptor, 8)?)
                };
                if length == 0 {
                    if extent_type != 0
                        || logical_block != 0
                        || (allocation_type == 1 && referenced_partition != 0)
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
                        length,
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
                let source_offset = match extent_type {
                    0 => Some(self.extent_source(partition, logical_block, u64::from(length))?),
                    1 => {
                        self.extent_source(partition, logical_block, u64::from(length))?;
                        None
                    },
                    2 if logical_block == 0
                        && (allocation_type == 0 || referenced_partition == 0) =>
                    {
                        None
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
                    .checked_add(u64::from(length))
                    .ok_or_else(|| udf_error(ErrorKind::Limit, "UDF allocation length overflow"))?;
                if logical_offset >= information_length {
                    if extent_type != 1 || !length.is_multiple_of(BLOCK_SIZE_U32) {
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
                    && !length.is_multiple_of(BLOCK_SIZE_U32)
                {
                    return Err(udf_error(
                        ErrorKind::Malformed,
                        "non-final UDF file-body extent is not block-aligned",
                    ));
                }
                if source_offset.is_none() {
                    sparse.push(SparseExtent {
                        offset: logical_offset,
                        length: u64::from(length)
                            .min(information_length.saturating_sub(logical_offset)),
                    });
                } else {
                    recorded_blocks = recorded_blocks
                        .checked_add(u64::from(length).div_ceil(BLOCK_SIZE))
                        .ok_or_else(|| {
                            udf_error(ErrorKind::Limit, "UDF recorded-block count overflow")
                        })?;
                }
                extents.push(UdfExtent {
                    source_offset,
                    length: u64::from(length),
                    logical_block,
                });
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
        let partition = self.partition(address.partition_ref)?.clone();
        let physical = u64::from(partition.start)
            .checked_add(u64::from(address.logical_block))
            .ok_or_else(|| udf_error(ErrorKind::Malformed, "UDF ICB block overflow"))?;
        let descriptor =
            self.read_descriptor_block(physical, u64::from(address.logical_block), None)?;
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

    fn extent_source(
        &self,
        partition: &Partition,
        logical_block: u32,
        length: u64,
    ) -> Result<u64, StreamError> {
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
        let physical_block = u64::from(partition.start)
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
        Ok(offset)
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
    let mut physical_maps = Vec::new();
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
            1 if length == 6 => physical_maps.push(le_u16(map, 4)?),
            1 => {
                return Err(udf_error(
                    ErrorKind::Malformed,
                    "UDF Type 1 partition map length is not 6",
                ));
            },
            2 => {
                let identifier = map.get(5..).unwrap_or_default();
                let context = if identifier
                    .windows(b"*UDF Metadata Partition".len())
                    .any(|value| value == b"*UDF Metadata Partition")
                {
                    "UDF Metadata Partition Map (2.50/2.60) is not supported"
                } else if identifier
                    .windows(b"*UDF Sparable Partition".len())
                    .any(|value| value == b"*UDF Sparable Partition")
                {
                    "UDF Sparable Partition Map is not supported"
                } else if identifier
                    .windows(b"*UDF Virtual Partition".len())
                    .any(|value| value == b"*UDF Virtual Partition")
                {
                    "UDF Virtual Partition Map/VAT is not supported"
                } else {
                    "UDF Type 2 partition maps are not supported"
                };
                return Err(udf_error(ErrorKind::Unsupported, context));
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
    if cursor != maps.len() || physical_maps.is_empty() {
        return Err(udf_error(
            ErrorKind::Malformed,
            "UDF partition map table length/count mismatch",
        ));
    }
    Ok(RawLogicalVolume {
        logical_volume_id,
        revision,
        maps: physical_maps,
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

fn optional_long_ad_present(
    bytes: &[u8],
    offset: usize,
    context: &str,
) -> Result<bool, StreamError> {
    let raw_length = le_u32(bytes, offset)?;
    if raw_length >> 30 != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("UDF {context} has non-zero extent type"),
        ));
    }
    if raw_length & 0x3fff_ffff != 0 {
        return Ok(true);
    }
    if le_u32(bytes, offset + 4)? != 0 || le_u16(bytes, offset + 8)? != 0 {
        return Err(udf_error(
            ErrorKind::Malformed,
            format!("empty UDF {context} has a non-zero extent location"),
        ));
    }
    Ok(false)
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
    Some(Timestamp { secs, nanos })
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
