// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Microsoft Cabinet set reconstruction over application-owned volumes.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use libarchive_oxide_core::{AccessMode, DirectionSet, ErrorKind, FormatId, Limits};

use super::{
    CabFile, CabSeekReader, FLAG_NEXT, FLAG_PREV, FLAG_RESERVE_PRESENT, FileContinuation, Method,
    cab_checksum, cab_error, ensure_stream_extent, read_cstring, read_files, read_folders,
    validate_cabinet_file_order,
};
use crate::provider::FormatCapabilities;
use crate::range_source::{
    RangeReader, ReadAt, SourceIdentity, VolumeId, VolumeSet, validate_read_at_snapshot,
};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
use crate::{ReaderEvent, StreamError};

const CAB_HEADER_SIZE: usize = 36;
const CAB_FOLDER_SIZE: usize = 8;
const CAB_FILE_SIZE: usize = 16;
const CAB_DATA_HEADER_SIZE: u64 = 8;
const CAB_DATA_RESERVE_MAX: usize = 255;

/// Built-in object-safe provider for a complete Microsoft Cabinet set.
///
/// `VolumeId(0)` must contain cabinet index zero. Further `VolumeId` values map
/// directly to `CFHEADER::iCabinet`; the application-owned [`VolumeSet`]
/// decides how those logical requests reach local or remote immutable objects.
/// Header names are validated as set links but are never interpreted as paths
/// and never trigger filesystem or network access.
#[derive(Debug, Default)]
pub struct CabVolumeProvider;

impl CabVolumeProvider {
    /// Creates the stateless CAB-set provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomAccessFormatProvider for CabVolumeProvider {
    fn format(&self) -> FormatId {
        FormatId::Cab
    }

    fn name(&self) -> &'static str {
        "cab-volume"
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Seek)
    }

    fn probe(&self, source: &VolumeSet, _limits: Limits) -> Result<bool, StreamError> {
        let primary = source.primary();
        if primary.len() < 4 {
            return Ok(false);
        }
        let mut magic = [0_u8; 4];
        primary.read_exact_at(0, &mut magic)?;
        Ok(&magic == b"MSCF")
    }

    fn open(
        &self,
        source: Arc<VolumeSet>,
        limits: Limits,
    ) -> Result<Box<dyn RandomAccessArchiveDecoder>, StreamError> {
        Ok(Box::new(CabVolumeReader::with_limits(
            source.as_ref(),
            limits,
        )?))
    }
}

/// Seek-native reader for a complete Microsoft Cabinet set.
///
/// Only headers, file tables, and physical CFDATA extents are indexed at open.
/// Compressed payload remains in the original [`ReadAt`] volumes and is fetched
/// lazily while entries are read. This API never performs implicit volume
/// discovery: every additional object is supplied by the caller's
/// [`crate::advanced::VolumeResolver`].
pub struct CabVolumeReader {
    inner: CabSeekReader<JoinedCabInput>,
}

impl fmt::Debug for CabVolumeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CabVolumeReader")
            .field("inner", &self.inner)
            .finish()
    }
}

impl CabVolumeReader {
    /// Opens a complete CAB set with finite safe defaults.
    pub fn new(source: &VolumeSet) -> Result<Self, StreamError> {
        Self::with_limits(source, Limits::default())
    }

    /// Opens a complete CAB set with explicit archive limits.
    pub fn with_limits(source: &VolumeSet, limits: Limits) -> Result<Self, StreamError> {
        let (joined, metadata_used) = build_joined_cab(source, limits)?;
        let parser_limits = limits.with_metadata_bytes(
            limits
                .metadata_bytes()
                .map(|maximum| maximum.saturating_sub(metadata_used)),
        );
        Ok(Self {
            inner: CabSeekReader::new_with_spanning(joined, parser_limits, true)?,
        })
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.inner.next_event()
    }

    /// Skips the open entry while preserving a continued folder's codec state.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.inner.skip_entry()
    }
}

impl RandomAccessArchiveDecoder for CabVolumeReader {
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        Self::next_event(self)
    }

    fn skip_entry(&mut self) -> Result<(), StreamError> {
        Self::skip_entry(self)
    }
}

struct ParsedCabinet {
    set_id: u16,
    cabinet_index: u16,
    flags: u16,
    previous_name: Option<Vec<u8>>,
    next_name: Option<Vec<u8>>,
    folders: Vec<FolderFragment>,
    files: Vec<CabFile>,
    metadata_bytes: usize,
}

struct FolderFragment {
    method: Method,
    records: Vec<PhysicalRecord>,
}

#[derive(Clone, Copy)]
struct PhysicalRecord {
    source_index: usize,
    payload_offset: u64,
    payload_len: u16,
    checksum: u32,
    uncompressed: u16,
}

struct LogicalFolder {
    method: Method,
    records: Vec<PhysicalRecord>,
}

struct OpenFile {
    file: CabFile,
    folder_index: usize,
    origin_cabinet: usize,
}

struct CapturedSource {
    source: Arc<dyn ReadAt>,
    identity: SourceIdentity,
    length: u64,
}

#[allow(clippy::too_many_lines)] // Resolution, set-chain validation, and lazy view creation are atomic.
fn build_joined_cab(
    volumes: &VolumeSet,
    limits: Limits,
) -> Result<(JoinedCabInput, usize), StreamError> {
    let mut sources = Vec::<CapturedSource>::new();
    let mut cabinets = Vec::<ParsedCabinet>::new();
    let mut expected_index = 0_u16;
    let mut expected_set = None;

    loop {
        let volume = VolumeId::new(u32::from(expected_index));
        let source = if expected_index == 0 {
            volumes.primary()
        } else {
            volumes.resolve_required(volume)?
        };
        let identity = source.identity().clone();
        let length = source.len();
        validate_read_at_snapshot(source.as_ref(), &identity, length)?;
        if sources.iter().any(|known| known.identity == identity) {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB set resolver returned a duplicate or cyclic source",
            ));
        }
        let source_index = sources.len();
        let cabinet = parse_cabinet(Arc::clone(&source), source_index, limits)?;
        validate_read_at_snapshot(source.as_ref(), &identity, length)?;
        if cabinet.cabinet_index != expected_index {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB set contains an out-of-order cabinet index",
            ));
        }
        if let Some(set_id) = expected_set {
            if cabinet.set_id != set_id {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB set identifier changed between cabinets",
                ));
            }
        } else {
            expected_set = Some(cabinet.set_id);
        }
        if expected_index == 0 && cabinet.flags & FLAG_PREV != 0 {
            return Err(cab_error(
                ErrorKind::Malformed,
                "cabinet index zero claims a previous cabinet",
            ));
        }
        if expected_index != 0 && cabinet.flags & FLAG_PREV == 0 {
            return Err(cab_error(
                ErrorKind::Malformed,
                "non-initial cabinet is missing its previous-cabinet link",
            ));
        }
        sources
            .try_reserve_exact(1)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB source index allocation failed"))?;
        cabinets
            .try_reserve_exact(1)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB volume index allocation failed"))?;
        sources.push(CapturedSource {
            source,
            identity,
            length,
        });
        let has_next = cabinet.flags & FLAG_NEXT != 0;
        cabinets.push(cabinet);
        enforce_metadata_limit(
            physical_set_metadata(&sources, sources.capacity(), &cabinets, cabinets.capacity())?,
            limits,
            "CAB physical-set metadata exceeds configured limit",
        )?;
        if !has_next {
            break;
        }
        expected_index = expected_index.checked_add(1).ok_or_else(|| {
            cab_error(
                ErrorKind::Limit,
                "CAB cabinet index overflowed its 16-bit domain",
            )
        })?;
    }

    let physical_metadata =
        physical_set_metadata(&sources, sources.capacity(), &cabinets, cabinets.capacity())?;
    let mut merge_peak = physical_metadata;
    validate_cabinet_names(&cabinets, limits, &mut merge_peak)?;
    let _checked_merge_peak =
        charge_metadata(merge_peak, merge_workspace_metadata(&cabinets)?, limits)?;
    let (folders, files) = merge_cabinets(cabinets, limits)?;
    let logical_metadata =
        logical_cab_metadata(&folders, folders.capacity(), &files, files.capacity())?;
    enforce_metadata_limit(
        source_index_metadata(&sources, sources.capacity())?
            .checked_add(logical_metadata)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB logical metadata overflow"))?,
        limits,
        "CAB logical-set metadata exceeds configured limit",
    )?;
    let (prefix, segments, total_len) =
        synthesize_cab(&folders, &files, expected_set.unwrap_or(0), limits)?;
    let joined_metadata = source_index_metadata(&sources, sources.capacity())?
        .checked_add(prefix.capacity())
        .and_then(|value| {
            segments
                .capacity()
                .checked_mul(std::mem::size_of::<VirtualSegment>())
                .and_then(|bytes| value.checked_add(bytes))
        })
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB joined metadata accounting overflow"))?;
    let synthesis_peak = source_index_metadata(&sources, sources.capacity())?
        .checked_add(logical_metadata)
        .and_then(|value| value.checked_add(prefix.capacity()))
        .and_then(|value| {
            segments
                .capacity()
                .checked_mul(std::mem::size_of::<VirtualSegment>())
                .and_then(|bytes| value.checked_add(bytes))
        })
        .ok_or_else(|| {
            cab_error(
                ErrorKind::Limit,
                "CAB synthesis metadata accounting overflow",
            )
        })?;
    enforce_metadata_limit(
        synthesis_peak,
        limits,
        "CAB synthesis metadata exceeds configured limit",
    )?;
    drop(folders);
    drop(files);
    let joined = JoinedCabInput {
        prefix,
        segments,
        sources,
        position: 0,
        total_len,
    };
    Ok((joined, joined_metadata))
}

#[allow(clippy::too_many_lines)] // One bounded pass preserves CFHEADER/table offset invariants.
fn parse_cabinet(
    source: Arc<dyn ReadAt>,
    source_index: usize,
    limits: Limits,
) -> Result<ParsedCabinet, StreamError> {
    let source_length = source.len();
    if source_length
        < u64::try_from(CAB_HEADER_SIZE)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB header size exceeds u64"))?
    {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB volume is shorter than the fixed CFHEADER",
        ));
    }
    let mut input = RangeReader::with_limits(source, limits)?;
    let mut header = [0_u8; CAB_HEADER_SIZE];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    if &header[0..4] != b"MSCF" {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB volume has a bad MSCF signature",
        ));
    }
    if header[24] != 3 || header[25] != 1 {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB volume has an unsupported format version",
        ));
    }
    let declared_size = u64::from(u32::from_le_bytes([
        header[8], header[9], header[10], header[11],
    ]));
    if declared_size
        < u64::try_from(CAB_HEADER_SIZE)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB header size exceeds u64"))?
    {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB cbCabinet is shorter than the fixed CFHEADER",
        ));
    }
    if declared_size > source_length {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB volume is shorter than cbCabinet",
        ));
    }
    let image_length = declared_size;
    let coff_files = u64::from(u32::from_le_bytes([
        header[16], header[17], header[18], header[19],
    ]));
    let folder_count = u16::from_le_bytes([header[26], header[27]]);
    let file_count = u16::from_le_bytes([header[28], header[29]]);
    let flags = u16::from_le_bytes([header[30], header[31]]);
    let set_id = u16::from_le_bytes([header[32], header[33]]);
    let cabinet_index = u16::from_le_bytes([header[34], header[35]]);
    if coff_files == 0 || coff_files >= image_length {
        return Err(cab_error(
            ErrorKind::Malformed,
            "resolved CAB CFFILE table offset is outside the cabinet",
        ));
    }
    if limits
        .entries()
        .is_some_and(|maximum| u64::from(file_count) > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "resolved CAB file count exceeds configured limit",
        ));
    }

    let (reserve_folder, reserve_data) = if flags & FLAG_RESERVE_PRESENT != 0 {
        ensure_stream_extent(
            &mut input,
            4,
            image_length,
            "CAB reserve descriptor extends past cbCabinet",
        )?;
        let mut reserve = [0_u8; 4];
        input.read_exact(&mut reserve).map_err(StreamError::io)?;
        let header_reserve = u64::from(u16::from_le_bytes([reserve[0], reserve[1]]));
        let after_reserve = input
            .stream_position()
            .map_err(StreamError::io)?
            .checked_add(header_reserve)
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "CAB reserve extent overflow"))?;
        if after_reserve > image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB header reserve extends past the volume",
            ));
        }
        input
            .seek(SeekFrom::Start(after_reserve))
            .map_err(StreamError::io)?;
        (reserve[2], reserve[3])
    } else {
        (0, 0)
    };

    let mut metadata_bytes = 0_usize;
    let (previous_name, previous_disk) = if flags & FLAG_PREV != 0 {
        (
            Some(read_cstring(
                &mut input,
                limits,
                limits.metadata_bytes(),
                image_length,
            )?),
            Some(read_cstring(
                &mut input,
                limits,
                limits.metadata_bytes(),
                image_length,
            )?),
        )
    } else {
        (None, None)
    };
    let (next_name, next_disk) = if flags & FLAG_NEXT != 0 {
        (
            Some(read_cstring(
                &mut input,
                limits,
                limits.metadata_bytes(),
                image_length,
            )?),
            Some(read_cstring(
                &mut input,
                limits,
                limits.metadata_bytes(),
                image_length,
            )?),
        )
    } else {
        (None, None)
    };
    for name in [
        previous_name.as_ref(),
        previous_disk.as_ref(),
        next_name.as_ref(),
        next_disk.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        metadata_bytes = metadata_bytes
            .checked_add(name.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB name metadata overflow"))?;
    }

    let folder_table = input.stream_position().map_err(StreamError::io)?;
    let (parsed_folders, folder_metadata) = read_folders(
        &mut input,
        folder_table,
        folder_count,
        reserve_folder,
        reserve_data,
        image_length,
        limits,
        false,
    )?;
    metadata_bytes = metadata_bytes
        .checked_add(folder_metadata)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB folder metadata overflow"))?;
    let file_limits = limits.with_metadata_bytes(
        limits
            .metadata_bytes()
            .map(|maximum| maximum.saturating_sub(metadata_bytes)),
    );
    let files = read_files(
        &mut input,
        coff_files,
        file_count,
        &parsed_folders,
        image_length,
        file_limits,
    )?;
    let file_metadata = files
        .len()
        .checked_mul(std::mem::size_of::<CabFile>())
        .and_then(|fixed| {
            files
                .iter()
                .try_fold(fixed, |total, file| total.checked_add(file.name.len()))
        })
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB file metadata overflow"))?;
    metadata_bytes = metadata_bytes
        .checked_add(file_metadata)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB metadata accounting overflow"))?;

    let parsed_folder_count = parsed_folders.len();
    let mut folders = Vec::new();
    folders
        .try_reserve_exact(parsed_folders.len())
        .map_err(|_| cab_error(ErrorKind::Limit, "CAB folder-fragment allocation failed"))?;
    for (folder_index, folder) in parsed_folders.into_iter().enumerate() {
        let record_count = usize::from(folder.num_data);
        let record_metadata = record_count
            .checked_mul(std::mem::size_of::<PhysicalRecord>())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA index metadata overflow"))?;
        metadata_bytes = metadata_bytes
            .checked_add(record_metadata)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA metadata accounting overflow"))?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(record_count)
            .map_err(|_| cab_error(ErrorKind::Limit, "CFDATA index allocation failed"))?;
        let mut cursor = folder.data_offset;
        for record_index in 0..folder.num_data {
            let payload_offset = cursor
                .checked_add(CAB_DATA_HEADER_SIZE)
                .and_then(|value| value.checked_add(u64::from(reserve_data)))
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA header extent overflow"))?;
            if payload_offset > image_length {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CFDATA header extends past cbCabinet",
                ));
            }
            input
                .seek(SeekFrom::Start(cursor))
                .map_err(StreamError::io)?;
            let mut data_header = [0_u8; 8];
            input
                .read_exact(&mut data_header)
                .map_err(StreamError::io)?;
            let stored_checksum = u32::from_le_bytes([
                data_header[0],
                data_header[1],
                data_header[2],
                data_header[3],
            ]);
            let cb_data = u64::from(u16::from_le_bytes([data_header[4], data_header[5]]));
            let cb_uncomp = u16::from_le_bytes([data_header[6], data_header[7]]);
            if cb_uncomp == 0
                && (folder_index + 1 != parsed_folder_count || record_index + 1 != folder.num_data)
            {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "split CFDATA is not the final record of its cabinet",
                ));
            }
            let end = payload_offset
                .checked_add(cb_data)
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA offset overflow"))?;
            if end > image_length {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CFDATA record extends past its cabinet volume",
                ));
            }
            let reserve_len = usize::from(reserve_data);
            let mut reserved = [0_u8; CAB_DATA_RESERVE_MAX];
            input
                .read_exact(&mut reserved[..reserve_len])
                .map_err(StreamError::io)?;
            let checksum = if stored_checksum == 0 {
                0
            } else {
                stored_checksum ^ cab_checksum(&reserved[..reserve_len], 0)
            };
            records.push(PhysicalRecord {
                source_index,
                payload_offset,
                payload_len: u16::try_from(cb_data)
                    .map_err(|_| cab_error(ErrorKind::Limit, "CFDATA payload exceeds u16"))?,
                checksum,
                uncompressed: cb_uncomp,
            });
            cursor = end;
        }
        folders.push(FolderFragment {
            method: folder.method,
            records,
        });
    }
    let retained_folder_bytes = capacity_bytes::<FolderFragment>(
        folders.capacity(),
        "CAB folder-fragment metadata accounting overflow",
    )?;
    let retained_record_bytes = folders.iter().try_fold(0_usize, |total, folder| {
        let bytes = capacity_bytes::<PhysicalRecord>(
            folder.records.capacity(),
            "CAB CFDATA index metadata accounting overflow",
        )?;
        total
            .checked_add(bytes)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB CFDATA metadata overflow"))
    })?;
    let retained_file_bytes =
        capacity_bytes::<CabFile>(files.capacity(), "CAB file metadata accounting overflow")?;
    let retained_path_bytes = files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.name.capacity())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB path metadata overflow"))
    })?;
    let retained_link_bytes = [previous_name.as_ref(), next_name.as_ref()]
        .into_iter()
        .flatten()
        .try_fold(0_usize, |total, name| {
            total
                .checked_add(name.capacity())
                .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB link-name metadata overflow"))
        })?;
    let retained_metadata = retained_folder_bytes
        .checked_add(retained_record_bytes)
        .and_then(|value| value.checked_add(retained_file_bytes))
        .and_then(|value| value.checked_add(retained_path_bytes))
        .and_then(|value| value.checked_add(retained_link_bytes))
        .ok_or_else(|| {
            cab_error(
                ErrorKind::Limit,
                "CAB retained metadata accounting overflow",
            )
        })?;
    metadata_bytes = metadata_bytes.max(retained_metadata);
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| metadata_bytes > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "CAB volume metadata exceeds configured limit",
        ));
    }

    Ok(ParsedCabinet {
        set_id,
        cabinet_index,
        flags,
        previous_name,
        next_name,
        folders,
        files,
        metadata_bytes,
    })
}

fn validate_cabinet_names(
    cabinets: &[ParsedCabinet],
    limits: Limits,
    metadata_used: &mut usize,
) -> Result<(), StreamError> {
    if cabinets.is_empty() {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CAB set did not contain a primary cabinet",
        ));
    }
    let mut names = vec![None::<Vec<u8>>; cabinets.len()];
    *metadata_used = charge_metadata(
        *metadata_used,
        capacity_bytes::<Option<Vec<u8>>>(
            names.capacity(),
            "CAB cabinet-name index metadata overflow",
        )?,
        limits,
    )?;
    for index in 0..cabinets.len().saturating_sub(1) {
        let current = &cabinets[index];
        let next = &cabinets[index + 1];
        let next_name = current.next_name.as_ref().ok_or_else(|| {
            cab_error(
                ErrorKind::Malformed,
                "CAB next-cabinet flag has no cabinet name",
            )
        })?;
        if next_name.is_empty() {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB next-cabinet name is empty",
            ));
        }
        if names
            .iter()
            .flatten()
            .any(|known| cabinet_name_eq(known, next_name))
        {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB next-cabinet names contain a cycle or duplicate",
            ));
        }
        names[index + 1] = Some(next_name.clone());
        let cloned_capacity = names[index + 1].as_ref().map_or(0, Vec::capacity);
        *metadata_used = charge_metadata(*metadata_used, cloned_capacity, limits)?;

        let previous_name = next.previous_name.as_ref().ok_or_else(|| {
            cab_error(
                ErrorKind::Malformed,
                "CAB previous-cabinet flag has no cabinet name",
            )
        })?;
        if index == 0 {
            if cabinet_name_eq(previous_name, next_name) {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB previous and current cabinet names form a cycle",
                ));
            }
            names[0] = Some(previous_name.clone());
            let cloned_capacity = names[0].as_ref().map_or(0, Vec::capacity);
            *metadata_used = charge_metadata(*metadata_used, cloned_capacity, limits)?;
        } else if !names[..=index]
            .iter()
            .flatten()
            .any(|known| cabinet_name_eq(known, previous_name))
        {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB previous-cabinet name does not identify an earlier volume",
            ));
        }
    }
    if cabinets
        .last()
        .is_some_and(|cabinet| cabinet.flags & FLAG_NEXT != 0)
    {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CAB set ended while a next-cabinet link remained",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Folder and file continuation invariants are validated together.
fn merge_cabinets(
    cabinets: Vec<ParsedCabinet>,
    limits: Limits,
) -> Result<(Vec<LogicalFolder>, Vec<CabFile>), StreamError> {
    let mut folders = Vec::<LogicalFolder>::new();
    let mut files = Vec::<CabFile>::new();
    let fragment_count = cabinets.iter().try_fold(0_usize, |total, cabinet| {
        total
            .checked_add(cabinet.folders.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB folder count overflow"))
    })?;
    let repeated_file_count = cabinets.iter().try_fold(0_usize, |total, cabinet| {
        total
            .checked_add(cabinet.files.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB file count overflow"))
    })?;
    folders
        .try_reserve_exact(fragment_count)
        .map_err(|_| cab_error(ErrorKind::Limit, "CAB logical folder allocation failed"))?;
    files
        .try_reserve_exact(repeated_file_count)
        .map_err(|_| cab_error(ErrorKind::Limit, "CAB logical file allocation failed"))?;
    let mut open_file = None::<OpenFile>;
    let mut cabinet_names = vec![None::<Vec<u8>>; cabinets.len()];
    for index in 0..cabinets.len().saturating_sub(1) {
        cabinet_names[index + 1].clone_from(&cabinets[index].next_name);
        if index == 0 {
            cabinet_names[0].clone_from(&cabinets[1].previous_name);
        }
    }

    for (cabinet_index, cabinet) in cabinets.into_iter().enumerate() {
        let declared_from_previous = cabinet
            .files
            .first()
            .is_some_and(|file| file.continuation.starts_before());
        if declared_from_previous != open_file.is_some() {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB continued-file sentinels do not form a complete chain",
            ));
        }
        if cabinet_index != 0 {
            let expected_previous = if let Some(open) = &open_file {
                cabinet_names
                    .get(open.origin_cabinet)
                    .and_then(Option::as_ref)
            } else {
                cabinet_names
                    .get(cabinet_index - 1)
                    .and_then(Option::as_ref)
            }
            .ok_or_else(|| {
                cab_error(
                    ErrorKind::Malformed,
                    "CAB set could not determine the expected previous name",
                )
            })?;
            let observed = cabinet.previous_name.as_ref().ok_or_else(|| {
                cab_error(
                    ErrorKind::Malformed,
                    "continued cabinet is missing its previous name",
                )
            })?;
            if !cabinet_name_eq(expected_previous, observed) {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB previous-cabinet name disagrees with continuation state",
                ));
            }
        }

        let mut folder_map = Vec::new();
        folder_map
            .try_reserve_exact(cabinet.folders.len())
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB folder-map allocation failed"))?;
        for (local_index, fragment) in cabinet.folders.into_iter().enumerate() {
            if local_index == 0 && open_file.is_some() {
                let logical_index = folders.len().checked_sub(1).ok_or_else(|| {
                    cab_error(
                        ErrorKind::Malformed,
                        "continued CAB folder has no preceding fragment",
                    )
                })?;
                let logical = folders.get_mut(logical_index).ok_or_else(|| {
                    cab_error(ErrorKind::Protocol, "CAB logical folder disappeared")
                })?;
                if logical.method != fragment.method {
                    return Err(cab_error(
                        ErrorKind::Malformed,
                        "continued CAB folder changed compression method",
                    ));
                }
                logical
                    .records
                    .try_reserve_exact(fragment.records.len())
                    .map_err(|_| {
                        cab_error(ErrorKind::Limit, "continued CFDATA index allocation failed")
                    })?;
                logical.records.extend(fragment.records);
                folder_map.push(logical_index);
            } else {
                let logical_index = folders.len();
                folders.push(LogicalFolder {
                    method: fragment.method,
                    records: fragment.records,
                });
                folder_map.push(logical_index);
            }
        }

        let file_count = cabinet.files.len();
        for (file_index, mut file) in cabinet.files.into_iter().enumerate() {
            if file.continuation.starts_before() && file_index != 0 {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "continued-from-previous file is not first in its cabinet",
                ));
            }
            if file.continuation.continues_after() && file_index + 1 != file_count {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "continued-to-next file is not last in its cabinet",
                ));
            }
            let logical_folder = *folder_map.get(file.folder_index).ok_or_else(|| {
                cab_error(
                    ErrorKind::Malformed,
                    "CAB file references a missing logical folder",
                )
            })?;
            if file.continuation.starts_before() {
                let open = open_file.as_ref().ok_or_else(|| {
                    cab_error(
                        ErrorKind::Malformed,
                        "CAB file continues from an unopened previous entry",
                    )
                })?;
                if open.folder_index != logical_folder || !same_file(&open.file, &file) {
                    return Err(cab_error(
                        ErrorKind::Malformed,
                        "CAB repeated continued-file metadata does not match",
                    ));
                }
                if file.continuation == FileContinuation::FromPrevious {
                    open_file = None;
                }
                continue;
            }

            file.folder_index = logical_folder;
            let continues = file.continuation.continues_after();
            file.continuation = FileContinuation::None;
            if limits.entries().is_some_and(|maximum| {
                u64::try_from(files.len() + 1).map_or(true, |count| count > maximum)
            }) {
                return Err(cab_error(
                    ErrorKind::Limit,
                    "CAB set entry count exceeds configured limit",
                ));
            }
            if continues {
                open_file = Some(OpenFile {
                    file: file.try_clone()?,
                    folder_index: logical_folder,
                    origin_cabinet: cabinet_index,
                });
            }
            files.push(file);
        }
        if open_file.is_some() && cabinet.flags & FLAG_NEXT == 0 {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB set ended before a continued file completed",
            ));
        }
    }
    if open_file.is_some() {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CAB set ended with an open continued file",
        ));
    }
    for folder in &folders {
        if folder
            .records
            .last()
            .is_some_and(|record| record.uncompressed == 0)
        {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB logical folder ends in an incomplete split CFDATA",
            ));
        }
    }
    validate_cabinet_file_order(&files)?;
    Ok((folders, files))
}

#[allow(clippy::too_many_lines)] // Metadata serialization and lazy segment offsets share one cursor.
fn synthesize_cab(
    folders: &[LogicalFolder],
    files: &[CabFile],
    set_id: u16,
    limits: Limits,
) -> Result<(Vec<u8>, Vec<VirtualSegment>, u64), StreamError> {
    let folder_count = u16::try_from(folders.len()).map_err(|_| {
        cab_error(
            ErrorKind::Limit,
            "logical CAB folder count exceeds the 16-bit format domain",
        )
    })?;
    let file_count = u16::try_from(files.len()).map_err(|_| {
        cab_error(
            ErrorKind::Limit,
            "logical CAB file count exceeds the 16-bit format domain",
        )
    })?;
    let header_size = CAB_HEADER_SIZE;
    let folder_bytes = folders
        .len()
        .checked_mul(CAB_FOLDER_SIZE)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CAB folder table overflow"))?;
    let file_bytes = files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(CAB_FILE_SIZE)
            .and_then(|value| value.checked_add(file.name.len()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CAB file table overflow"))
    })?;
    let coff_files = header_size
        .checked_add(folder_bytes)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CAB table offset overflow"))?;
    let data_start = coff_files
        .checked_add(file_bytes)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CAB data offset overflow"))?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| data_start > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "logical CAB metadata exceeds configured limit",
        ));
    }
    let coff_files_u32 = u32::try_from(coff_files).map_err(|_| {
        cab_error(
            ErrorKind::Limit,
            "logical CAB file table exceeds the 32-bit format domain",
        )
    })?;

    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(data_start)
        .map_err(|_| cab_error(ErrorKind::Limit, "logical CAB metadata allocation failed"))?;
    prefix.resize(header_size + folder_bytes, 0);
    prefix[0..4].copy_from_slice(b"MSCF");
    prefix[16..20].copy_from_slice(&coff_files_u32.to_le_bytes());
    prefix[24] = 3;
    prefix[25] = 1;
    prefix[26..28].copy_from_slice(&folder_count.to_le_bytes());
    prefix[28..30].copy_from_slice(&file_count.to_le_bytes());
    prefix[32..34].copy_from_slice(&set_id.to_le_bytes());

    for file in files {
        let size = u32::try_from(file.size)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB file size exceeds u32"))?;
        let offset = u32::try_from(file.folder_offset)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB folder offset exceeds u32"))?;
        let folder_index = u16::try_from(file.folder_index).map_err(|_| {
            cab_error(
                ErrorKind::Limit,
                "CAB file folder index exceeds the 16-bit format domain",
            )
        })?;
        prefix.extend_from_slice(&size.to_le_bytes());
        prefix.extend_from_slice(&offset.to_le_bytes());
        prefix.extend_from_slice(&folder_index.to_le_bytes());
        prefix.extend_from_slice(&file.date.to_le_bytes());
        prefix.extend_from_slice(&file.time.to_le_bytes());
        prefix.extend_from_slice(&file.attribs.to_le_bytes());
        prefix.extend_from_slice(&file.name);
        prefix.push(0);
    }
    if prefix.len() != data_start {
        return Err(cab_error(
            ErrorKind::Protocol,
            "logical CAB metadata size is inconsistent",
        ));
    }

    let record_count = folders.iter().try_fold(0_usize, |total, folder| {
        total
            .checked_add(folder.records.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CFDATA count overflow"))
    })?;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(record_count)
        .map_err(|_| cab_error(ErrorKind::Limit, "logical CFDATA map allocation failed"))?;
    let mut virtual_cursor = u64::try_from(data_start)
        .map_err(|_| cab_error(ErrorKind::Limit, "logical CAB data offset exceeds u64"))?;
    for (folder_index, folder) in folders.iter().enumerate() {
        let data_offset = u32::try_from(virtual_cursor).map_err(|_| {
            cab_error(
                ErrorKind::Limit,
                "logical CAB folder offset exceeds the 32-bit format domain",
            )
        })?;
        let num_data = u16::try_from(folder.records.len()).map_err(|_| {
            cab_error(
                ErrorKind::Limit,
                "continued CAB folder has too many physical CFDATA records",
            )
        })?;
        let table_offset = header_size + folder_index * CAB_FOLDER_SIZE;
        prefix[table_offset..table_offset + 4].copy_from_slice(&data_offset.to_le_bytes());
        prefix[table_offset + 4..table_offset + 6].copy_from_slice(&num_data.to_le_bytes());
        prefix[table_offset + 6..table_offset + 8]
            .copy_from_slice(&encode_method(folder.method).to_le_bytes());
        for record in &folder.records {
            let payload_len = u64::from(record.payload_len);
            let segment_len = CAB_DATA_HEADER_SIZE
                .checked_add(payload_len)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CFDATA extent overflow"))?;
            let mut header = [0_u8; 8];
            header[0..4].copy_from_slice(&record.checksum.to_le_bytes());
            header[4..6].copy_from_slice(&record.payload_len.to_le_bytes());
            header[6..8].copy_from_slice(&record.uncompressed.to_le_bytes());
            segments.push(VirtualSegment {
                virtual_start: virtual_cursor,
                source_index: record.source_index,
                payload_start: record.payload_offset,
                payload_len,
                header,
            });
            virtual_cursor = virtual_cursor
                .checked_add(segment_len)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "logical CAB extent overflow"))?;
        }
    }
    let cabinet_size = u32::try_from(virtual_cursor).map_err(|_| {
        cab_error(
            ErrorKind::Limit,
            "logical CAB extent exceeds the 32-bit format domain",
        )
    })?;
    prefix[8..12].copy_from_slice(&cabinet_size.to_le_bytes());
    Ok((prefix, segments, virtual_cursor))
}

const fn encode_method(method: Method) -> u16 {
    match method {
        Method::Store => 0,
        Method::Mszip => 1,
        Method::Quantum { window_bits } => (window_bits as u16) << 8 | 0x12,
        Method::Lzx { window_bits } => (window_bits as u16) << 8 | 3,
        Method::Unsupported(method) => method,
    }
}

fn same_file(left: &CabFile, right: &CabFile) -> bool {
    left.name == right.name
        && left.size == right.size
        && left.folder_offset == right.folder_offset
        && left.date == right.date
        && left.time == right.time
        && left.attribs == right.attribs
}

fn cabinet_name_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn capacity_bytes<T>(capacity: usize, context: &'static str) -> Result<usize, StreamError> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(|| cab_error(ErrorKind::Limit, context))
}

fn source_index_metadata(
    sources: &[CapturedSource],
    capacity: usize,
) -> Result<usize, StreamError> {
    let fixed = capacity_bytes::<CapturedSource>(
        capacity,
        "CAB source-index metadata accounting overflow",
    )?;
    sources.iter().try_fold(fixed, |total, source| {
        total
            .checked_add(source.identity.allocation_bytes())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB source identity metadata overflow"))
    })
}

fn physical_set_metadata(
    sources: &[CapturedSource],
    source_capacity: usize,
    cabinets: &[ParsedCabinet],
    cabinet_capacity: usize,
) -> Result<usize, StreamError> {
    let source_bytes = source_index_metadata(sources, source_capacity)?;
    let cabinet_bytes = capacity_bytes::<ParsedCabinet>(
        cabinet_capacity,
        "CAB volume-index metadata accounting overflow",
    )?;
    cabinets.iter().try_fold(
        source_bytes.checked_add(cabinet_bytes).ok_or_else(|| {
            cab_error(
                ErrorKind::Limit,
                "CAB physical metadata accounting overflow",
            )
        })?,
        |total, cabinet| {
            total.checked_add(cabinet.metadata_bytes).ok_or_else(|| {
                cab_error(
                    ErrorKind::Limit,
                    "CAB physical metadata accounting overflow",
                )
            })
        },
    )
}

fn merge_workspace_metadata(cabinets: &[ParsedCabinet]) -> Result<usize, StreamError> {
    let fragments = cabinets.iter().try_fold(0_usize, |total, cabinet| {
        total
            .checked_add(cabinet.folders.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB merge folder count overflow"))
    })?;
    let files = cabinets.iter().try_fold(0_usize, |total, cabinet| {
        total
            .checked_add(cabinet.files.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB merge file count overflow"))
    })?;
    let largest_folder_map = cabinets
        .iter()
        .map(|cabinet| cabinet.folders.len())
        .max()
        .unwrap_or(0);
    let cloned_names = cabinets
        .iter()
        .flat_map(|cabinet| [cabinet.previous_name.as_ref(), cabinet.next_name.as_ref()])
        .flatten()
        .try_fold(0_usize, |total, name| {
            total
                .checked_add(name.capacity())
                .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB merge-name metadata overflow"))
        })?;
    capacity_bytes::<LogicalFolder>(fragments, "CAB logical-folder metadata overflow")?
        .checked_add(capacity_bytes::<CabFile>(
            files,
            "CAB logical-file metadata overflow",
        )?)
        .and_then(|value| {
            capacity_bytes::<Option<Vec<u8>>>(
                cabinets.len(),
                "CAB merge-name index metadata overflow",
            )
            .ok()
            .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| {
            capacity_bytes::<usize>(
                largest_folder_map,
                "CAB folder-map metadata accounting overflow",
            )
            .ok()
            .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| value.checked_add(cloned_names))
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB merge metadata accounting overflow"))
}

fn logical_cab_metadata(
    folders: &[LogicalFolder],
    folder_capacity: usize,
    files: &[CabFile],
    file_capacity: usize,
) -> Result<usize, StreamError> {
    let folder_fixed = capacity_bytes::<LogicalFolder>(
        folder_capacity,
        "CAB logical-folder metadata accounting overflow",
    )?;
    let records = folders.iter().try_fold(0_usize, |total, folder| {
        let bytes = capacity_bytes::<PhysicalRecord>(
            folder.records.capacity(),
            "CAB logical CFDATA metadata accounting overflow",
        )?;
        total
            .checked_add(bytes)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB logical CFDATA metadata overflow"))
    })?;
    let file_fixed = capacity_bytes::<CabFile>(
        file_capacity,
        "CAB logical-file metadata accounting overflow",
    )?;
    let names = files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.name.capacity())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB logical path metadata overflow"))
    })?;
    folder_fixed
        .checked_add(records)
        .and_then(|value| value.checked_add(file_fixed))
        .and_then(|value| value.checked_add(names))
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB logical metadata accounting overflow"))
}

fn enforce_metadata_limit(
    used: usize,
    limits: Limits,
    message: &'static str,
) -> Result<(), StreamError> {
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| used > maximum)
    {
        return Err(cab_error(ErrorKind::Limit, message));
    }
    Ok(())
}

fn charge_metadata(
    current: usize,
    additional: usize,
    limits: Limits,
) -> Result<usize, StreamError> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CAB set metadata accounting overflow"))?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| total > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "CAB set metadata exceeds configured limit",
        ));
    }
    Ok(total)
}

#[derive(Clone, Copy, Debug)]
struct VirtualSegment {
    virtual_start: u64,
    source_index: usize,
    payload_start: u64,
    payload_len: u64,
    header: [u8; 8],
}

struct JoinedCabInput {
    prefix: Vec<u8>,
    segments: Vec<VirtualSegment>,
    sources: Vec<CapturedSource>,
    position: u64,
    total_len: u64,
}

impl fmt::Debug for JoinedCabInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinedCabInput")
            .field("prefix_bytes", &self.prefix.len())
            .field("segments", &self.segments.len())
            .field("sources", &self.sources.len())
            .field("position", &self.position)
            .field("total_len", &self.total_len)
            .finish()
    }
}

impl Read for JoinedCabInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        let mut written = 0_usize;
        while written < output.len() && self.position < self.total_len {
            let prefix_len = u64::try_from(self.prefix.len())
                .map_err(|_| io::Error::other("CAB prefix length exceeds u64"))?;
            if self.position < prefix_len {
                let available = usize::try_from(prefix_len - self.position)
                    .map_err(|_| io::Error::other("CAB prefix range exceeds address space"))?;
                let count = available.min(output.len() - written);
                let start = usize::try_from(self.position)
                    .map_err(|_| io::Error::other("CAB prefix offset exceeds address space"))?;
                output[written..written + count]
                    .copy_from_slice(&self.prefix[start..start + count]);
                self.position += u64::try_from(count)
                    .map_err(|_| io::Error::other("CAB read count exceeds u64"))?;
                written += count;
                continue;
            }
            let segment_index = self
                .segments
                .partition_point(|segment| segment.virtual_start <= self.position)
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("CAB virtual extent has a gap"))?;
            let segment = self
                .segments
                .get(segment_index)
                .ok_or_else(|| io::Error::other("CAB virtual segment disappeared"))?;
            let segment_end = segment
                .virtual_start
                .checked_add(CAB_DATA_HEADER_SIZE)
                .and_then(|value| value.checked_add(segment.payload_len))
                .ok_or_else(|| io::Error::other("CAB virtual segment overflow"))?;
            if self.position >= segment_end {
                return Err(io::Error::other("CAB virtual extent has a gap"));
            }
            let within = self.position - segment.virtual_start;
            if within < CAB_DATA_HEADER_SIZE {
                let header_offset = usize::try_from(within)
                    .map_err(|_| io::Error::other("CAB header offset exceeds address space"))?;
                let available = segment.header.len() - header_offset;
                let count = available.min(output.len() - written);
                output[written..written + count]
                    .copy_from_slice(&segment.header[header_offset..header_offset + count]);
                self.position += u64::try_from(count)
                    .map_err(|_| io::Error::other("CAB read count exceeds u64"))?;
                written += count;
                continue;
            }
            let payload_within = within - CAB_DATA_HEADER_SIZE;
            let available = usize::try_from(segment_end - self.position)
                .map_err(|_| io::Error::other("CAB virtual range exceeds address space"))?;
            let count = available.min(output.len() - written);
            let source = self
                .sources
                .get(segment.source_index)
                .ok_or_else(|| io::Error::other("CAB source segment is missing"))?;
            let source_offset = segment
                .payload_start
                .checked_add(payload_within)
                .ok_or_else(|| io::Error::other("CAB source offset overflow"))?;
            validate_read_at_snapshot(source.source.as_ref(), &source.identity, source.length)?;
            source
                .source
                .read_exact_at(source_offset, &mut output[written..written + count])?;
            validate_read_at_snapshot(source.source.as_ref(), &source.identity, source.length)?;
            self.position +=
                u64::try_from(count).map_err(|_| io::Error::other("CAB read count exceeds u64"))?;
            written += count;
        }
        Ok(written)
    }
}

impl Seek for JoinedCabInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let requested = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(delta) => i128::from(self.total_len) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if !(0..=i128::from(u64::MAX)).contains(&requested) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CAB seek target is outside the u64 domain",
            ));
        }
        self.position = u64::try_from(requested).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CAB seek target exceeds the u64 domain",
            )
        })?;
        Ok(self.position)
    }
}
