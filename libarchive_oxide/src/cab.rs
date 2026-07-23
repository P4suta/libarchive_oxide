// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Microsoft Cabinet (`.cab`) read-only, seek-native provider (RM-305).
//!
//! A bounded parser for the MSCF container: `CFHEADER`, the `CFFOLDER` table,
//! the `CFFILE` table, and the per-folder `CFDATA` blocks. Two folder
//! compression methods are decoded — `NONE` (stored) and `MSZIP` (a `'CK'`
//! prefix followed by a raw-DEFLATE stream whose LZ77 window is carried across
//! the folder's blocks). `QUANTUM` and `LZX` are surfaced as structured
//! `Unsupported`, as are cross-cabinet continuation files.
//!
//! A folder is a solid unit: the decompressed output of its `CFDATA` blocks is
//! concatenated and each file is sliced from `uoffFolderStart`. The decoder is
//! streamed one `CFDATA` block at a time (each `<= 32 KiB` uncompressed), so no
//! whole folder is ever materialized and every emitted chunk stays within the
//! 64 KiB event budget.
//!
//! Known limitation: because the MSZIP history is a 32 KiB wrapping ring, a
//! *malformed* block whose back-reference distance reaches before the folder's
//! start resolves against the zero-initialized window instead of erroring. Every
//! spec-conforming cabinet stays within the valid window, so this only affects
//! deliberately corrupt input, and the output stays bounded and panic-free.

use std::io::{Read, Seek, SeekFrom};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Limits, Owner, PathEncoding, Timestamp,
};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use crate::{ReaderEvent, StreamError};

/// Maximum size of a streamed payload chunk.
const BUFFER: usize = 64 * 1024;
/// The MSZIP LZ77 window size; also the maximum `CFDATA` uncompressed size.
const MSZIP_WINDOW: usize = 0x8000;
/// The `CFHEADER` `RESERVE_PRESENT` flag.
const FLAG_RESERVE_PRESENT: u16 = 0x0004;
/// The `CFHEADER` `PREV_CABINET` flag.
const FLAG_PREV: u16 = 0x0001;
/// The `CFHEADER` `NEXT_CABINET` flag.
const FLAG_NEXT: u16 = 0x0002;
/// The `CFFILE` "name is UTF-8" attribute bit.
const ATTR_NAME_UTF8: u16 = 0x80;

/// The compression method of a folder (`typeCompress & 0x000F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// Stored: each `CFDATA` payload is the literal decompressed bytes.
    Store,
    /// MSZIP: a `'CK'` prefix then a raw-DEFLATE stream, window carried across blocks.
    Mszip,
    /// Quantum, LZX, or an unknown method — metadata is listed, payload is unsupported.
    Unsupported(u16),
}

/// A parsed `CFFOLDER` record.
#[derive(Debug, Clone, Copy)]
struct CabFolder {
    /// Absolute offset of this folder's first `CFDATA` block.
    data_offset: u64,
    /// Number of `CFDATA` blocks in the folder.
    num_data: u16,
    /// The folder's compression method.
    method: Method,
}

/// A parsed `CFFILE` record.
#[derive(Debug, Clone)]
struct CabFile {
    /// Path with backslashes normalized to `/`.
    name: Vec<u8>,
    /// Uncompressed file size (`cbFile`).
    size: u64,
    /// Byte offset of the file within its folder's decompressed stream.
    folder_offset: u64,
    /// Index into the folder table.
    folder_index: usize,
    /// Whether `iFolder` was a cross-cabinet continuation sentinel.
    continuation: bool,
    /// Modification time from the DOS date/time fields.
    mtime: Option<Timestamp>,
    /// Whether the name is UTF-8 (else code-page bytes preserved verbatim).
    is_utf8: bool,
}

/// The streaming decoder for one solid folder.
struct FolderStream {
    /// Which folder this stream decodes.
    folder_index: usize,
    /// The folder's compression method.
    method: Method,
    /// Number of `CFDATA` blocks in the folder.
    num_blocks: u16,
    /// Index of the next `CFDATA` block to decode.
    next_block: u16,
    /// Absolute file offset of the next `CFDATA` block header.
    block_cursor: u64,
    /// Per-`CFDATA` reserved-field size from the header.
    reserve_data: u8,
    /// Total decompressed bytes already consumed by the reader.
    produced: u64,
    /// Decompressed bytes of the current block awaiting consumption.
    buf: Vec<u8>,
    /// Consumption cursor within [`FolderStream::buf`].
    buf_pos: usize,
    /// The MSZIP sliding window (empty for stored folders).
    ring: Vec<u8>,
    /// Write position within [`FolderStream::ring`].
    ring_pos: usize,
}

/// The reader's payload state machine (mirrors the 7z reader's phases).
#[derive(Debug, Clone, Copy)]
enum CabPhase {
    /// Between entries.
    Idle,
    /// Streaming a file payload with this many bytes still to emit.
    Data { remaining: u64 },
    /// The open entry lives in an unsupported / cross-cabinet folder.
    Unsupported,
    /// The open entry's payload is exhausted.
    EndEntry,
    /// The archive is fully consumed.
    Done,
}

/// Seek-capable read-only Microsoft Cabinet reader.
pub(crate) struct CabSeekReader<R> {
    input: R,
    limits: Limits,
    image_length: u64,
    archive_metadata: Option<ArchiveMetadata>,
    folders: Vec<CabFolder>,
    files: Vec<CabFile>,
    next_file: usize,
    phase: CabPhase,
    folder_stream: Option<FolderStream>,
    reserve_data: u8,
    event_data: Vec<u8>,
    decoded_total: u64,
}

impl<R> std::fmt::Debug for CabSeekReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CabSeekReader")
            .field("folders", &self.folders.len())
            .field("files", &self.files.len())
            .field("next_file", &self.next_file)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> CabSeekReader<R> {
    pub(crate) fn new(mut input: R, limits: Limits) -> core::result::Result<Self, StreamError> {
        let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;

        let mut header = [0_u8; 36];
        input.read_exact(&mut header).map_err(StreamError::io)?;
        if &header[0..4] != b"MSCF" {
            return Err(cab_error(ErrorKind::Malformed, "bad MSCF signature"));
        }
        let coff_files = u64::from(u32::from_le_bytes([
            header[16], header[17], header[18], header[19],
        ]));
        let num_folders = u16::from_le_bytes([header[26], header[27]]);
        let num_files = u16::from_le_bytes([header[28], header[29]]);
        let flags = u16::from_le_bytes([header[30], header[31]]);

        if coff_files == 0 || coff_files >= image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CFFILE table offset is outside the cabinet",
            ));
        }
        if limits
            .entries()
            .is_some_and(|maximum| u64::from(num_files) > maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "file count exceeds configured limit",
            ));
        }

        let (reserve_folder, reserve_data) = if flags & FLAG_RESERVE_PRESENT != 0 {
            let mut reserve = [0_u8; 4];
            input.read_exact(&mut reserve).map_err(StreamError::io)?;
            let cb_header = u16::from_le_bytes([reserve[0], reserve[1]]);
            if cb_header != 0 {
                input
                    .seek(SeekFrom::Current(i64::from(cb_header)))
                    .map_err(StreamError::io)?;
            }
            (reserve[2], reserve[3])
        } else {
            (0_u8, 0_u8)
        };

        if flags & FLAG_PREV != 0 {
            skip_cstring(&mut input, limits)?;
            skip_cstring(&mut input, limits)?;
        }
        if flags & FLAG_NEXT != 0 {
            skip_cstring(&mut input, limits)?;
            skip_cstring(&mut input, limits)?;
        }

        let folder_table = input.stream_position().map_err(StreamError::io)?;
        let folders = read_folders(
            &mut input,
            folder_table,
            num_folders,
            reserve_folder,
            image_length,
        )?;
        let files = read_files(&mut input, coff_files, num_files, &folders, limits)?;

        Ok(Self {
            input,
            limits,
            image_length,
            archive_metadata: Some(ArchiveMetadata::new()),
            folders,
            files,
            next_file: 0,
            phase: CabPhase::Idle,
            folder_stream: None,
            reserve_data,
            event_data: Vec::with_capacity(BUFFER),
            decoded_total: 0,
        })
    }

    pub(crate) fn next_event(&mut self) -> core::result::Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        if let Some(metadata) = self.archive_metadata.take() {
            return Ok(ReaderEvent::ArchiveMetadata(metadata));
        }
        loop {
            match self.phase {
                CabPhase::Idle => {
                    let Some(file) = self.files.get(self.next_file).cloned() else {
                        self.phase = CabPhase::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    self.next_file += 1;
                    let metadata = self.prepare_file(&file)?;
                    return Ok(ReaderEvent::Entry(metadata));
                },
                CabPhase::Data { remaining: 0 } => {
                    self.phase = CabPhase::EndEntry;
                },
                CabPhase::Data { remaining } => {
                    let want = usize::try_from(remaining.min(BUFFER as u64)).map_err(|_| {
                        cab_error(ErrorKind::Limit, "payload chunk exceeds address space")
                    })?;
                    let count = self.pull_into_event(want)?;
                    if count == 0 {
                        return Err(cab_error(
                            ErrorKind::Malformed,
                            "folder ended before the declared file size",
                        ));
                    }
                    self.phase = CabPhase::Data {
                        remaining: remaining - count as u64,
                    };
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                CabPhase::Unsupported => {
                    return Err(cab_error(
                        ErrorKind::Unsupported,
                        "folder compression method is unsupported",
                    ));
                },
                CabPhase::EndEntry => {
                    self.phase = CabPhase::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                CabPhase::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> core::result::Result<(), StreamError> {
        match self.phase {
            CabPhase::Data { mut remaining } => {
                while remaining != 0 {
                    let step = self.discard_decoded(remaining)?;
                    if step == 0 {
                        return Err(cab_error(
                            ErrorKind::Malformed,
                            "folder ended while skipping a file",
                        ));
                    }
                    remaining -= step;
                }
                self.phase = CabPhase::EndEntry;
                Ok(())
            },
            CabPhase::Unsupported => {
                self.phase = CabPhase::EndEntry;
                Ok(())
            },
            CabPhase::EndEntry => Ok(()),
            CabPhase::Idle | CabPhase::Done => Err(cab_error(
                ErrorKind::Protocol,
                "skip_entry called without an open entry",
            )),
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.input
    }

    pub(crate) fn source_ref(&self) -> &R {
        &self.input
    }

    /// Positions the folder decoder and payload phase for `file`, then builds its metadata.
    fn prepare_file(&mut self, file: &CabFile) -> core::result::Result<EntryMetadata, StreamError> {
        if file.continuation {
            self.phase = CabPhase::Unsupported;
        } else {
            let folder = self
                .folders
                .get(file.folder_index)
                .copied()
                .ok_or_else(|| {
                    cab_error(ErrorKind::Malformed, "file references a missing folder")
                })?;
            match folder.method {
                Method::Unsupported(_) => self.phase = CabPhase::Unsupported,
                Method::Store | Method::Mszip => {
                    self.ensure_folder_stream(file.folder_index, folder);
                    self.drain_to(file.folder_offset)?;
                    self.phase = CabPhase::Data {
                        remaining: file.size,
                    };
                },
            }
        }

        let path = if file.is_utf8 {
            ArchivePath::from_encoded(file.name.clone(), PathEncoding::Utf8)
        } else {
            ArchivePath::from_bytes(file.name.clone())
        };
        let times = EntryTimes {
            modified: file.mtime,
            ..EntryTimes::default()
        };
        Ok(EntryMetadata::builder(EntryKind::File, path)
            .size(Some(file.size))
            .mode(Some(0o644))
            .owner(Owner::default())
            .times(times)
            .build())
    }

    /// Installs a fresh [`FolderStream`] for `index` unless the current one already decodes it.
    fn ensure_folder_stream(&mut self, index: usize, folder: CabFolder) {
        if self
            .folder_stream
            .as_ref()
            .is_some_and(|stream| stream.folder_index == index)
        {
            return;
        }
        let ring = if folder.method == Method::Mszip {
            vec![0_u8; MSZIP_WINDOW]
        } else {
            Vec::new()
        };
        self.folder_stream = Some(FolderStream {
            folder_index: index,
            method: folder.method,
            num_blocks: folder.num_data,
            next_block: 0,
            block_cursor: folder.data_offset,
            reserve_data: self.reserve_data,
            produced: 0,
            buf: Vec::new(),
            buf_pos: 0,
            ring,
            ring_pos: 0,
        });
    }

    /// Advances the folder decoder to `offset`, discarding intervening bytes.
    fn drain_to(&mut self, offset: u64) -> core::result::Result<(), StreamError> {
        let produced = self
            .folder_stream
            .as_ref()
            .map_or(0, |stream| stream.produced);
        if offset < produced {
            return Err(cab_error(
                ErrorKind::Malformed,
                "file offsets are not monotonic within a folder",
            ));
        }
        let mut remaining = offset - produced;
        while remaining != 0 {
            let step = self.discard_decoded(remaining)?;
            if step == 0 {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "folder ended before a file offset",
                ));
            }
            remaining -= step;
        }
        Ok(())
    }

    /// Copies up to `max` decoded bytes into `event_data`, returning the count.
    fn pull_into_event(&mut self, max: usize) -> core::result::Result<usize, StreamError> {
        if !self.ensure_block()? {
            return Ok(0);
        }
        let stream = self
            .folder_stream
            .as_mut()
            .ok_or_else(|| cab_error(ErrorKind::Protocol, "folder stream disappeared"))?;
        let available = stream.buf.len() - stream.buf_pos;
        let count = available.min(max);
        self.event_data
            .extend_from_slice(&stream.buf[stream.buf_pos..stream.buf_pos + count]);
        stream.buf_pos += count;
        stream.produced += count as u64;
        Ok(count)
    }

    /// Advances the folder decoder by up to `max` bytes without copying, returning the count.
    fn discard_decoded(&mut self, max: u64) -> core::result::Result<u64, StreamError> {
        if !self.ensure_block()? {
            return Ok(0);
        }
        let stream = self
            .folder_stream
            .as_mut()
            .ok_or_else(|| cab_error(ErrorKind::Protocol, "folder stream disappeared"))?;
        let available = (stream.buf.len() - stream.buf_pos) as u64;
        let step = available.min(max);
        let advance = usize::try_from(step)
            .map_err(|_| cab_error(ErrorKind::Limit, "skip step exceeds address space"))?;
        stream.buf_pos += advance;
        stream.produced += step;
        Ok(step)
    }

    /// Ensures the current folder block buffer has unconsumed bytes, decoding the next
    /// `CFDATA` block when needed. Returns `false` once the folder is fully decoded.
    fn ensure_block(&mut self) -> core::result::Result<bool, StreamError> {
        loop {
            {
                let stream = self
                    .folder_stream
                    .as_ref()
                    .ok_or_else(|| cab_error(ErrorKind::Protocol, "no folder stream is open"))?;
                if stream.buf_pos < stream.buf.len() {
                    return Ok(true);
                }
                if stream.next_block >= stream.num_blocks {
                    return Ok(false);
                }
            }
            let Self {
                input,
                folder_stream,
                image_length,
                limits,
                decoded_total,
                ..
            } = self;
            let stream = folder_stream
                .as_mut()
                .ok_or_else(|| cab_error(ErrorKind::Protocol, "no folder stream is open"))?;
            let produced = decode_next_block(input, stream, *image_length)?;
            *decoded_total = decoded_total
                .checked_add(produced as u64)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "decoded total overflow"))?;
            if limits
                .decoded_total()
                .is_some_and(|maximum| *decoded_total > maximum)
            {
                return Err(cab_error(
                    ErrorKind::Limit,
                    "decoded total exceeds configured limit",
                ));
            }
        }
    }
}

/// Reads the `CFFOLDER` table starting at `offset`.
fn read_folders<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    count: u16,
    reserve_folder: u8,
    image_length: u64,
) -> core::result::Result<Vec<CabFolder>, StreamError> {
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut folders = Vec::new();
    for _ in 0..count {
        let mut record = [0_u8; 8];
        input.read_exact(&mut record).map_err(StreamError::io)?;
        let data_offset = u64::from(u32::from_le_bytes([
            record[0], record[1], record[2], record[3],
        ]));
        let num_data = u16::from_le_bytes([record[4], record[5]]);
        let type_compress = u16::from_le_bytes([record[6], record[7]]);
        if data_offset >= image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "folder data offset is outside the cabinet",
            ));
        }
        let method = match type_compress & 0x000F {
            0 => Method::Store,
            1 => Method::Mszip,
            other => Method::Unsupported(other),
        };
        folders.push(CabFolder {
            data_offset,
            num_data,
            method,
        });
        if reserve_folder != 0 {
            input
                .seek(SeekFrom::Current(i64::from(reserve_folder)))
                .map_err(StreamError::io)?;
        }
    }
    Ok(folders)
}

/// Reads the `CFFILE` table starting at `offset`, bounding names and metadata by `limits`.
fn read_files<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    count: u16,
    folders: &[CabFolder],
    limits: Limits,
) -> core::result::Result<Vec<CabFile>, StreamError> {
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut files = Vec::new();
    let mut metadata_used = 0_usize;
    for _ in 0..count {
        let mut record = [0_u8; 16];
        input.read_exact(&mut record).map_err(StreamError::io)?;
        let size = u64::from(u32::from_le_bytes([
            record[0], record[1], record[2], record[3],
        ]));
        let folder_offset = u64::from(u32::from_le_bytes([
            record[4], record[5], record[6], record[7],
        ]));
        let i_folder = u16::from_le_bytes([record[8], record[9]]);
        let date = u16::from_le_bytes([record[10], record[11]]);
        let time = u16::from_le_bytes([record[12], record[13]]);
        let attribs = u16::from_le_bytes([record[14], record[15]]);

        let raw_name = read_cstring(input, limits)?;
        let name: Vec<u8> = raw_name
            .iter()
            .map(|&byte| if byte == b'\\' { b'/' } else { byte })
            .collect();

        if limits.entry_bytes().is_some_and(|maximum| size > maximum) {
            return Err(cab_error(
                ErrorKind::Limit,
                "file size exceeds configured limit",
            ));
        }
        metadata_used = metadata_used
            .checked_add(name.len())
            .and_then(|value| value.checked_add(core::mem::size_of::<CabFile>()))
            .ok_or_else(|| cab_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| metadata_used > maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "file metadata exceeds configured limit",
            ));
        }

        let continuation = matches!(i_folder, 0xFFFD..=0xFFFF);
        let folder_index = if continuation {
            0
        } else {
            usize::from(i_folder)
        };
        if !continuation && folder_index >= folders.len() {
            return Err(cab_error(
                ErrorKind::Malformed,
                "file references a folder index out of range",
            ));
        }

        files.push(CabFile {
            name,
            size,
            folder_offset,
            folder_index,
            continuation,
            mtime: dos_datetime_to_timestamp(date, time),
            is_utf8: attribs & ATTR_NAME_UTF8 != 0,
        });
    }
    Ok(files)
}

/// Decodes the next `CFDATA` block of `stream`, replacing its buffer. Returns the block's
/// decompressed byte count.
fn decode_next_block<R: Read + Seek>(
    input: &mut R,
    stream: &mut FolderStream,
    image_length: u64,
) -> core::result::Result<usize, StreamError> {
    let start = stream.block_cursor;
    input
        .seek(SeekFrom::Start(start))
        .map_err(StreamError::io)?;
    let mut header = [0_u8; 8];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    let cb_data = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let cb_uncomp = usize::from(u16::from_le_bytes([header[6], header[7]]));

    if cb_uncomp == 0 {
        return Err(cab_error(
            ErrorKind::Unsupported,
            "spanning CFDATA block continues in another cabinet",
        ));
    }
    if cb_uncomp > MSZIP_WINDOW {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CFDATA uncompressed size exceeds 32 KiB",
        ));
    }

    let reserve = u64::from(stream.reserve_data);
    let payload_offset = start
        .checked_add(8)
        .and_then(|value| value.checked_add(reserve))
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA offset overflow"))?;
    let next_cursor = payload_offset
        .checked_add(cb_data as u64)
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA extent overflow"))?;
    if next_cursor > image_length {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CFDATA block extends past the cabinet",
        ));
    }

    input
        .seek(SeekFrom::Start(payload_offset))
        .map_err(StreamError::io)?;
    let mut payload = vec![0_u8; cb_data];
    input.read_exact(&mut payload).map_err(StreamError::io)?;
    stream.block_cursor = next_cursor;
    stream.next_block += 1;

    let decoded = match stream.method {
        Method::Store => {
            if cb_data != cb_uncomp {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "stored CFDATA compressed and uncompressed sizes disagree",
                ));
            }
            payload
        },
        Method::Mszip => {
            if payload.len() < 2 || &payload[0..2] != b"CK" {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "MSZIP CFDATA block missing 'CK' signature",
                ));
            }
            mszip_inflate_block(
                &mut stream.ring,
                &mut stream.ring_pos,
                &payload[2..],
                cb_uncomp,
            )?
        },
        Method::Unsupported(_) => {
            return Err(cab_error(
                ErrorKind::Unsupported,
                "folder compression method is unsupported",
            ));
        },
    };

    let produced = decoded.len();
    stream.buf = decoded;
    stream.buf_pos = 0;
    Ok(produced)
}

/// Inflates one MSZIP block's raw-DEFLATE stream into the folder's wrapping window `ring`,
/// carrying the LZ77 history across blocks. Returns exactly `expected` decompressed bytes.
fn mszip_inflate_block(
    ring: &mut [u8],
    ring_pos: &mut usize,
    deflate: &[u8],
    expected: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    let mask = ring.len() - 1;
    let mut decompressor = DecompressorOxide::new();
    let mut output = Vec::with_capacity(expected);
    let mut input = deflate;
    // flags == 0: raw DEFLATE (no zlib header), wrapping output buffer, all input present.
    loop {
        let start = *ring_pos;
        let (status, consumed, written) = decompress(&mut decompressor, input, ring, start, 0);
        output.extend_from_slice(&ring[start..start + written]);
        input = input
            .get(consumed..)
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP consumed count overflow"))?;
        *ring_pos = (start + written) & mask;
        if output.len() > expected {
            return Err(cab_error(
                ErrorKind::Malformed,
                "MSZIP block produced more than its declared size",
            ));
        }
        match status {
            TINFLStatus::Done => break,
            TINFLStatus::HasMoreOutput => {
                if written == 0 && consumed == 0 {
                    return Err(cab_error(
                        ErrorKind::Malformed,
                        "MSZIP decoder made no progress",
                    ));
                }
            },
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "truncated MSZIP DEFLATE stream",
                ));
            },
            _ => {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "invalid MSZIP DEFLATE stream",
                ));
            },
        }
    }
    if output.len() != expected {
        return Err(cab_error(
            ErrorKind::Malformed,
            "MSZIP block size does not match its header",
        ));
    }
    Ok(output)
}

/// Reads a NUL-terminated name from the stream, bounding its length by `path_bytes`.
fn read_cstring<R: Read>(
    input: &mut R,
    limits: Limits,
) -> core::result::Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        input.read_exact(&mut byte).map_err(StreamError::io)?;
        if byte[0] == 0 {
            return Ok(out);
        }
        if limits
            .path_bytes()
            .is_some_and(|maximum| out.len() >= maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "name exceeds configured path limit",
            ));
        }
        out.push(byte[0]);
    }
}

/// Skips a NUL-terminated cabinet header string, bounded by `path_bytes`.
fn skip_cstring<R: Read>(input: &mut R, limits: Limits) -> core::result::Result<(), StreamError> {
    read_cstring(input, limits).map(|_| ())
}

/// Converts DOS date and time fields to a Unix [`Timestamp`], or `None` when unset/invalid.
fn dos_datetime_to_timestamp(date: u16, time: u16) -> Option<Timestamp> {
    if date == 0 && time == 0 {
        return None;
    }
    let year = 1980 + i64::from(date >> 9);
    let month = i64::from((date >> 5) & 0x0F);
    let day = i64::from(date & 0x1F);
    let hour = i64::from((time >> 11) & 0x1F);
    let minute = i64::from((time >> 5) & 0x3F);
    let second = i64::from(time & 0x1F) * 2;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    Some(Timestamp { secs, nanos: 0 })
}

/// Days from the Unix epoch to the given civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Builds a `cab`-tagged structured error.
fn cab_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("cab")
            .with_context(context),
    )
}
