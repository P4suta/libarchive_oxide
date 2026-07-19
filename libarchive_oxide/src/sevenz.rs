// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seek-capable, payload-streaming 7z reader and writer.
//!
//! Supports one folder, pack stream, and coder. Writers emit LZMA2. Readers
//! accept LZMA2 or LZMA, including encoded headers. BCJ, delta, AES, `PPMd`,
//! multiple folders, multiple coders, and coder graphs are unsupported.

use std::io::{Read, Seek, SeekFrom, Take, Write};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Extension, Limits, Owner, PathEncoding, Timestamp,
};

use crate::{ReaderEvent, StreamError};

type Result<T> = core::result::Result<T, HeaderError>;

#[derive(Debug, Clone, Copy)]
enum HeaderError {
    Malformed(&'static str),
    Unsupported(&'static str),
    LimitExceeded(&'static str),
}

/// The 6-byte 7z signature magic (`'7' 'z' 0xBC 0xAF 0x27 0x1C`).
const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
/// Size of the fixed signature header at the start of every 7z file.
const SIGNATURE_HEADER_SIZE: usize = 32;

// 7z header property ids (a self-describing tag-length-ish structure).
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_CTIME: u8 = 0x12;
const K_ATIME: u8 = 0x13;
const K_MTIME: u8 = 0x14;
const K_WIN_ATTRIBUTES: u8 = 0x15;
const K_ENCODED_HEADER: u8 = 0x17;
const K_START_POS: u8 = 0x18;

/// LZMA2 coder method id (1 byte).
const METHOD_LZMA2: u8 = 0x21;
/// LZMA (v1) coder method id (3 bytes) — how mainstream 7-Zip compresses encoded headers and folders.
const METHOD_LZMA: [u8; 3] = [0x03, 0x01, 0x01];

/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTR_DIRECTORY: u32 = 0x10;
/// 7-Zip's "the high 16 bits carry a Unix `st_mode`" marker.
const ATTR_UNIX_EXTENSION: u32 = 0x8000;

/// Seconds between the Windows `FILETIME` epoch (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;

/// Cap on the file count declared in `FilesInfo`, applied before allocating.
const MAX_FILES: u64 = 1 << 24;

/// The LZMA2 dictionary size the writer uses (matches `lzma_rust2` preset 6 = 8 MiB).
const WRITER_DICT_SIZE: u32 = 1 << 23;
/// The LZMA2 encoder preset the writer uses.
const WRITER_PRESET: u32 = 6;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Parsed structures
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// The single-coder codec of a folder. Reading supports both LZMA2 (what this crate writes) and plain
/// LZMA (what 7-Zip and `sevenz-rust2` use for compressed/encoded headers and folders).
#[derive(Debug, Clone, Copy)]
enum FolderCoder {
    /// LZMA2, carrying its one-byte dictionary-size property.
    Lzma2 { dict_prop: u8 },
    /// LZMA (v1), carrying its 5 property bytes: `lc/lp/pb` byte + little-endian `u32` dict size.
    Lzma { props: [u8; 5] },
    /// A coder whose metadata can be listed but whose payload cannot be decoded.
    Unsupported,
}

/// The restricted single-folder description parsed from a `StreamsInfo`.
#[derive(Debug, Clone)]
struct FolderInfo {
    /// Absolute offset of the packed stream within the archive bytes.
    pack_offset: usize,
    /// Length of the packed stream.
    pack_size: usize,
    /// Uncompressed size of the whole folder.
    unpack_size: u64,
    /// The folder's single coder and its properties.
    coder: FolderCoder,
    /// Per-substream (per content file) uncompressed sizes, in file order.
    substream_sizes: Vec<u64>,
}

/// A parsed directory-entry-like record: name, kind, permissions, mtime, and (for content files)
/// the window into the decompressed folder buffer.
#[derive(Debug, Clone)]
struct FileRec {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    times: EntryTimes,
    anti: bool,
    start_position: Option<u64>,
    has_stream: bool,
    stream_offset: usize,
    size: usize,
}

/// Bounded parser for the 7z next-header metadata.
#[derive(Debug, Default)]
struct HeaderParser {
    files: Vec<FileRec>,
    folder: Option<FolderInfo>,
    header_extensions: Vec<libarchive_oxide_core::Extension>,
}

impl HeaderParser {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            folder: None,
            header_extensions: Vec::new(),
        }
    }

    /// Parses a plain `kHeader` body: optional main streams info, then files info.
    fn parse_header(&mut self, r: &mut ByteReader<'_>) -> Result<()> {
        let mut folder: Option<FolderInfo> = None;
        loop {
            match r.u8()? {
                K_END => break,
                K_ARCHIVE_PROPERTIES => self.parse_archive_properties(r)?,
                K_MAIN_STREAMS_INFO => folder = Some(parse_streams_info(r)?),
                K_FILES_INFO => self.parse_files_info(r, folder.as_ref())?,
                _ => return Err(HeaderError::Unsupported("7z: unsupported header property")),
            }
        }
        self.folder = folder;
        Ok(())
    }

    fn parse_archive_properties(&mut self, r: &mut ByteReader<'_>) -> Result<()> {
        loop {
            let property = r.u8()?;
            if property == K_END {
                return Ok(());
            }
            let size = usize_of(r.number()?)?;
            let value = r.bytes(size)?;
            self.header_extensions
                .push(libarchive_oxide_core::Extension::new(
                    "7z-archive-property",
                    vec![property],
                    value.to_vec(),
                ));
        }
    }

    /// Parses `FilesInfo`, assembling [`FileRec`]s and assigning content-file windows in order.
    #[allow(clippy::too_many_lines, clippy::needless_range_loop)]
    fn parse_files_info(
        &mut self,
        r: &mut ByteReader<'_>,
        folder: Option<&FolderInfo>,
    ) -> Result<()> {
        let num_files = usize_of(r.number()?)?;
        if num_files as u64 > MAX_FILES {
            return Err(HeaderError::LimitExceeded("7z: too many files"));
        }
        // Bomb defense: the entire next-header is already resident, so no honest archive can declare
        // more files than there are header bytes left to describe them (each file carries at least a
        // 2-byte UTF-16 name terminator, and usually attributes and a timestamp besides). Capping
        // against the remaining bytes keeps the per-file allocations below proportional to the input
        // and blocks a tiny header from forcing a multi-hundred-megabyte allocation up front.
        if num_files > r.remaining() {
            return Err(HeaderError::Malformed("7z: file count exceeds header size"));
        }

        let mut empty_stream = vec![false; num_files];
        let mut empty_file: Vec<bool> = Vec::new();
        let mut anti_empty: Vec<bool> = Vec::new();
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut created: Vec<Option<Timestamp>> = vec![None; num_files];
        let mut accessed: Vec<Option<Timestamp>> = vec![None; num_files];
        let mut modified: Vec<Option<Timestamp>> = vec![None; num_files];
        let mut start_positions: Vec<Option<u64>> = vec![None; num_files];
        let mut modes: Vec<Option<u32>> = vec![None; num_files];

        loop {
            let prop = r.number()?;
            if prop == u64::from(K_END) {
                break;
            }
            let size = usize_of(r.number()?)?;
            let body = r.bytes(size)?;
            let mut br = ByteReader::new(body);
            match u8::try_from(prop).unwrap_or(0xFF) {
                K_EMPTY_STREAM => empty_stream = br.bit_vector(num_files)?,
                K_EMPTY_FILE => {
                    let num_empty = empty_stream.iter().filter(|&&b| b).count();
                    empty_file = br.bit_vector(num_empty)?;
                },
                K_ANTI => {
                    let num_empty = empty_stream.iter().filter(|&&value| value).count();
                    anti_empty = br.bit_vector(num_empty)?;
                },
                K_NAME => names = parse_names(&mut br, num_files)?,
                K_CTIME => created = parse_times(&mut br, num_files)?,
                K_ATIME => accessed = parse_times(&mut br, num_files)?,
                K_MTIME => modified = parse_times(&mut br, num_files)?,
                K_WIN_ATTRIBUTES => modes = parse_attributes(&mut br, num_files)?,
                K_START_POS => start_positions = parse_positions(&mut br, num_files)?,
                _ => {},
            }
            self.header_extensions
                .push(libarchive_oxide_core::Extension::new(
                    "7z-files-property",
                    prop.to_le_bytes().to_vec(),
                    body.to_vec(),
                ));
        }

        // Assemble records. Content files consume substream windows in file order; empty-stream
        // files are directories unless flagged as empty files.
        let sizes = folder.map_or(&[][..], |f| f.substream_sizes.as_slice());
        let mut content_index = 0usize;
        let mut running = 0usize;
        let mut empty_index = 0usize;

        for i in 0..num_files {
            let name = names.get(i).cloned().unwrap_or_default();
            let full_mode = modes.get(i).copied().flatten();
            let has_stream = !empty_stream[i];

            let (kind, offset, size, is_anti) = if has_stream {
                let size = usize_of(*sizes.get(content_index).ok_or(HeaderError::Malformed(
                    "7z: content stream index out of range",
                ))?)?;
                let offset = running;
                running = running
                    .checked_add(size)
                    .ok_or(HeaderError::Malformed("7z: folder offset overflow"))?;
                content_index += 1;
                let kind = if full_mode.is_some_and(|m| m & 0o170_000 == 0o120_000) {
                    EntryKind::Symlink
                } else {
                    EntryKind::File
                };
                (kind, offset, size, false)
            } else {
                let is_empty_file = empty_file.get(empty_index).copied().unwrap_or(false);
                let is_anti = anti_empty.get(empty_index).copied().unwrap_or(false);
                empty_index += 1;
                let kind = if is_empty_file {
                    EntryKind::File
                } else {
                    EntryKind::Dir
                };
                (kind, 0, 0, is_anti)
            };

            let mode = permission_bits(full_mode, kind);
            self.files.push(FileRec {
                name,
                kind,
                mode,
                times: EntryTimes {
                    modified: modified.get(i).copied().flatten(),
                    accessed: accessed.get(i).copied().flatten(),
                    changed: None,
                    created: created.get(i).copied().flatten(),
                },
                anti: is_anti,
                start_position: start_positions.get(i).copied().flatten(),
                has_stream,
                stream_offset: offset,
                size,
            });
        }
        Ok(())
    }
}

enum SevenDecoder<R> {
    Lzma2(lzma_rust2::Lzma2Reader<Take<R>>),
    Lzma(lzma_rust2::LzmaReader<Take<R>>),
}

enum SevenInput<R> {
    Source(R),
    Decoder(Box<SevenDecoder<R>>),
}

impl<R: Read> SevenDecoder<R> {
    fn source_ref(&self) -> &R {
        match self {
            Self::Lzma2(reader) => reader.inner().get_ref(),
            Self::Lzma(reader) => reader.inner().get_ref(),
        }
    }

    fn into_inner(self) -> R {
        match self {
            Self::Lzma2(reader) => reader.into_inner().into_inner(),
            Self::Lzma(reader) => reader.into_inner().into_inner(),
        }
    }
}

impl<R: Read> SevenInput<R> {
    fn source_ref(&self) -> &R {
        match self {
            Self::Source(source) => source,
            Self::Decoder(decoder) => decoder.source_ref(),
        }
    }
}

impl<R: Read> Read for SevenDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Lzma2(reader) => reader.read(output),
            Self::Lzma(reader) => reader.read(output),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SevenPhase {
    Idle,
    Data { remaining: usize },
    Unsupported,
    EndEntry,
    Done,
}

/// Seek-capable 7z reader used by the opaque runtime dispatch.
pub(crate) struct SevenZSeekReader<R> {
    input: SevenInput<R>,
    limits: Limits,
    archive_metadata: Option<ArchiveMetadata>,
    files: Vec<FileRec>,
    folder: Option<FolderInfo>,
    next_file: usize,
    phase: SevenPhase,
    event_data: Vec<u8>,
    decoded_position: usize,
    decoded_total: u64,
}

impl<R> std::fmt::Debug for SevenZSeekReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SevenZSeekReader")
            .field("files", &self.files.len())
            .field("next_file", &self.next_file)
            .field("phase", &self.phase)
            .field("decoded_position", &self.decoded_position)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> SevenZSeekReader<R> {
    pub(crate) fn new(mut input: R, limits: Limits) -> core::result::Result<Self, StreamError> {
        let (archive_metadata, files, folder) = parse_seek_layout(&mut input, limits)?;
        validate_seek_layout(&files, folder.as_ref(), limits)?;
        let input = match folder.as_ref().map(|folder| folder.coder) {
            None | Some(FolderCoder::Unsupported) => SevenInput::Source(input),
            Some(coder) => {
                let folder = folder
                    .as_ref()
                    .ok_or_else(|| seven_error(ErrorKind::Protocol, "folder state disappeared"))?;
                input
                    .seek(SeekFrom::Start(u64::try_from(folder.pack_offset).map_err(
                        |_| seven_error(ErrorKind::Limit, "pack offset exceeds u64"),
                    )?))
                    .map_err(StreamError::io)?;
                let take = input.take(
                    u64::try_from(folder.pack_size)
                        .map_err(|_| seven_error(ErrorKind::Limit, "pack size exceeds u64"))?,
                );
                let decoder = build_seven_decoder(take, coder, folder.unpack_size, limits)?;
                SevenInput::Decoder(Box::new(decoder))
            },
        };
        Ok(Self {
            input,
            limits,
            archive_metadata: Some(archive_metadata),
            files,
            folder,
            next_file: 0,
            phase: SevenPhase::Idle,
            event_data: Vec::with_capacity(64 * 1024),
            decoded_position: 0,
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
                SevenPhase::Idle => {
                    let Some(record) = self.files.get(self.next_file).cloned() else {
                        self.verify_folder_end()?;
                        self.phase = SevenPhase::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    let index = self.next_file;
                    self.next_file += 1;
                    let metadata = self.prepare_record(index, &record)?;
                    return Ok(ReaderEvent::Entry(metadata));
                },
                SevenPhase::Data { remaining: 0 } => {
                    self.phase = SevenPhase::EndEntry;
                },
                SevenPhase::Data { remaining } => {
                    let amount = remaining.min(64 * 1024);
                    self.event_data.resize(amount, 0);
                    let count = self.read_decoded_into_event(amount)?;
                    if count == 0 {
                        return Err(seven_error(
                            ErrorKind::Malformed,
                            "folder ended before the declared substream size",
                        ));
                    }
                    self.event_data.truncate(count);
                    self.phase = SevenPhase::Data {
                        remaining: remaining - count,
                    };
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                SevenPhase::Unsupported => {
                    return Err(seven_error(
                        ErrorKind::Unsupported,
                        "payload coder is unsupported",
                    ));
                },
                SevenPhase::EndEntry => {
                    self.phase = SevenPhase::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                SevenPhase::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> core::result::Result<(), StreamError> {
        match self.phase {
            SevenPhase::Data { mut remaining } => {
                let mut scratch = vec![0_u8; 64 * 1024];
                while remaining != 0 {
                    let amount = remaining.min(scratch.len());
                    let count = self.read_decoded(&mut scratch[..amount])?;
                    if count == 0 {
                        return Err(seven_error(
                            ErrorKind::Malformed,
                            "folder ended while skipping a substream",
                        ));
                    }
                    remaining -= count;
                }
                self.phase = SevenPhase::EndEntry;
                Ok(())
            },
            SevenPhase::Unsupported => {
                self.phase = SevenPhase::EndEntry;
                Ok(())
            },
            SevenPhase::EndEntry => Ok(()),
            SevenPhase::Idle | SevenPhase::Done => Err(seven_error(
                ErrorKind::Protocol,
                "skip_entry called without an open 7z entry",
            )),
        }
    }

    pub(crate) fn into_inner(self) -> R {
        match self.input {
            SevenInput::Source(source) => source,
            SevenInput::Decoder(decoder) => (*decoder).into_inner(),
        }
    }

    pub(crate) fn source_ref(&self) -> &R {
        self.input.source_ref()
    }

    fn prepare_record(
        &mut self,
        _index: usize,
        record: &FileRec,
    ) -> core::result::Result<EntryMetadata, StreamError> {
        if record.has_stream && self.has_decoder() {
            self.drain_to(record.stream_offset)?;
        }
        let mut link_target = None;
        if record.has_stream && record.kind == EntryKind::Symlink && self.has_decoder() {
            if self
                .limits
                .path_bytes()
                .is_some_and(|maximum| record.size > maximum)
            {
                return Err(seven_error(
                    ErrorKind::Limit,
                    "symbolic-link target exceeds path limit",
                ));
            }
            let mut target = vec![0; record.size];
            self.read_decoded_exact(&mut target)?;
            link_target = Some(ArchivePath::from_encoded(target, PathEncoding::Utf8));
            self.phase = SevenPhase::EndEntry;
        } else if record.has_stream {
            self.phase = if self.has_decoder() {
                SevenPhase::Data {
                    remaining: record.size,
                }
            } else {
                SevenPhase::Unsupported
            };
        } else {
            self.phase = SevenPhase::EndEntry;
        }
        let mut builder = EntryMetadata::builder(
            record.kind,
            ArchivePath::from_encoded(record.name.clone(), PathEncoding::Utf8),
        )
        .size(Some(u64::try_from(record.size).map_err(|_| {
            seven_error(ErrorKind::Limit, "entry size exceeds u64")
        })?))
        .mode(Some(record.mode))
        .owner(Owner::default())
        .times(record.times)
        .link_target(link_target)
        .extension(libarchive_oxide_core::Extension::new(
            "7z-property",
            b"stream-offset".to_vec(),
            record.stream_offset.to_le_bytes().to_vec(),
        ));
        if record.anti {
            builder = builder.extension(libarchive_oxide_core::Extension::new(
                "7z-property",
                b"anti".to_vec(),
                vec![1],
            ));
        }
        if let Some(position) = record.start_position {
            builder = builder.extension(libarchive_oxide_core::Extension::new(
                "7z-property",
                b"start-position".to_vec(),
                position.to_le_bytes().to_vec(),
            ));
        }
        Ok(builder.build())
    }

    fn drain_to(&mut self, offset: usize) -> core::result::Result<(), StreamError> {
        if offset < self.decoded_position {
            return Err(seven_error(
                ErrorKind::Malformed,
                "substream offsets are not monotonic",
            ));
        }
        let mut remaining = offset - self.decoded_position;
        let mut scratch = vec![0_u8; 64 * 1024];
        while remaining != 0 {
            let amount = remaining.min(scratch.len());
            let count = self.read_decoded(&mut scratch[..amount])?;
            if count == 0 {
                return Err(seven_error(
                    ErrorKind::Malformed,
                    "folder ended before a substream offset",
                ));
            }
            remaining -= count;
        }
        Ok(())
    }

    fn read_decoded_exact(&mut self, output: &mut [u8]) -> core::result::Result<(), StreamError> {
        let mut filled = 0;
        while filled < output.len() {
            let count = self.read_decoded(&mut output[filled..])?;
            if count == 0 {
                return Err(seven_error(
                    ErrorKind::Malformed,
                    "folder ended before the declared entry size",
                ));
            }
            filled += count;
        }
        Ok(())
    }

    fn read_decoded_into_event(
        &mut self,
        amount: usize,
    ) -> core::result::Result<usize, StreamError> {
        let count = match &mut self.input {
            SevenInput::Decoder(decoder) => decoder
                .read(&mut self.event_data[..amount])
                .map_err(seven_decode_error)?,
            SevenInput::Source(_) => {
                return Err(seven_error(
                    ErrorKind::Unsupported,
                    "payload coder is unsupported",
                ));
            },
        };
        self.account_decoded(count)?;
        Ok(count)
    }

    fn read_decoded(&mut self, output: &mut [u8]) -> core::result::Result<usize, StreamError> {
        let decoder = self
            .decoder_mut()
            .ok_or_else(|| seven_error(ErrorKind::Unsupported, "payload coder is unsupported"))?;
        let count = decoder.read(output).map_err(seven_decode_error)?;
        self.account_decoded(count)?;
        Ok(count)
    }

    fn account_decoded(&mut self, count: usize) -> core::result::Result<(), StreamError> {
        self.decoded_position = self
            .decoded_position
            .checked_add(count)
            .ok_or_else(|| seven_error(ErrorKind::Limit, "folder position overflow"))?;
        self.decoded_total = self
            .decoded_total
            .checked_add(count as u64)
            .ok_or_else(|| seven_error(ErrorKind::Limit, "decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| self.decoded_total > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "decoded total exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn verify_folder_end(&mut self) -> core::result::Result<(), StreamError> {
        let Some(folder) = &self.folder else {
            return Ok(());
        };
        if !self.has_decoder() {
            return Ok(());
        }
        let expected = usize::try_from(folder.unpack_size)
            .map_err(|_| seven_error(ErrorKind::Limit, "folder size exceeds address space"))?;
        if self.decoded_position != expected {
            return Err(seven_error(
                ErrorKind::Malformed,
                "decoded folder size does not match its header",
            ));
        }
        let mut extra = [0_u8; 1];
        if self.read_decoded(&mut extra)? != 0 {
            return Err(seven_error(
                ErrorKind::Integrity,
                "folder produced data past its declared size",
            ));
        }
        Ok(())
    }

    const fn has_decoder(&self) -> bool {
        matches!(&self.input, SevenInput::Decoder(_))
    }

    fn decoder_mut(&mut self) -> Option<&mut SevenDecoder<R>> {
        match &mut self.input {
            SevenInput::Source(_) => None,
            SevenInput::Decoder(decoder) => Some(decoder.as_mut()),
        }
    }
}

fn parse_seek_layout(
    input: &mut (impl Read + Seek),
    limits: Limits,
) -> core::result::Result<(ArchiveMetadata, Vec<FileRec>, Option<FolderInfo>), StreamError> {
    let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
    input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    let mut signature = [0_u8; SIGNATURE_HEADER_SIZE];
    input.read_exact(&mut signature).map_err(StreamError::io)?;
    if !signature.starts_with(&SIGNATURE) {
        return Err(seven_error(ErrorKind::Malformed, "bad signature header"));
    }
    let start_crc = u32_le(&signature, 8).map_err(seven_legacy_error)?;
    if crate::filter::crc32(&signature[12..32]) != start_crc {
        return Err(seven_error(
            ErrorKind::Integrity,
            "start-header CRC mismatch",
        ));
    }
    let header_offset = u64_le(&signature, 12).map_err(seven_legacy_error)?;
    let header_size = u64_le(&signature, 20).map_err(seven_legacy_error)?;
    let header_crc = u32_le(&signature, 28).map_err(seven_legacy_error)?;
    if header_size == 0 {
        return Ok((ArchiveMetadata::new(), Vec::new(), None));
    }
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| header_size > maximum as u64)
    {
        return Err(seven_error(
            ErrorKind::Limit,
            "next header exceeds metadata limit",
        ));
    }
    let header_start = u64::try_from(SIGNATURE_HEADER_SIZE)
        .ok()
        .and_then(|base| base.checked_add(header_offset))
        .ok_or_else(|| seven_error(ErrorKind::Malformed, "next-header offset overflow"))?;
    if header_start
        .checked_add(header_size)
        .is_none_or(|end| end > image_length)
    {
        return Err(seven_error(
            ErrorKind::Malformed,
            "next header is outside the archive",
        ));
    }
    input
        .seek(SeekFrom::Start(header_start))
        .map_err(StreamError::io)?;
    let mut header = vec![
        0;
        usize::try_from(header_size).map_err(|_| {
            seven_error(ErrorKind::Limit, "next-header size exceeds address space")
        })?
    ];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    if crate::filter::crc32(&header) != header_crc {
        return Err(seven_error(
            ErrorKind::Integrity,
            "next-header CRC mismatch",
        ));
    }
    let decoded_header = match header.first().copied() {
        Some(K_HEADER) => header,
        Some(K_ENCODED_HEADER) => {
            let mut encoded = ByteReader::new(&header[1..]);
            let folder = parse_streams_info(&mut encoded).map_err(seven_legacy_error)?;
            if matches!(folder.coder, FolderCoder::Unsupported) {
                return Err(seven_error(
                    ErrorKind::Unsupported,
                    "encoded-header coder is unsupported",
                ));
            }
            decode_seek_header(input, &folder, limits, image_length)?
        },
        _ => {
            return Err(seven_error(
                ErrorKind::Malformed,
                "unexpected next-header property",
            ));
        },
    };
    if decoded_header.first() != Some(&K_HEADER) {
        return Err(seven_error(
            ErrorKind::Malformed,
            "decoded header does not begin with kHeader",
        ));
    }
    let mut parser = HeaderParser::new();
    let mut bytes = ByteReader::new(&decoded_header[1..]);
    parser
        .parse_header(&mut bytes)
        .map_err(seven_legacy_error)?;
    if let Some(folder) = &parser.folder {
        validate_folder_range(folder, image_length)?;
    }
    let archive_metadata = parser
        .header_extensions
        .into_iter()
        .fold(ArchiveMetadata::new(), ArchiveMetadata::with_extension);
    Ok((archive_metadata, parser.files, parser.folder))
}

fn decode_seek_header(
    input: &mut (impl Read + Seek),
    folder: &FolderInfo,
    limits: Limits,
    image_length: u64,
) -> core::result::Result<Vec<u8>, StreamError> {
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| folder.unpack_size > maximum as u64)
    {
        return Err(seven_error(
            ErrorKind::Limit,
            "decoded header exceeds metadata limit",
        ));
    }
    validate_folder_range(folder, image_length)?;
    input
        .seek(SeekFrom::Start(u64::try_from(folder.pack_offset).map_err(
            |_| seven_error(ErrorKind::Limit, "encoded-header offset exceeds u64"),
        )?))
        .map_err(StreamError::io)?;
    let take = input.take(
        u64::try_from(folder.pack_size)
            .map_err(|_| seven_error(ErrorKind::Limit, "encoded-header pack size exceeds u64"))?,
    );
    let mut decoder = build_seven_decoder(take, folder.coder, folder.unpack_size, limits)?;
    let length = usize::try_from(folder.unpack_size)
        .map_err(|_| seven_error(ErrorKind::Limit, "decoded header exceeds address space"))?;
    let mut output = vec![0; length];
    decoder
        .read_exact(&mut output)
        .map_err(seven_decode_error)?;
    let mut extra = [0_u8; 1];
    if decoder.read(&mut extra).map_err(seven_decode_error)? != 0 {
        return Err(seven_error(
            ErrorKind::Integrity,
            "encoded header exceeds its declared size",
        ));
    }
    Ok(output)
}

fn validate_seek_layout(
    files: &[FileRec],
    folder: Option<&FolderInfo>,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    if limits
        .entries()
        .is_some_and(|maximum| files.len() as u64 > maximum)
    {
        return Err(seven_error(
            ErrorKind::Limit,
            "file count exceeds configured limit",
        ));
    }
    let mut metadata = 0usize;
    for file in files {
        if limits
            .path_bytes()
            .is_some_and(|maximum| file.name.len() > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "file name exceeds configured path limit",
            ));
        }
        if limits
            .entry_bytes()
            .is_some_and(|maximum| file.size as u64 > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "file size exceeds configured limit",
            ));
        }
        metadata = metadata
            .checked_add(file.name.len())
            .and_then(|value| value.checked_add(core::mem::size_of::<FileRec>()))
            .ok_or_else(|| seven_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    }
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| metadata > maximum)
    {
        return Err(seven_error(
            ErrorKind::Limit,
            "file metadata exceeds configured limit",
        ));
    }
    if let Some(folder) = folder {
        if limits
            .decoded_total()
            .is_some_and(|maximum| folder.unpack_size > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "folder output exceeds decoded-total limit",
            ));
        }
        let total = files
            .iter()
            .filter(|file| file.has_stream)
            .try_fold(0usize, |sum, file| sum.checked_add(file.size))
            .ok_or_else(|| seven_error(ErrorKind::Malformed, "substream size sum overflow"))?;
        if u64::try_from(total).ok() != Some(folder.unpack_size) {
            return Err(seven_error(
                ErrorKind::Malformed,
                "substream sizes do not equal folder size",
            ));
        }
    }
    Ok(())
}

fn validate_folder_range(
    folder: &FolderInfo,
    image_length: u64,
) -> core::result::Result<(), StreamError> {
    let start = u64::try_from(folder.pack_offset)
        .map_err(|_| seven_error(ErrorKind::Limit, "pack offset exceeds u64"))?;
    let size = u64::try_from(folder.pack_size)
        .map_err(|_| seven_error(ErrorKind::Limit, "pack size exceeds u64"))?;
    if start.checked_add(size).is_none_or(|end| end > image_length) {
        return Err(seven_error(
            ErrorKind::Malformed,
            "packed stream is outside the archive",
        ));
    }
    Ok(())
}

fn build_seven_decoder<R: Read>(
    input: Take<R>,
    coder: FolderCoder,
    unpack_size: u64,
    limits: Limits,
) -> core::result::Result<SevenDecoder<R>, StreamError> {
    match coder {
        FolderCoder::Lzma2 { dict_prop } => {
            let dictionary = lzma2_dict_size(dict_prop).map_err(seven_legacy_error)?;
            validate_dictionary(dictionary, limits)?;
            Ok(SevenDecoder::Lzma2(lzma_rust2::Lzma2Reader::new(
                input, dictionary, None,
            )))
        },
        FolderCoder::Lzma { props } => {
            let dictionary = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
            validate_dictionary(dictionary, limits)?;
            Ok(SevenDecoder::Lzma(
                lzma_rust2::LzmaReader::new_with_props(
                    input,
                    unpack_size,
                    props[0],
                    dictionary,
                    None,
                )
                .map_err(|_| seven_error(ErrorKind::Malformed, "LZMA decoder setup failed"))?,
            ))
        },
        FolderCoder::Unsupported => Err(seven_error(
            ErrorKind::Unsupported,
            "payload coder is unsupported",
        )),
    }
}

fn validate_dictionary(dictionary: u32, limits: Limits) -> core::result::Result<(), StreamError> {
    if limits
        .codec_memory()
        .is_some_and(|maximum| u64::from(dictionary) > maximum as u64)
    {
        return Err(seven_error(
            ErrorKind::Limit,
            "LZMA dictionary exceeds codec workspace limit",
        ));
    }
    Ok(())
}

fn seven_decode_error(error: std::io::Error) -> StreamError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
    ) {
        seven_error(ErrorKind::Malformed, "LZMA payload decode failed")
    } else {
        StreamError::io(error)
    }
}

fn seven_legacy_error(error: HeaderError) -> StreamError {
    let (kind, context) = match error {
        HeaderError::Malformed(context) => (ErrorKind::Malformed, context),
        HeaderError::Unsupported(context) => (ErrorKind::Unsupported, context),
        HeaderError::LimitExceeded(context) => (ErrorKind::Limit, context),
    };
    seven_error(kind, context)
}

fn seven_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("7z")
            .with_context(context),
    )
}

/// Parses a `StreamsInfo` (`PackInfo`, `UnpackInfo`, `SubStreamsInfo`) restricted to one pack, one folder,
/// and one LZMA2 coder.
fn parse_streams_info(r: &mut ByteReader<'_>) -> Result<FolderInfo> {
    let mut pack_pos = 0u64;
    let mut pack_size: Option<u64> = None;
    let mut coder: Option<FolderCoder> = None;
    let mut unpack_size = 0u64;
    let mut num_substreams = 1usize;
    let mut substream_sizes: Option<Vec<u64>> = None;
    // Whether the folder's UnpackInfo carried a CRC. Mainstream 7-Zip and `sevenz-rust2` do NOT put
    // the folder CRC here — they store it only in SubStreamsInfo — so a single-substream folder still
    // carries a digest in SubStreamsInfo. Tracking this is what makes real compressed headers parse.
    let mut folder_has_crc = false;

    loop {
        match r.u8()? {
            K_END => break,
            K_PACK_INFO => {
                pack_pos = r.number()?;
                let num_pack = r.number()?;
                if num_pack != 1 {
                    return Err(HeaderError::Unsupported(
                        "7z: only a single pack stream is supported",
                    ));
                }
                loop {
                    match r.u8()? {
                        K_END => break,
                        K_SIZE => pack_size = Some(r.number()?),
                        K_CRC => read_digests(r, 1)?,
                        _ => {
                            return Err(HeaderError::Unsupported(
                                "7z: unsupported pack-info property",
                            ));
                        },
                    }
                }
            },
            K_UNPACK_INFO => {
                if r.u8()? != K_FOLDER {
                    return Err(HeaderError::Malformed("7z: unpack info missing kFolder"));
                }
                if r.number()? != 1 {
                    return Err(HeaderError::Unsupported(
                        "7z: only a single folder is supported",
                    ));
                }
                if r.u8()? != 0 {
                    return Err(HeaderError::Unsupported("7z: external folder definitions"));
                }
                coder = Some(read_folder(r)?);
                if r.u8()? != K_CODERS_UNPACK_SIZE {
                    return Err(HeaderError::Malformed("7z: missing coders-unpack-size"));
                }
                unpack_size = r.number()?;
                loop {
                    match r.u8()? {
                        K_END => break,
                        K_CRC => {
                            folder_has_crc = true;
                            read_digests(r, 1)?;
                        },
                        _ => {
                            return Err(HeaderError::Unsupported(
                                "7z: unsupported unpack-info property",
                            ));
                        },
                    }
                }
            },
            K_SUBSTREAMS_INFO => {
                let (n, sizes) = parse_substreams_info(r, unpack_size, folder_has_crc)?;
                num_substreams = n;
                substream_sizes = Some(sizes);
            },
            _ => {
                return Err(HeaderError::Unsupported(
                    "7z: unsupported streams-info property",
                ));
            },
        }
    }

    let pack_size = pack_size.ok_or(HeaderError::Malformed("7z: missing pack size"))?;
    let coder = coder.ok_or(HeaderError::Malformed("7z: missing coder properties"))?;
    let substream_sizes = match substream_sizes {
        Some(s) => s,
        None => vec![unpack_size],
    };
    let _ = num_substreams;
    let pack_offset = SIGNATURE_HEADER_SIZE
        .checked_add(usize_of(pack_pos)?)
        .ok_or(HeaderError::Malformed("7z: pack offset overflow"))?;

    Ok(FolderInfo {
        pack_offset,
        pack_size: usize_of(pack_size)?,
        unpack_size,
        coder,
        substream_sizes,
    })
}

/// Parses a single folder definition, returning its coder (LZMA2 or plain LZMA) and properties.
fn read_folder(r: &mut ByteReader<'_>) -> Result<FolderCoder> {
    if r.number()? != 1 {
        return Err(HeaderError::Unsupported(
            "7z: only a single coder is supported",
        ));
    }
    let flags = r.u8()?;
    let id_size = usize::from(flags & 0x0F);
    let is_complex = flags & 0x10 != 0;
    let has_attributes = flags & 0x20 != 0;
    if flags & 0x80 != 0 {
        return Err(HeaderError::Unsupported("7z: reserved coder flag set"));
    }
    let codec = r.bytes(id_size)?;
    if is_complex {
        return Err(HeaderError::Unsupported(
            "7z: complex coders are not supported",
        ));
    }
    if !has_attributes {
        return Err(HeaderError::Unsupported("7z: coder without properties"));
    }
    let prop_size = usize_of(r.number()?)?;
    let props = r.bytes(prop_size)?;
    if codec == [METHOD_LZMA2] {
        if prop_size != 1 {
            return Err(HeaderError::Unsupported(
                "7z: unexpected LZMA2 property size",
            ));
        }
        Ok(FolderCoder::Lzma2 {
            dict_prop: props[0],
        })
    } else if codec == METHOD_LZMA {
        if prop_size != 5 {
            return Err(HeaderError::Unsupported(
                "7z: unexpected LZMA property size",
            ));
        }
        let mut p = [0u8; 5];
        p.copy_from_slice(props);
        Ok(FolderCoder::Lzma { props: p })
    } else {
        Ok(FolderCoder::Unsupported)
    }
}

/// Parses a `SubStreamsInfo` block for the single folder, returning `(num_substreams, sizes)`.
///
/// `folder_has_crc` says whether the folder's `UnpackInfo` already defined a CRC: a single-substream
/// folder repeats no digest here only when it did, matching the 7z rule
/// `numDigests = Σ folders where (numSubstreams != 1 || !folderCrcDefined)`.
fn parse_substreams_info(
    r: &mut ByteReader<'_>,
    folder_unpack: u64,
    folder_has_crc: bool,
) -> Result<(usize, Vec<u64>)> {
    let mut num = 1usize;
    let mut sizes: Vec<u64> = Vec::new();
    let mut have_sizes = false;

    loop {
        match r.u8()? {
            K_END => break,
            K_NUM_UNPACK_STREAM => num = usize_of(r.number()?)?,
            K_SIZE => {
                let mut sum = 0u64;
                for _ in 0..num.saturating_sub(1) {
                    let s = r.number()?;
                    sum = sum
                        .checked_add(s)
                        .ok_or(HeaderError::Malformed("7z: substream size overflow"))?;
                    sizes.push(s);
                }
                let last = folder_unpack
                    .checked_sub(sum)
                    .ok_or(HeaderError::Malformed("7z: substream sizes exceed folder"))?;
                sizes.push(last);
                have_sizes = true;
            },
            K_CRC => {
                // A digest is present for every substream except the single-substream case whose CRC
                // is already defined on the folder (then it is not repeated).
                let unknown = if num == 1 && folder_has_crc { 0 } else { num };
                read_digests(r, unknown)?;
            },
            _ => {
                return Err(HeaderError::Unsupported(
                    "7z: unsupported substreams property",
                ));
            },
        }
    }

    if !have_sizes {
        if num == 1 {
            sizes = vec![folder_unpack];
        } else {
            return Err(HeaderError::Malformed("7z: missing substream sizes"));
        }
    }
    if sizes.len() != num {
        return Err(HeaderError::Malformed("7z: substream count mismatch"));
    }
    Ok((num, sizes))
}

/// Reads a `Digests` structure (`AllAreDefined` byte + optional bit vector + one CRC per defined
/// item), discarding the values after bounds-checking them.
fn read_digests(r: &mut ByteReader<'_>, count: usize) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let all_defined = r.u8()?;
    let defined = if all_defined != 0 {
        count
    } else {
        r.bit_vector(count)?.iter().filter(|&&b| b).count()
    };
    for _ in 0..defined {
        let _ = r.u32()?;
    }
    Ok(())
}

/// Parses the `kName` property: an external byte (must be 0) then null-terminated UTF-16LE names.
fn parse_names(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Vec<u8>>> {
    if r.u8()? != 0 {
        return Err(HeaderError::Unsupported("7z: names in an external stream"));
    }
    let mut names = Vec::with_capacity(num_files);
    for _ in 0..num_files {
        let start = r.pos;
        loop {
            if r.u16()? == 0 {
                break;
            }
        }
        let raw = r
            .data
            .get(start..r.pos - 2)
            .ok_or(HeaderError::Malformed("7z: bad name range"))?;
        names.push(utf16le_to_bytes(raw));
    }
    Ok(names)
}

/// Parses the `kMTime` property into a per-file list of optional timestamps.
fn parse_times(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Option<Timestamp>>> {
    let defined = read_all_defined(r, num_files)?;
    if r.u8()? != 0 {
        return Err(HeaderError::Unsupported("7z: times in an external stream"));
    }
    let mut out = vec![None; num_files];
    for (i, &is_def) in defined.iter().enumerate() {
        if is_def {
            out[i] = Some(filetime_to_timestamp(r.u64()?));
        }
    }
    Ok(out)
}

fn parse_positions(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Option<u64>>> {
    let defined = read_all_defined(r, num_files)?;
    if r.u8()? != 0 {
        return Err(HeaderError::Unsupported(
            "7z: start positions in an external stream",
        ));
    }
    let mut out = vec![None; num_files];
    for (index, is_defined) in defined.into_iter().enumerate() {
        if is_defined {
            out[index] = Some(r.u64()?);
        }
    }
    Ok(out)
}

/// Parses the `kWinAttributes` property into a per-file optional full Unix mode (with type bits),
/// present only when the entry carries the Unix-extension marker.
fn parse_attributes(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Option<u32>>> {
    let defined = read_all_defined(r, num_files)?;
    if r.u8()? != 0 {
        return Err(HeaderError::Unsupported(
            "7z: attributes in an external stream",
        ));
    }
    let mut out = vec![None; num_files];
    for (i, &is_def) in defined.iter().enumerate() {
        if is_def {
            let attr = r.u32()?;
            if attr & ATTR_UNIX_EXTENSION != 0 {
                out[i] = Some(attr >> 16);
            }
        }
    }
    Ok(out)
}

/// Reads an "`AllAreDefined`" boolean vector: a flag byte, and when it is zero, a following bit vector.
fn read_all_defined(r: &mut ByteReader<'_>, n: usize) -> Result<Vec<bool>> {
    if r.u8()? != 0 {
        Ok(vec![true; n])
    } else {
        r.bit_vector(n)
    }
}

/// The permission bits to expose for an entry: the stored `mode & 0o7777`, or a sensible default.
fn permission_bits(full_mode: Option<u32>, kind: EntryKind) -> u32 {
    match full_mode {
        Some(m) if m & 0o7777 != 0 => m & 0o7777,
        _ => match kind {
            EntryKind::Dir => 0o755,
            _ => 0o644,
        },
    }
}

#[derive(Debug)]
struct SeekStoredEntry {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    size: u64,
    has_stream: bool,
    crc32: u32,
}

#[derive(Debug)]
struct SeekPendingEntry {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    declared_size: Option<u64>,
    size: u64,
    crc: crate::filter::Crc32,
}

/// Payload-streaming 7z writer for seekable destinations.
///
/// Only entry metadata is retained. File bytes flow directly into one solid
/// LZMA2 folder; finish appends the next header and seeks back only to the
/// fixed 32-byte signature header.
pub(crate) struct SevenZSeekWriter<W: Write + Seek> {
    encoder: Option<lzma_rust2::Lzma2Writer<W>>,
    entries: Vec<SeekStoredEntry>,
    pending: Option<SeekPendingEntry>,
    limits: Limits,
    metadata_used: usize,
    decoded_total: u64,
    folder_crc: crate::filter::Crc32,
    archive_metadata: ArchiveMetadata,
}

impl<W: Write + Seek> std::fmt::Debug for SevenZSeekWriter<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SevenZSeekWriter")
            .field("entries", &self.entries.len())
            .field("pending", &self.pending.is_some())
            .field("decoded_total", &self.decoded_total)
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> SevenZSeekWriter<W> {
    pub(crate) fn new(mut output: W, limits: Limits) -> core::result::Result<Self, StreamError> {
        validate_dictionary(WRITER_DICT_SIZE, limits)?;
        output.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        output
            .write_all(&[0_u8; SIGNATURE_HEADER_SIZE])
            .map_err(StreamError::io)?;
        let options = lzma_rust2::Lzma2Options::with_preset(WRITER_PRESET);
        Ok(Self {
            encoder: Some(lzma_rust2::Lzma2Writer::new(output, options)),
            entries: Vec::new(),
            pending: None,
            limits,
            metadata_used: 0,
            decoded_total: 0,
            folder_crc: crate::filter::Crc32::new(),
            archive_metadata: ArchiveMetadata::new(),
        })
    }

    pub(crate) fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> core::result::Result<(), StreamError> {
        if self.pending.is_some() || !self.entries.is_empty() || self.decoded_total != 0 {
            return Err(seven_error(
                ErrorKind::Protocol,
                "7z archive metadata must be set before the first entry",
            ));
        }
        if metadata.volume_name().is_some()
            || metadata.comment().is_some()
            || metadata.extensions().iter().any(|extension| {
                !matches!(
                    extension.namespace(),
                    "7z-archive-property" | "7z-files-property"
                )
            })
        {
            return Err(seven_error(
                ErrorKind::Unsupported,
                "7z archive metadata contains an unrepresentable property",
            ));
        }
        let cost = metadata
            .extensions()
            .iter()
            .try_fold(
                core::mem::size_of::<ArchiveMetadata>(),
                |total, extension| {
                    total
                        .checked_add(extension.namespace().len())
                        .and_then(|value| value.checked_add(extension.key().len()))
                        .and_then(|value| value.checked_add(extension.value().len()))
                },
            )
            .ok_or_else(|| seven_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| self.metadata_used.saturating_add(cost) > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "7z archive metadata exceeds configured limit",
            ));
        }
        validate_archive_extensions(metadata.extensions())?;
        self.metadata_used = self
            .metadata_used
            .checked_add(cost)
            .ok_or_else(|| seven_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        self.archive_metadata = metadata.clone();
        Ok(())
    }

    pub(crate) fn start_entry(
        &mut self,
        metadata: &EntryMetadata,
    ) -> core::result::Result<(), StreamError> {
        if self.pending.is_some() {
            return Err(seven_error(
                ErrorKind::Protocol,
                "previous 7z entry is still open",
            ));
        }
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.entries.len() as u64 >= maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "entry count exceeds configured limit",
            ));
        }
        let mut name = metadata.path().as_bytes().to_vec();
        if metadata.kind() == EntryKind::Dir {
            while name.ends_with(b"/") {
                name.pop();
            }
        }
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| name.len() > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "entry path exceeds configured limit",
            ));
        }
        let accounted = name
            .len()
            .checked_add(core::mem::size_of::<SeekStoredEntry>())
            .ok_or_else(|| seven_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounted)
            .ok_or_else(|| seven_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| self.metadata_used > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "entry metadata exceeds configured limit",
            ));
        }
        self.pending = Some(SeekPendingEntry {
            name,
            kind: metadata.kind(),
            mode: metadata.mode().unwrap_or(match metadata.kind() {
                EntryKind::Dir => 0o755,
                _ => 0o644,
            }),
            mtime: metadata.times().modified,
            link_target: metadata
                .link_target()
                .map(|target| target.as_bytes().to_vec()),
            declared_size: metadata.size(),
            size: 0,
            crc: crate::filter::Crc32::new(),
        });
        Ok(())
    }

    pub(crate) fn write_data(&mut self, bytes: &[u8]) -> core::result::Result<(), StreamError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "7z data supplied outside an entry"))?;
        if pending.kind != EntryKind::File {
            return Err(seven_error(
                ErrorKind::Protocol,
                "only regular-file entries accept 7z payload commands",
            ));
        }
        let next_size = pending
            .size
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| seven_error(ErrorKind::Limit, "write size exceeds u64"))?,
            )
            .ok_or_else(|| seven_error(ErrorKind::Limit, "entry size overflow"))?;
        self.check_output_limits(next_size, bytes.len())?;
        self.encoder_mut()?
            .write_all(bytes)
            .map_err(seven_encode_error)?;
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "7z pending entry disappeared"))?;
        pending.crc.update(bytes);
        pending.size = next_size;
        self.folder_crc.update(bytes);
        self.decoded_total = self
            .decoded_total
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| seven_error(ErrorKind::Limit, "write size exceeds u64"))?,
            )
            .ok_or_else(|| seven_error(ErrorKind::Limit, "decoded total overflow"))?;
        Ok(())
    }

    pub(crate) fn end_entry(&mut self) -> core::result::Result<(), StreamError> {
        let mut pending = self
            .pending
            .take()
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "end_entry called without an entry"))?;
        if pending.kind == EntryKind::Symlink {
            let target = pending
                .link_target
                .take()
                .ok_or_else(|| seven_error(ErrorKind::Malformed, "symbolic link has no target"))?;
            let size = u64::try_from(target.len())
                .map_err(|_| seven_error(ErrorKind::Limit, "link target size exceeds u64"))?;
            self.check_output_limits(size, target.len())?;
            self.encoder_mut()?
                .write_all(&target)
                .map_err(seven_encode_error)?;
            pending.crc.update(&target);
            pending.size = size;
            self.folder_crc.update(&target);
            self.decoded_total += size;
        }
        if pending.kind == EntryKind::Dir && pending.size != 0 {
            return Err(seven_error(
                ErrorKind::Protocol,
                "directory entry carried payload",
            ));
        }
        if pending
            .declared_size
            .is_some_and(|declared| declared != pending.size)
        {
            return Err(seven_error(
                ErrorKind::Protocol,
                "7z entry size does not match its declared size",
            ));
        }
        let has_stream = pending.kind != EntryKind::Dir && pending.size != 0;
        self.entries.push(SeekStoredEntry {
            name: pending.name,
            kind: pending.kind,
            mode: pending.mode,
            mtime: pending.mtime,
            size: pending.size,
            has_stream,
            crc32: pending.crc.finalize(),
        });
        Ok(())
    }

    pub(crate) fn finish(mut self) -> core::result::Result<W, StreamError> {
        if self.pending.is_some() {
            return Err(seven_error(
                ErrorKind::Protocol,
                "7z entry is open at finish",
            ));
        }
        let encoder = self
            .encoder
            .take()
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "7z writer was already finalized"))?;
        let mut output = encoder.finish().map_err(seven_encode_error)?;
        let packed_end = output.stream_position().map_err(StreamError::io)?;
        let packed_size = packed_end
            .checked_sub(SIGNATURE_HEADER_SIZE as u64)
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "packed output position underflow"))?;
        let sub_sizes: Vec<u64> = self
            .entries
            .iter()
            .filter(|entry| entry.has_stream)
            .map(|entry| entry.size)
            .collect();
        let sub_crcs: Vec<u32> = self
            .entries
            .iter()
            .filter(|entry| entry.has_stream)
            .map(|entry| entry.crc32)
            .collect();
        let mut header = vec![K_HEADER];
        write_archive_properties(&mut header, self.archive_metadata.extensions())?;
        if !sub_sizes.is_empty() {
            header.push(K_MAIN_STREAMS_INFO);
            write_pack_info(&mut header, packed_size);
            write_unpack_info(
                &mut header,
                lzma2_dict_prop(WRITER_DICT_SIZE),
                self.decoded_total,
                self.folder_crc.finalize(),
            );
            write_substreams_info(&mut header, sub_sizes.len(), &sub_sizes, &sub_crcs);
            header.push(K_END);
        }
        write_seek_files_info(
            &mut header,
            &self.entries,
            self.archive_metadata.extensions(),
        )?;
        header.push(K_END);
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| header.len() > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "final 7z header exceeds metadata limit",
            ));
        }
        let header_crc = crate::filter::crc32(&header);
        output.write_all(&header).map_err(StreamError::io)?;
        let archive_end = output.stream_position().map_err(StreamError::io)?;
        let mut signature = [0_u8; SIGNATURE_HEADER_SIZE];
        signature[..6].copy_from_slice(&SIGNATURE);
        signature[7] = 4;
        signature[12..20].copy_from_slice(&packed_size.to_le_bytes());
        signature[20..28].copy_from_slice(
            &u64::try_from(header.len())
                .map_err(|_| seven_error(ErrorKind::Limit, "header size exceeds u64"))?
                .to_le_bytes(),
        );
        signature[28..32].copy_from_slice(&header_crc.to_le_bytes());
        let start_crc = crate::filter::crc32(&signature[12..32]);
        signature[8..12].copy_from_slice(&start_crc.to_le_bytes());
        output.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        output.write_all(&signature).map_err(StreamError::io)?;
        output
            .seek(SeekFrom::Start(archive_end))
            .map_err(StreamError::io)?;
        output.flush().map_err(StreamError::io)?;
        Ok(output)
    }

    pub(crate) fn abort(mut self) -> core::result::Result<W, StreamError> {
        self.encoder
            .take()
            .map(lzma_rust2::Lzma2Writer::into_inner)
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "7z writer is finalized"))
    }

    fn encoder_mut(
        &mut self,
    ) -> core::result::Result<&mut lzma_rust2::Lzma2Writer<W>, StreamError> {
        self.encoder
            .as_mut()
            .ok_or_else(|| seven_error(ErrorKind::Protocol, "7z writer is finalized"))
    }

    fn check_output_limits(
        &self,
        entry_size: u64,
        additional: usize,
    ) -> core::result::Result<(), StreamError> {
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| entry_size > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "entry exceeds configured size limit",
            ));
        }
        let total = self
            .decoded_total
            .checked_add(additional as u64)
            .ok_or_else(|| seven_error(ErrorKind::Limit, "decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| total > maximum)
        {
            return Err(seven_error(
                ErrorKind::Limit,
                "decoded total exceeds configured limit",
            ));
        }
        Ok(())
    }
}

fn write_seek_files_info(
    header: &mut Vec<u8>,
    entries: &[SeekStoredEntry],
    extensions: &[Extension],
) -> core::result::Result<(), StreamError> {
    header.push(K_FILES_INFO);
    write_number(header, entries.len() as u64);
    let empty_stream: Vec<bool> = entries.iter().map(|entry| !entry.has_stream).collect();
    if empty_stream.iter().any(|value| *value) {
        let mut body = Vec::new();
        write_bit_vector(&mut body, &empty_stream);
        header.push(K_EMPTY_STREAM);
        write_number(header, body.len() as u64);
        header.extend_from_slice(&body);
        let empty_file: Vec<bool> = entries
            .iter()
            .filter(|entry| !entry.has_stream)
            .map(|entry| entry.kind != EntryKind::Dir)
            .collect();
        if empty_file.iter().any(|value| *value) {
            let mut body = Vec::new();
            write_bit_vector(&mut body, &empty_file);
            header.push(K_EMPTY_FILE);
            write_number(header, body.len() as u64);
            header.extend_from_slice(&body);
        }
    }
    let mut names = vec![0];
    for entry in entries {
        bytes_to_utf16le(&entry.name, &mut names);
    }
    header.push(K_NAME);
    write_number(header, names.len() as u64);
    header.extend_from_slice(&names);
    let mut attributes = vec![1, 0];
    for entry in entries {
        attributes.extend_from_slice(&windows_attributes(entry.kind, entry.mode).to_le_bytes());
    }
    header.push(K_WIN_ATTRIBUTES);
    write_number(header, attributes.len() as u64);
    header.extend_from_slice(&attributes);
    let defined: Vec<bool> = entries.iter().map(|entry| entry.mtime.is_some()).collect();
    if defined.iter().any(|value| *value) {
        let mut times = Vec::new();
        if defined.iter().all(|value| *value) {
            times.push(1);
        } else {
            times.push(0);
            write_bit_vector(&mut times, &defined);
        }
        times.push(0);
        for entry in entries {
            if let Some(timestamp) = entry.mtime {
                times.extend_from_slice(&timestamp_to_filetime(timestamp).to_le_bytes());
            }
        }
        header.push(K_MTIME);
        write_number(header, times.len() as u64);
        header.extend_from_slice(&times);
    }
    for extension in extensions
        .iter()
        .filter(|extension| extension.namespace() == "7z-files-property")
    {
        let key: [u8; 8] = extension.key().try_into().map_err(|_| {
            seven_error(
                ErrorKind::Malformed,
                "preserved 7z file property has an invalid key",
            )
        })?;
        let property = u64::from_le_bytes(key);
        if matches!(
            u8::try_from(property),
            Ok(K_EMPTY_STREAM
                | K_EMPTY_FILE
                | K_ANTI
                | K_NAME
                | K_CTIME
                | K_ATIME
                | K_MTIME
                | K_WIN_ATTRIBUTES
                | K_START_POS)
        ) {
            continue;
        }
        write_number(header, property);
        write_number(header, extension.value().len() as u64);
        header.extend_from_slice(extension.value());
    }
    header.push(K_END);
    Ok(())
}

fn validate_archive_extensions(extensions: &[Extension]) -> core::result::Result<(), StreamError> {
    for extension in extensions {
        match extension.namespace() {
            "7z-archive-property" if extension.key().len() == 1 => {},
            "7z-files-property" if extension.key().len() == 8 => {},
            "7z-archive-property" | "7z-files-property" => {
                return Err(seven_error(
                    ErrorKind::Malformed,
                    "preserved 7z property has an invalid key",
                ));
            },
            _ => {},
        }
    }
    Ok(())
}

fn write_archive_properties(
    header: &mut Vec<u8>,
    extensions: &[Extension],
) -> core::result::Result<(), StreamError> {
    let properties: Vec<_> = extensions
        .iter()
        .filter(|extension| extension.namespace() == "7z-archive-property")
        .collect();
    if properties.is_empty() {
        return Ok(());
    }
    header.push(K_ARCHIVE_PROPERTIES);
    for extension in properties {
        let property = *extension.key().first().ok_or_else(|| {
            seven_error(
                ErrorKind::Malformed,
                "preserved 7z archive property has no id",
            )
        })?;
        header.push(property);
        write_number(header, extension.value().len() as u64);
        header.extend_from_slice(extension.value());
    }
    header.push(K_END);
    Ok(())
}

fn seven_encode_error(error: std::io::Error) -> StreamError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        seven_error(ErrorKind::Malformed, "LZMA2 encoder failed")
    } else {
        StreamError::io(error)
    }
}

/// Emits a `PackInfo` block for a single pack stream at pack position 0.
fn write_pack_info(header: &mut Vec<u8>, pack_size: u64) {
    header.push(K_PACK_INFO);
    write_number(header, 0); // PackPos (relative to the end of the signature header)
    write_number(header, 1); // NumPackStreams
    header.push(K_SIZE);
    write_number(header, pack_size);
    header.push(K_END);
}

/// Emits an `UnpackInfo` block for a single LZMA2 folder with a known CRC.
fn write_unpack_info(header: &mut Vec<u8>, dict_prop: u8, unpack_size: u64, folder_crc: u32) {
    header.push(K_UNPACK_INFO);
    header.push(K_FOLDER);
    write_number(header, 1); // NumFolders
    header.push(0); // External = 0
    // One coder: flags = idSize(1) | kAttributes(0x20) = 0x21; codec id = LZMA2 (0x21); 1 prop byte.
    write_number(header, 1); // NumCoders
    header.push(0x21);
    header.push(METHOD_LZMA2);
    write_number(header, 1); // property size
    header.push(dict_prop);
    header.push(K_CODERS_UNPACK_SIZE);
    write_number(header, unpack_size);
    header.push(K_CRC);
    header.push(1); // AllAreDefined
    header.extend_from_slice(&folder_crc.to_le_bytes());
    header.push(K_END);
}

/// Emits a `SubStreamsInfo` block for the single folder's content substreams.
fn write_substreams_info(header: &mut Vec<u8>, num: usize, sizes: &[u64], crcs: &[u32]) {
    header.push(K_SUBSTREAMS_INFO);
    header.push(K_NUM_UNPACK_STREAM);
    write_number(header, num as u64);
    if num > 1 {
        header.push(K_SIZE);
        // Sizes for all but the last substream; the last is derived from the folder size.
        for &s in &sizes[..num - 1] {
            write_number(header, s);
        }
        // Per-substream CRCs (the single-substream case reuses the folder CRC and is omitted).
        header.push(K_CRC);
        header.push(1); // AllAreDefined
        for &c in crcs {
            header.extend_from_slice(&c.to_le_bytes());
        }
    }
    header.push(K_END);
}

/// Computes a 7z `WinAttributes` word carrying the directory bit and the Unix mode extension.
fn windows_attributes(kind: EntryKind, mode: u32) -> u32 {
    let type_bits = match kind {
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        _ => 0o100_000,
    };
    let unix = type_bits | (mode & 0o7777);
    let mut attr = ATTR_UNIX_EXTENSION | (unix << 16);
    if kind == EntryKind::Dir {
        attr |= ATTR_DIRECTORY;
    }
    attr
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// LZMA2 glue
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Decodes an LZMA2 dictionary-size property byte into a dictionary size in bytes.
///
/// `dict_size = (2 | (p & 1)) << (p / 2 + 11)`, with `40` reserved for `u32::MAX`.
fn lzma2_dict_size(prop: u8) -> Result<u32> {
    if prop > 40 {
        return Err(HeaderError::Unsupported(
            "7z: invalid LZMA2 dictionary property",
        ));
    }
    if prop == 40 {
        return Ok(u32::MAX);
    }
    let base = 2 | u32::from(prop & 1);
    let shift = u32::from(prop) / 2 + 11;
    Ok(base << shift)
}

/// Encodes a dictionary size into the smallest LZMA2 property byte whose size is `>= dict`.
fn lzma2_dict_prop(dict: u32) -> u8 {
    if dict == u32::MAX {
        return 40;
    }
    let mut prop = 0u8;
    while prop < 40 {
        if lzma2_dict_size(prop).is_ok_and(|d| d >= dict) {
            break;
        }
        prop += 1;
    }
    prop
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// 7z number / bit-vector / time / name primitives
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A bounds-checked cursor over a byte slice for parsing the 7z header grammar.
struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(HeaderError::Malformed("7z: unexpected end of header"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Number of unconsumed bytes — an upper bound on how much more this reader can yield.
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(HeaderError::Malformed("7z: header length overflow"))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(HeaderError::Malformed("7z: truncated header field"))?;
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a 7z variable-length number (`ReadNumber`).
    fn number(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let mut value = 0u64;
        let mut mask = 0x80u8;
        for i in 0..8u32 {
            if first & mask == 0 {
                value |= u64::from(first & (mask.wrapping_sub(1))) << (8 * i);
                return Ok(value);
            }
            value |= u64::from(self.u8()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// Reads `n` bits (MSB-first) into a boolean vector, consuming `ceil(n/8)` bytes.
    fn bit_vector(&mut self, n: usize) -> Result<Vec<bool>> {
        let mut bits = Vec::with_capacity(n);
        let mut cur = 0u8;
        let mut mask = 0u8;
        for _ in 0..n {
            if mask == 0 {
                cur = self.u8()?;
                mask = 0x80;
            }
            bits.push(cur & mask != 0);
            mask >>= 1;
        }
        Ok(bits)
    }
}

/// Writes a 7z variable-length number (`WriteNumber`).
///
/// Each `as u8` cast retains the low byte required by the encoding.
#[allow(clippy::cast_possible_truncation)]
fn write_number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0u32;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    let mut v = value;
    for _ in 0..i {
        out.push(v as u8);
        v >>= 8;
    }
}

/// Writes an MSB-first bit vector, emitting `ceil(bits.len()/8)` bytes.
fn write_bit_vector(out: &mut Vec<u8>, bits: &[bool]) {
    let mut cur = 0u8;
    let mut mask = 0x80u8;
    for &bit in bits {
        if bit {
            cur |= mask;
        }
        mask >>= 1;
        if mask == 0 {
            out.push(cur);
            cur = 0;
            mask = 0x80;
        }
    }
    if mask != 0x80 {
        out.push(cur);
    }
}

/// Converts a Unix timestamp to a Windows `FILETIME` (100-ns ticks since 1601-01-01).
fn timestamp_to_filetime(ts: Timestamp) -> u64 {
    let secs = ts.secs.saturating_add(FILETIME_EPOCH_DIFF);
    let ticks = secs
        .saturating_mul(10_000_000)
        .saturating_add(i64::from(ts.nanos / 100));
    u64::try_from(ticks).unwrap_or(0)
}

/// Converts a Windows `FILETIME` to a Unix [`Timestamp`].
fn filetime_to_timestamp(ft: u64) -> Timestamp {
    let ticks = i64::try_from(ft).unwrap_or(i64::MAX);
    let secs = ticks.div_euclid(10_000_000) - FILETIME_EPOCH_DIFF;
    let rem = ticks.rem_euclid(10_000_000);
    Timestamp {
        secs,
        nanos: u32::try_from(rem).unwrap_or(0).saturating_mul(100),
    }
}

/// Decodes null-stripped UTF-16LE code units into raw UTF-8 bytes (lossy for unpaired surrogates).
fn utf16le_to_bytes(raw: &[u8]) -> Vec<u8> {
    let units = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    let s: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    s.into_bytes()
}

/// Encodes `name` (interpreted as UTF-8) as null-terminated UTF-16LE code units.
fn bytes_to_utf16le(name: &[u8], out: &mut Vec<u8>) {
    for unit in String::from_utf8_lossy(name).encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

// ── Little-endian slice readers over the fixed signature header ──────────────────────────────────

/// Reads a little-endian `u32` at `off` within `data`.
fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(HeaderError::Malformed("7z: truncated signature field"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a little-endian `u64` at `off` within `data`.
fn u64_le(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or(HeaderError::Malformed("7z: truncated signature field"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// `u64` to `usize`, mapped to a limit error where it would truncate (32-bit hosts).
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| HeaderError::LimitExceeded("7z: value exceeds usize"))
}
