// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seek-capable streaming archive adapters.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, Device, EntryKind, EntryMetadata, EntryTimes,
    ErrorKind, Extension, FormatId, Limits, Owner, PathEncoding, Timestamp,
};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

#[cfg(feature = "zstd")]
use libarchive_oxide_core::filter::FilterId;
#[cfg(feature = "zstd")]
use libarchive_oxide_core::{CodecStatus, EndOfInput};

use crate::filter::gzip::Crc32;
use crate::{ArchiveWriter, ReaderEvent, SecretBytes, StreamError};

const BUFFER: usize = 64 * 1024;
const EOCD_MIN: usize = 22;
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;
const ZIP64_LOCATOR: usize = 20;
const ISO_SECTOR: u64 = 2048;
const ISO_SECTOR_USIZE: usize = 2048;
const ISO_SECTOR_U16: u16 = 2048;
const ISO_DESCRIPTOR_START: u64 = 16;
const ISO_MAX_DESCRIPTORS: u64 = 64;
const ISO_DIRECTORY_RECORD_BASE: usize = 33;
const ISO_DIRECTORY_FLAG: u8 = 0x02;

#[cfg(feature = "aes")]
struct ZipAesDecoder {
    cipher: ctr::Ctr128LE<aes::Aes256>,
    mac: hmac::Hmac<sha1::Sha1>,
}

#[cfg(feature = "aes")]
impl std::fmt::Debug for ZipAesDecoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ZipAesDecoder([REDACTED])")
    }
}

#[cfg(feature = "aes")]
impl ZipAesDecoder {
    fn new(password: &[u8], salt: [u8; 16], verifier: [u8; 2]) -> Result<Self, StreamError> {
        use ctr::cipher::KeyIvInit;
        use hmac::digest::KeyInit;
        use subtle::ConstantTimeEq;
        use zeroize::Zeroize;

        let mut key_material = [0_u8; 66];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt, 1_000, &mut key_material);
        if key_material[64..].ct_eq(&verifier).unwrap_u8() != 1 {
            key_material.zeroize();
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Integrity)
                    .with_format("zip")
                    .with_context("WinZip AES password verifier mismatch"),
            ));
        }
        let mut initial_counter = [0_u8; 16];
        initial_counter[0] = 1;
        let cipher =
            ctr::Ctr128LE::<aes::Aes256>::new_from_slices(&key_material[..32], &initial_counter)
                .map_err(|_| {
                    StreamError::archive(
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("zip")
                            .with_context("WinZip AES cipher initialization failed"),
                    )
                })?;
        let mac = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&key_material[32..64])
            .map_err(|_| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("WinZip AES MAC initialization failed"),
                )
            })?;
        key_material.zeroize();
        Ok(Self { cipher, mac })
    }

    fn decrypt(&mut self, bytes: &mut [u8]) {
        use ctr::cipher::StreamCipher;
        use hmac::Mac;

        self.mac.update(bytes);
        self.cipher.apply_keystream(bytes);
    }

    fn verify(&self, expected: [u8; 10]) -> Result<(), StreamError> {
        use hmac::Mac;
        use subtle::ConstantTimeEq;

        let actual = self.mac.clone().finalize().into_bytes();
        if actual[..10].ct_eq(&expected).unwrap_u8() != 1 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Integrity)
                    .with_format("zip")
                    .with_context("WinZip AES authentication failed"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ZipIndex {
    metadata: EntryMetadata,
    raw_name: Vec<u8>,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    aes_real_method: Option<u16>,
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    aes_strength: Option<u8>,
}

#[derive(Debug, Clone)]
struct IsoIndex {
    metadata: EntryMetadata,
    data_offset: u64,
    size: u64,
}

#[derive(Debug, Clone)]
enum IndexedEntry {
    Zip(ZipIndex),
    Iso(IsoIndex),
}

enum ZipBody {
    Idle,
    Stored {
        remaining: u64,
        expected_crc: u32,
        crc: Crc32,
        end_offset: u64,
    },
    Deflate {
        compressed_unread: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        inflate: Box<InflateState>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "bzip2")]
    Bzip2 {
        compressed_unread: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        decompress: Box<bzip2::Decompress>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "zstd")]
    Zstd {
        compressed_unread: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        decoder: Box<crate::pipeline_codec::PipelineCodec>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "aes")]
    AesStored {
        encrypted_remaining: u64,
        decoder: ZipAesDecoder,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "aes")]
    AesDeflate {
        encrypted_remaining: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        decoder: ZipAesDecoder,
        inflate: Box<InflateState>,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    Unsupported {
        method: u16,
        end_offset: u64,
    },
    Raw {
        remaining: u64,
        end_offset: u64,
    },
    EndEntry,
    Done,
}

impl std::fmt::Debug for ZipBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let phase = match self {
            Self::Idle => "Idle",
            Self::Stored { .. } => "Stored",
            Self::Deflate { .. } => "Deflate",
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { .. } => "Bzip2",
            #[cfg(feature = "zstd")]
            Self::Zstd { .. } => "Zstd",
            #[cfg(feature = "aes")]
            Self::AesStored { .. } => "AesStored",
            #[cfg(feature = "aes")]
            Self::AesDeflate { .. } => "AesDeflate",
            Self::Unsupported { .. } => "Unsupported",
            Self::Raw { .. } => "Raw",
            Self::EndEntry => "EndEntry",
            Self::Done => "Done",
        };
        f.debug_tuple("ZipBody").field(&phase).finish()
    }
}

#[derive(Debug)]
enum SeekDispatch<R> {
    Indexed(Box<IndexedArchiveReader<R>>),
    #[cfg(feature = "sevenz")]
    SevenZ(Box<crate::sevenz::SevenZSeekReader<R>>),
}

/// Seek-capable archive reader.
///
/// ZIP central directories, 7z file/folder metadata, and ISO directory
/// indexes are retained within the configured metadata budget. File payloads
/// are streamed from their extents or solid-folder decoder.
#[derive(Debug)]
pub struct SeekArchiveReader<R> {
    inner: SeekDispatch<R>,
}

impl<R: Read + Seek> SeekArchiveReader<R> {
    /// Opens a seek-required archive with safe default limits.
    pub fn new(input: R) -> Result<Self, StreamError> {
        Self::with_limits(input, Limits::default())
    }

    /// Opens a seek-required archive with explicit limits.
    pub fn with_limits(input: R, limits: Limits) -> Result<Self, StreamError> {
        Self::open(input, limits, None)
    }

    /// Opens an archive with a zeroizing password for authenticated ZIP entries.
    pub fn with_password(input: R, password: SecretBytes) -> Result<Self, StreamError> {
        Self::open(input, Limits::default(), Some(password))
    }

    /// Opens an archive with explicit limits and a zeroizing password.
    pub fn with_limits_and_password(
        input: R,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        Self::open(input, limits, Some(password))
    }

    fn open(
        mut input: R,
        limits: Limits,
        password: Option<SecretBytes>,
    ) -> Result<Self, StreamError> {
        let mut signature = [0_u8; 6];
        let read = read_prefix(&mut input, &mut signature)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        if read == signature.len() && signature == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
            #[cfg(feature = "sevenz")]
            {
                return Ok(Self {
                    inner: SeekDispatch::SevenZ(Box::new(crate::sevenz::SevenZSeekReader::new(
                        input, limits,
                    )?)),
                });
            }
            #[cfg(not(feature = "sevenz"))]
            {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("7z")
                        .with_context("7z support is disabled"),
                ));
            }
        }
        Ok(Self {
            inner: SeekDispatch::Indexed(Box::new(IndexedArchiveReader::with_options(
                input, limits, password,
            )?)),
        })
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match &mut self.inner {
            SeekDispatch::Indexed(reader) => reader.next_event(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.next_event(),
        }
    }

    /// Skips the current payload while preserving solid-stream decoder state.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekDispatch::Indexed(reader) => reader.skip_entry(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.skip_entry(),
        }
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        match &self.inner {
            SeekDispatch::Indexed(reader) => reader.format(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(_) => FormatId::SevenZip,
        }
    }

    /// Returns the underlying seekable source.
    #[must_use]
    pub fn into_inner(self) -> R {
        match self.inner {
            SeekDispatch::Indexed(reader) => reader.into_inner(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.into_inner(),
        }
    }

    pub(crate) fn source_ref(&self) -> &R {
        match &self.inner {
            SeekDispatch::Indexed(reader) => reader.source_ref(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.source_ref(),
        }
    }
}

#[derive(Debug)]
enum SeekWriterDispatch<W: Write + Seek> {
    Sequential(Box<ArchiveWriter<W>>),
    Iso(Box<crate::iso_stream::IsoSeekWriter<W>>),
    #[cfg(feature = "sevenz")]
    SevenZ(Box<crate::sevenz::SevenZSeekWriter<W>>),
}

/// Archive writer for destinations with `Write + Seek`.
///
/// Sequential formats reuse [`ArchiveWriter`]. Seek-native formats may retain
/// bounded metadata indexes and backpatch structural headers, but never retain
/// regular-file payloads.
#[derive(Debug)]
pub struct SeekArchiveWriter<W: Write + Seek> {
    inner: SeekWriterDispatch<W>,
    format: FormatId,
}

impl<W: Write + Seek> SeekArchiveWriter<W> {
    /// Creates a writer for one built-in format with explicit limits.
    pub fn with_format(output: W, format: FormatId, limits: Limits) -> Result<Self, StreamError> {
        let inner = match format {
            FormatId::Tar | FormatId::Cpio | FormatId::Ar | FormatId::Zip => {
                SeekWriterDispatch::Sequential(Box::new(
                    ArchiveWriter::with_format_and_limits(output, format, limits)
                        .map_err(StreamError::archive)?,
                ))
            },
            FormatId::SevenZip => {
                #[cfg(feature = "sevenz")]
                {
                    SeekWriterDispatch::SevenZ(Box::new(crate::sevenz::SevenZSeekWriter::new(
                        output, limits,
                    )?))
                }
                #[cfg(not(feature = "sevenz"))]
                {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Unsupported)
                            .with_format("7z")
                            .with_context("7z support is disabled"),
                    ));
                }
            },
            FormatId::Iso9660 => SeekWriterDispatch::Iso(Box::new(
                crate::iso_stream::IsoSeekWriter::new(output, limits)?,
            )),
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Unsupported)
                        .with_context("unknown archive format"),
                ));
            },
        };
        Ok(Self { inner, format })
    }

    /// Sets archive-level metadata before the first entry.
    pub fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.set_archive_metadata(metadata),
            SeekWriterDispatch::Iso(writer) => writer.set_archive_metadata(metadata),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.set_archive_metadata(metadata),
        }
    }

    /// Begins one entry.
    pub fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.start_entry(metadata),
            SeekWriterDispatch::Iso(writer) => writer.start_entry(metadata),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.start_entry(metadata),
        }
    }

    /// Writes entry bytes without retaining them in the writer.
    pub fn write_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.write_data(bytes),
            SeekWriterDispatch::Iso(writer) => writer.write_data(bytes),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.write_data(bytes),
        }
    }

    /// Ends the current entry.
    pub fn end_entry(&mut self) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.end_entry(),
            SeekWriterDispatch::Iso(writer) => writer.end_entry(),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.end_entry(),
        }
    }

    /// Finalizes the archive and returns its destination.
    pub fn finish(self) -> Result<W, StreamError> {
        match self.inner {
            SeekWriterDispatch::Sequential(writer) => (*writer).finish(),
            SeekWriterDispatch::Iso(writer) => (*writer).finish(),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => (*writer).finish(),
        }
    }

    /// Abandons the archive without writing its terminal metadata.
    pub fn abort(self) -> Result<W, StreamError> {
        match self.inner {
            SeekWriterDispatch::Sequential(writer) => (*writer).abort(),
            SeekWriterDispatch::Iso(writer) => Ok((*writer).abort()),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => (*writer).abort(),
        }
    }

    /// Output archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }
}

#[derive(Debug)]
struct IndexedArchiveReader<R> {
    input: R,
    limits: Limits,
    format: FormatId,
    archive_metadata: Option<ArchiveMetadata>,
    entries: Vec<IndexedEntry>,
    next_entry: usize,
    body: ZipBody,
    event_data: Vec<u8>,
    decoded_total: u64,
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    password: Option<SecretBytes>,
}

impl<R: Read + Seek> IndexedArchiveReader<R> {
    fn with_options(
        mut input: R,
        limits: Limits,
        password: Option<SecretBytes>,
    ) -> Result<Self, StreamError> {
        let mut signature = [0_u8; 6];
        let read = read_prefix(&mut input, &mut signature)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        if read >= 4 && (&signature[..4] == b"PK\x03\x04" || &signature[..4] == b"PK\x05\x06") {
            let (archive_metadata, entries) = parse_zip_index(&mut input, limits)?;
            return Ok(Self {
                input,
                limits,
                format: FormatId::Zip,
                archive_metadata: Some(archive_metadata),
                entries: entries.into_iter().map(IndexedEntry::Zip).collect(),
                next_entry: 0,
                body: ZipBody::Idle,
                event_data: Vec::with_capacity(BUFFER),
                decoded_total: 0,
                password,
            });
        }
        if read == 6 && signature == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("7z")
                    .with_context("incremental 7z seek driver is not available"),
            ));
        }
        input
            .seek(SeekFrom::Start(ISO_DESCRIPTOR_START * ISO_SECTOR + 1))
            .map_err(StreamError::io)?;
        let mut iso_signature = [0_u8; 5];
        let iso_read = read_prefix(&mut input, &mut iso_signature)?;
        if iso_read == iso_signature.len() && &iso_signature == b"CD001" {
            let (archive_metadata, entries) = parse_iso_index(&mut input, limits)?;
            return Ok(Self {
                input,
                limits,
                format: FormatId::Iso9660,
                archive_metadata: Some(archive_metadata),
                entries: entries.into_iter().map(IndexedEntry::Iso).collect(),
                next_entry: 0,
                body: ZipBody::Idle,
                event_data: Vec::with_capacity(BUFFER),
                decoded_total: 0,
                password,
            });
        }
        Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Unsupported)
                .with_context("no seek-capable archive format matched"),
        ))
    }

    /// Produces the next archive event.
    #[allow(clippy::too_many_lines)]
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        if let Some(metadata) = self.archive_metadata.take() {
            return Ok(ReaderEvent::ArchiveMetadata(metadata));
        }
        loop {
            match &mut self.body {
                ZipBody::Idle => {
                    let Some(entry) = self.entries.get(self.next_entry).cloned() else {
                        self.body = ZipBody::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    let metadata = match entry {
                        IndexedEntry::Zip(entry) => {
                            self.prepare_zip_body(&entry)?;
                            entry.metadata
                        },
                        IndexedEntry::Iso(entry) => {
                            self.prepare_iso_body(&entry)?;
                            entry.metadata
                        },
                    };
                    self.next_entry += 1;
                    return Ok(ReaderEvent::Entry(metadata));
                },
                ZipBody::Stored {
                    remaining,
                    expected_crc,
                    crc,
                    ..
                } => {
                    if *remaining == 0 {
                        if crc.finalize() != *expected_crc {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("stored entry CRC32 mismatch"),
                            ));
                        }
                        self.body = ZipBody::EndEntry;
                        continue;
                    }
                    let count = usize::try_from((*remaining).min(BUFFER as u64)).map_err(|_| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("stored read size exceeds address space"),
                        )
                    })?;
                    self.event_data.resize(count, 0);
                    self.input
                        .read_exact(&mut self.event_data)
                        .map_err(StreamError::io)?;
                    crc.update(&self.event_data);
                    *remaining -= count as u64;
                    self.account_decoded(count)?;
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                ZipBody::Deflate {
                    compressed_unread,
                    compressed,
                    compressed_start,
                    inflate: state,
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *compressed_start == compressed.len() && *compressed_unread != 0 {
                        let count = usize::try_from((*compressed_unread).min(BUFFER as u64))
                            .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("compressed read size exceeds address space"),
                                )
                            })?;
                        let mut next = vec![0; count];
                        self.input.read_exact(&mut next).map_err(StreamError::io)?;
                        *compressed = next;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let result = inflate(
                        state,
                        &compressed[*compressed_start..],
                        &mut self.event_data,
                        if *compressed_start == compressed.len() && *compressed_unread == 0 {
                            MZFlush::Finish
                        } else {
                            MZFlush::None
                        },
                    );
                    *compressed_start += result.bytes_consumed;
                    self.event_data.truncate(result.bytes_written);
                    crc.update(&self.event_data);
                    *produced = produced
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("deflate output count overflow"),
                            )
                        })?;
                    let next_total = self
                        .decoded_total
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("decoded total overflow"),
                            )
                        })?;
                    if self
                        .limits
                        .decoded_total()
                        .is_some_and(|limit| next_total > limit)
                    {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("decoded total exceeds configured limit"),
                        ));
                    }
                    self.decoded_total = next_total;
                    match result.status {
                        Ok(MZStatus::StreamEnd) => {
                            if *produced != *expected_size {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(
                                            "deflate size does not match central directory",
                                        ),
                                ));
                            }
                            if crc.finalize() != *expected_crc {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context("deflate entry CRC32 mismatch"),
                                ));
                            }
                            self.body = ZipBody::EndEntry;
                        },
                        Ok(_) => {
                            if result.bytes_consumed == 0
                                && result.bytes_written == 0
                                && *compressed_unread == 0
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated deflate stream"),
                                ));
                            }
                        },
                        Err(_) => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("deflate decoder failed"),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "bzip2")]
                ZipBody::Bzip2 {
                    compressed_unread,
                    compressed,
                    compressed_start,
                    decompress: state,
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *compressed_start == compressed.len() && *compressed_unread != 0 {
                        let count = usize::try_from((*compressed_unread).min(BUFFER as u64))
                            .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("compressed read size exceeds address space"),
                                )
                            })?;
                        let mut next = vec![0; count];
                        self.input.read_exact(&mut next).map_err(StreamError::io)?;
                        *compressed = next;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let before_in = state.total_in();
                    let before_out = state.total_out();
                    let status = state
                        .decompress(&compressed[*compressed_start..], &mut self.event_data)
                        .map_err(|_| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("bzip2 decoder failed"),
                            )
                        })?;
                    if matches!(status, bzip2::Status::MemNeeded) {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Malformed)
                                .with_format("zip")
                                .with_context("bzip2 decoder ran out of memory"),
                        ));
                    }
                    let consumed = usize::try_from(state.total_in() - before_in).map_err(|_| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("bzip2 consumed count exceeds address space"),
                        )
                    })?;
                    let written =
                        usize::try_from(state.total_out() - before_out).map_err(|_| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("bzip2 output count exceeds address space"),
                            )
                        })?;
                    *compressed_start += consumed;
                    self.event_data.truncate(written);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(written as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("bzip2 output count overflow"),
                        )
                    })?;
                    let next_total =
                        self.decoded_total
                            .checked_add(written as u64)
                            .ok_or_else(|| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("decoded total overflow"),
                                )
                            })?;
                    if self
                        .limits
                        .decoded_total()
                        .is_some_and(|limit| next_total > limit)
                    {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("decoded total exceeds configured limit"),
                        ));
                    }
                    self.decoded_total = next_total;
                    match status {
                        bzip2::Status::StreamEnd => {
                            if *produced != *expected_size {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(
                                            "bzip2 size does not match central directory",
                                        ),
                                ));
                            }
                            if crc.finalize() != *expected_crc {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context("bzip2 entry CRC32 mismatch"),
                                ));
                            }
                            self.body = ZipBody::EndEntry;
                        },
                        _ => {
                            if consumed == 0 && written == 0 && *compressed_unread == 0 {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated bzip2 stream"),
                                ));
                            }
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "zstd")]
                ZipBody::Zstd {
                    compressed_unread,
                    compressed,
                    compressed_start,
                    decoder,
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *compressed_start == compressed.len() && *compressed_unread != 0 {
                        let count = usize::try_from((*compressed_unread).min(BUFFER as u64))
                            .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("compressed read size exceeds address space"),
                                )
                            })?;
                        let mut next = vec![0; count];
                        self.input.read_exact(&mut next).map_err(StreamError::io)?;
                        *compressed = next;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let end = if *compressed_unread == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = decoder
                        .process(&compressed[*compressed_start..], &mut self.event_data, end)
                        .map_err(StreamError::archive)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("zstd output count overflow"),
                        )
                    })?;
                    let next_total = self
                        .decoded_total
                        .checked_add(step.produced as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("decoded total overflow"),
                            )
                        })?;
                    if self
                        .limits
                        .decoded_total()
                        .is_some_and(|limit| next_total > limit)
                    {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("decoded total exceeds configured limit"),
                        ));
                    }
                    self.decoded_total = next_total;
                    if matches!(step.status, CodecStatus::Done) {
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("zstd size does not match central directory"),
                            ));
                        }
                        if crc.finalize() != *expected_crc {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("zstd entry CRC32 mismatch"),
                            ));
                        }
                        self.body = ZipBody::EndEntry;
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "aes")]
                ZipBody::AesStored {
                    encrypted_remaining,
                    decoder,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *encrypted_remaining == 0 {
                        let mut authentication = [0_u8; 10];
                        self.input
                            .read_exact(&mut authentication)
                            .map_err(StreamError::io)?;
                        decoder.verify(authentication)?;
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context(
                                        "AES stored size does not match central directory",
                                    ),
                            ));
                        }
                        self.body = ZipBody::EndEntry;
                        continue;
                    }
                    let count = usize::try_from((*encrypted_remaining).min(BUFFER as u64))
                        .map_err(|_| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("AES stored read size exceeds address space"),
                            )
                        })?;
                    self.event_data.resize(count, 0);
                    self.input
                        .read_exact(&mut self.event_data)
                        .map_err(StreamError::io)?;
                    decoder.decrypt(&mut self.event_data);
                    *encrypted_remaining -= count as u64;
                    *produced = produced.checked_add(count as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("AES stored output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("AES stored payload exceeds declared size"),
                        ));
                    }
                    self.account_decoded(count)?;
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                #[cfg(feature = "aes")]
                ZipBody::AesDeflate {
                    encrypted_remaining,
                    compressed,
                    compressed_start,
                    decoder,
                    inflate: state,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *compressed_start == compressed.len() && *encrypted_remaining != 0 {
                        let count = usize::try_from((*encrypted_remaining).min(BUFFER as u64))
                            .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context(
                                            "AES deflate read size exceeds address space",
                                        ),
                                )
                            })?;
                        let mut next = vec![0; count];
                        self.input.read_exact(&mut next).map_err(StreamError::io)?;
                        decoder.decrypt(&mut next);
                        *compressed = next;
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let result = inflate(
                        state,
                        &compressed[*compressed_start..],
                        &mut self.event_data,
                        if *compressed_start == compressed.len() && *encrypted_remaining == 0 {
                            MZFlush::Finish
                        } else {
                            MZFlush::None
                        },
                    );
                    *compressed_start += result.bytes_consumed;
                    self.event_data.truncate(result.bytes_written);
                    *produced = produced
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("AES deflate output count overflow"),
                            )
                        })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("AES deflate payload exceeds declared size"),
                        ));
                    }
                    let next_total = self
                        .decoded_total
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("decoded total overflow"),
                            )
                        })?;
                    if self
                        .limits
                        .decoded_total()
                        .is_some_and(|limit| next_total > limit)
                    {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("decoded total exceeds configured limit"),
                        ));
                    }
                    self.decoded_total = next_total;
                    match result.status {
                        Ok(MZStatus::StreamEnd) => {
                            if *compressed_start != compressed.len()
                                || *encrypted_remaining != 0
                                || *produced != *expected_size
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(
                                            "AES deflate extent disagrees with central directory",
                                        ),
                                ));
                            }
                            let mut authentication = [0_u8; 10];
                            self.input
                                .read_exact(&mut authentication)
                                .map_err(StreamError::io)?;
                            decoder.verify(authentication)?;
                            self.body = ZipBody::EndEntry;
                        },
                        Ok(_) => {
                            if result.bytes_consumed == 0
                                && result.bytes_written == 0
                                && *encrypted_remaining == 0
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated AES deflate stream"),
                                ));
                            }
                        },
                        Err(_) => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("AES deflate decoder failed"),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                ZipBody::Unsupported { method, .. } => {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Unsupported)
                            .with_format("zip")
                            .with_context(format!("payload coder {method} is unsupported")),
                    ));
                },
                ZipBody::Raw { remaining, .. } => {
                    if *remaining == 0 {
                        self.body = ZipBody::EndEntry;
                        continue;
                    }
                    let count = usize::try_from((*remaining).min(BUFFER as u64)).map_err(|_| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("iso9660")
                                .with_context("extent read size exceeds address space"),
                        )
                    })?;
                    self.event_data.resize(count, 0);
                    self.input
                        .read_exact(&mut self.event_data)
                        .map_err(StreamError::io)?;
                    *remaining -= count as u64;
                    self.account_decoded(count)?;
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                ZipBody::EndEntry => {
                    self.body = ZipBody::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                ZipBody::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    /// Skips the current payload, allowing metadata listing even when its
    /// coder is unsupported.
    fn skip_entry(&mut self) -> Result<(), StreamError> {
        let end_offset = match self.body {
            ZipBody::Stored { end_offset, .. }
            | ZipBody::Deflate { end_offset, .. }
            | ZipBody::Unsupported { end_offset, .. }
            | ZipBody::Raw { end_offset, .. } => end_offset,
            #[cfg(feature = "bzip2")]
            ZipBody::Bzip2 { end_offset, .. } => end_offset,
            #[cfg(feature = "zstd")]
            ZipBody::Zstd { end_offset, .. } => end_offset,
            #[cfg(feature = "aes")]
            ZipBody::AesStored { end_offset, .. } | ZipBody::AesDeflate { end_offset, .. } => {
                end_offset
            },
            ZipBody::EndEntry => return Ok(()),
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format(format_name(self.format))
                        .with_context("skip_entry called without an open payload"),
                ));
            },
        };
        self.input
            .seek(SeekFrom::Start(end_offset))
            .map_err(StreamError::io)?;
        self.body = ZipBody::EndEntry;
        Ok(())
    }

    /// Archive format.
    #[must_use]
    const fn format(&self) -> FormatId {
        self.format
    }

    /// Returns the underlying seekable source.
    #[must_use]
    fn into_inner(self) -> R {
        self.input
    }

    fn source_ref(&self) -> &R {
        &self.input
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_zip_body(&mut self, entry: &ZipIndex) -> Result<(), StreamError> {
        self.input
            .seek(SeekFrom::Start(entry.local_offset))
            .map_err(StreamError::io)?;
        let mut header = [0_u8; 30];
        self.input
            .read_exact(&mut header)
            .map_err(StreamError::io)?;
        if &header[..4] != b"PK\x03\x04" {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("bad local-header signature"),
            ));
        }
        let local_flags = le16(&header, 6)?;
        let local_method = le16(&header, 8)?;
        if local_method != entry.method || local_flags & 0x0809 != entry.flags & 0x0809 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("central/local method or flags disagree"),
            ));
        }
        let name_length = usize::from(le16(&header, 26)?);
        let extra_length = u64::from(le16(&header, 28)?);
        let mut local_name = vec![0; name_length];
        self.input
            .read_exact(&mut local_name)
            .map_err(StreamError::io)?;
        if local_name != entry.raw_name {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("central/local entry names disagree"),
            ));
        }
        let data_offset = entry
            .local_offset
            .checked_add(30)
            .and_then(|value| value.checked_add(name_length as u64))
            .and_then(|value| value.checked_add(extra_length))
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("local data offset overflow"),
                )
            })?;
        let end_offset = data_offset
            .checked_add(entry.compressed_size)
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("compressed data range overflow"),
                )
            })?;
        self.input
            .seek(SeekFrom::Start(data_offset))
            .map_err(StreamError::io)?;
        if entry.method == 99 {
            #[cfg(feature = "aes")]
            return self.prepare_aes_body(entry, end_offset);
            #[cfg(not(feature = "aes"))]
            {
                self.prepare_aes_body(entry, end_offset);
                return Ok(());
            }
        }
        self.body = if entry.flags & 0x0001 != 0 {
            ZipBody::Unsupported {
                method: 99,
                end_offset,
            }
        } else {
            match entry.method {
                0 => ZipBody::Stored {
                    remaining: entry.compressed_size,
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    end_offset,
                },
                8 => ZipBody::Deflate {
                    compressed_unread: entry.compressed_size,
                    compressed: Vec::with_capacity(BUFFER),
                    compressed_start: 0,
                    inflate: Box::new(InflateState::new(DataFormat::Raw)),
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: entry.uncompressed_size,
                    end_offset,
                },
                #[cfg(feature = "bzip2")]
                12 => ZipBody::Bzip2 {
                    compressed_unread: entry.compressed_size,
                    compressed: Vec::with_capacity(BUFFER),
                    compressed_start: 0,
                    decompress: Box::new(bzip2::Decompress::new(false)),
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: entry.uncompressed_size,
                    end_offset,
                },
                #[cfg(feature = "zstd")]
                93 => ZipBody::Zstd {
                    compressed_unread: entry.compressed_size,
                    compressed: Vec::with_capacity(BUFFER),
                    compressed_start: 0,
                    decoder: Box::new(crate::pipeline_codec::PipelineCodec::new(
                        FilterId::Zstd,
                        self.limits,
                    )?),
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: entry.uncompressed_size,
                    end_offset,
                },
                method => ZipBody::Unsupported { method, end_offset },
            }
        };
        Ok(())
    }

    #[cfg(feature = "aes")]
    fn prepare_aes_body(&mut self, entry: &ZipIndex, end_offset: u64) -> Result<(), StreamError> {
        if entry.aes_strength != Some(3) {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("only WinZip AES-256 strength is supported"),
            ));
        }
        let encrypted_remaining = entry.compressed_size.checked_sub(28).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("WinZip AES payload is shorter than its framing"),
            )
        })?;
        let password = self.password.as_ref().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("WinZip AES entry requires a password"),
            )
        })?;
        let mut salt = [0_u8; 16];
        let mut verifier = [0_u8; 2];
        self.input.read_exact(&mut salt).map_err(StreamError::io)?;
        self.input
            .read_exact(&mut verifier)
            .map_err(StreamError::io)?;
        let decoder = ZipAesDecoder::new(password.expose(), salt, verifier)?;
        self.body = match entry.aes_real_method {
            Some(0) => ZipBody::AesStored {
                encrypted_remaining,
                decoder,
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            Some(8) => ZipBody::AesDeflate {
                encrypted_remaining,
                compressed: Vec::with_capacity(BUFFER),
                compressed_start: 0,
                decoder,
                inflate: Box::new(InflateState::new(DataFormat::Raw)),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            Some(method) => ZipBody::Unsupported { method, end_offset },
            None => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("WinZip AES method is missing"),
                ));
            },
        };
        Ok(())
    }

    #[cfg(not(feature = "aes"))]
    fn prepare_aes_body(&mut self, _entry: &ZipIndex, end_offset: u64) {
        self.body = ZipBody::Unsupported {
            method: 99,
            end_offset,
        };
    }

    fn prepare_iso_body(&mut self, entry: &IsoIndex) -> Result<(), StreamError> {
        self.input
            .seek(SeekFrom::Start(entry.data_offset))
            .map_err(StreamError::io)?;
        let end_offset = entry
            .data_offset
            .checked_add(entry.size)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "file extent offset overflow"))?;
        self.body = ZipBody::Raw {
            remaining: entry.size,
            end_offset,
        };
        Ok(())
    }

    fn account_decoded(&mut self, count: usize) -> Result<(), StreamError> {
        self.decoded_total = self
            .decoded_total
            .checked_add(count as u64)
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format(format_name(self.format))
                        .with_context("decoded total overflow"),
                )
            })?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|limit| self.decoded_total > limit)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format(format_name(self.format))
                    .with_context("decoded total exceeds configured limit"),
            ));
        }
        Ok(())
    }
}

fn read_prefix(input: &mut impl Read, output: &mut [u8]) -> Result<usize, StreamError> {
    let mut filled = 0;
    while filled < output.len() {
        match input.read(&mut output[filled..]).map_err(StreamError::io)? {
            0 => break,
            count => filled += count,
        }
    }
    Ok(filled)
}

#[derive(Debug, Clone, Copy)]
struct IsoRoot {
    lba: u32,
    size: u32,
    joliet: bool,
}

#[derive(Debug)]
struct IsoDirectory {
    lba: u32,
    size: u32,
    prefix: Vec<u8>,
    depth: usize,
}

#[allow(clippy::too_many_lines)]
fn parse_iso_index<R: Read + Seek>(
    input: &mut R,
    limits: Limits,
) -> Result<(ArchiveMetadata, Vec<IsoIndex>), StreamError> {
    let image_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
    let mut primary = None;
    let mut joliet = None;
    let mut archive_metadata = ArchiveMetadata::new();
    let mut saw_terminator = false;
    for index in 0..ISO_MAX_DESCRIPTORS {
        let offset = (ISO_DESCRIPTOR_START + index)
            .checked_mul(ISO_SECTOR)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "descriptor offset overflow"))?;
        if offset
            .checked_add(ISO_SECTOR)
            .is_none_or(|end| end > image_length)
        {
            return Err(iso_error(
                ErrorKind::Malformed,
                "truncated volume descriptor set",
            ));
        }
        input
            .seek(SeekFrom::Start(offset))
            .map_err(StreamError::io)?;
        let mut descriptor = [0_u8; ISO_SECTOR_USIZE];
        input.read_exact(&mut descriptor).map_err(StreamError::io)?;
        if &descriptor[1..6] != b"CD001" || descriptor[6] != 1 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "invalid volume descriptor identifier or version",
            ));
        }
        match descriptor[0] {
            1 => {
                if iso_u16(&descriptor, 128)? != ISO_SECTOR_U16 {
                    return Err(iso_error(
                        ErrorKind::Unsupported,
                        "logical block size is not 2048",
                    ));
                }
                primary = Some(IsoRoot {
                    lba: iso_u32(&descriptor, 158)?,
                    size: iso_u32(&descriptor, 166)?,
                    joliet: false,
                });
                let volume = trim_iso_text(&descriptor[40..72]);
                if !volume.is_empty() {
                    archive_metadata = archive_metadata.with_volume_name(encoded_iso_text(volume));
                }
                for (key, value) in [
                    (&b"system-id"[..], trim_iso_text(&descriptor[8..40])),
                    (&b"application-id"[..], trim_iso_text(&descriptor[574..702])),
                ] {
                    if !value.is_empty() {
                        archive_metadata = archive_metadata.with_extension(Extension::new(
                            "iso9660-volume",
                            key.to_vec(),
                            value.to_vec(),
                        ));
                    }
                }
            },
            2 if is_joliet_descriptor(&descriptor) => {
                joliet = Some(IsoRoot {
                    lba: iso_u32(&descriptor, 158)?,
                    size: iso_u32(&descriptor, 166)?,
                    joliet: true,
                });
            },
            255 => {
                saw_terminator = true;
                break;
            },
            _ => {},
        }
    }
    if !saw_terminator {
        return Err(iso_error(
            ErrorKind::Malformed,
            "volume descriptor terminator is missing",
        ));
    }
    let primary = primary
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "primary volume descriptor is missing"))?;
    let rock_ridge_skip = detect_rock_ridge(input, primary, image_length, limits)?;
    let (root, susp_skip) = if let Some(skip) = rock_ridge_skip {
        (primary, skip)
    } else {
        (joliet.unwrap_or(primary), 0)
    };
    let mut stack = vec![IsoDirectory {
        lba: root.lba,
        size: root.size,
        prefix: Vec::new(),
        depth: 0,
    }];
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    let mut metadata_used = archive_metadata_size(&archive_metadata);
    while let Some(directory) = stack.pop() {
        if limits
            .nesting()
            .is_some_and(|maximum| directory.depth > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "directory nesting exceeds configured limit",
            ));
        }
        if !visited.insert((directory.lba, directory.size)) {
            continue;
        }
        let extent_size = usize::try_from(directory.size).map_err(|_| {
            iso_error(
                ErrorKind::Limit,
                "directory extent exceeds the address space",
            )
        })?;
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| extent_size > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "directory extent exceeds the in-flight buffer limit",
            ));
        }
        let extent_offset = u64::from(directory.lba)
            .checked_mul(ISO_SECTOR)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "directory extent offset overflow"))?;
        if extent_offset
            .checked_add(u64::from(directory.size))
            .is_none_or(|end| end > image_length)
        {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory extent is outside the image",
            ));
        }
        input
            .seek(SeekFrom::Start(extent_offset))
            .map_err(StreamError::io)?;
        let mut extent = vec![0; extent_size];
        input.read_exact(&mut extent).map_err(StreamError::io)?;
        parse_iso_directory(
            &extent,
            &directory,
            root.joliet,
            susp_skip,
            image_length,
            limits,
            &mut metadata_used,
            &mut entries,
            &mut stack,
        )?;
    }
    Ok((archive_metadata, entries))
}

fn detect_rock_ridge(
    input: &mut (impl Read + Seek),
    root: IsoRoot,
    image_length: u64,
    limits: Limits,
) -> Result<Option<usize>, StreamError> {
    let offset = u64::from(root.lba)
        .checked_mul(ISO_SECTOR)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "root extent offset overflow"))?;
    let read_length = usize::try_from(root.size.min(u32::from(ISO_SECTOR_U16))).map_err(|_| {
        iso_error(
            ErrorKind::Limit,
            "root directory record exceeds address space",
        )
    })?;
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| read_length > maximum)
        || offset
            .checked_add(read_length as u64)
            .is_none_or(|end| end > image_length)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "root directory record exceeds configured limits",
        ));
    }
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut bytes = vec![0; read_length];
    input.read_exact(&mut bytes).map_err(StreamError::io)?;
    let record_length = bytes.first().copied().map_or(0, usize::from);
    let record = bytes
        .get(..record_length)
        .filter(|record| record.len() > ISO_DIRECTORY_RECORD_BASE)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "invalid root directory record"))?;
    let identifier_length = usize::from(record[32]);
    let system_use_start = ISO_DIRECTORY_RECORD_BASE
        .checked_add(identifier_length)
        .and_then(|value| value.checked_add(usize::from(identifier_length.is_multiple_of(2))))
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "root system-use offset overflow"))?;
    let system_use = record.get(system_use_start..).unwrap_or_default();
    let mut cursor = 0;
    let mut saw_rock_ridge = false;
    let mut skip = 0;
    while cursor + 4 <= system_use.len() {
        let length = usize::from(system_use[cursor + 2]);
        if length < 4 {
            break;
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "root system-use length overflow"))?;
        let Some(field) = system_use.get(cursor..end) else {
            break;
        };
        match &field[..2] {
            b"SP" if field.len() >= 7 && field[4..6] == [0xbe, 0xef] => {
                skip = usize::from(field[6]);
                saw_rock_ridge = true;
            },
            b"RR" | b"ER" | b"PX" => saw_rock_ridge = true,
            _ => {},
        }
        cursor = end;
    }
    Ok(saw_rock_ridge.then_some(skip))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn parse_iso_directory(
    extent: &[u8],
    directory: &IsoDirectory,
    joliet: bool,
    susp_skip: usize,
    image_length: u64,
    limits: Limits,
    metadata_used: &mut usize,
    entries: &mut Vec<IsoIndex>,
    stack: &mut Vec<IsoDirectory>,
) -> Result<(), StreamError> {
    let mut position = 0;
    while position < extent.len() {
        let record_length = usize::from(extent[position]);
        if record_length == 0 {
            position = position
                .checked_div(ISO_SECTOR_USIZE)
                .and_then(|sector| sector.checked_add(1))
                .and_then(|sector| sector.checked_mul(ISO_SECTOR_USIZE))
                .ok_or_else(|| iso_error(ErrorKind::Malformed, "directory position overflow"))?;
            continue;
        }
        let end = position
            .checked_add(record_length)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "directory record length overflow"))?;
        let record = extent.get(position..end).ok_or_else(|| {
            iso_error(ErrorKind::Malformed, "directory record exceeds its extent")
        })?;
        position = end;
        if record.len() < ISO_DIRECTORY_RECORD_BASE + 1 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory record is too short",
            ));
        }
        let identifier_length = usize::from(record[32]);
        let identifier_end = ISO_DIRECTORY_RECORD_BASE
            .checked_add(identifier_length)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "identifier length overflow"))?;
        let identifier = record
            .get(ISO_DIRECTORY_RECORD_BASE..identifier_end)
            .ok_or_else(|| {
                iso_error(ErrorKind::Malformed, "identifier exceeds directory record")
            })?;
        if identifier_length == 1 && matches!(identifier[0], 0 | 1) {
            continue;
        }
        if record[25] & 0x80 != 0 {
            return Err(iso_error(
                ErrorKind::Unsupported,
                "multi-extent files are not yet supported",
            ));
        }
        let lba = iso_u32(record, 2)?;
        let size = iso_u32(record, 10)?;
        let data_offset = u64::from(lba)
            .checked_mul(ISO_SECTOR)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "file extent offset overflow"))?;
        if data_offset
            .checked_add(u64::from(size))
            .is_none_or(|end| end > image_length)
        {
            return Err(iso_error(
                ErrorKind::Malformed,
                "entry extent is outside the image",
            ));
        }
        if limits
            .entry_bytes()
            .is_some_and(|maximum| u64::from(size) > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "entry exceeds configured size limit",
            ));
        }
        let is_directory = record[25] & ISO_DIRECTORY_FLAG != 0;
        let mut name = decode_iso_identifier(identifier, joliet, is_directory)?;
        let system_use_start = identifier_end
            .checked_add(usize::from(identifier_length.is_multiple_of(2)))
            .and_then(|value| value.checked_add(susp_skip))
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "system-use offset overflow"))?;
        let system_use = record.get(system_use_start..).unwrap_or_default();
        let rock_ridge = parse_rock_ridge(system_use)?;
        if rock_ridge.relocated {
            continue;
        }
        if let Some(rr_name) = &rock_ridge.name {
            name.clone_from(rr_name);
        }
        let mut path = directory.prefix.clone();
        path.extend_from_slice(&name);
        if is_directory {
            path.push(b'/');
        }
        if limits
            .path_bytes()
            .is_some_and(|maximum| path.len() > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "entry path exceeds configured limit",
            ));
        }
        let kind = rock_ridge.kind.unwrap_or(if is_directory {
            EntryKind::Dir
        } else {
            EntryKind::File
        });
        let encoding = if joliet {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        let mut builder =
            EntryMetadata::builder(kind, ArchivePath::from_encoded(path.clone(), encoding))
                .size(Some(if is_directory { 0 } else { u64::from(size) }))
                .mode(
                    rock_ridge
                        .mode
                        .or(Some(if is_directory { 0o755 } else { 0o644 })),
                )
                .owner(Owner {
                    uid: rock_ridge.uid,
                    gid: rock_ridge.gid,
                    ..Owner::default()
                })
                .times(EntryTimes {
                    modified: rock_ridge.modified.or_else(|| iso_record_time(record)),
                    accessed: rock_ridge.accessed,
                    changed: rock_ridge.changed,
                    created: rock_ridge.created,
                })
                .link_target(
                    rock_ridge
                        .link_target
                        .map(|target| ArchivePath::from_encoded(target, PathEncoding::Bytes)),
                )
                .inode_and_links(rock_ridge.inode, rock_ridge.links)
                .devices(None, rock_ridge.referenced_device);
        for extension in rock_ridge.extensions {
            builder = builder.extension(extension);
        }
        let accounted = path
            .len()
            .checked_add(system_use.len())
            .and_then(|value| value.checked_add(core::mem::size_of::<IsoIndex>()))
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        *metadata_used = metadata_used
            .checked_add(accounted)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| *metadata_used > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO metadata exceeds configured limit",
            ));
        }
        if limits
            .entries()
            .is_some_and(|maximum| entries.len() as u64 >= maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "entry count exceeds configured limit",
            ));
        }
        if is_directory {
            let mut prefix = path;
            if !prefix.ends_with(b"/") {
                prefix.push(b'/');
            }
            stack.push(IsoDirectory {
                lba: rock_ridge.child_link.unwrap_or(lba),
                size,
                prefix,
                depth: directory.depth + 1,
            });
        }
        entries.push(IsoIndex {
            metadata: builder.build(),
            data_offset,
            size: if is_directory { 0 } else { u64::from(size) },
        });
    }
    Ok(())
}

#[derive(Debug, Default)]
struct RockRidge {
    name: Option<Vec<u8>>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    inode: Option<u64>,
    links: Option<u64>,
    kind: Option<EntryKind>,
    referenced_device: Option<Device>,
    modified: Option<Timestamp>,
    accessed: Option<Timestamp>,
    changed: Option<Timestamp>,
    created: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    child_link: Option<u32>,
    relocated: bool,
    extensions: Vec<Extension>,
}

fn parse_rock_ridge(system_use: &[u8]) -> Result<RockRidge, StreamError> {
    let mut result = RockRidge::default();
    let mut cursor = 0;
    while cursor + 4 <= system_use.len() {
        let signature = &system_use[cursor..cursor + 2];
        let length = usize::from(system_use[cursor + 2]);
        if length < 4 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "invalid system-use field length",
            ));
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "system-use length overflow"))?;
        let field = system_use.get(cursor..end).ok_or_else(|| {
            iso_error(
                ErrorKind::Malformed,
                "system-use field exceeds directory record",
            )
        })?;
        match signature {
            b"NM" if field.len() >= 5 => {
                let flags = field[4];
                if flags & 0x06 == 0 {
                    result
                        .name
                        .get_or_insert_with(Vec::new)
                        .extend_from_slice(&field[5..]);
                }
            },
            b"PX" if field.len() >= 36 => {
                let mode = iso_u32(field, 4)?;
                result.mode = Some(mode & 0o7777);
                result.kind = mode_to_entry_kind(mode);
                result.links = Some(u64::from(iso_u32(field, 12)?));
                result.uid = Some(u64::from(iso_u32(field, 20)?));
                result.gid = Some(u64::from(iso_u32(field, 28)?));
                if field.len() >= 44 {
                    result.inode = Some(u64::from(iso_u32(field, 36)?));
                }
            },
            b"PN" if field.len() >= 20 => {
                result.referenced_device = Some(Device {
                    major: u64::from(iso_u32(field, 4)?),
                    minor: u64::from(iso_u32(field, 12)?),
                });
            },
            b"SL" if field.len() >= 5 => {
                result.link_target = Some(parse_sl_components(&field[5..])?);
                result.kind = Some(EntryKind::Symlink);
            },
            b"TF" if field.len() >= 5 => parse_tf(field, &mut result)?,
            b"CL" if field.len() >= 12 => result.child_link = Some(iso_u32(field, 4)?),
            b"RE" => result.relocated = true,
            _ => {},
        }
        result.extensions.push(Extension::new(
            "iso-system-use",
            signature.to_vec(),
            field.to_vec(),
        ));
        cursor = end;
    }
    Ok(result)
}

fn mode_to_entry_kind(mode: u32) -> Option<EntryKind> {
    match mode & 0o170_000 {
        0o100_000 => Some(EntryKind::File),
        0o040_000 => Some(EntryKind::Dir),
        0o120_000 => Some(EntryKind::Symlink),
        0o060_000 => Some(EntryKind::Block),
        0o020_000 => Some(EntryKind::Char),
        0o010_000 => Some(EntryKind::Fifo),
        0o140_000 => Some(EntryKind::Socket),
        _ => None,
    }
}

fn parse_sl_components(bytes: &[u8]) -> Result<Vec<u8>, StreamError> {
    let mut target = Vec::new();
    let mut cursor = 0;
    while cursor + 2 <= bytes.len() {
        let flags = bytes[cursor];
        let length = usize::from(bytes[cursor + 1]);
        let end = cursor
            .checked_add(2)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "SL component length overflow"))?;
        let value = bytes.get(cursor + 2..end).ok_or_else(|| {
            iso_error(
                ErrorKind::Malformed,
                "SL component exceeds system-use field",
            )
        })?;
        if !target.is_empty() && !target.ends_with(b"/") {
            target.push(b'/');
        }
        match flags & 0x0e {
            0x02 => target.extend_from_slice(b"."),
            0x04 => target.extend_from_slice(b".."),
            0x08 => {
                target.clear();
                target.push(b'/');
            },
            _ => target.extend_from_slice(value),
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(iso_error(ErrorKind::Malformed, "truncated SL component"));
    }
    Ok(target)
}

fn parse_tf(field: &[u8], result: &mut RockRidge) -> Result<(), StreamError> {
    let flags = field[4];
    let long = flags & 0x80 != 0;
    let width: usize = if long { 17 } else { 7 };
    let mut cursor: usize = 5;
    for bit in 0..7 {
        if flags & (1 << bit) == 0 {
            continue;
        }
        let end = cursor
            .checked_add(width)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "TF timestamp length overflow"))?;
        let raw = field.get(cursor..end).ok_or_else(|| {
            iso_error(
                ErrorKind::Malformed,
                "TF timestamp exceeds system-use field",
            )
        })?;
        let timestamp = if long {
            long_iso_time(raw)
        } else {
            short_iso_time(raw)
        };
        match bit {
            0 => result.created = timestamp,
            1 => result.modified = timestamp,
            2 => result.accessed = timestamp,
            3 => result.changed = timestamp,
            _ => {},
        }
        cursor = end;
    }
    Ok(())
}

fn iso_record_time(record: &[u8]) -> Option<Timestamp> {
    record.get(18..25).and_then(short_iso_time)
}

fn short_iso_time(raw: &[u8]) -> Option<Timestamp> {
    let raw: [u8; 7] = raw.try_into().ok()?;
    timestamp_from_parts(
        i32::from(raw[0]) + 1900,
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        i8::from_ne_bytes([raw[6]]),
        0,
    )
}

fn long_iso_time(raw: &[u8]) -> Option<Timestamp> {
    let raw: [u8; 17] = raw.try_into().ok()?;
    let digits = |range: core::ops::Range<usize>| {
        core::str::from_utf8(&raw[range]).ok()?.parse::<u32>().ok()
    };
    timestamp_from_parts(
        i32::try_from(digits(0..4)?).ok()?,
        u8::try_from(digits(4..6)?).ok()?,
        u8::try_from(digits(6..8)?).ok()?,
        u8::try_from(digits(8..10)?).ok()?,
        u8::try_from(digits(10..12)?).ok()?,
        u8::try_from(digits(12..14)?).ok()?,
        i8::from_ne_bytes([raw[16]]),
        digits(14..16)? * 10_000_000,
    )
}

#[allow(clippy::too_many_arguments)]
fn timestamp_from_parts(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    offset_quarters: i8,
    nanos: u32,
) -> Option<Timestamp> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || !(-48..=52).contains(&offset_quarters)
    {
        return None;
    }
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i32::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i32::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = i64::from(era * 146_097 + day_of_era - 719_468);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?
        .checked_sub(i64::from(offset_quarters) * 15 * 60)?;
    Some(Timestamp { secs, nanos })
}

fn decode_iso_identifier(
    identifier: &[u8],
    joliet: bool,
    is_directory: bool,
) -> Result<Vec<u8>, StreamError> {
    let mut name = if joliet {
        if !identifier.len().is_multiple_of(2) {
            return Err(iso_error(
                ErrorKind::Malformed,
                "odd-length Joliet identifier",
            ));
        }
        let units = identifier
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
        char::decode_utf16(units)
            .map(|value| value.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
            .into_bytes()
    } else {
        identifier.to_vec()
    };
    if let Some(position) = name.iter().position(|byte| *byte == b';') {
        name.truncate(position);
    }
    if !joliet && !is_directory && name.ends_with(b".") {
        name.pop();
    }
    Ok(name)
}

fn is_joliet_descriptor(descriptor: &[u8]) -> bool {
    descriptor.get(88..120).is_some_and(|escape| {
        escape.windows(3).any(|value| {
            value[0] == 0x25 && value[1] == 0x2f && matches!(value[2], 0x40 | 0x43 | 0x45)
        })
    })
}

fn trim_iso_text(value: &[u8]) -> &[u8] {
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | 0))
        .map_or(0, |index| index + 1);
    &value[..end]
}

fn encoded_iso_text(value: &[u8]) -> ArchivePath {
    if core::str::from_utf8(value).is_ok() {
        ArchivePath::from_encoded(value.to_vec(), PathEncoding::Utf8)
    } else {
        ArchivePath::from_bytes(value.to_vec())
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

fn iso_u16(bytes: &[u8], offset: usize) -> Result<u16, StreamError> {
    let little: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "truncated both-endian u16"))?;
    let big: [u8; 2] = bytes
        .get(offset + 2..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "truncated both-endian u16"))?;
    let little = u16::from_le_bytes(little);
    if little != u16::from_be_bytes(big) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "both-endian u16 values disagree",
        ));
    }
    Ok(little)
}

fn iso_u32(bytes: &[u8], offset: usize) -> Result<u32, StreamError> {
    let little: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "truncated both-endian u32"))?;
    let big: [u8; 4] = bytes
        .get(offset + 4..offset + 8)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "truncated both-endian u32"))?;
    let little = u32::from_le_bytes(little);
    if little != u32::from_be_bytes(big) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "both-endian u32 values disagree",
        ));
    }
    Ok(little)
}

fn format_name(format: FormatId) -> &'static str {
    match format {
        FormatId::Tar => "tar",
        FormatId::Cpio => "cpio",
        FormatId::Ar => "ar",
        FormatId::Zip => "zip",
        FormatId::SevenZip => "7z",
        FormatId::Iso9660 => "iso9660",
        _ => "archive",
    }
}

fn iso_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("iso9660")
            .with_context(context),
    )
}

#[allow(clippy::too_many_lines)]
fn parse_zip_index<R: Read + Seek>(
    input: &mut R,
    limits: Limits,
) -> Result<(ArchiveMetadata, Vec<ZipIndex>), StreamError> {
    let end = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
    let tail_length = end.min(EOCD_SEARCH);
    input
        .seek(SeekFrom::Start(end - tail_length))
        .map_err(StreamError::io)?;
    let mut tail = vec![
        0;
        usize::try_from(tail_length).map_err(|_| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("EOCD search range exceeds address space"),
            )
        })?
    ];
    input.read_exact(&mut tail).map_err(StreamError::io)?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("end-of-central-directory record not found"),
            )
        })?;
    if tail.len() - eocd < EOCD_MIN {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("truncated end-of-central-directory record"),
        ));
    }
    let comment_length = usize::from(le16(&tail[eocd..], 20)?);
    let comment_start = eocd + EOCD_MIN;
    let comment_end = comment_start.checked_add(comment_length).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("archive comment length overflow"),
        )
    })?;
    let archive_comment = tail.get(comment_start..comment_end).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("truncated archive comment"),
        )
    })?;
    if limits
        .metadata_bytes()
        .is_some_and(|limit| archive_comment.len() > limit)
    {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zip")
                .with_context("archive comment exceeds metadata limit"),
        ));
    }
    let archive_metadata = if archive_comment.is_empty() {
        ArchiveMetadata::new()
    } else {
        ArchiveMetadata::new().with_comment(archive_comment.to_vec())
    };
    let eocd_absolute = end - tail_length + eocd as u64;
    let mut count = u64::from(le16(&tail[eocd..], 10)?);
    let mut central_offset = u64::from(le32(&tail[eocd..], 16)?);
    if count == u64::from(u16::MAX) || central_offset == u64::from(u32::MAX) {
        if eocd_absolute < ZIP64_LOCATOR as u64 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("ZIP64 locator is missing"),
            ));
        }
        input
            .seek(SeekFrom::Start(eocd_absolute - ZIP64_LOCATOR as u64))
            .map_err(StreamError::io)?;
        let mut locator = [0_u8; ZIP64_LOCATOR];
        input.read_exact(&mut locator).map_err(StreamError::io)?;
        if &locator[..4] != b"PK\x06\x07" {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("bad ZIP64 locator"),
            ));
        }
        let record_offset = le64(&locator, 8)?;
        input
            .seek(SeekFrom::Start(record_offset))
            .map_err(StreamError::io)?;
        let mut record = [0_u8; 56];
        input.read_exact(&mut record).map_err(StreamError::io)?;
        if &record[..4] != b"PK\x06\x06" {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("bad ZIP64 end record"),
            ));
        }
        count = le64(&record, 32)?;
        central_offset = le64(&record, 48)?;
    }
    if limits.entries().is_some_and(|limit| count > limit) {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zip")
                .with_context("central-directory entry count exceeds limit"),
        ));
    }
    input
        .seek(SeekFrom::Start(central_offset))
        .map_err(StreamError::io)?;
    let capacity = usize::try_from(count.min(4096)).unwrap_or(4096);
    let mut entries = Vec::with_capacity(capacity);
    let mut metadata_used = archive_comment.len();
    for _ in 0..count {
        let mut fixed = [0_u8; 46];
        input.read_exact(&mut fixed).map_err(StreamError::io)?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("bad central-directory signature"),
            ));
        }
        let flags = le16(&fixed, 8)?;
        let method = le16(&fixed, 10)?;
        let crc32 = le32(&fixed, 16)?;
        let compressed32 = le32(&fixed, 20)?;
        let uncompressed32 = le32(&fixed, 24)?;
        let name_length = usize::from(le16(&fixed, 28)?);
        let extra_length = usize::from(le16(&fixed, 30)?);
        let comment_length = usize::from(le16(&fixed, 32)?);
        let external_attributes = le32(&fixed, 38)?;
        let local32 = le32(&fixed, 42)?;
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("central variable fields overflow"),
                )
            })?;
        metadata_used = metadata_used
            .checked_add(variable_length)
            .and_then(|value| value.checked_add(core::mem::size_of::<ZipIndex>()))
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zip")
                        .with_context("metadata accounting overflow"),
                )
            })?;
        if limits
            .metadata_bytes()
            .is_some_and(|limit| metadata_used > limit)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("central-directory metadata exceeds limit"),
            ));
        }
        let mut variable = vec![0; variable_length];
        input.read_exact(&mut variable).map_err(StreamError::io)?;
        let raw_name = &variable[..name_length];
        let extra = &variable[name_length..name_length + extra_length];
        let raw_comment = &variable[name_length + extra_length..];
        let (uncompressed_size, compressed_size, local_offset) =
            zip64_values(extra, uncompressed32, compressed32, local32)?;
        let (aes_real_method, aes_strength) = zip_aes_parameters(extra, method)?;
        let name = unicode_zip_value(extra, 0x7075, raw_name)?.unwrap_or(raw_name);
        let comment = unicode_zip_value(extra, 0x6375, raw_comment)?.unwrap_or(raw_comment);
        if limits
            .entry_bytes()
            .is_some_and(|limit| uncompressed_size > limit)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP entry exceeds configured size limit"),
            ));
        }
        if limits.path_bytes().is_some_and(|limit| name.len() > limit) {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP pathname exceeds configured limit"),
            ));
        }
        let unix_mode = external_attributes >> 16;
        let dos_attributes = u8::try_from(external_attributes & 0xff).unwrap_or(0);
        let kind = match unix_mode & 0o170_000 {
            0o040_000 => EntryKind::Dir,
            0o120_000 => EntryKind::Symlink,
            _ if name.ends_with(b"/") || dos_attributes & 0x10 != 0 => EntryKind::Dir,
            _ => EntryKind::File,
        };
        let encoding = if flags & 0x0800 != 0 || core::str::from_utf8(name).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        let times = zip_times(extra)?;
        let mut builder =
            EntryMetadata::builder(kind, ArchivePath::from_encoded(name.to_vec(), encoding))
                .size(Some(uncompressed_size))
                .mode((unix_mode != 0).then_some(unix_mode & 0o7777))
                .owner(Owner::default())
                .encrypted(flags & 0x0001 != 0)
                .comment((!comment.is_empty()).then(|| comment.to_vec()))
                .times(times);
        let mut cursor = 0;
        while cursor + 4 <= extra.len() {
            let id = le16(extra, cursor)?;
            let length = usize::from(le16(extra, cursor + 2)?);
            let start = cursor + 4;
            let finish = start.checked_add(length).ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("extra field length overflow"),
                )
            })?;
            let value = extra.get(start..finish).ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("truncated extra field"),
                )
            })?;
            builder = builder.extension(Extension::new(
                "zip-extra",
                id.to_le_bytes().to_vec(),
                value.to_vec(),
            ));
            cursor = finish;
        }
        entries.push(ZipIndex {
            metadata: builder.build(),
            raw_name: raw_name.to_vec(),
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            local_offset,
            aes_real_method,
            aes_strength,
        });
    }
    hydrate_zip_symlink_targets(input, &mut entries, limits)?;
    Ok((archive_metadata, entries))
}

fn zip_aes_parameters(extra: &[u8], method: u16) -> Result<(Option<u16>, Option<u8>), StreamError> {
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let end = start.checked_add(length).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("AES extra length overflow"),
            )
        })?;
        let value = extra.get(start..end).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated AES extra field"),
            )
        })?;
        if id == 0x9901 {
            if value.len() != 7 || &value[2..4] != b"AE" {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("invalid WinZip AES extra field"),
                ));
            }
            return Ok((Some(le16(value, 5)?), Some(value[4])));
        }
        cursor = end;
    }
    if method == 99 {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("AES method is missing its extra field"),
        ));
    }
    Ok((None, None))
}

fn hydrate_zip_symlink_targets<R: Read + Seek>(
    input: &mut R,
    entries: &mut [ZipIndex],
    limits: Limits,
) -> Result<(), StreamError> {
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.metadata.kind() == EntryKind::Symlink)
    {
        if entry.flags & 0x0001 != 0 {
            continue;
        }
        let maximum = limits.path_bytes().unwrap_or(usize::MAX);
        let target_len = usize::try_from(entry.uncompressed_size).map_err(|_| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP symbolic-link target exceeds address space"),
            )
        })?;
        if target_len > maximum {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP symbolic-link target exceeds path limit"),
            ));
        }
        let Some(target) = read_zip_metadata_payload(input, entry, target_len)? else {
            continue;
        };
        let encoding = if core::str::from_utf8(&target).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        entry.metadata = entry
            .metadata
            .clone()
            .into_builder()
            .link_target(Some(ArchivePath::from_encoded(target, encoding)))
            .build();
    }
    Ok(())
}

fn read_zip_metadata_payload<R: Read + Seek>(
    input: &mut R,
    entry: &ZipIndex,
    expected_size: usize,
) -> Result<Option<Vec<u8>>, StreamError> {
    input
        .seek(SeekFrom::Start(entry.local_offset))
        .map_err(StreamError::io)?;
    let mut header = [0_u8; 30];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    if &header[..4] != b"PK\x03\x04" {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("bad local header for symbolic link"),
        ));
    }
    let local_flags = le16(&header, 6)?;
    let local_method = le16(&header, 8)?;
    if local_flags & 0x0809 != entry.flags & 0x0809 || local_method != entry.method {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("central/local symbolic-link fields disagree"),
        ));
    }
    let name_length = usize::from(le16(&header, 26)?);
    let extra_length = usize::from(le16(&header, 28)?);
    let mut name = vec![0_u8; name_length];
    input.read_exact(&mut name).map_err(StreamError::io)?;
    if name != entry.raw_name {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("central/local symbolic-link names disagree"),
        ));
    }
    input
        .seek(SeekFrom::Current(i64::try_from(extra_length).map_err(
            |_| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("ZIP local extra length exceeds seek range"),
                )
            },
        )?))
        .map_err(StreamError::io)?;

    let target = match entry.method {
        0 => {
            if entry.compressed_size != entry.uncompressed_size {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Integrity)
                        .with_format("zip")
                        .with_context("stored symbolic-link sizes disagree"),
                ));
            }
            let mut target = vec![0_u8; expected_size];
            input.read_exact(&mut target).map_err(StreamError::io)?;
            target
        },
        8 => inflate_zip_metadata_payload(input, entry, expected_size)?,
        _ => return Ok(None),
    };
    let mut crc = Crc32::new();
    crc.update(&target);
    if crc.finalize() != entry.crc32 {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Integrity)
                .with_format("zip")
                .with_context("symbolic-link target CRC32 mismatch"),
        ));
    }
    Ok(Some(target))
}

fn inflate_zip_metadata_payload<R: Read>(
    input: &mut R,
    entry: &ZipIndex,
    expected_size: usize,
) -> Result<Vec<u8>, StreamError> {
    let mut compressed_remaining = entry.compressed_size;
    let mut compressed = vec![0_u8; BUFFER];
    let mut state = InflateState::new(DataFormat::Raw);
    let mut output = Vec::with_capacity(expected_size);
    let mut scratch = vec![0_u8; BUFFER];
    while compressed_remaining != 0 {
        let count = usize::try_from(compressed_remaining.min(BUFFER as u64)).map_err(|_| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("compressed symbolic-link payload exceeds address space"),
            )
        })?;
        input
            .read_exact(&mut compressed[..count])
            .map_err(StreamError::io)?;
        compressed_remaining -= count as u64;
        let mut start = 0;
        while start < count {
            let result = inflate(
                &mut state,
                &compressed[start..count],
                &mut scratch,
                if compressed_remaining == 0 {
                    MZFlush::Finish
                } else {
                    MZFlush::None
                },
            );
            start += result.bytes_consumed;
            if output
                .len()
                .checked_add(result.bytes_written)
                .is_none_or(|size| size > expected_size)
            {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Integrity)
                        .with_format("zip")
                        .with_context("symbolic-link target exceeds declared size"),
                ));
            }
            output.extend_from_slice(&scratch[..result.bytes_written]);
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    if start != count || compressed_remaining != 0 || output.len() != expected_size
                    {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("symbolic-link deflate extent is inconsistent"),
                        ));
                    }
                    return Ok(output);
                },
                Ok(_) if result.bytes_consumed != 0 || result.bytes_written != 0 => {},
                Ok(_) | Err(MZError::Buf) => {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("zip")
                            .with_context("symbolic-link deflate decoder made no progress"),
                    ));
                },
                Err(_) => {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("zip")
                            .with_context("invalid symbolic-link deflate payload"),
                    ));
                },
            }
        }
    }
    Err(StreamError::archive(
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zip")
            .with_context("truncated symbolic-link deflate payload"),
    ))
}

fn zip64_values(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local: u32,
) -> Result<(u64, u64, u64), StreamError> {
    let mut values = None;
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start.checked_add(length).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("ZIP64 extra length overflow"),
            )
        })?;
        let value = extra.get(start..finish).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated ZIP extra field"),
            )
        })?;
        if id == 0x0001 {
            values = Some(value);
            break;
        }
        cursor = finish;
    }
    let mut zip64 = values.unwrap_or(&[]);
    let mut take = || -> Result<u64, StreamError> {
        if zip64.len() < 8 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated ZIP64 value"),
            ));
        }
        let value = le64(zip64, 0)?;
        zip64 = &zip64[8..];
        Ok(value)
    };
    let uncompressed = if uncompressed == u32::MAX {
        take()?
    } else {
        u64::from(uncompressed)
    };
    let compressed = if compressed == u32::MAX {
        take()?
    } else {
        u64::from(compressed)
    };
    let local = if local == u32::MAX {
        take()?
    } else {
        u64::from(local)
    };
    Ok((uncompressed, compressed, local))
}

fn unicode_zip_value<'a>(
    extra: &'a [u8],
    wanted: u16,
    original: &[u8],
) -> Result<Option<&'a [u8]>, StreamError> {
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start.checked_add(length).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("Unicode extra field length overflow"),
            )
        })?;
        let value = extra.get(start..finish).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated Unicode extra field"),
            )
        })?;
        if id == wanted
            && value.len() >= 5
            && value[0] == 1
            && le32(value, 1)? == crate::filter::crc32(original)
        {
            core::str::from_utf8(&value[5..]).map_err(|_| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("Unicode ZIP extra is not UTF-8"),
                )
            })?;
            return Ok(Some(&value[5..]));
        }
        cursor = finish;
    }
    if cursor != extra.len() {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("truncated ZIP extra field header"),
        ));
    }
    Ok(None)
}

fn zip_times(extra: &[u8]) -> Result<EntryTimes, StreamError> {
    let mut times = EntryTimes::default();
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start.checked_add(length).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("timestamp extra field length overflow"),
            )
        })?;
        let value = extra.get(start..finish).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated timestamp extra field"),
            )
        })?;
        match id {
            0x5455 if !value.is_empty() => {
                let flags = value[0];
                let mut position = 1;
                for (bit, destination) in [
                    (0x01, &mut times.modified),
                    (0x02, &mut times.accessed),
                    (0x04, &mut times.changed),
                ] {
                    if flags & bit == 0 {
                        continue;
                    }
                    let seconds: [u8; 4] = value
                        .get(position..position + 4)
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("truncated extended timestamp value"),
                            )
                        })?;
                    *destination = Some(Timestamp {
                        secs: i64::from(i32::from_le_bytes(seconds)),
                        nanos: 0,
                    });
                    position += 4;
                }
            },
            0x000a if value.len() >= 4 => {
                parse_ntfs_times(&value[4..], &mut times)?;
            },
            _ => {},
        }
        cursor = finish;
    }
    if cursor != extra.len() {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("truncated ZIP extra field header"),
        ));
    }
    Ok(times)
}

fn parse_ntfs_times(mut tags: &[u8], times: &mut EntryTimes) -> Result<(), StreamError> {
    while tags.len() >= 4 {
        let tag = le16(tags, 0)?;
        let size = usize::from(le16(tags, 2)?);
        let end = 4_usize.checked_add(size).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("NTFS tag length overflow"),
            )
        })?;
        let value = tags.get(4..end).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated NTFS timestamp tag"),
            )
        })?;
        if tag == 1 && value.len() >= 24 {
            times.modified = filetime_timestamp(le64(value, 0)?);
            times.accessed = filetime_timestamp(le64(value, 8)?);
            times.created = filetime_timestamp(le64(value, 16)?);
        }
        tags = &tags[end..];
    }
    if !tags.is_empty() {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("truncated NTFS tag header"),
        ));
    }
    Ok(())
}

fn filetime_timestamp(ticks: u64) -> Option<Timestamp> {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const UNIX_EPOCH_SECONDS: i128 = 11_644_473_600;

    if ticks == 0 {
        return None;
    }
    let seconds = i128::from(ticks / TICKS_PER_SECOND) - UNIX_EPOCH_SECONDS;
    Some(Timestamp {
        secs: i64::try_from(seconds).ok()?,
        nanos: u32::try_from(ticks % TICKS_PER_SECOND)
            .ok()?
            .checked_mul(100)?,
    })
}

fn le16(bytes: &[u8], offset: usize) -> Result<u16, StreamError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed_number("u16"))?;
    Ok(u16::from_le_bytes(value))
}

fn le32(bytes: &[u8], offset: usize) -> Result<u32, StreamError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed_number("u32"))?;
    Ok(u32::from_le_bytes(value))
}

fn le64(bytes: &[u8], offset: usize) -> Result<u64, StreamError> {
    let value: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed_number("u64"))?;
    Ok(u64::from_le_bytes(value))
}

fn malformed_number(name: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zip")
            .with_context(format!("truncated little-endian {name}")),
    )
}
