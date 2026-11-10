// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seek-capable streaming archive adapters.

use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, Codec, CodecStatus, Device, EndOfInput, EntryKind,
    EntryMetadata, EntryTimes, ErrorKind, Extension, FormatId, Limits, Owner, PathEncoding,
    Timestamp,
};

#[cfg(feature = "sevenz")]
use crate::SevenZipWriteOptions;
#[cfg(feature = "gzip")]
use crate::deflate64::{InflateResult, InflaterManaged};
use crate::filter::gzip::{Crc32, RawInflateDecoder};
#[cfg(feature = "aes")]
use crate::zipaes::ZipAesDecoder;
#[cfg(feature = "aes")]
use crate::zipcrypto::ZipCrypto;
use crate::{ArchiveReader, ArchiveWriter, ReaderEvent, SecretBytes, StreamError};
#[cfg(not(target_os = "wasi"))]
use crate::{BackendPreference, XarWriteOptions, ZipMethod};
#[cfg(any(feature = "aes", feature = "xz", feature = "zstd"))]
use libarchive_oxide_core::filter::FilterId;

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

#[cfg(feature = "gzip")]
fn inflate64_extent_step(
    state: &mut InflaterManaged,
    input: &[u8],
    compressed_unread: u64,
    output: &mut [u8],
) -> InflateResult {
    if compressed_unread != 0 || input.is_empty() {
        return state.inflate(input, output);
    }

    // Keep the final declared byte out of the decoder's look-ahead. If the
    // stream finishes without it, that full byte is trailing data. A zero
    // progress result is safe to retry with the complete slice because the
    // first call consumed and emitted nothing.
    let result = state.inflate(&input[..input.len() - 1], output);
    if result.data_error
        || state.finished()
        || result.bytes_consumed != 0
        || result.bytes_written != 0
    {
        result
    } else {
        state.inflate(input, output)
    }
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
struct ZipAesRead<R> {
    input: R,
    crypto: ZipAesDecoder,
    remaining: u64,
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
impl<R: Read> Read for ZipAesRead<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let output_len = u64::try_from(output.len()).unwrap_or(u64::MAX);
        let count = usize::try_from(self.remaining.min(output_len)).unwrap_or(output.len());
        if count == 0 {
            return Ok(0);
        }
        let read = self.input.read(&mut output[..count])?;
        self.crypto.decrypt(&mut output[..read]);
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
impl<R> ZipAesRead<R> {
    const fn new(input: R, crypto: ZipAesDecoder, remaining: u64) -> Self {
        Self {
            input,
            crypto,
            remaining,
        }
    }

    fn into_parts(self) -> (R, ZipAesDecoder, u64) {
        (self.input, self.crypto, self.remaining)
    }

    #[cfg(feature = "ppmd")]
    const fn get_ref(&self) -> &R {
        &self.input
    }
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
struct ZipCryptoRead<R> {
    input: R,
    crypto: ZipCrypto,
    remaining: u64,
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
impl<R: Read> Read for ZipCryptoRead<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let output_len = u64::try_from(output.len()).unwrap_or(u64::MAX);
        let count = usize::try_from(self.remaining.min(output_len)).unwrap_or(output.len());
        if count == 0 {
            return Ok(0);
        }
        let read = self.input.read(&mut output[..count])?;
        self.crypto.decrypt(&mut output[..read]);
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
impl<R> ZipCryptoRead<R> {
    const fn new(input: R, crypto: ZipCrypto, remaining: u64) -> Self {
        Self {
            input,
            crypto,
            remaining,
        }
    }

    fn into_parts(self) -> (R, u64) {
        (self.input, self.remaining)
    }

    #[cfg(feature = "ppmd")]
    const fn get_ref(&self) -> &R {
        &self.input
    }
}

#[cfg(any(feature = "xz", feature = "ppmd"))]
enum OwnedZipDecoder<R: Read> {
    #[cfg(feature = "xz")]
    Lzma(Box<lzma_rust2::LzmaReader<std::io::Take<R>>>),
    #[cfg(feature = "ppmd")]
    Ppmd8(Box<ppmd_rust::Ppmd8Decoder<std::io::Take<R>>>),
    #[cfg(all(feature = "aes", feature = "xz"))]
    AesLzma(Box<lzma_rust2::LzmaReader<ZipAesRead<R>>>),
    #[cfg(all(feature = "aes", feature = "ppmd"))]
    AesPpmd8(Box<ppmd_rust::Ppmd8Decoder<ZipAesRead<R>>>),
    #[cfg(all(feature = "aes", feature = "xz"))]
    ZipCryptoLzma(Box<lzma_rust2::LzmaReader<ZipCryptoRead<R>>>),
    #[cfg(all(feature = "aes", feature = "ppmd"))]
    ZipCryptoPpmd8(Box<ppmd_rust::Ppmd8Decoder<ZipCryptoRead<R>>>),
}

#[cfg(any(feature = "xz", feature = "ppmd"))]
impl<R: Read> Read for OwnedZipDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "xz")]
            Self::Lzma(decoder) => decoder.read(output),
            #[cfg(feature = "ppmd")]
            Self::Ppmd8(decoder) => decoder.read(output),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::AesLzma(decoder) => decoder.read(output),
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::AesPpmd8(decoder) => decoder.read(output),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::ZipCryptoLzma(decoder) => decoder.read(output),
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::ZipCryptoPpmd8(decoder) => decoder.read(output),
        }
    }
}

#[cfg(any(feature = "xz", feature = "ppmd"))]
impl<R: Read> OwnedZipDecoder<R> {
    fn is_zipcrypto(&self) -> bool {
        match self {
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::ZipCryptoLzma(_) => true,
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::ZipCryptoPpmd8(_) => true,
            _ => false,
        }
    }

    #[allow(clippy::unnecessary_wraps)] // LZMA variants cannot expose R; feature sets may omit them.
    fn source_ref(&self) -> Option<&R> {
        match self {
            #[cfg(feature = "xz")]
            Self::Lzma(_) => None,
            #[cfg(feature = "ppmd")]
            Self::Ppmd8(decoder) => Some(decoder.get_ref().get_ref()),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::AesLzma(_) => None,
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::AesPpmd8(decoder) => Some(decoder.get_ref().get_ref()),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::ZipCryptoLzma(_) => None,
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::ZipCryptoPpmd8(decoder) => Some(decoder.get_ref().get_ref()),
        }
    }

    fn into_source_unchecked(self) -> R {
        match self {
            #[cfg(feature = "xz")]
            Self::Lzma(decoder) => decoder.into_inner().into_inner(),
            #[cfg(feature = "ppmd")]
            Self::Ppmd8(decoder) => decoder.into_inner().into_inner(),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::AesLzma(decoder) => decoder.into_inner().into_parts().0,
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::AesPpmd8(decoder) => decoder.into_inner().into_parts().0,
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::ZipCryptoLzma(decoder) => decoder.into_inner().into_parts().0,
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::ZipCryptoPpmd8(decoder) => decoder.into_inner().into_parts().0,
        }
    }

    #[cfg_attr(not(feature = "aes"), allow(clippy::unnecessary_wraps))]
    fn finish(self) -> Result<R, StreamError> {
        match self {
            #[cfg(feature = "xz")]
            Self::Lzma(decoder) => Ok(decoder.into_inner().into_inner()),
            #[cfg(feature = "ppmd")]
            Self::Ppmd8(decoder) => Ok(decoder.into_inner().into_inner()),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::AesLzma(decoder) => finish_owned_aes(decoder.into_inner()),
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::AesPpmd8(decoder) => finish_owned_aes(decoder.into_inner()),
            #[cfg(all(feature = "aes", feature = "xz"))]
            Self::ZipCryptoLzma(decoder) => finish_owned_zipcrypto(decoder.into_inner()),
            #[cfg(all(feature = "aes", feature = "ppmd"))]
            Self::ZipCryptoPpmd8(decoder) => finish_owned_zipcrypto(decoder.into_inner()),
        }
    }
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
fn finish_owned_aes<R: Read>(mut reader: ZipAesRead<R>) -> Result<R, StreamError> {
    let mut scratch = vec![0_u8; BUFFER];
    while reader.remaining != 0 {
        let read = reader.read(&mut scratch).map_err(StreamError::io)?;
        if read == 0 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated AES compressed extent"),
            ));
        }
    }
    let (mut input, crypto, _) = reader.into_parts();
    let mut authentication = [0_u8; 10];
    input
        .read_exact(&mut authentication)
        .map_err(StreamError::io)?;
    crypto.verify(authentication)?;
    Ok(input)
}

#[cfg(all(feature = "aes", any(feature = "xz", feature = "ppmd")))]
fn finish_owned_zipcrypto<R: Read>(mut reader: ZipCryptoRead<R>) -> Result<R, StreamError> {
    let mut scratch = vec![0_u8; BUFFER];
    while reader.remaining != 0 {
        let read = reader.read(&mut scratch).map_err(StreamError::io)?;
        if read == 0 {
            return Err(zipcrypto_integrity(
                "truncated or unauthenticated ZipCrypto compressed extent",
            ));
        }
    }
    let (input, _) = reader.into_parts();
    Ok(input)
}

#[derive(Debug, Clone)]
struct ZipIndex {
    metadata: EntryMetadata,
    raw_name: Vec<u8>,
    method: u16,
    flags: u16,
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    dos_time: u16,
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
    extents: Arc<[IsoExtent]>,
}

#[derive(Debug, Clone, Copy)]
struct IsoExtent {
    data_offset: u64,
    size: u64,
    unit_bytes: u64,
    gap_bytes: u64,
    physical_end: u64,
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
        inflate: Box<RawInflateDecoder>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "gzip")]
    Deflate64 {
        compressed_unread: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        inflate: Box<InflaterManaged>,
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
    #[cfg(feature = "xz")]
    Xz {
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
    #[cfg(feature = "xz")]
    Lzma {
        expected_crc: Option<u32>,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "ppmd")]
    Ppmd8 {
        expected_crc: Option<u32>,
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
        inflate: Box<RawInflateDecoder>,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz")
    ))]
    AesPipeline {
        method: u16,
        encrypted_remaining: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        crypto: ZipAesDecoder,
        codec: Box<crate::pipeline_codec::PipelineCodec>,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(all(feature = "aes", feature = "gzip"))]
    AesDeflate64 {
        encrypted_remaining: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        decoder: ZipAesDecoder,
        inflate: Box<InflaterManaged>,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "aes")]
    ZipCryptoStored {
        encrypted_remaining: u64,
        decoder: ZipCrypto,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(feature = "aes")]
    ZipCryptoDeflate {
        encrypted_remaining: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        decoder: ZipCrypto,
        inflate: Box<RawInflateDecoder>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz")
    ))]
    ZipCryptoPipeline {
        method: u16,
        encrypted_remaining: u64,
        compressed: Vec<u8>,
        compressed_start: usize,
        crypto: ZipCrypto,
        codec: Box<crate::pipeline_codec::PipelineCodec>,
        expected_crc: u32,
        crc: Crc32,
        produced: u64,
        expected_size: u64,
        end_offset: u64,
    },
    Unsupported {
        method: u16,
        end_offset: u64,
    },
    Raw {
        extents: Arc<[IsoExtent]>,
        extent_index: usize,
        remaining: u64,
        unit_remaining: u64,
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
            #[cfg(feature = "gzip")]
            Self::Deflate64 { .. } => "Deflate64",
            #[cfg(feature = "bzip2")]
            Self::Bzip2 { .. } => "Bzip2",
            #[cfg(feature = "zstd")]
            Self::Zstd { .. } => "Zstd",
            #[cfg(feature = "xz")]
            Self::Xz { .. } => "Xz",
            #[cfg(feature = "xz")]
            Self::Lzma { .. } => "Lzma",
            #[cfg(feature = "ppmd")]
            Self::Ppmd8 { .. } => "Ppmd8",
            #[cfg(feature = "aes")]
            Self::AesStored { .. } => "AesStored",
            #[cfg(feature = "aes")]
            Self::AesDeflate { .. } => "AesDeflate",
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz")
            ))]
            Self::AesPipeline { .. } => "AesPipeline",
            #[cfg(all(feature = "aes", feature = "gzip"))]
            Self::AesDeflate64 { .. } => "AesDeflate64",
            #[cfg(feature = "aes")]
            Self::ZipCryptoStored { .. } => "ZipCryptoStored",
            #[cfg(feature = "aes")]
            Self::ZipCryptoDeflate { .. } => "ZipCryptoDeflate",
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz")
            ))]
            Self::ZipCryptoPipeline { .. } => "ZipCryptoPipeline",
            Self::Unsupported { .. } => "Unsupported",
            Self::Raw { .. } => "Raw",
            Self::EndEntry => "EndEntry",
            Self::Done => "Done",
        };
        f.debug_tuple("ZipBody").field(&phase).finish()
    }
}

#[derive(Debug)]
enum SeekDispatch<R: Read + Seek> {
    Filtered {
        reader: Box<ArchiveReader<R>>,
        format: FormatId,
    },
    Indexed(Box<IndexedArchiveReader<R>>),
    Udf(Box<crate::udf::UdfSeekReader<R>>),
    #[cfg(feature = "sevenz")]
    SevenZ(Box<crate::sevenz::SevenZSeekReader<R>>),
    Cab(Box<crate::cab::CabSeekReader<R>>),
    Xar(Box<crate::xar::XarSeekReader<R>>),
    #[cfg(feature = "lha")]
    Lha(Box<crate::lha::LhaSeekReader<R>>),
}

/// Seek-capable archive reader.
///
/// ZIP central directories, 7z file/folder metadata, and ISO/UDF directory
/// indexes are retained within the configured metadata budget. File payloads
/// are streamed from their extents or solid-folder decoder.
#[derive(Debug)]
pub struct SeekArchiveReader<R: Read + Seek> {
    inner: SeekDispatch<R>,
}

impl<R: Read + Seek> SeekArchiveReader<R> {
    pub(crate) fn with_split_zip(
        input: R,
        disk_starts: &[u64],
        options: &crate::OpenOptions,
    ) -> Result<Self, StreamError> {
        if options
            .format()
            .is_some_and(|format| format != FormatId::Zip)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("zip")
                    .with_context("split ZIP reader requires ZIP format selection"),
            ));
        }
        if options.filter().is_some() || options.volumes().is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("zip")
                    .with_context("split ZIP seek adapter received incoherent open options"),
            ));
        }
        let passwords = options
            .password_candidates(crate::PasswordRequest::new(
                FormatId::Zip,
                None,
                crate::PasswordPurpose::Header,
            ))
            .map_err(StreamError::io)?;
        Ok(Self {
            inner: SeekDispatch::Indexed(Box::new(IndexedArchiveReader::with_split_zip(
                input,
                options.limits(),
                passwords,
                disk_starts,
            )?)),
        })
    }

    /// Opens a seek-capable archive with the common option model.
    pub fn with_options(mut input: R, options: &crate::OpenOptions) -> Result<Self, StreamError> {
        if options.volumes().is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_context("use a volume reader for OpenOptions containing VolumeSet"),
            ));
        }
        if options.filter().is_some() {
            let format = options.format().ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Capability).with_context(
                        "seek and range readers require an explicit archive format when an outer filter is selected",
                    ),
                )
            })?;
            let reader = ArchiveReader::with_options(input, options)?;
            return Ok(Self {
                inner: SeekDispatch::Filtered {
                    reader: Box::new(reader),
                    format,
                },
            });
        }
        let mut signature = [0_u8; 6];
        let read = read_prefix(&mut input, &mut signature)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let password_format = options.format().unwrap_or_else(|| {
            if read == signature.len() && signature == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
                FormatId::SevenZip
            } else {
                FormatId::Zip
            }
        });
        let passwords = options
            .password_candidates(crate::PasswordRequest::new(
                password_format,
                None,
                crate::PasswordPurpose::Header,
            ))
            .map_err(StreamError::io)?;
        if options.format() == Some(FormatId::Lha) {
            #[cfg(feature = "lha")]
            {
                return Ok(Self {
                    inner: SeekDispatch::Lha(Box::new(crate::lha::LhaSeekReader::new(
                        input,
                        options.limits(),
                    )?)),
                });
            }
            #[cfg(not(feature = "lha"))]
            {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("lha")
                        .with_context("LHA support is disabled"),
                ));
            }
        }
        let reader = Self::open(input, options.limits(), passwords)?;
        if options
            .format()
            .is_some_and(|expected| reader.format() != expected)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_context("detected archive format does not match OpenOptions format"),
            ));
        }
        Ok(reader)
    }

    /// Opens a seek-required archive with safe default limits.
    pub fn new(input: R) -> Result<Self, StreamError> {
        Self::with_limits(input, Limits::default())
    }

    /// Opens a seek-required archive with explicit limits.
    pub fn with_limits(input: R, limits: Limits) -> Result<Self, StreamError> {
        Self::open(input, limits, Vec::new())
    }

    /// Opens an archive with a zeroizing password for authenticated ZIP entries.
    pub fn with_password(input: R, password: SecretBytes) -> Result<Self, StreamError> {
        Self::open(input, Limits::default(), vec![password])
    }

    /// Opens an archive with explicit limits and a zeroizing password.
    pub fn with_limits_and_password(
        input: R,
        limits: Limits,
        password: SecretBytes,
    ) -> Result<Self, StreamError> {
        Self::open(input, limits, vec![password])
    }

    fn open(
        mut input: R,
        limits: Limits,
        passwords: Vec<SecretBytes>,
    ) -> Result<Self, StreamError> {
        let mut signature = [0_u8; 7];
        let read = read_prefix(&mut input, &mut signature)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        if read >= 4 && &signature[..4] == b"MSCF" {
            return Ok(Self {
                inner: SeekDispatch::Cab(Box::new(crate::cab::CabSeekReader::new(input, limits)?)),
            });
        }
        if read >= 4 && &signature[..4] == b"xar!" {
            return Ok(Self {
                inner: SeekDispatch::Xar(Box::new(crate::xar::XarSeekReader::new(input, limits)?)),
            });
        }
        if read >= 7
            && matches!(
                FormatId::probe(&signature[..read]),
                libarchive_oxide_core::ProbeResult::Match(FormatId::Lha)
            )
        {
            #[cfg(feature = "lha")]
            {
                return Ok(Self {
                    inner: SeekDispatch::Lha(Box::new(crate::lha::LhaSeekReader::new(
                        input, limits,
                    )?)),
                });
            }
            #[cfg(not(feature = "lha"))]
            {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("lha")
                        .with_context("LHA support is disabled"),
                ));
            }
        }
        #[cfg(feature = "lha")]
        if read >= 2
            && signature[..2] == *b"MZ"
            && crate::lha::LhaSeekReader::<R>::find_sfx_header(&mut input)?.is_some()
        {
            return Ok(Self {
                inner: SeekDispatch::Lha(Box::new(crate::lha::LhaSeekReader::new(input, limits)?)),
            });
        }
        if read >= 6 && signature[..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
            #[cfg(feature = "sevenz")]
            {
                return Ok(Self {
                    inner: SeekDispatch::SevenZ(Box::new(crate::sevenz::SevenZSeekReader::new(
                        input, limits, passwords,
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
        if crate::udf::probe_vrs(&mut input)? {
            return Ok(Self {
                inner: SeekDispatch::Udf(Box::new(crate::udf::UdfSeekReader::new(input, limits)?)),
            });
        }
        Ok(Self {
            inner: SeekDispatch::Indexed(Box::new(IndexedArchiveReader::with_options(
                input, limits, passwords,
            )?)),
        })
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match &mut self.inner {
            SeekDispatch::Filtered { reader, .. } => reader.next_event(),
            SeekDispatch::Indexed(reader) => reader.next_event(),
            SeekDispatch::Udf(reader) => reader.next_event(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.next_event(),
            SeekDispatch::Cab(reader) => reader.next_event(),
            SeekDispatch::Xar(reader) => reader.next_event(),
            #[cfg(feature = "lha")]
            SeekDispatch::Lha(reader) => reader.next_event(),
        }
    }

    /// Skips the current payload while preserving solid-stream decoder state.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekDispatch::Filtered { reader, .. } => loop {
                match reader.next_event()? {
                    ReaderEvent::Data(_) => {},
                    ReaderEvent::EndEntry => return Ok(()),
                    ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::Done => {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_context("skip_entry called without an open payload"),
                        ));
                    },
                }
            },
            SeekDispatch::Indexed(reader) => reader.skip_entry(),
            SeekDispatch::Udf(reader) => reader.skip_entry(),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.skip_entry(),
            SeekDispatch::Cab(reader) => reader.skip_entry(),
            SeekDispatch::Xar(reader) => reader.skip_entry(),
            #[cfg(feature = "lha")]
            SeekDispatch::Lha(reader) => reader.skip_entry(),
        }
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        match &self.inner {
            SeekDispatch::Filtered { format, .. } => *format,
            SeekDispatch::Indexed(reader) => reader.format(),
            SeekDispatch::Udf(_) => FormatId::Udf,
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(_) => FormatId::SevenZip,
            SeekDispatch::Cab(_) => FormatId::Cab,
            SeekDispatch::Xar(_) => FormatId::Xar,
            #[cfg(feature = "lha")]
            SeekDispatch::Lha(_) => FormatId::Lha,
        }
    }

    /// Returns the underlying seekable source when ownership is recoverable.
    ///
    /// # Errors
    ///
    /// Returns a protocol error if a seek decoder lost its source while
    /// switching an incremental decode graph.
    #[cfg_attr(not(feature = "sevenz"), allow(clippy::unnecessary_wraps))]
    pub fn into_inner(self) -> Result<R, ArchiveError> {
        match self.inner {
            SeekDispatch::Filtered { reader, .. } => reader.into_inner(),
            SeekDispatch::Indexed(reader) => reader.into_inner(),
            SeekDispatch::Udf(reader) => Ok(reader.into_inner()),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.into_inner(),
            SeekDispatch::Cab(reader) => Ok(reader.into_inner()),
            SeekDispatch::Xar(reader) => Ok(reader.into_inner()),
            #[cfg(feature = "lha")]
            SeekDispatch::Lha(reader) => reader.into_inner(),
        }
    }

    #[cfg_attr(not(feature = "sevenz"), allow(clippy::unnecessary_wraps))]
    pub(crate) fn with_source<T>(&self, inspect: impl FnOnce(&R) -> T) -> Result<T, ArchiveError> {
        match &self.inner {
            SeekDispatch::Filtered { reader, .. } => reader.with_source(inspect),
            SeekDispatch::Indexed(reader) => reader.source_ref().map(inspect),
            SeekDispatch::Udf(reader) => Ok(inspect(reader.source_ref())),
            #[cfg(feature = "sevenz")]
            SeekDispatch::SevenZ(reader) => reader.with_source(inspect),
            SeekDispatch::Cab(reader) => Ok(inspect(reader.source_ref())),
            SeekDispatch::Xar(reader) => Ok(inspect(reader.source_ref())),
            #[cfg(feature = "lha")]
            SeekDispatch::Lha(reader) => Ok(reader.with_source(inspect)),
        }
    }
}

#[derive(Debug)]
enum SeekWriterDispatch<W: Write + Seek> {
    Sequential(Box<ArchiveWriter<W>>),
    Iso(Box<crate::iso_stream::IsoSeekWriter<W>>),
    #[cfg(not(target_os = "wasi"))]
    Xar(Box<crate::xar::XarSeekWriter<W>>),
    #[cfg(feature = "sevenz")]
    SevenZ(Box<crate::sevenz::SevenZSeekWriter<W>>),
}

/// Archive writer for destinations with `Write + Seek`.
///
/// Sequential formats reuse [`ArchiveWriter`]. Seek-native formats retain
/// bounded metadata indexes and may backpatch structural headers. XAR is the
/// exception for payload handling: its TOC precedes its heap, so the writer uses
/// a bounded spool that spills regular-file payloads to a temporary file.
#[derive(Debug)]
pub struct SeekArchiveWriter<W: Write + Seek> {
    inner: SeekWriterDispatch<W>,
    format: FormatId,
}

impl<W: Write + Seek> SeekArchiveWriter<W> {
    #[cfg(not(target_os = "wasi"))]
    pub(crate) fn with_zip_method_and_backend(
        output: W,
        method: ZipMethod,
        limits: Limits,
        backend: BackendPreference,
    ) -> Self {
        Self {
            inner: SeekWriterDispatch::Sequential(Box::new(
                ArchiveWriter::with_zip_method_and_backend(output, method, limits, backend),
            )),
            format: FormatId::Zip,
        }
    }

    #[cfg(feature = "sevenz")]
    pub(crate) fn with_sevenz_options(
        output: W,
        options: SevenZipWriteOptions,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        Ok(Self {
            inner: SeekWriterDispatch::SevenZ(Box::new(
                crate::sevenz::SevenZSeekWriter::new_with_options(output, limits, options)?,
            )),
            format: FormatId::SevenZip,
        })
    }

    #[cfg(not(target_os = "wasi"))]
    pub(crate) fn with_xar_options(
        output: W,
        options: XarWriteOptions,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        Ok(Self {
            inner: SeekWriterDispatch::Xar(Box::new(crate::xar::XarSeekWriter::new_with_options(
                output, limits, options,
            )?)),
            format: FormatId::Xar,
        })
    }

    #[cfg(all(feature = "sevenz", feature = "aes"))]
    pub(crate) fn with_sevenz_options_and_password(
        output: W,
        options: SevenZipWriteOptions,
        password: &SecretBytes,
        limits: Limits,
    ) -> Result<Self, StreamError> {
        Ok(Self {
            inner: SeekWriterDispatch::SevenZ(Box::new(
                crate::sevenz::SevenZSeekWriter::new_with_options_and_password(
                    output, limits, options, password,
                )?,
            )),
            format: FormatId::SevenZip,
        })
    }

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
            #[cfg(not(target_os = "wasi"))]
            FormatId::Xar => {
                SeekWriterDispatch::Xar(Box::new(crate::xar::XarSeekWriter::new(output, limits)?))
            },
            FormatId::Udf => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("udf")
                        .with_context("UDF write is not supported"),
                ));
            },
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
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => writer.set_archive_metadata(metadata),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.set_archive_metadata(metadata),
        }
    }

    /// Begins one entry.
    pub fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        metadata.validate().map_err(StreamError::archive)?;
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.start_entry(metadata),
            SeekWriterDispatch::Iso(writer) => writer.start_entry(metadata),
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => writer.start_entry(metadata),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.start_entry(metadata),
        }
    }

    /// Writes entry bytes without retaining them in the writer.
    pub fn write_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.write_data(bytes),
            SeekWriterDispatch::Iso(writer) => writer.write_data(bytes),
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => writer.write_data(bytes),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.write_data(bytes),
        }
    }

    /// Ends the current entry.
    pub fn end_entry(&mut self) -> Result<(), StreamError> {
        match &mut self.inner {
            SeekWriterDispatch::Sequential(writer) => writer.end_entry(),
            SeekWriterDispatch::Iso(writer) => writer.end_entry(),
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => writer.end_entry(),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => writer.end_entry(),
        }
    }

    /// Finalizes the archive and returns its destination.
    pub fn finish(self) -> Result<W, StreamError> {
        match self.inner {
            SeekWriterDispatch::Sequential(writer) => (*writer).finish(),
            SeekWriterDispatch::Iso(writer) => (*writer).finish(),
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => (*writer).finish(),
            #[cfg(feature = "sevenz")]
            SeekWriterDispatch::SevenZ(writer) => (*writer).finish(),
        }
    }

    /// Abandons the archive without writing its terminal metadata.
    pub fn abort(self) -> Result<W, StreamError> {
        match self.inner {
            SeekWriterDispatch::Sequential(writer) => (*writer).abort(),
            SeekWriterDispatch::Iso(writer) => Ok((*writer).abort()),
            #[cfg(not(target_os = "wasi"))]
            SeekWriterDispatch::Xar(writer) => Ok((*writer).abort()),
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

struct IndexedArchiveReader<R: Read> {
    input: Option<R>,
    limits: Limits,
    format: FormatId,
    archive_metadata: Option<ArchiveMetadata>,
    entries: Vec<IndexedEntry>,
    next_entry: usize,
    body: ZipBody,
    event_data: Vec<u8>,
    decoded_total: u64,
    #[cfg(any(feature = "xz", feature = "ppmd"))]
    owned_decoder: Option<OwnedZipDecoder<R>>,
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    passwords: Vec<SecretBytes>,
}

impl<R: Read> core::fmt::Debug for IndexedArchiveReader<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IndexedArchiveReader")
            .field("format", &self.format)
            .field("entries", &self.entries.len())
            .field("next_entry", &self.next_entry)
            .field("body", &self.body)
            .field("decoded_total", &self.decoded_total)
            .finish_non_exhaustive()
    }
}

fn indexed_input_mut<R>(input: &mut Option<R>) -> Result<&mut R, StreamError> {
    input.as_mut().ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Protocol)
                .with_format("zip")
                .with_context("archive source is owned by an active payload decoder"),
        )
    })
}

#[cfg(feature = "aes")]
fn encrypted_pipeline_filter(method: u16) -> Option<FilterId> {
    match method {
        #[cfg(feature = "bzip2")]
        12 => Some(FilterId::Bzip2),
        #[cfg(feature = "zstd")]
        93 => Some(FilterId::Zstd),
        #[cfg(feature = "xz")]
        95 => Some(FilterId::Xz),
        _ => None,
    }
}

#[cfg(feature = "aes")]
fn encrypted_owned_method_supported(method: u16) -> bool {
    match method {
        #[cfg(feature = "xz")]
        14 => true,
        #[cfg(feature = "ppmd")]
        98 => true,
        _ => false,
    }
}

#[cfg(any(feature = "aes", feature = "xz", feature = "ppmd"))]
fn zipcrypto_integrity(context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(ErrorKind::Integrity)
            .with_format("zip")
            .with_context(context),
    )
}

#[cfg(feature = "aes")]
fn zipcrypto_validation_error(error: StreamError) -> StreamError {
    if error.kind() == ErrorKind::Malformed {
        zipcrypto_integrity("ZipCrypto password or encrypted payload failed validation")
    } else {
        error
    }
}

#[cfg(all(feature = "aes", feature = "xz"))]
fn malformed(context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zip")
            .with_context(context),
    )
}

#[cfg(all(feature = "aes", feature = "xz"))]
fn read_zip_lzma_properties<R: Read>(
    input: &mut R,
    limits: Limits,
) -> Result<(u8, u32), StreamError> {
    let malformed = |context: &'static str| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context(context),
        )
    };
    let mut head = [0_u8; 9];
    input.read_exact(&mut head).map_err(StreamError::io)?;
    if u16::from_le_bytes([head[2], head[3]]) != 5 {
        return Err(malformed("ZIP LZMA property size is not 5"));
    }
    let dict_size = u32::from_le_bytes([head[5], head[6], head[7], head[8]]);
    if limits
        .codec_memory()
        .is_some_and(|maximum| u64::from(dict_size) > maximum as u64)
    {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zip")
                .with_context("LZMA dictionary exceeds codec workspace limit"),
        ));
    }
    Ok((head[4], dict_size))
}

#[cfg(all(feature = "aes", feature = "ppmd"))]
fn read_zip_ppmd_parameters<R: Read>(
    input: &mut R,
    limits: Limits,
    compressed_size: u64,
) -> Result<(u32, u32, u32), StreamError> {
    let malformed = |context: &'static str| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context(context),
        )
    };
    if compressed_size < 6 {
        return Err(malformed("ZIP PPMd range stream is truncated"));
    }
    let mut parameter_bytes = [0_u8; 2];
    input
        .read_exact(&mut parameter_bytes)
        .map_err(StreamError::io)?;
    let parameters = u16::from_le_bytes(parameter_bytes);
    let order = u32::from((parameters & 0x0f) + 1);
    let memory_mb = u32::from(((parameters >> 4) & 0xff) + 1);
    let memory_size = memory_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| malformed("ZIP PPMd model size overflows"))?;
    let restoration = u32::from((parameters >> 12) & 0x0f);
    if !(2..=16).contains(&order) || restoration > 2 {
        return Err(malformed("invalid ZIP PPMd parameters"));
    }
    if limits
        .codec_memory()
        .is_some_and(|maximum| memory_size as usize > maximum)
    {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zip")
                .with_context("ZIP PPMd model exceeds codec workspace limit"),
        ));
    }
    Ok((order, memory_size, restoration))
}

impl<R: Read + Seek> IndexedArchiveReader<R> {
    fn with_options(
        mut input: R,
        limits: Limits,
        passwords: Vec<SecretBytes>,
    ) -> Result<Self, StreamError> {
        let mut signature = [0_u8; 6];
        let read = read_prefix(&mut input, &mut signature)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        if read >= 4 && (&signature[..4] == b"PK\x03\x04" || &signature[..4] == b"PK\x05\x06") {
            let (archive_metadata, entries) = parse_zip_index(&mut input, limits, None)?;
            return Ok(Self {
                input: Some(input),
                limits,
                format: FormatId::Zip,
                archive_metadata: Some(archive_metadata),
                entries: entries.into_iter().map(IndexedEntry::Zip).collect(),
                next_entry: 0,
                body: ZipBody::Idle,
                event_data: Vec::with_capacity(BUFFER),
                decoded_total: 0,
                #[cfg(any(feature = "xz", feature = "ppmd"))]
                owned_decoder: None,
                passwords,
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
                input: Some(input),
                limits,
                format: FormatId::Iso9660,
                archive_metadata: Some(archive_metadata),
                entries: entries.into_iter().map(IndexedEntry::Iso).collect(),
                next_entry: 0,
                body: ZipBody::Idle,
                event_data: Vec::with_capacity(BUFFER),
                decoded_total: 0,
                #[cfg(any(feature = "xz", feature = "ppmd"))]
                owned_decoder: None,
                passwords,
            });
        }
        Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Unsupported)
                .with_context("no seek-capable archive format matched"),
        ))
    }

    fn with_split_zip(
        mut input: R,
        limits: Limits,
        passwords: Vec<SecretBytes>,
        disk_starts: &[u64],
    ) -> Result<Self, StreamError> {
        let (archive_metadata, entries) = parse_zip_index(&mut input, limits, Some(disk_starts))?;
        Ok(Self {
            input: Some(input),
            limits,
            format: FormatId::Zip,
            archive_metadata: Some(archive_metadata),
            entries: entries.into_iter().map(IndexedEntry::Zip).collect(),
            next_entry: 0,
            body: ZipBody::Idle,
            event_data: Vec::with_capacity(BUFFER),
            decoded_total: 0,
            #[cfg(any(feature = "xz", feature = "ppmd"))]
            owned_decoder: None,
            passwords,
        })
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
                    indexed_input_mut(&mut self.input)?
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
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
                        *compressed = next;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let input = &compressed[*compressed_start..];
                    let end = if *compressed_unread == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = state
                        .process(input, &mut self.event_data, end)
                        .and_then(|step| step.validate(input.len(), self.event_data.len()))
                        .map_err(StreamError::archive)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("deflate output count overflow"),
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
                    match step.status {
                        CodecStatus::Done => {
                            if *compressed_start != compressed.len()
                                || *compressed_unread != 0
                                || *produced != *expected_size
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(
                                            "deflate extent or size disagrees with central directory",
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
                        CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                            if step.consumed == 0 && step.produced == 0 && *compressed_unread == 0 {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated deflate stream"),
                                ));
                            }
                        },
                        _ => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context("deflate decoder returned an unknown status"),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "gzip")]
                ZipBody::Deflate64 {
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
                                        .with_context(
                                            "Deflate64 compressed read size exceeds address space",
                                        ),
                                )
                            })?;
                        compressed.resize(count, 0);
                        indexed_input_mut(&mut self.input)?
                            .read_exact(compressed)
                            .map_err(StreamError::io)?;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let result = inflate64_extent_step(
                        state,
                        &compressed[*compressed_start..],
                        *compressed_unread,
                        &mut self.event_data,
                    );
                    *compressed_start += result.bytes_consumed;
                    self.event_data.truncate(result.bytes_written);
                    if result.data_error || state.errored() {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Malformed)
                                .with_format("zip")
                                .with_context("Deflate64 decoder rejected the bitstream"),
                        ));
                    }
                    crc.update(&self.event_data);
                    *produced = produced
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("Deflate64 output count overflow"),
                            )
                        })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("Deflate64 payload exceeds declared size"),
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
                    if state.finished() {
                        if *compressed_start != compressed.len() || *compressed_unread != 0 {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context(
                                        "Deflate64 stream ended before its compressed extent",
                                    ),
                            ));
                        }
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context(
                                        "Deflate64 size does not match central directory",
                                    ),
                            ));
                        }
                        if crc.finalize() != *expected_crc {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("Deflate64 entry CRC32 mismatch"),
                            ));
                        }
                        self.body = ZipBody::EndEntry;
                    } else if result.bytes_consumed == 0 && result.bytes_written == 0 {
                        if *compressed_unread == 0 {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("truncated Deflate64 stream"),
                            ));
                        }
                        let retained = compressed.len().saturating_sub(*compressed_start);
                        compressed.copy_within(*compressed_start.., 0);
                        compressed.truncate(retained);
                        let available = BUFFER.checked_sub(retained).ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("Deflate64 decoder made no progress"),
                            )
                        })?;
                        if available == 0 {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("Deflate64 decoder made no progress"),
                            ));
                        }
                        let count = usize::try_from((*compressed_unread).min(available as u64))
                            .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context(
                                            "Deflate64 compressed read size exceeds address space",
                                        ),
                                )
                            })?;
                        let old_len = compressed.len();
                        compressed.resize(
                            old_len.checked_add(count).ok_or_else(|| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("Deflate64 input buffer length overflow"),
                                )
                            })?,
                            0,
                        );
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut compressed[old_len..])
                            .map_err(StreamError::io)?;
                        *compressed_unread -= count as u64;
                        *compressed_start = 0;
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
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
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
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
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
                #[cfg(feature = "xz")]
                ZipBody::Xz {
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
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
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
                                .with_context("XZ output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("XZ output exceeds central-directory size"),
                        ));
                    }
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
                                    .with_context("XZ size does not match central directory"),
                            ));
                        }
                        if crc.finalize() != *expected_crc {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("XZ entry CRC32 mismatch"),
                            ));
                        }
                        self.body = ZipBody::EndEntry;
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "xz")]
                ZipBody::Lzma {
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    end_offset,
                } => {
                    let decoder = self.owned_decoder.as_mut().ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_format("zip")
                                .with_context("ZIP LZMA decoder state is missing"),
                        )
                    })?;
                    self.event_data.resize(BUFFER, 0);
                    let zipcrypto = decoder.is_zipcrypto();
                    let n = decoder.read(&mut self.event_data).map_err(|_| {
                        if zipcrypto {
                            zipcrypto_integrity(
                                "ZipCrypto LZMA password or payload failed validation",
                            )
                        } else {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("truncated or invalid LZMA stream"),
                            )
                        }
                    })?;
                    self.event_data.truncate(n);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(n as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("LZMA output count overflow"),
                        )
                    })?;
                    let next_total = self.decoded_total.checked_add(n as u64).ok_or_else(|| {
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
                    if n == 0 {
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("LZMA size does not match central directory"),
                            ));
                        }
                        if expected_crc
                            .as_ref()
                            .is_some_and(|expected| crc.finalize() != *expected)
                        {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("LZMA entry CRC32 mismatch"),
                            ));
                        }
                        let decoder = self.owned_decoder.take().ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context("ZIP LZMA decoder disappeared"),
                            )
                        })?;
                        let mut input = decoder.finish()?;
                        input
                            .seek(SeekFrom::Start(*end_offset))
                            .map_err(StreamError::io)?;
                        self.input = Some(input);
                        self.body = ZipBody::EndEntry;
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "ppmd")]
                ZipBody::Ppmd8 {
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    end_offset,
                } => {
                    let decoder = self.owned_decoder.as_mut().ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_format("zip")
                                .with_context("ZIP PPMd decoder state is missing"),
                        )
                    })?;
                    self.event_data.resize(BUFFER, 0);
                    let zipcrypto = decoder.is_zipcrypto();
                    let n = decoder.read(&mut self.event_data).map_err(|_| {
                        if zipcrypto {
                            zipcrypto_integrity(
                                "ZipCrypto PPMd password or payload failed validation",
                            )
                        } else {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("truncated or invalid ZIP PPMd stream"),
                            )
                        }
                    })?;
                    self.event_data.truncate(n);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(n as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("PPMd output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("PPMd output exceeds central-directory size"),
                        ));
                    }
                    let next_total = self.decoded_total.checked_add(n as u64).ok_or_else(|| {
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
                    if n == 0 {
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("PPMd size does not match central directory"),
                            ));
                        }
                        if expected_crc
                            .as_ref()
                            .is_some_and(|expected| crc.finalize() != *expected)
                        {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("PPMd entry CRC32 mismatch"),
                            ));
                        }
                        let decoder = self.owned_decoder.take().ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context("ZIP PPMd decoder disappeared"),
                            )
                        })?;
                        let mut input = decoder.finish()?;
                        input
                            .seek(SeekFrom::Start(*end_offset))
                            .map_err(StreamError::io)?;
                        self.input = Some(input);
                        self.body = ZipBody::EndEntry;
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(feature = "aes")]
                ZipBody::ZipCryptoStored {
                    encrypted_remaining,
                    decoder,
                    expected_crc,
                    crc,
                    produced,
                    expected_size,
                    ..
                } => {
                    if *encrypted_remaining == 0 {
                        if *produced != *expected_size {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context(
                                        "ZipCrypto stored size does not match central directory",
                                    ),
                            ));
                        }
                        if crc.finalize() != *expected_crc {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context("ZipCrypto stored entry CRC32 mismatch"),
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
                                    .with_context(
                                        "ZipCrypto stored read size exceeds address space",
                                    ),
                            )
                        })?;
                    self.event_data.resize(count, 0);
                    indexed_input_mut(&mut self.input)?
                        .read_exact(&mut self.event_data)
                        .map_err(StreamError::io)?;
                    decoder.decrypt(&mut self.event_data);
                    *encrypted_remaining -= count as u64;
                    *produced = produced.checked_add(count as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("ZipCrypto stored output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("ZipCrypto stored payload exceeds declared size"),
                        ));
                    }
                    crc.update(&self.event_data);
                    self.account_decoded(count)?;
                    return Ok(ReaderEvent::Data(&self.event_data));
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
                        indexed_input_mut(&mut self.input)?
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
                    indexed_input_mut(&mut self.input)?
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
                ZipBody::ZipCryptoDeflate {
                    encrypted_remaining,
                    compressed,
                    compressed_start,
                    decoder,
                    inflate: state,
                    expected_crc,
                    crc,
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
                                            "ZipCrypto deflate read size exceeds address space",
                                        ),
                                )
                            })?;
                        let mut next = vec![0; count];
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
                        decoder.decrypt(&mut next);
                        *compressed = next;
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let input = &compressed[*compressed_start..];
                    let end = if *encrypted_remaining == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = state
                        .process(input, &mut self.event_data, end)
                        .and_then(|step| step.validate(input.len(), self.event_data.len()))
                        .map_err(StreamError::archive)
                        .map_err(zipcrypto_validation_error)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("ZipCrypto deflate output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("ZipCrypto deflate payload exceeds declared size"),
                        ));
                    }
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
                    match step.status {
                        CodecStatus::Done => {
                            if *compressed_start != compressed.len()
                                || *encrypted_remaining != 0
                                || *produced != *expected_size
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(
                                            "ZipCrypto deflate extent disagrees with central directory",
                                        ),
                                ));
                            }
                            if crc.finalize() != *expected_crc {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context("ZipCrypto deflate entry CRC32 mismatch"),
                                ));
                            }
                            self.body = ZipBody::EndEntry;
                        },
                        CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                            if step.consumed == 0 && step.produced == 0 && *encrypted_remaining == 0
                            {
                                return Err(zipcrypto_integrity(
                                    "truncated or unauthenticated ZipCrypto deflate stream",
                                ));
                            }
                        },
                        _ => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context(
                                        "ZipCrypto deflate decoder returned an unknown status",
                                    ),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(all(
                    feature = "aes",
                    any(feature = "bzip2", feature = "zstd", feature = "xz")
                ))]
                ZipBody::ZipCryptoPipeline {
                    method,
                    encrypted_remaining,
                    compressed,
                    compressed_start,
                    crypto,
                    codec,
                    expected_crc,
                    crc,
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
                                            "ZipCrypto compressed read size exceeds address space",
                                        ),
                                )
                            })?;
                        let mut next = vec![0; count];
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
                        crypto.decrypt(&mut next);
                        *compressed = next;
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let input = &compressed[*compressed_start..];
                    let end = if *encrypted_remaining == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = codec
                        .process(input, &mut self.event_data, end)
                        .and_then(|step| step.validate(input.len(), self.event_data.len()))
                        .map_err(StreamError::archive)
                        .map_err(zipcrypto_validation_error)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    crc.update(&self.event_data);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("ZipCrypto compressed output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("ZipCrypto output exceeds central-directory size"),
                        ));
                    }
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
                    match step.status {
                        CodecStatus::Done => {
                            if *compressed_start != compressed.len()
                                || *encrypted_remaining != 0
                                || *produced != *expected_size
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(format!(
                                            "ZipCrypto method {method} extent disagrees with central directory"
                                        )),
                                ));
                            }
                            if crc.finalize() != *expected_crc {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context("ZipCrypto compressed entry CRC32 mismatch"),
                                ));
                            }
                            self.body = ZipBody::EndEntry;
                        },
                        CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                            if step.consumed == 0 && step.produced == 0 && *encrypted_remaining == 0
                            {
                                return Err(zipcrypto_integrity(
                                    "truncated or unauthenticated ZipCrypto compressed stream",
                                ));
                            }
                        },
                        _ => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context(
                                        "ZipCrypto compressed decoder returned an unknown status",
                                    ),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
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
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
                        decoder.decrypt(&mut next);
                        *compressed = next;
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let input = &compressed[*compressed_start..];
                    let end = if *encrypted_remaining == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = state
                        .process(input, &mut self.event_data, end)
                        .and_then(|step| step.validate(input.len(), self.event_data.len()))
                        .map_err(StreamError::archive)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
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
                    match step.status {
                        CodecStatus::Done => {
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
                            indexed_input_mut(&mut self.input)?
                                .read_exact(&mut authentication)
                                .map_err(StreamError::io)?;
                            decoder.verify(authentication)?;
                            self.body = ZipBody::EndEntry;
                        },
                        CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                            if step.consumed == 0 && step.produced == 0 && *encrypted_remaining == 0
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated AES deflate stream"),
                                ));
                            }
                        },
                        _ => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context("AES deflate decoder returned an unknown status"),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(all(
                    feature = "aes",
                    any(feature = "bzip2", feature = "zstd", feature = "xz")
                ))]
                ZipBody::AesPipeline {
                    method,
                    encrypted_remaining,
                    compressed,
                    compressed_start,
                    crypto,
                    codec,
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
                                            "AES compressed read size exceeds address space",
                                        ),
                                )
                            })?;
                        let mut next = vec![0; count];
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut next)
                            .map_err(StreamError::io)?;
                        crypto.decrypt(&mut next);
                        *compressed = next;
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let input = &compressed[*compressed_start..];
                    let end = if *encrypted_remaining == 0 {
                        EndOfInput::End
                    } else {
                        EndOfInput::More
                    };
                    let step = codec
                        .process(input, &mut self.event_data, end)
                        .and_then(|step| step.validate(input.len(), self.event_data.len()))
                        .map_err(StreamError::archive)?;
                    *compressed_start += step.consumed;
                    self.event_data.truncate(step.produced);
                    *produced = produced.checked_add(step.produced as u64).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("zip")
                                .with_context("AES compressed output count overflow"),
                        )
                    })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("AES output exceeds central-directory size"),
                        ));
                    }
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
                    match step.status {
                        CodecStatus::Done => {
                            if *compressed_start != compressed.len()
                                || *encrypted_remaining != 0
                                || *produced != *expected_size
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Integrity)
                                        .with_format("zip")
                                        .with_context(format!(
                                            "AES method {method} extent disagrees with central directory"
                                        )),
                                ));
                            }
                            let mut authentication = [0_u8; 10];
                            indexed_input_mut(&mut self.input)?
                                .read_exact(&mut authentication)
                                .map_err(StreamError::io)?;
                            crypto.verify(authentication)?;
                            self.body = ZipBody::EndEntry;
                        },
                        CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                            if step.consumed == 0 && step.produced == 0 && *encrypted_remaining == 0
                            {
                                return Err(StreamError::archive(
                                    ArchiveError::new(ErrorKind::Malformed)
                                        .with_format("zip")
                                        .with_context("truncated AES compressed stream"),
                                ));
                            }
                        },
                        _ => {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_format("zip")
                                    .with_context(
                                        "AES compressed decoder returned an unknown status",
                                    ),
                            ));
                        },
                    }
                    if !self.event_data.is_empty() {
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
                },
                #[cfg(all(feature = "aes", feature = "gzip"))]
                ZipBody::AesDeflate64 {
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
                                            "AES Deflate64 read size exceeds address space",
                                        ),
                                )
                            })?;
                        compressed.resize(count, 0);
                        indexed_input_mut(&mut self.input)?
                            .read_exact(compressed)
                            .map_err(StreamError::io)?;
                        decoder.decrypt(compressed);
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
                    }
                    self.event_data.resize(BUFFER, 0);
                    let result = inflate64_extent_step(
                        state,
                        &compressed[*compressed_start..],
                        *encrypted_remaining,
                        &mut self.event_data,
                    );
                    *compressed_start += result.bytes_consumed;
                    self.event_data.truncate(result.bytes_written);
                    if result.data_error || state.errored() {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Malformed)
                                .with_format("zip")
                                .with_context("AES Deflate64 decoder rejected the bitstream"),
                        ));
                    }
                    *produced = produced
                        .checked_add(result.bytes_written as u64)
                        .ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("AES Deflate64 output count overflow"),
                            )
                        })?;
                    if *produced > *expected_size {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Integrity)
                                .with_format("zip")
                                .with_context("AES Deflate64 payload exceeds declared size"),
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
                    if state.finished() {
                        if *compressed_start != compressed.len()
                            || *encrypted_remaining != 0
                            || *produced != *expected_size
                        {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Integrity)
                                    .with_format("zip")
                                    .with_context(
                                        "AES Deflate64 extent disagrees with central directory",
                                    ),
                            ));
                        }
                        let mut authentication = [0_u8; 10];
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut authentication)
                            .map_err(StreamError::io)?;
                        decoder.verify(authentication)?;
                        self.body = ZipBody::EndEntry;
                    } else if result.bytes_consumed == 0 && result.bytes_written == 0 {
                        if *encrypted_remaining == 0 {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("truncated AES Deflate64 stream"),
                            ));
                        }
                        let retained = compressed.len().saturating_sub(*compressed_start);
                        compressed.copy_within(*compressed_start.., 0);
                        compressed.truncate(retained);
                        let available = BUFFER.checked_sub(retained).ok_or_else(|| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("AES Deflate64 decoder made no progress"),
                            )
                        })?;
                        if available == 0 {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Malformed)
                                    .with_format("zip")
                                    .with_context("AES Deflate64 decoder made no progress"),
                            ));
                        }
                        let count = usize::try_from((*encrypted_remaining).min(available as u64))
                            .map_err(|_| {
                            StreamError::archive(
                                ArchiveError::new(ErrorKind::Limit)
                                    .with_format("zip")
                                    .with_context("AES Deflate64 read size exceeds address space"),
                            )
                        })?;
                        let old_len = compressed.len();
                        compressed.resize(
                            old_len.checked_add(count).ok_or_else(|| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("zip")
                                        .with_context("AES Deflate64 input buffer length overflow"),
                                )
                            })?,
                            0,
                        );
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut compressed[old_len..])
                            .map_err(StreamError::io)?;
                        decoder.decrypt(&mut compressed[old_len..]);
                        *encrypted_remaining -= count as u64;
                        *compressed_start = 0;
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
                ZipBody::Raw {
                    extents,
                    extent_index,
                    remaining,
                    unit_remaining,
                    ..
                } => {
                    let mut finished = false;
                    while *remaining == 0 {
                        *extent_index = extent_index.checked_add(1).ok_or_else(|| {
                            iso_error(ErrorKind::Malformed, "file extent index overflow")
                        })?;
                        let Some(extent) = extents.get(*extent_index) else {
                            finished = true;
                            break;
                        };
                        indexed_input_mut(&mut self.input)?
                            .seek(SeekFrom::Start(extent.data_offset))
                            .map_err(StreamError::io)?;
                        *remaining = extent.size;
                        *unit_remaining = iso_extent_first_unit(*extent);
                    }
                    if finished {
                        self.body = ZipBody::EndEntry;
                    } else {
                        let extent = extents.get(*extent_index).ok_or_else(|| {
                            iso_error(ErrorKind::Protocol, "active file extent is absent")
                        })?;
                        if *unit_remaining == 0 {
                            let gap = i64::try_from(extent.gap_bytes).map_err(|_| {
                                iso_error(ErrorKind::Limit, "interleave gap exceeds seek range")
                            })?;
                            indexed_input_mut(&mut self.input)?
                                .seek(SeekFrom::Current(gap))
                                .map_err(StreamError::io)?;
                            *unit_remaining = (*remaining).min(extent.unit_bytes);
                        }
                        let count =
                            usize::try_from((*remaining).min(*unit_remaining).min(BUFFER as u64))
                                .map_err(|_| {
                                StreamError::archive(
                                    ArchiveError::new(ErrorKind::Limit)
                                        .with_format("iso9660")
                                        .with_context("extent read size exceeds address space"),
                                )
                            })?;
                        self.event_data.resize(count, 0);
                        indexed_input_mut(&mut self.input)?
                            .read_exact(&mut self.event_data)
                            .map_err(StreamError::io)?;
                        *remaining -= count as u64;
                        *unit_remaining -= count as u64;
                        self.account_decoded(count)?;
                        return Ok(ReaderEvent::Data(&self.event_data));
                    }
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
        #[cfg(any(feature = "xz", feature = "ppmd"))]
        let owned_decoder_active = match self.body {
            #[cfg(feature = "xz")]
            ZipBody::Lzma { .. } => true,
            #[cfg(feature = "ppmd")]
            ZipBody::Ppmd8 { .. } => true,
            _ => false,
        };
        let end_offset = match self.body {
            ZipBody::Stored { end_offset, .. }
            | ZipBody::Deflate { end_offset, .. }
            | ZipBody::Unsupported { end_offset, .. }
            | ZipBody::Raw { end_offset, .. } => end_offset,
            #[cfg(feature = "gzip")]
            ZipBody::Deflate64 { end_offset, .. } => end_offset,
            #[cfg(feature = "bzip2")]
            ZipBody::Bzip2 { end_offset, .. } => end_offset,
            #[cfg(feature = "zstd")]
            ZipBody::Zstd { end_offset, .. } => end_offset,
            #[cfg(feature = "xz")]
            ZipBody::Xz { end_offset, .. } => end_offset,
            #[cfg(feature = "xz")]
            ZipBody::Lzma { end_offset, .. } => end_offset,
            #[cfg(feature = "ppmd")]
            ZipBody::Ppmd8 { end_offset, .. } => end_offset,
            #[cfg(feature = "aes")]
            ZipBody::AesStored { end_offset, .. } | ZipBody::AesDeflate { end_offset, .. } => {
                end_offset
            },
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz")
            ))]
            ZipBody::AesPipeline { end_offset, .. }
            | ZipBody::ZipCryptoPipeline { end_offset, .. } => end_offset,
            #[cfg(all(feature = "aes", feature = "gzip"))]
            ZipBody::AesDeflate64 { end_offset, .. } => end_offset,
            #[cfg(feature = "aes")]
            ZipBody::ZipCryptoStored { end_offset, .. }
            | ZipBody::ZipCryptoDeflate { end_offset, .. } => end_offset,
            ZipBody::EndEntry => return Ok(()),
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format(format_name(self.format))
                        .with_context("skip_entry called without an open payload"),
                ));
            },
        };
        #[cfg(any(feature = "xz", feature = "ppmd"))]
        if owned_decoder_active {
            let decoder = self.owned_decoder.take().ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("zip")
                        .with_context("owned ZIP decoder state is missing while skipping"),
                )
            })?;
            let mut input = decoder.into_source_unchecked();
            input
                .seek(SeekFrom::Start(end_offset))
                .map_err(StreamError::io)?;
            self.input = Some(input);
        } else {
            indexed_input_mut(&mut self.input)?
                .seek(SeekFrom::Start(end_offset))
                .map_err(StreamError::io)?;
        }
        #[cfg(not(any(feature = "xz", feature = "ppmd")))]
        indexed_input_mut(&mut self.input)?
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
    fn into_inner(self) -> Result<R, ArchiveError> {
        if let Some(input) = self.input {
            return Ok(input);
        }
        #[cfg(any(feature = "xz", feature = "ppmd"))]
        if let Some(decoder) = self.owned_decoder {
            return Ok(decoder.into_source_unchecked());
        }
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_format("zip")
            .with_context("seek archive source is unavailable"))
    }

    fn source_ref(&self) -> Result<&R, ArchiveError> {
        if let Some(input) = &self.input {
            return Ok(input);
        }
        #[cfg(any(feature = "xz", feature = "ppmd"))]
        if let Some(decoder) = &self.owned_decoder
            && let Some(source) = decoder.source_ref()
        {
            return Ok(source);
        }
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_format("zip")
            .with_context("seek archive source is unavailable"))
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_zip_body(&mut self, entry: &ZipIndex) -> Result<(), StreamError> {
        indexed_input_mut(&mut self.input)?
            .seek(SeekFrom::Start(entry.local_offset))
            .map_err(StreamError::io)?;
        let mut header = [0_u8; 30];
        indexed_input_mut(&mut self.input)?
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
        indexed_input_mut(&mut self.input)?
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
        indexed_input_mut(&mut self.input)?
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
        if entry.flags & 0x0001 != 0 {
            #[cfg(feature = "aes")]
            return self.prepare_zipcrypto_body(entry, end_offset);
            #[cfg(not(feature = "aes"))]
            {
                self.body = ZipBody::Unsupported {
                    method: entry.method,
                    end_offset,
                };
                return Ok(());
            }
        }
        self.body = {
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
                    inflate: Box::new(
                        RawInflateDecoder::with_limits(self.limits)
                            .map_err(StreamError::archive)?,
                    ),
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: entry.uncompressed_size,
                    end_offset,
                },
                #[cfg(feature = "gzip")]
                9 => ZipBody::Deflate64 {
                    compressed_unread: entry.compressed_size,
                    compressed: Vec::with_capacity(BUFFER),
                    compressed_start: 0,
                    inflate: Box::new(InflaterManaged::new()),
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
                #[cfg(feature = "xz")]
                95 => ZipBody::Xz {
                    compressed_unread: entry.compressed_size,
                    compressed: Vec::with_capacity(BUFFER),
                    compressed_start: 0,
                    decoder: Box::new(crate::pipeline_codec::PipelineCodec::new(
                        FilterId::Xz,
                        self.limits,
                    )?),
                    expected_crc: entry.crc32,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: entry.uncompressed_size,
                    end_offset,
                },
                #[cfg(feature = "xz")]
                14 => self.prepare_lzma_body(entry, end_offset)?,
                #[cfg(feature = "ppmd")]
                98 => self.prepare_ppmd_body(entry, end_offset)?,
                method => ZipBody::Unsupported { method, end_offset },
            }
        };
        Ok(())
    }

    /// Parses the 9-byte ZIP-LZMA header and transfers the seek source into a length-limited pull decoder.
    /// The source is recovered when the member ends, so compressed input is never buffered as a whole.
    #[cfg(feature = "xz")]
    fn prepare_lzma_body(
        &mut self,
        entry: &ZipIndex,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        let malformed = |context: &'static str| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context(context),
            )
        };
        // ZIP-LZMA header: [2] version, [2] prop_size (== 5), [5] props.
        let mut head = [0_u8; 9];
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut head)
            .map_err(StreamError::io)?;
        let prop_size = u16::from_le_bytes([head[2], head[3]]);
        if prop_size != 5 {
            return Err(malformed("ZIP LZMA property size is not 5"));
        }
        let props = head[4];
        let dict_size = u32::from_le_bytes([head[5], head[6], head[7], head[8]]);
        if self
            .limits
            .codec_memory()
            .is_some_and(|maximum| u64::from(dict_size) > maximum as u64)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("LZMA dictionary exceeds codec workspace limit"),
            ));
        }
        let payload_len = entry
            .compressed_size
            .checked_sub(9)
            .ok_or_else(|| malformed("ZIP LZMA member is shorter than its 9-byte header"))?;
        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("ZIP LZMA source is unavailable"),
            )
        })?;
        // Drive the reader with the central-directory uncompressed size unconditionally: LzmaReader stops at "known size OR end marker,
        // whichever first", decoding both EOS-marker and known-size members.
        let reader = lzma_rust2::LzmaReader::new_with_props(
            input.take(payload_len),
            entry.uncompressed_size,
            props,
            dict_size,
            None,
        )
        .map_err(|_| malformed("ZIP LZMA decoder setup failed"))?;
        self.owned_decoder = Some(OwnedZipDecoder::Lzma(Box::new(reader)));
        Ok(ZipBody::Lzma {
            expected_crc: Some(entry.crc32),
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    /// Parses ZIP method 98's two-byte parameter word and transfers the seek source into a length-limited streaming method-98 decoder.
    #[cfg(feature = "ppmd")]
    fn prepare_ppmd_body(
        &mut self,
        entry: &ZipIndex,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        let malformed = |context: &'static str| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context(context),
            )
        };
        let payload_len = entry
            .compressed_size
            .checked_sub(2)
            .ok_or_else(|| malformed("ZIP PPMd member is shorter than its parameter header"))?;
        let mut parameter_bytes = [0_u8; 2];
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut parameter_bytes)
            .map_err(StreamError::io)?;
        let parameters = u16::from_le_bytes(parameter_bytes);
        let order = u32::from((parameters & 0x0f) + 1);
        let memory_mb = u32::from(((parameters >> 4) & 0xff) + 1);
        let memory_size = memory_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| malformed("ZIP PPMd model size overflows"))?;
        let restoration = (parameters >> 12) & 0x0f;
        if !(2..=16).contains(&order) || restoration > 2 {
            return Err(malformed("invalid ZIP PPMd parameters"));
        }
        if self
            .limits
            .codec_memory()
            .is_some_and(|maximum| memory_size as usize > maximum)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP PPMd model exceeds codec workspace limit"),
            ));
        }
        if payload_len < 4 {
            return Err(malformed("ZIP PPMd range stream is truncated"));
        }
        // Ppmd8Decoder consumes four range-code bytes in its constructor.
        // Preview them while R is still recoverable, then rewind.
        // This keeps a malformed header from consuming and dropping the caller's source.
        let mut range_header = [0_u8; 4];
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut range_header)
            .map_err(StreamError::io)?;
        if range_header == [0xff; 4] {
            return Err(malformed("invalid ZIP PPMd range decoder header"));
        }
        indexed_input_mut(&mut self.input)?
            .seek(SeekFrom::Current(-4))
            .map_err(StreamError::io)?;

        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("ZIP PPMd source is unavailable"),
            )
        })?;
        let decoder = ppmd_rust::Ppmd8Decoder::new(
            input.take(payload_len),
            order,
            memory_size,
            restoration.into(),
        )
        .map_err(|error| zip_ppmd_setup_error(&error))?;
        self.owned_decoder = Some(OwnedZipDecoder::Ppmd8(Box::new(decoder)));
        Ok(ZipBody::Ppmd8 {
            expected_crc: Some(entry.crc32),
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    #[cfg(all(feature = "aes", feature = "xz"))]
    fn prepare_zipcrypto_lzma_body(
        &mut self,
        entry: &ZipIndex,
        encrypted_remaining: u64,
        crypto: ZipCrypto,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        if encrypted_remaining < 9 {
            return Err(malformed(
                "ZIP LZMA member is shorter than its 9-byte header",
            ));
        }
        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("ZipCrypto LZMA source is unavailable"),
            )
        })?;
        let mut source = ZipCryptoRead::new(input, crypto, encrypted_remaining);
        let (props, dict_size) = read_zip_lzma_properties(&mut source, self.limits)
            .map_err(zipcrypto_validation_error)?;
        let decoder = lzma_rust2::LzmaReader::new_with_props(
            source,
            entry.uncompressed_size,
            props,
            dict_size,
            None,
        )
        .map_err(|_| zipcrypto_integrity("ZipCrypto LZMA decoder setup failed"))?;
        self.owned_decoder = Some(OwnedZipDecoder::ZipCryptoLzma(Box::new(decoder)));
        Ok(ZipBody::Lzma {
            expected_crc: Some(entry.crc32),
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    #[cfg(all(feature = "aes", feature = "ppmd"))]
    fn prepare_zipcrypto_ppmd_body(
        &mut self,
        entry: &ZipIndex,
        encrypted_remaining: u64,
        crypto: ZipCrypto,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("ZipCrypto PPMd source is unavailable"),
            )
        })?;
        let mut source = ZipCryptoRead::new(input, crypto, encrypted_remaining);
        let (order, memory_size, restoration) =
            read_zip_ppmd_parameters(&mut source, self.limits, encrypted_remaining)
                .map_err(zipcrypto_validation_error)?;
        let decoder = ppmd_rust::Ppmd8Decoder::new(source, order, memory_size, restoration.into())
            .map_err(|error| zip_ppmd_setup_error(&error))
            .map_err(zipcrypto_validation_error)?;
        self.owned_decoder = Some(OwnedZipDecoder::ZipCryptoPpmd8(Box::new(decoder)));
        Ok(ZipBody::Ppmd8 {
            expected_crc: Some(entry.crc32),
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    #[cfg(all(feature = "aes", feature = "xz"))]
    fn prepare_aes_lzma_body(
        &mut self,
        entry: &ZipIndex,
        encrypted_remaining: u64,
        crypto: ZipAesDecoder,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        if encrypted_remaining < 9 {
            return Err(malformed(
                "ZIP LZMA member is shorter than its 9-byte header",
            ));
        }
        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("AES LZMA source is unavailable"),
            )
        })?;
        let mut source = ZipAesRead::new(input, crypto, encrypted_remaining);
        let (props, dict_size) = read_zip_lzma_properties(&mut source, self.limits)?;
        let decoder = lzma_rust2::LzmaReader::new_with_props(
            source,
            entry.uncompressed_size,
            props,
            dict_size,
            None,
        )
        .map_err(|_| malformed("ZIP LZMA decoder setup failed"))?;
        self.owned_decoder = Some(OwnedZipDecoder::AesLzma(Box::new(decoder)));
        Ok(ZipBody::Lzma {
            expected_crc: None,
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    #[cfg(all(feature = "aes", feature = "ppmd"))]
    fn prepare_aes_ppmd_body(
        &mut self,
        entry: &ZipIndex,
        encrypted_remaining: u64,
        crypto: ZipAesDecoder,
        end_offset: u64,
    ) -> Result<ZipBody, StreamError> {
        let input = self.input.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zip")
                    .with_context("AES PPMd source is unavailable"),
            )
        })?;
        let mut source = ZipAesRead::new(input, crypto, encrypted_remaining);
        let (order, memory_size, restoration) =
            read_zip_ppmd_parameters(&mut source, self.limits, encrypted_remaining)?;
        let decoder = ppmd_rust::Ppmd8Decoder::new(source, order, memory_size, restoration.into())
            .map_err(|error| zip_ppmd_setup_error(&error))?;
        self.owned_decoder = Some(OwnedZipDecoder::AesPpmd8(Box::new(decoder)));
        Ok(ZipBody::Ppmd8 {
            expected_crc: None,
            crc: Crc32::new(),
            produced: 0,
            expected_size: entry.uncompressed_size,
            end_offset,
        })
    }

    #[cfg(feature = "aes")]
    fn prepare_zipcrypto_body(
        &mut self,
        entry: &ZipIndex,
        end_offset: u64,
    ) -> Result<(), StreamError> {
        let pipeline_filter = encrypted_pipeline_filter(entry.method);
        if entry.flags & 0x0040 != 0
            || (!matches!(entry.method, 0 | 8)
                && pipeline_filter.is_none()
                && !encrypted_owned_method_supported(entry.method))
        {
            self.body = ZipBody::Unsupported {
                method: entry.method,
                end_offset,
            };
            return Ok(());
        }
        let encrypted_remaining = entry.compressed_size.checked_sub(12).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("ZipCrypto payload is shorter than its 12-byte header"),
            )
        })?;
        let mut header = [0_u8; 12];
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut header)
            .map_err(StreamError::io)?;
        let verifier = if entry.flags & 0x0008 != 0 {
            (entry.dos_time >> 8) as u8
        } else {
            (entry.crc32 >> 24) as u8
        };
        let decoder = self.select_zipcrypto_decoder(header, verifier)?;
        self.body = match entry.method {
            0 => ZipBody::ZipCryptoStored {
                encrypted_remaining,
                decoder,
                expected_crc: entry.crc32,
                crc: Crc32::new(),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            8 => ZipBody::ZipCryptoDeflate {
                encrypted_remaining,
                compressed: Vec::with_capacity(BUFFER),
                compressed_start: 0,
                decoder,
                inflate: Box::new(
                    RawInflateDecoder::with_limits(self.limits).map_err(StreamError::archive)?,
                ),
                expected_crc: entry.crc32,
                crc: Crc32::new(),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            #[cfg(feature = "xz")]
            14 => {
                self.prepare_zipcrypto_lzma_body(entry, encrypted_remaining, decoder, end_offset)?
            },
            #[cfg(feature = "ppmd")]
            98 => {
                self.prepare_zipcrypto_ppmd_body(entry, encrypted_remaining, decoder, end_offset)?
            },
            #[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz"))]
            method => ZipBody::ZipCryptoPipeline {
                method,
                encrypted_remaining,
                compressed: Vec::with_capacity(BUFFER),
                compressed_start: 0,
                crypto: decoder,
                codec: Box::new(crate::pipeline_codec::PipelineCodec::new(
                    pipeline_filter.ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_format("zip")
                                .with_context("ZipCrypto pipeline method changed after validation"),
                        )
                    })?,
                    self.limits,
                )?),
                expected_crc: entry.crc32,
                crc: Crc32::new(),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            #[cfg(not(any(feature = "bzip2", feature = "zstd", feature = "xz")))]
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("zip")
                        .with_context("ZipCrypto method changed after validation"),
                ));
            },
        };
        Ok(())
    }

    #[cfg(feature = "aes")]
    fn select_zipcrypto_decoder(
        &self,
        encrypted_header: [u8; 12],
        verifier: u8,
    ) -> Result<ZipCrypto, StreamError> {
        use subtle::ConstantTimeEq;

        if self.passwords.is_empty() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("ZipCrypto entry requires a password"),
            ));
        }
        for password in &self.passwords {
            let mut decoder = ZipCrypto::new(password.expose());
            let mut header = encrypted_header;
            decoder.decrypt(&mut header);
            if header[11].ct_eq(&verifier).unwrap_u8() == 1 {
                return Ok(decoder);
            }
        }
        Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Integrity)
                .with_format("zip")
                .with_context("no password candidate matched ZipCrypto verifier"),
        ))
    }

    #[cfg(feature = "aes")]
    #[allow(clippy::too_many_lines)]
    fn prepare_aes_body(&mut self, entry: &ZipIndex, end_offset: u64) -> Result<(), StreamError> {
        match entry.aes_real_method {
            Some(0 | 8) => {},
            #[cfg(feature = "gzip")]
            Some(9) => {},
            #[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz"))]
            Some(method) if encrypted_pipeline_filter(method).is_some() => {},
            Some(method) if encrypted_owned_method_supported(method) => {},
            Some(method) => {
                self.body = ZipBody::Unsupported { method, end_offset };
                return Ok(());
            },
            None => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("WinZip AES method is missing"),
                ));
            },
        }
        let strength = entry.aes_strength.ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("WinZip AES strength is missing"),
            )
        })?;
        let salt_len = match strength {
            1 => 8,
            2 => 12,
            3 => 16,
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("invalid WinZip AES strength code"),
                ));
            },
        };
        let framing_len = u64::try_from(salt_len + 2 + 10).map_err(|_| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("WinZip AES framing length exceeds address space"),
            )
        })?;
        let encrypted_remaining =
            entry
                .compressed_size
                .checked_sub(framing_len)
                .ok_or_else(|| {
                    StreamError::archive(
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("zip")
                            .with_context("WinZip AES payload is shorter than its framing"),
                    )
                })?;
        let mut salt = vec![0_u8; salt_len];
        let mut verifier = [0_u8; 2];
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut salt)
            .map_err(StreamError::io)?;
        indexed_input_mut(&mut self.input)?
            .read_exact(&mut verifier)
            .map_err(StreamError::io)?;
        let decoder = self.select_zip_aes_decoder(&salt, verifier, strength)?;
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
                inflate: Box::new(
                    RawInflateDecoder::with_limits(self.limits).map_err(StreamError::archive)?,
                ),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            #[cfg(feature = "xz")]
            Some(14) => {
                self.prepare_aes_lzma_body(entry, encrypted_remaining, decoder, end_offset)?
            },
            #[cfg(feature = "ppmd")]
            Some(98) => {
                self.prepare_aes_ppmd_body(entry, encrypted_remaining, decoder, end_offset)?
            },
            #[cfg(feature = "gzip")]
            Some(9) => ZipBody::AesDeflate64 {
                encrypted_remaining,
                compressed: Vec::with_capacity(BUFFER),
                compressed_start: 0,
                decoder,
                inflate: Box::new(InflaterManaged::new()),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            #[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz"))]
            Some(method) => ZipBody::AesPipeline {
                method,
                encrypted_remaining,
                compressed: Vec::with_capacity(BUFFER),
                compressed_start: 0,
                crypto: decoder,
                codec: Box::new(crate::pipeline_codec::PipelineCodec::new(
                    encrypted_pipeline_filter(method).ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_format("zip")
                                .with_context("AES pipeline method changed after validation"),
                        )
                    })?,
                    self.limits,
                )?),
                produced: 0,
                expected_size: entry.uncompressed_size,
                end_offset,
            },
            #[cfg(not(any(feature = "bzip2", feature = "zstd", feature = "xz")))]
            Some(_) => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("zip")
                        .with_context("WinZip AES method changed after validation"),
                ));
            },
            None => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("zip")
                        .with_context("WinZip AES method disappeared"),
                ));
            },
        };
        Ok(())
    }

    #[cfg(feature = "aes")]
    fn select_zip_aes_decoder(
        &self,
        salt: &[u8],
        verifier: [u8; 2],
        strength: u8,
    ) -> Result<ZipAesDecoder, StreamError> {
        if self.passwords.is_empty() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("WinZip AES entry requires a password"),
            ));
        }
        let mut mismatch = None;
        for password in &self.passwords {
            match ZipAesDecoder::new(password.expose(), salt, verifier, strength) {
                Ok(decoder) => return Ok(decoder),
                Err(error) if error.kind() == ErrorKind::Integrity => mismatch = Some(error),
                Err(error) => return Err(error.into()),
            }
        }
        Err(mismatch
            .unwrap_or_else(|| {
                ArchiveError::new(ErrorKind::Integrity)
                    .with_format("zip")
                    .with_context("no password candidate matched WinZip AES verifier")
            })
            .into())
    }

    #[cfg(not(feature = "aes"))]
    fn prepare_aes_body(&mut self, _entry: &ZipIndex, end_offset: u64) {
        self.body = ZipBody::Unsupported {
            method: 99,
            end_offset,
        };
    }

    fn prepare_iso_body(&mut self, entry: &IsoIndex) -> Result<(), StreamError> {
        let first = entry
            .extents
            .first()
            .copied()
            .ok_or_else(|| iso_error(ErrorKind::Protocol, "ISO entry has no file extent"))?;
        indexed_input_mut(&mut self.input)?
            .seek(SeekFrom::Start(first.data_offset))
            .map_err(StreamError::io)?;
        let last = entry.extents.last().copied().ok_or_else(|| {
            iso_error(ErrorKind::Protocol, "ISO entry lost its final file extent")
        })?;
        self.body = ZipBody::Raw {
            extents: Arc::clone(&entry.extents),
            extent_index: 0,
            remaining: first.size,
            unit_remaining: iso_extent_first_unit(first),
            end_offset: last.physical_end,
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
    extended_attribute_blocks: u8,
    volume_length: u64,
    volume_sequence: u16,
}

#[derive(Debug)]
struct IsoDirectory {
    lba: u32,
    size: u32,
    extended_attribute_blocks: u8,
    prefix: Vec<u8>,
    depth: usize,
}

#[derive(Debug, Default)]
struct IsoExtendedMetadata {
    mode: Option<u32>,
    owner: Owner,
    times: EntryTimes,
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
    let mut descriptor_set_end = None;
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
                validate_iso_logical_block_size(&descriptor)?;
                let volume_length = iso_volume_length(&descriptor, image_length)?;
                let volume_sequence = iso_volume_sequence(&descriptor)?;
                primary = Some(IsoRoot {
                    lba: iso_u32(&descriptor, 158)?,
                    size: iso_u32(&descriptor, 166)?,
                    joliet: false,
                    extended_attribute_blocks: descriptor[157],
                    volume_length,
                    volume_sequence,
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
                validate_iso_logical_block_size(&descriptor)?;
                let volume_length = iso_volume_length(&descriptor, image_length)?;
                let volume_sequence = iso_volume_sequence(&descriptor)?;
                joliet = Some(IsoRoot {
                    lba: iso_u32(&descriptor, 158)?,
                    size: iso_u32(&descriptor, 166)?,
                    joliet: true,
                    extended_attribute_blocks: descriptor[157],
                    volume_length,
                    volume_sequence,
                });
            },
            255 => {
                descriptor_set_end = Some(offset.checked_add(ISO_SECTOR).ok_or_else(|| {
                    iso_error(ErrorKind::Malformed, "descriptor set end overflow")
                })?);
                break;
            },
            _ => {},
        }
    }
    let primary = primary
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "primary volume descriptor is missing"))?;
    let descriptor_set_end = descriptor_set_end.ok_or_else(|| {
        iso_error(
            ErrorKind::Malformed,
            "volume descriptor terminator is missing",
        )
    })?;
    if primary.volume_length < descriptor_set_end
        || joliet.is_some_and(|root| root.volume_length < descriptor_set_end)
    {
        return Err(iso_error(
            ErrorKind::Malformed,
            "volume descriptor set exceeds the declared volume",
        ));
    }
    let rock_ridge_skip = detect_rock_ridge(input, primary, primary.volume_length, limits)?;
    let (root, susp_skip) = if let Some(skip) = rock_ridge_skip {
        (primary, skip)
    } else {
        (joliet.unwrap_or(primary), 0)
    };
    let mut stack = vec![IsoDirectory {
        lba: root.lba,
        size: root.size,
        extended_attribute_blocks: root.extended_attribute_blocks,
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
        if !visited.insert((
            directory.lba,
            directory.size,
            directory.extended_attribute_blocks,
        )) {
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
        let extent_offset =
            iso_extent_data_offset(directory.lba, directory.extended_attribute_blocks)?;
        if extent_offset
            .checked_add(u64::from(directory.size))
            .is_none_or(|end| end > root.volume_length)
        {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory extent is outside the declared volume",
            ));
        }
        input
            .seek(SeekFrom::Start(extent_offset))
            .map_err(StreamError::io)?;
        let mut extent = vec![0; extent_size];
        input.read_exact(&mut extent).map_err(StreamError::io)?;
        parse_iso_directory(
            input,
            &extent,
            &directory,
            root.joliet,
            susp_skip,
            root.volume_length,
            root.volume_sequence,
            limits,
            &mut metadata_used,
            &mut entries,
            &mut stack,
        )?;
    }
    Ok((archive_metadata, entries))
}

fn validate_iso_logical_block_size(descriptor: &[u8]) -> Result<(), StreamError> {
    if iso_u16(descriptor, 128)? != ISO_SECTOR_U16 {
        return Err(iso_error(
            ErrorKind::Unsupported,
            "logical block size is not 2048",
        ));
    }
    Ok(())
}

fn iso_volume_length(descriptor: &[u8], image_length: u64) -> Result<u64, StreamError> {
    let blocks = iso_u32(descriptor, 80)?;
    if blocks == 0 {
        return Err(iso_error(
            ErrorKind::Malformed,
            "declared volume space is empty",
        ));
    }
    let length = u64::from(blocks)
        .checked_mul(ISO_SECTOR)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "declared volume size overflow"))?;
    if length > image_length {
        return Err(iso_error(
            ErrorKind::Malformed,
            "declared volume space exceeds the image",
        ));
    }
    Ok(length)
}

fn iso_volume_sequence(descriptor: &[u8]) -> Result<u16, StreamError> {
    let volume_set_size = iso_u16(descriptor, 120)?;
    let volume_sequence = iso_u16(descriptor, 124)?;
    if volume_set_size == 0 || volume_sequence == 0 || volume_sequence > volume_set_size {
        return Err(iso_error(
            ErrorKind::Malformed,
            "invalid ISO volume-set size or volume sequence number",
        ));
    }
    let root = descriptor
        .get(156..190)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "root directory record is truncated"))?;
    if root[0] != 34
        || root[25] != ISO_DIRECTORY_FLAG
        || root[26] != 0
        || root[27] != 0
        || root[32] != 1
        || root[33] != 0
    {
        return Err(iso_error(
            ErrorKind::Malformed,
            "invalid root directory record in volume descriptor",
        ));
    }
    if iso_u16(descriptor, 184)? != volume_sequence {
        return Err(iso_error(
            ErrorKind::Malformed,
            "root directory record has a different volume sequence number",
        ));
    }
    Ok(volume_sequence)
}

fn detect_rock_ridge(
    input: &mut (impl Read + Seek),
    root: IsoRoot,
    volume_length: u64,
    limits: Limits,
) -> Result<Option<usize>, StreamError> {
    let offset = iso_extent_data_offset(root.lba, root.extended_attribute_blocks)?;
    let read_length = usize::try_from(root.size.min(u32::from(ISO_SECTOR_U16))).map_err(|_| {
        iso_error(
            ErrorKind::Limit,
            "root directory record exceeds address space",
        )
    })?;
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| read_length > maximum)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "root directory record exceeds configured limits",
        ));
    }
    if offset
        .checked_add(read_length as u64)
        .is_none_or(|end| end > volume_length)
    {
        return Err(iso_error(
            ErrorKind::Malformed,
            "root directory extent is outside the declared volume",
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
fn parse_iso_directory<R: Read + Seek>(
    input: &mut R,
    extent: &[u8],
    directory: &IsoDirectory,
    joliet: bool,
    susp_skip: usize,
    volume_length: u64,
    volume_sequence: u16,
    limits: Limits,
    metadata_used: &mut usize,
    entries: &mut Vec<IsoIndex>,
    stack: &mut Vec<IsoDirectory>,
) -> Result<(), StreamError> {
    let mut position = 0;
    while let Some(record) = next_iso_directory_record(extent, &mut position)? {
        let (identifier, identifier_end) = iso_directory_identifier(record)?;
        if identifier.len() == 1 && matches!(identifier[0], 0 | 1) {
            validate_iso_volume_reference(record, volume_sequence)?;
            if record[1] == 0 && record[25] & 0x18 != 0 {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "special directory flags require an extended attribute record",
                ));
            }
            if record[25] & 0xe2 != ISO_DIRECTORY_FLAG || record[26] != 0 || record[27] != 0 {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "special directory record has invalid flags or interleaving",
                ));
            }
            continue;
        }
        let identifier_length = identifier.len();
        let is_directory = record[25] & ISO_DIRECTORY_FLAG != 0;
        if is_directory && record[25] & 0x80 != 0 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory record sets the multi-extent flag",
            ));
        }
        let stable_flags = record[25] & 0x6f;
        let lba = iso_u32(record, 2)?;
        let first_size = iso_u32(record, 10)?;
        let mut section = record;
        let mut extents = Vec::new();
        let mut extended_metadata: Option<IsoExtendedMetadata>;
        let mut extended_records = Vec::new();
        let mut extended_metadata_bytes = 0_usize;
        let mut size = 0_u64;
        loop {
            validate_iso_volume_reference(section, volume_sequence)?;
            let (section_identifier, _) = iso_directory_identifier(section)?;
            if section_identifier != identifier || section[25] & 0x6f != stable_flags {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "multi-extent file sections have inconsistent directory records",
                ));
            }
            if section[25] & 0x60 != 0 {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "directory record uses reserved file flags",
                ));
            }
            let extended_attribute_blocks = section[1];
            if extended_attribute_blocks == 0 && section[25] & 0x18 != 0 {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "record/protection flags require an extended attribute record",
                ));
            }
            let file_unit_blocks = u64::from(section[26]);
            let gap_blocks = u64::from(section[27]);
            if file_unit_blocks == 0 && gap_blocks != 0 {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "interleave gap is present without a file unit",
                ));
            }
            if is_directory && (file_unit_blocks != 0 || gap_blocks != 0) {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "directory extent is recorded in interleaved mode",
                ));
            }
            let unit_bytes = file_unit_blocks
                .checked_mul(ISO_SECTOR)
                .ok_or_else(|| iso_error(ErrorKind::Malformed, "file unit size overflow"))?;
            let gap_bytes = gap_blocks
                .checked_mul(ISO_SECTOR)
                .ok_or_else(|| iso_error(ErrorKind::Malformed, "interleave gap size overflow"))?;
            let section_lba = iso_u32(section, 2)?;
            let section_size = iso_u32(section, 10)?;
            let extent_count = extents
                .len()
                .checked_add(1)
                .ok_or_else(|| iso_error(ErrorKind::Limit, "file extent count overflow"))?;
            let extent_bytes = extent_count
                .checked_mul(core::mem::size_of::<IsoExtent>())
                .ok_or_else(|| iso_error(ErrorKind::Limit, "file extent metadata overflow"))?;
            let provisional_metadata = (*metadata_used)
                .checked_add(core::mem::size_of::<IsoIndex>())
                .and_then(|value| value.checked_add(extent_bytes))
                .and_then(|value| value.checked_add(extended_metadata_bytes))
                .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
            if limits
                .metadata_bytes()
                .is_some_and(|maximum| provisional_metadata > maximum)
            {
                return Err(iso_error(
                    ErrorKind::Limit,
                    "ISO metadata exceeds configured limit",
                ));
            }
            let record_budget = limits
                .metadata_bytes()
                .map(|maximum| maximum - provisional_metadata);
            let section_extended = if extended_attribute_blocks == 0 {
                None
            } else {
                let (metadata, raw) = parse_iso_extended_attribute_record(
                    input,
                    section_lba,
                    extended_attribute_blocks,
                    section[25],
                    volume_length,
                    limits,
                    record_budget,
                )?;
                extended_metadata_bytes = extended_metadata_bytes
                    .checked_add(raw.len())
                    .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
                extended_records.try_reserve_exact(1).map_err(|_| {
                    iso_error(
                        ErrorKind::Limit,
                        "extended attribute table allocation failed",
                    )
                })?;
                extended_records.push(Extension::new(
                    "iso-extended-attribute",
                    b"record".to_vec(),
                    raw,
                ));
                Some(metadata)
            };
            extended_metadata = section_extended;
            let data_offset = iso_extent_data_offset(section_lba, extended_attribute_blocks)?;
            let physical_end = iso_extent_physical_end(
                data_offset,
                u64::from(section_size),
                unit_bytes,
                gap_bytes,
            )?;
            if physical_end > volume_length {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "entry extent is outside the declared volume",
                ));
            }
            size = size
                .checked_add(u64::from(section_size))
                .ok_or_else(|| iso_error(ErrorKind::Limit, "entry size overflow"))?;
            if limits.entry_bytes().is_some_and(|maximum| size > maximum) {
                return Err(iso_error(
                    ErrorKind::Limit,
                    "entry exceeds configured size limit",
                ));
            }
            let provisional_metadata = (*metadata_used)
                .checked_add(core::mem::size_of::<IsoIndex>())
                .and_then(|value| value.checked_add(extent_bytes))
                .and_then(|value| value.checked_add(extended_metadata_bytes))
                .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
            if limits
                .metadata_bytes()
                .is_some_and(|maximum| provisional_metadata > maximum)
            {
                return Err(iso_error(
                    ErrorKind::Limit,
                    "ISO metadata exceeds configured limit",
                ));
            }
            extents
                .try_reserve_exact(1)
                .map_err(|_| iso_error(ErrorKind::Limit, "file extent table allocation failed"))?;
            extents.push(IsoExtent {
                data_offset,
                size: u64::from(section_size),
                unit_bytes,
                gap_bytes,
                physical_end,
            });
            if section[25] & 0x80 == 0 {
                break;
            }
            section = next_iso_directory_record(extent, &mut position)?.ok_or_else(|| {
                iso_error(
                    ErrorKind::Malformed,
                    "multi-extent file is missing its final directory record",
                )
            })?;
        }
        let mut name = decode_iso_identifier(identifier, joliet, is_directory)?;
        let system_use_start = identifier_end
            .checked_add(usize::from(identifier_length.is_multiple_of(2)))
            .and_then(|value| value.checked_add(susp_skip))
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "system-use offset overflow"))?;
        let system_use = record.get(system_use_start..).unwrap_or_default();
        let (rock_ridge, continuation_bytes) =
            parse_rock_ridge_with_continuations(input, system_use, volume_length, limits)?;
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
        let path_value = ArchivePath::try_from_encoded(path.clone(), encoding)?;
        let link_target = rock_ridge
            .link_target
            .map(|target| ArchivePath::try_from_encoded(target, PathEncoding::Bytes))
            .transpose()?;
        let extended_metadata = extended_metadata.unwrap_or_default();
        let mut builder = EntryMetadata::builder(kind, path_value)
            .size(Some(if is_directory { 0 } else { size }))
            .mode(
                rock_ridge
                    .mode
                    .or(extended_metadata.mode)
                    .or(Some(if is_directory { 0o755 } else { 0o644 })),
            )
            .owner(Owner {
                uid: rock_ridge.uid.or(extended_metadata.owner.uid),
                gid: rock_ridge.gid.or(extended_metadata.owner.gid),
                ..Owner::default()
            })
            .times(EntryTimes {
                modified: rock_ridge
                    .modified
                    .or(extended_metadata.times.modified)
                    .or_else(|| iso_record_time(record)),
                accessed: rock_ridge.accessed.or(extended_metadata.times.accessed),
                changed: rock_ridge.changed.or(extended_metadata.times.changed),
                created: rock_ridge.created.or(extended_metadata.times.created),
            })
            .link_target(link_target)
            .inode_and_links(rock_ridge.inode, rock_ridge.links)
            .devices(None, rock_ridge.referenced_device);
        for extension in extended_records.into_iter().chain(rock_ridge.extensions) {
            builder = builder.extension(extension);
        }
        let accounted = path
            .len()
            .checked_add(system_use.len())
            .and_then(|value| value.checked_add(continuation_bytes))
            .and_then(|value| value.checked_add(extended_metadata_bytes))
            .and_then(|value| value.checked_add(core::mem::size_of::<IsoIndex>()))
            .and_then(|value| {
                value.checked_add(
                    extents
                        .len()
                        .checked_mul(core::mem::size_of::<IsoExtent>())?,
                )
            })
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
                size: first_size,
                extended_attribute_blocks: record[1],
                prefix,
                depth: directory.depth + 1,
            });
            for extent in &mut extents {
                extent.size = 0;
                extent.physical_end = extent.data_offset;
            }
        }
        entries.push(IsoIndex {
            metadata: builder.build(),
            extents: extents.into(),
        });
    }
    Ok(())
}

fn validate_iso_volume_reference(record: &[u8], volume_sequence: u16) -> Result<(), StreamError> {
    let referenced_volume = iso_u16(record, 28)?;
    if referenced_volume == 0 {
        return Err(iso_error(
            ErrorKind::Malformed,
            "directory record has a zero volume sequence number",
        ));
    }
    if referenced_volume != volume_sequence {
        return Err(iso_error(
            ErrorKind::Unsupported,
            "directory record references another ISO volume",
        ));
    }
    Ok(())
}

fn iso_extent_first_unit(extent: IsoExtent) -> u64 {
    if extent.unit_bytes == 0 {
        extent.size
    } else {
        extent.size.min(extent.unit_bytes)
    }
}

fn iso_extent_data_offset(
    logical_block: u32,
    extended_attribute_blocks: u8,
) -> Result<u64, StreamError> {
    u64::from(logical_block)
        .checked_add(u64::from(extended_attribute_blocks))
        .and_then(|block| block.checked_mul(ISO_SECTOR))
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "ISO extent offset overflow"))
}

fn iso_extent_physical_end(
    data_offset: u64,
    size: u64,
    unit_bytes: u64,
    gap_bytes: u64,
) -> Result<u64, StreamError> {
    let gaps = if size == 0 || unit_bytes == 0 {
        0
    } else {
        (size - 1) / unit_bytes
    };
    gaps.checked_mul(gap_bytes)
        .and_then(|gap_total| size.checked_add(gap_total))
        .and_then(|span| data_offset.checked_add(span))
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "interleaved file extent overflow"))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn parse_iso_extended_attribute_record<R: Read + Seek>(
    input: &mut R,
    logical_block: u32,
    allocated_blocks: u8,
    file_flags: u8,
    volume_length: u64,
    limits: Limits,
    metadata_budget: Option<usize>,
) -> Result<(IsoExtendedMetadata, Vec<u8>), StreamError> {
    const HEADER: usize = 250;
    const REQUIRED_PERMISSION_BITS: u16 = 0xaaaa;
    const ACCESS_PERMISSION_BITS: u16 = 0x5555;

    let allocated_bytes = u64::from(allocated_blocks)
        .checked_mul(ISO_SECTOR)
        .ok_or_else(|| {
            iso_error(
                ErrorKind::Malformed,
                "extended attribute allocation overflow",
            )
        })?;
    let offset = u64::from(logical_block)
        .checked_mul(ISO_SECTOR)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "extended attribute offset overflow"))?;
    if offset
        .checked_add(allocated_bytes)
        .is_none_or(|end| end > volume_length)
    {
        return Err(iso_error(
            ErrorKind::Malformed,
            "extended attribute record is outside the declared volume",
        ));
    }
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| HEADER > maximum)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "extended attribute header exceeds the in-flight buffer limit",
        ));
    }
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut raw = vec![0; HEADER];
    input.read_exact(&mut raw).map_err(StreamError::io)?;

    if raw[180] != 1 {
        return Err(iso_error(
            ErrorKind::Unsupported,
            "unsupported ISO extended attribute record version",
        ));
    }
    if raw[182..246].iter().any(|byte| *byte != 0) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "extended attribute reserved bytes are nonzero",
        ));
    }
    let application_length = usize::from(iso_u16(&raw, 246)?);
    let escape_length = usize::from(raw[181]);
    let used = HEADER
        .checked_add(application_length)
        .and_then(|value| value.checked_add(escape_length))
        .ok_or_else(|| {
            iso_error(
                ErrorKind::Limit,
                "extended attribute record length overflow",
            )
        })?;
    if u64::try_from(used)
        .ok()
        .is_none_or(|used| used > allocated_bytes)
    {
        return Err(iso_error(
            ErrorKind::Malformed,
            "extended attribute fields exceed their allocation",
        ));
    }
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| used > maximum)
        || metadata_budget.is_some_and(|maximum| used > maximum)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "extended attribute record exceeds configured limits",
        ));
    }
    raw.try_reserve_exact(used - HEADER).map_err(|_| {
        iso_error(
            ErrorKind::Limit,
            "extended attribute record allocation failed",
        )
    })?;
    raw.resize(used, 0);
    input
        .read_exact(&mut raw[HEADER..])
        .map_err(StreamError::io)?;

    let owner = iso_u16(&raw, 0)?;
    let group = iso_u16(&raw, 4)?;
    let permissions = u16::from_be_bytes([raw[8], raw[9]]);
    if permissions & REQUIRED_PERMISSION_BITS != REQUIRED_PERMISSION_BITS {
        return Err(iso_error(
            ErrorKind::Malformed,
            "extended attribute permissions omit required bits",
        ));
    }
    let protected = file_flags & 0x10 != 0;
    if protected {
        if owner == 0 || group == 0 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "protected entry omits its owner or group",
            ));
        }
    } else if owner != 0 || group != 0 || permissions & ACCESS_PERMISSION_BITS != 0 {
        return Err(iso_error(
            ErrorKind::Malformed,
            "unprotected entry has protected ownership or permissions",
        ));
    }

    let record_format = raw[78];
    if (file_flags & 0x08 != 0) != (record_format != 0) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "record flag and extended attribute format disagree",
        ));
    }
    let record_length = iso_u16(&raw, 80)?;
    if record_format == 0 && record_length != 0 {
        return Err(iso_error(
            ErrorKind::Malformed,
            "unspecified record format has a nonzero record length",
        ));
    }

    let mode = protected.then(|| {
        [
            (4, 0o400),
            (6, 0o100),
            (8, 0o040),
            (10, 0o010),
            (12, 0o004),
            (14, 0o001),
        ]
        .into_iter()
        .fold(0, |mode, (bit, value)| {
            if permissions & (1 << bit) == 0 {
                mode | value
            } else {
                mode
            }
        })
    });
    let created = iso_extended_time(&raw[10..27], "invalid ISO extended attribute creation time")?;
    let modified = iso_extended_time(
        &raw[27..44],
        "invalid ISO extended attribute modification time",
    )?;
    iso_extended_time(
        &raw[44..61],
        "invalid ISO extended attribute expiration time",
    )?;
    iso_extended_time(
        &raw[61..78],
        "invalid ISO extended attribute effective time",
    )?;
    Ok((
        IsoExtendedMetadata {
            mode,
            owner: Owner {
                uid: protected.then_some(u64::from(owner)),
                gid: protected.then_some(u64::from(group)),
                ..Owner::default()
            },
            times: EntryTimes {
                created,
                modified,
                ..EntryTimes::default()
            },
        },
        raw,
    ))
}

fn next_iso_directory_record<'a>(
    extent: &'a [u8],
    position: &mut usize,
) -> Result<Option<&'a [u8]>, StreamError> {
    loop {
        if *position >= extent.len() {
            return Ok(None);
        }
        let block_end = position
            .checked_div(ISO_SECTOR_USIZE)
            .and_then(|sector| sector.checked_add(1))
            .and_then(|sector| sector.checked_mul(ISO_SECTOR_USIZE))
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "directory position overflow"))?
            .min(extent.len());
        let record_length = usize::from(extent[*position]);
        if record_length == 0 {
            if extent[*position..block_end].iter().any(|byte| *byte != 0) {
                return Err(iso_error(
                    ErrorKind::Malformed,
                    "directory block padding contains nonzero bytes",
                ));
            }
            *position = block_end;
            continue;
        }
        let end = position
            .checked_add(record_length)
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "directory record length overflow"))?;
        if end > block_end {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory record crosses a logical block",
            ));
        }
        let record = extent.get(*position..end).ok_or_else(|| {
            iso_error(ErrorKind::Malformed, "directory record exceeds its extent")
        })?;
        *position = end;
        if record.len() < ISO_DIRECTORY_RECORD_BASE + 1 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "directory record is too short",
            ));
        }
        return Ok(Some(record));
    }
}

fn iso_directory_identifier(record: &[u8]) -> Result<(&[u8], usize), StreamError> {
    let identifier_length = usize::from(record[32]);
    let identifier_end = ISO_DIRECTORY_RECORD_BASE
        .checked_add(identifier_length)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "identifier length overflow"))?;
    let identifier = record
        .get(ISO_DIRECTORY_RECORD_BASE..identifier_end)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, "identifier exceeds directory record"))?;
    if identifier_length.is_multiple_of(2) && record.get(identifier_end).copied() != Some(0) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "directory record has invalid identifier padding",
        ));
    }
    Ok((identifier, identifier_end))
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
    name_continues: bool,
    link_continues: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IsoContinuation {
    block: u32,
    offset: u32,
    length: u32,
}

fn parse_rock_ridge_with_continuations<R: Read + Seek>(
    input: &mut R,
    system_use: &[u8],
    volume_length: u64,
    limits: Limits,
) -> Result<(RockRidge, usize), StreamError> {
    let mut result = RockRidge::default();
    let mut pending = VecDeque::from(parse_rock_ridge_area(system_use, &mut result)?);
    let mut visited = BTreeSet::new();
    let mut continuation_bytes = 0_usize;
    while let Some(continuation) = pending.pop_front() {
        if !visited.insert(continuation) {
            return Err(iso_error(
                ErrorKind::Malformed,
                "cyclic or duplicate SUSP continuation area",
            ));
        }
        if continuation.offset >= u32::from(ISO_SECTOR_U16) {
            return Err(iso_error(
                ErrorKind::Malformed,
                "SUSP continuation offset exceeds its logical block",
            ));
        }
        if limits
            .nesting()
            .is_some_and(|maximum| visited.len() > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "SUSP continuation nesting exceeds configured limit",
            ));
        }
        let length = usize::try_from(continuation.length).map_err(|_| {
            iso_error(
                ErrorKind::Limit,
                "SUSP continuation length exceeds the address space",
            )
        })?;
        if length == 0 {
            return Err(iso_error(
                ErrorKind::Malformed,
                "SUSP continuation area is empty",
            ));
        }
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| length > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "SUSP continuation exceeds the in-flight buffer limit",
            ));
        }
        continuation_bytes = continuation_bytes
            .checked_add(length)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "SUSP continuation size overflow"))?;
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| continuation_bytes > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "SUSP continuations exceed the metadata limit",
            ));
        }
        let start = u64::from(continuation.block)
            .checked_mul(ISO_SECTOR)
            .and_then(|value| value.checked_add(u64::from(continuation.offset)))
            .ok_or_else(|| iso_error(ErrorKind::Malformed, "SUSP continuation offset overflow"))?;
        if start
            .checked_add(u64::from(continuation.length))
            .is_none_or(|end| end > volume_length)
        {
            return Err(iso_error(
                ErrorKind::Malformed,
                "SUSP continuation is outside the declared volume",
            ));
        }
        input
            .seek(SeekFrom::Start(start))
            .map_err(StreamError::io)?;
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes).map_err(StreamError::io)?;
        pending.extend(parse_rock_ridge_area(&bytes, &mut result)?);
    }
    if result.name_continues || result.link_continues {
        return Err(iso_error(
            ErrorKind::Malformed,
            "Rock Ridge continuation flag has no following field",
        ));
    }
    Ok((result, continuation_bytes))
}

fn parse_rock_ridge_area(
    system_use: &[u8],
    result: &mut RockRidge,
) -> Result<Vec<IsoContinuation>, StreamError> {
    let mut continuations = Vec::new();
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
                    result.name_continues = flags & 0x01 != 0;
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
                let segment = parse_sl_components(&field[5..])?;
                append_sl_segment(result.link_target.get_or_insert_with(Vec::new), &segment);
                result.link_continues = field[4] & 0x01 != 0;
                result.kind = Some(EntryKind::Symlink);
            },
            b"TF" if field.len() >= 5 => parse_tf(field, result)?,
            b"CL" if field.len() >= 12 => result.child_link = Some(iso_u32(field, 4)?),
            b"RE" => result.relocated = true,
            b"CE" if field.len() == 28 => continuations.push(IsoContinuation {
                block: iso_u32(field, 4)?,
                offset: iso_u32(field, 12)?,
                length: iso_u32(field, 20)?,
            }),
            b"ST" if field.len() == 4 => {
                cursor = system_use.len();
                break;
            },
            _ => {},
        }
        if !matches!(signature, b"CE" | b"ST") {
            result.extensions.push(Extension::new(
                "iso-system-use",
                signature.to_vec(),
                field.to_vec(),
            ));
        }
        cursor = end;
    }
    if system_use[cursor..].iter().any(|byte| *byte != 0) {
        return Err(iso_error(
            ErrorKind::Malformed,
            "truncated bytes follow SUSP fields",
        ));
    }
    Ok(continuations)
}

fn append_sl_segment(target: &mut Vec<u8>, segment: &[u8]) {
    if segment.starts_with(b"/") {
        target.clear();
        target.extend_from_slice(segment);
        return;
    }
    if !target.is_empty() && !target.ends_with(b"/") && !segment.is_empty() {
        target.push(b'/');
    }
    target.extend_from_slice(segment);
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

fn iso_extended_time(
    raw: &[u8],
    invalid_context: &'static str,
) -> Result<Option<Timestamp>, StreamError> {
    let unspecified = raw.iter().all(|byte| *byte == 0)
        || raw
            .get(..16)
            .is_some_and(|digits| digits.iter().all(|byte| *byte == b'0'))
            && raw.get(16) == Some(&0);
    if unspecified {
        return Ok(None);
    }
    long_iso_time(raw)
        .map(Some)
        .ok_or_else(|| iso_error(ErrorKind::Malformed, invalid_context))
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
    Timestamp::new(secs, nanos).ok()
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
            .as_chunks::<2>()
            .0
            .iter()
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
    match core::str::from_utf8(value) {
        Ok(text) => ArchivePath::from_utf8(text),
        Err(_) => ArchivePath::from_bytes(value.to_vec()),
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
    libarchive_oxide_core::capability::format_capability(format)
        .map_or("archive", |record| record.name())
}

#[cfg(feature = "ppmd")]
fn zip_ppmd_setup_error(error: &ppmd_rust::Error) -> StreamError {
    let (kind, context) = match error {
        ppmd_rust::Error::MemoryAllocation => {
            (ErrorKind::Limit, "ZIP PPMd model allocation failed")
        },
        ppmd_rust::Error::RangeDecoderInitialization => (
            ErrorKind::Malformed,
            "ZIP PPMd range decoder initialization failed",
        ),
        ppmd_rust::Error::InvalidParameter => {
            (ErrorKind::Malformed, "invalid ZIP PPMd coder parameters")
        },
        ppmd_rust::Error::IoError(_) => (ErrorKind::Malformed, "truncated ZIP PPMd range header"),
    };
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("zip")
            .with_context(context),
    )
}

fn iso_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("iso9660")
            .with_context(context),
    )
}

fn validate_zip_disk_count(disk_starts: Option<&[u64]>, declared: u32) -> Result<(), StreamError> {
    let actual = disk_starts.map_or(1, <[u64]>::len);
    if usize::try_from(declared).ok() != Some(actual) {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP64 locator disk count disagrees with supplied volumes"),
        ));
    }
    Ok(())
}

fn validate_zip_disk_topology(
    disk_starts: Option<&[u64]>,
    this_disk: u32,
    central_disk: u32,
    count_on_disk: u64,
    count: u64,
) -> Result<(), StreamError> {
    if count_on_disk > count {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP entry count on final disk exceeds the total count"),
        ));
    }
    let Some(starts) = disk_starts else {
        if this_disk != 0 || central_disk != 0 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("multi-disk ZIP requires a VolumeSet reader"),
            ));
        }
        if count_on_disk != count {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("single-disk ZIP entry counts disagree"),
            ));
        }
        return Ok(());
    };
    if starts.is_empty() || starts[0] != 0 || !starts.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Protocol)
                .with_format("zip")
                .with_context("split ZIP disk layout is empty or non-monotonic"),
        ));
    }
    let final_disk = u32::try_from(starts.len() - 1).map_err(|_| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zip")
                .with_context("split ZIP disk count exceeds u32"),
        )
    })?;
    if this_disk != final_disk || central_disk > this_disk {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP end record disk topology disagrees with supplied volumes"),
        ));
    }
    Ok(())
}

fn zip_disk_offset(
    disk_starts: Option<&[u64]>,
    archive_end: u64,
    disk: u32,
    offset: u64,
    context: &'static str,
) -> Result<u64, StreamError> {
    let Some(starts) = disk_starts else {
        if disk != 0 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_format("zip")
                    .with_context("multi-disk ZIP requires a VolumeSet reader"),
            ));
        }
        if offset > archive_end {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context(context),
            ));
        }
        return Ok(offset);
    };
    let index = usize::try_from(disk).map_err(|_| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP disk number exceeds address space"),
        )
    })?;
    let start = *starts.get(index).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP record references an unavailable disk"),
        )
    })?;
    let finish = starts.get(index + 1).copied().unwrap_or(archive_end);
    let disk_length = finish.checked_sub(start).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Protocol)
                .with_format("zip")
                .with_context("split ZIP disk layout is non-monotonic"),
        )
    })?;
    if offset > disk_length {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context(context),
        ));
    }
    start.checked_add(offset).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("ZIP disk-relative offset overflow"),
        )
    })
}

#[allow(clippy::too_many_lines)]
fn parse_zip_index<R: Read + Seek>(
    input: &mut R,
    limits: Limits,
    disk_starts: Option<&[u64]>,
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
    let classic_this_disk = le16(&tail[eocd..], 4)?;
    let classic_central_disk = le16(&tail[eocd..], 6)?;
    let classic_count_on_disk = le16(&tail[eocd..], 8)?;
    let classic_count = le16(&tail[eocd..], 10)?;
    let classic_central_size = le32(&tail[eocd..], 12)?;
    let classic_central_offset = le32(&tail[eocd..], 16)?;
    let mut this_disk = u32::from(classic_this_disk);
    let mut central_disk = u32::from(classic_central_disk);
    let mut count_on_disk = u64::from(classic_count_on_disk);
    let mut count = u64::from(classic_count);
    let mut central_size = u64::from(classic_central_size);
    let mut central_relative = u64::from(classic_central_offset);
    let zip64 = classic_this_disk == u16::MAX
        || classic_central_disk == u16::MAX
        || classic_count_on_disk == u16::MAX
        || classic_count == u16::MAX
        || classic_central_size == u32::MAX
        || classic_central_offset == u32::MAX;
    let mut zip64_record_absolute = None;
    if zip64 {
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
        let locator_disk = le32(&locator, 4)?;
        let record_offset = zip_disk_offset(
            disk_starts,
            end,
            locator_disk,
            le64(&locator, 8)?,
            "ZIP64 end record offset is outside its declared disk",
        )?;
        let total_disks = le32(&locator, 16)?;
        validate_zip_disk_count(disk_starts, total_disks)?;
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
        if le64(&record, 4)? < 44 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("ZIP64 end record is shorter than its fixed fields"),
            ));
        }
        this_disk = le32(&record, 16)?;
        central_disk = le32(&record, 20)?;
        count_on_disk = le64(&record, 24)?;
        count = le64(&record, 32)?;
        central_size = le64(&record, 40)?;
        central_relative = le64(&record, 48)?;
        if locator_disk != this_disk {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("ZIP64 locator and end record disk numbers disagree"),
            ));
        }
        zip64_record_absolute = Some(record_offset);
    }
    validate_zip_disk_topology(disk_starts, this_disk, central_disk, count_on_disk, count)?;
    let central_offset = zip_disk_offset(
        disk_starts,
        end,
        central_disk,
        central_relative,
        "central-directory offset is outside its declared disk",
    )?;
    let central_end = central_offset.checked_add(central_size).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("central-directory extent overflow"),
        )
    })?;
    if central_end > zip64_record_absolute.unwrap_or(eocd_absolute) {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("central directory overlaps its end records"),
        ));
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
        let dos_time = le16(&fixed, 12)?;
        let crc32 = le32(&fixed, 16)?;
        let compressed32 = le32(&fixed, 20)?;
        let uncompressed32 = le32(&fixed, 24)?;
        let name_length = usize::from(le16(&fixed, 28)?);
        let extra_length = usize::from(le16(&fixed, 30)?);
        let comment_length = usize::from(le16(&fixed, 32)?);
        let disk16 = le16(&fixed, 34)?;
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
        let (uncompressed_size, compressed_size, local_relative, local_disk) =
            zip64_values(extra, uncompressed32, compressed32, local32, disk16)?;
        let local_offset = zip_disk_offset(
            disk_starts,
            end,
            local_disk,
            local_relative,
            "local-header offset is outside its declared disk",
        )?;
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
        let owner = zip_unix_owner(extra)?;
        let mut builder = EntryMetadata::builder(
            kind,
            ArchivePath::try_from_encoded(name.to_vec(), encoding)?,
        )
        .size(Some(uncompressed_size))
        .mode((unix_mode != 0).then_some(unix_mode & 0o7777))
        .owner(owner)
        .encrypted(flags & 0x0001 != 0)
        .file_flags(u64::from(dos_attributes & !0x10))
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
            dos_time,
            crc32,
            compressed_size,
            uncompressed_size,
            local_offset,
            aes_real_method,
            aes_strength,
        });
    }
    let parsed_central_end = input.stream_position().map_err(StreamError::io)?;
    if parsed_central_end > central_end {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("central-directory records exceed the declared extent"),
        ));
    }
    hydrate_zip_symlink_targets(input, &mut entries, limits, &mut metadata_used)?;
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
    metadata_used: &mut usize,
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
        if zip_metadata_method_supported(entry.method) {
            let projected = metadata_used.checked_add(target_len).ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zip")
                        .with_context("ZIP symbolic-link metadata accounting overflow"),
                )
            })?;
            if limits
                .metadata_bytes()
                .is_some_and(|limit| projected > limit)
            {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zip")
                        .with_context("ZIP symbolic-link targets exceed metadata limit"),
                ));
            }
        }
        let Some(target) = read_zip_metadata_payload(input, entry, target_len, limits)? else {
            continue;
        };
        *metadata_used = metadata_used.checked_add(target.len()).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP symbolic-link metadata accounting overflow"),
            )
        })?;
        if limits
            .metadata_bytes()
            .is_some_and(|limit| *metadata_used > limit)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("zip")
                    .with_context("ZIP symbolic-link targets exceed metadata limit"),
            ));
        }
        let encoding = if core::str::from_utf8(&target).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        entry.metadata = entry
            .metadata
            .clone()
            .into_builder()
            .link_target(Some(ArchivePath::try_from_encoded(target, encoding)?))
            .build();
    }
    Ok(())
}

fn zip_metadata_method_supported(method: u16) -> bool {
    matches!(method, 0 | 8) || cfg!(feature = "gzip") && method == 9
}

fn read_zip_metadata_payload<R: Read + Seek>(
    input: &mut R,
    entry: &ZipIndex,
    expected_size: usize,
    limits: Limits,
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
        8 => inflate_zip_metadata_payload(input, entry, expected_size, limits)?,
        #[cfg(feature = "gzip")]
        9 => inflate64_zip_metadata_payload(input, entry, expected_size)?,
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

#[cfg(feature = "gzip")]
#[allow(clippy::too_many_lines)]
fn inflate64_zip_metadata_payload<R: Read>(
    input: &mut R,
    entry: &ZipIndex,
    expected_size: usize,
) -> Result<Vec<u8>, StreamError> {
    let mut compressed_remaining = entry.compressed_size;
    let mut compressed = Vec::with_capacity(BUFFER);
    let mut compressed_start = 0;
    let mut state = InflaterManaged::new();
    let mut output = Vec::with_capacity(expected_size);
    let mut scratch = vec![0_u8; BUFFER];
    loop {
        if compressed_start == compressed.len() && compressed_remaining != 0 {
            let count = usize::try_from(compressed_remaining.min(BUFFER as u64)).map_err(|_| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zip")
                        .with_context(
                            "compressed Deflate64 symbolic-link payload exceeds address space",
                        ),
                )
            })?;
            compressed.resize(count, 0);
            input.read_exact(&mut compressed).map_err(StreamError::io)?;
            compressed_remaining -= count as u64;
            compressed_start = 0;
        }

        let result = inflate64_extent_step(
            &mut state,
            &compressed[compressed_start..],
            compressed_remaining,
            &mut scratch,
        );
        compressed_start += result.bytes_consumed;
        if result.data_error || state.errored() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("invalid symbolic-link Deflate64 payload"),
            ));
        }
        if output
            .len()
            .checked_add(result.bytes_written)
            .is_none_or(|size| size > expected_size)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Integrity)
                    .with_format("zip")
                    .with_context("Deflate64 symbolic-link target exceeds declared size"),
            ));
        }
        output.extend_from_slice(&scratch[..result.bytes_written]);

        if state.finished() {
            if compressed_start != compressed.len() || compressed_remaining != 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Integrity)
                        .with_format("zip")
                        .with_context(
                            "Deflate64 symbolic-link stream ended before its compressed extent",
                        ),
                ));
            }
            if output.len() != expected_size {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Integrity)
                        .with_format("zip")
                        .with_context("Deflate64 symbolic-link target size is inconsistent"),
                ));
            }
            return Ok(output);
        }

        if result.bytes_consumed == 0 && result.bytes_written == 0 {
            if compressed_remaining == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("truncated symbolic-link Deflate64 payload"),
                ));
            }
            let retained = compressed.len().saturating_sub(compressed_start);
            compressed.copy_within(compressed_start.., 0);
            compressed.truncate(retained);
            let available = BUFFER.checked_sub(retained).ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("symbolic-link Deflate64 decoder made no progress"),
                )
            })?;
            if available == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("symbolic-link Deflate64 decoder made no progress"),
                ));
            }
            let count =
                usize::try_from(compressed_remaining.min(available as u64)).map_err(|_| {
                    StreamError::archive(
                        ArchiveError::new(ErrorKind::Limit)
                            .with_format("zip")
                            .with_context(
                                "compressed Deflate64 symbolic-link payload exceeds address space",
                            ),
                    )
                })?;
            let old_len = compressed.len();
            compressed.resize(
                old_len.checked_add(count).ok_or_else(|| {
                    StreamError::archive(
                        ArchiveError::new(ErrorKind::Limit)
                            .with_format("zip")
                            .with_context("Deflate64 symbolic-link input buffer length overflow"),
                    )
                })?,
                0,
            );
            input
                .read_exact(&mut compressed[old_len..])
                .map_err(StreamError::io)?;
            compressed_remaining -= count as u64;
            compressed_start = 0;
        }
    }
}

fn inflate_zip_metadata_payload<R: Read>(
    input: &mut R,
    entry: &ZipIndex,
    expected_size: usize,
    limits: Limits,
) -> Result<Vec<u8>, StreamError> {
    let mut compressed_remaining = entry.compressed_size;
    let mut compressed = Vec::with_capacity(BUFFER);
    let mut compressed_start = 0;
    let mut state = RawInflateDecoder::with_limits(limits).map_err(StreamError::archive)?;
    let mut output = Vec::with_capacity(expected_size);
    let mut scratch = vec![0_u8; BUFFER];
    loop {
        if compressed_start == compressed.len() && compressed_remaining != 0 {
            let count = usize::try_from(compressed_remaining.min(BUFFER as u64)).map_err(|_| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zip")
                        .with_context("compressed symbolic-link payload exceeds address space"),
                )
            })?;
            compressed.resize(count, 0);
            input.read_exact(&mut compressed).map_err(StreamError::io)?;
            compressed_remaining -= count as u64;
            compressed_start = 0;
        }

        let encoded = &compressed[compressed_start..];
        let end = if compressed_remaining == 0 {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let step = state
            .process(encoded, &mut scratch, end)
            .and_then(|step| step.validate(encoded.len(), scratch.len()))
            .map_err(StreamError::archive)?;
        compressed_start += step.consumed;
        if output
            .len()
            .checked_add(step.produced)
            .is_none_or(|size| size > expected_size)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Integrity)
                    .with_format("zip")
                    .with_context("symbolic-link target exceeds declared size"),
            ));
        }
        output.extend_from_slice(&scratch[..step.produced]);
        match step.status {
            CodecStatus::Done => {
                if compressed_start != compressed.len()
                    || compressed_remaining != 0
                    || output.len() != expected_size
                {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Integrity)
                            .with_format("zip")
                            .with_context("symbolic-link deflate extent is inconsistent"),
                    ));
                }
                return Ok(output);
            },
            CodecStatus::NeedInput | CodecStatus::NeedOutput
                if step.consumed != 0 || step.produced != 0 => {},
            CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("symbolic-link deflate decoder made no progress"),
                ));
            },
            _ => {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("zip")
                        .with_context("symbolic-link deflate decoder returned an unknown status"),
                ));
            },
        }
    }
}

fn zip64_values(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local: u32,
    disk: u16,
) -> Result<(u64, u64, u64, u32), StreamError> {
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
    let disk = if disk == u16::MAX {
        if zip64.len() < 4 {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated ZIP64 disk number"),
            ));
        }
        le32(zip64, 0)?
    } else {
        u32::from(disk)
    };
    Ok((uncompressed, compressed, local, disk))
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
                    *destination = Some(Timestamp::from_seconds(i64::from(i32::from_le_bytes(
                        seconds,
                    ))));
                    position += 4;
                }
            },
            0x000a if value.len() >= 4 => {
                parse_ntfs_times(&value[4..], &mut times)?;
            },
            0x5855 if value.len() >= 8 => {
                if let Some(bytes) = value
                    .get(0..4)
                    .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
                {
                    times.accessed = Some(Timestamp::from_seconds(i64::from(i32::from_le_bytes(
                        bytes,
                    ))));
                }
                if let Some(bytes) = value
                    .get(4..8)
                    .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
                {
                    times.modified = Some(Timestamp::from_seconds(i64::from(i32::from_le_bytes(
                        bytes,
                    ))));
                }
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

/// Parses Info-ZIP numeric uid/gid from the central-directory extra fields.
///
/// Only the New Unix field (`Ux`, 0x7855) is read for ownership: when its body is
/// present it is `uid`(2), `gid`(2). The older Unix field (`UX`, 0x5855) is *not*
/// read for uid/gid here — its central-directory form is defined as access and
/// modification times only (uid/gid appear only in the local header), so reading
/// bytes 8..12 of a central `UX` field would be a positional guess; those times
/// are surfaced by [`zip_times`] instead. Truncated fields are structured errors;
/// absent fields leave the id unset. Info-ZIP archives that place uid/gid solely
/// in the local header are not surfaced by this central-directory reader (the raw
/// fields are still preserved); arca records uid/gid in the central directory on
/// write so its own round trips keep ownership. [`zip_times`] runs first and
/// rejects a malformed extra header before this parser is reached.
fn zip_unix_owner(extra: &[u8]) -> Result<Owner, StreamError> {
    let mut owner = Owner::default();
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start.checked_add(length).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("Unix extra field length overflow"),
            )
        })?;
        let value = extra.get(start..finish).ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("truncated Unix extra field"),
            )
        })?;
        if id == 0x7855 && value.len() >= 4 {
            owner.uid = Some(u64::from(le16(value, 0)?));
            owner.gid = Some(u64::from(le16(value, 2)?));
        }
        cursor = finish;
    }
    Ok(owner)
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
    Timestamp::new(
        i64::try_from(seconds).ok()?,
        u32::try_from(ticks % TICKS_PER_SECOND)
            .ok()?
            .checked_mul(100)?,
    )
    .ok()
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
