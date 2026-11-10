// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Incremental ZIP writer used by the common sync and async drivers.

#[cfg(feature = "bzip2")]
use bzip2::{Action, Compress, Compression, Status as BzStatus};
#[cfg(feature = "native-codecs")]
use compression_codecs::Encode;
#[cfg(feature = "native-codecs")]
use compression_codecs::core::util::PartialBuffer;
use libarchive_oxide_core::{
    ArchiveEncoder, ArchiveError, ArchiveMetadata, Codec, CodecStatus, EncodeCommand, EncodeStatus,
    EncodeStep, EndOfInput, EntryKind, EntryMetadata, EntryTimes, ErrorKind, Extension, Limits,
    Owner, PathEncoding, Timestamp,
};

#[cfg(feature = "zstd")]
use crate::Backend;
use crate::BackendPreference;
use crate::filter::gzip::{Crc32, RawDeflateEncoder};
#[cfg(feature = "aes")]
use crate::zipcrypto::ZipCrypto;
#[cfg(feature = "aes")]
use crate::{AesStrength, SecretBytes};

const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 0x0001;
const ZIP_DOS_FILE_FLAGS: u64 = 0x0000_00ef;
const AES_EXTRA: u16 = 0x9901;
const UNICODE_PATH_EXTRA: u16 = 0x7075;
const UNICODE_COMMENT_EXTRA: u16 = 0x6375;
/// Info-ZIP Extended Timestamp extra field (`UT`).
const EXTENDED_TIMESTAMP_EXTRA: u16 = 0x5455;
/// NTFS timestamps extra field (0x000a): also carries modification/access/change times.
const NTFS_TIMESTAMP_EXTRA: u16 = 0x000a;
/// Info-ZIP New Unix extra field (`Ux`): numeric uid/gid.
const INFOZIP_UNIX_NEW_EXTRA: u16 = 0x7855;
/// Info-ZIP Unix extra field (`UX`): access/modification time (uid/gid live in the local header).
const INFOZIP_UNIX_OLD_EXTRA: u16 = 0x5855;
const U16_SENTINEL: u16 = u16::MAX;
const U32_SENTINEL: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
pub(crate) enum StreamZipMethod {
    Store,
    Deflate,
    #[cfg(feature = "bzip2")]
    Bzip2,
    #[cfg(feature = "zstd")]
    Zstd,
    #[cfg(feature = "xz")]
    Lzma,
    #[cfg(feature = "xz")]
    Xz,
    #[cfg(feature = "ppmd")]
    Ppmd8,
}

/// Deterministic LZMA preset for ZIP member production (method 14).
///
/// Preset 6 yields props byte 93 (lc=3, lp=0, pb=2) and an 8 MiB dictionary,
/// matching CPython/liblzma's default ZIP-LZMA header. Consumers compare
/// decoded content, not compressed bytes.
#[cfg(feature = "xz")]
const ZIP_LZMA_PRESET: u32 = 6;

/// Informational LZMA SDK version bytes written into the ZIP-LZMA header.
///
/// Decoder-ignored (the `zip` crate reads it into a dropped field; `CPython`
/// emits `[9, 4]`); any value is spec-valid.
#[cfg(feature = "xz")]
const ZIP_LZMA_VERSION: [u8; 2] = [9, 20];

/// Reproducible ZIP method-98 writer profile.
#[cfg(feature = "ppmd")]
const ZIP_PPMD_ORDER: u32 = 8;
#[cfg(feature = "ppmd")]
const ZIP_PPMD_MEMORY: u32 = 8 * 1024 * 1024;

/// In-crate `std::io::Write` sink that appends into an owned `Vec<u8>`.
///
/// `LzmaWriter` owns its output, but the ZIP writer must drain compressed
/// bytes between `write` calls; this sink is reached via `inner_mut().0`.
/// Keeps `#![forbid(unsafe_code)]` intact and adds no trait object.
#[cfg(any(feature = "xz", feature = "ppmd"))]
struct VecSink(Vec<u8>);

#[cfg(any(feature = "xz", feature = "ppmd"))]
impl std::io::Write for VecSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deterministic Zstandard compression level for ZIP member production.
///
/// Pinned so interop byte comparisons stay stable across `compression-codecs`
/// patch releases; consumers compare decoded content, not compressed bytes.
#[cfg(all(feature = "zstd", feature = "native-codecs"))]
const ZIP_ZSTD_LEVEL: i32 = 3;

#[cfg(feature = "zstd")]
enum ZipZstdEncoder {
    Portable(Box<crate::filter::zstd::ZstdEncoder>),
    #[cfg(feature = "native-codecs")]
    Native(compression_codecs::ZstdEncoder),
}

#[cfg(feature = "zstd")]
impl ZipZstdEncoder {
    fn new(backend: Backend, limits: Limits) -> Result<Self, ArchiveError> {
        match backend {
            Backend::Portable => crate::filter::zstd::ZstdEncoder::with_limits(limits)
                .map(Box::new)
                .map(Self::Portable),
            Backend::Native => {
                #[cfg(feature = "native-codecs")]
                {
                    Ok(Self::Native(compression_codecs::ZstdEncoder::new(
                        ZIP_ZSTD_LEVEL,
                    )))
                }
                #[cfg(not(feature = "native-codecs"))]
                {
                    Err(ArchiveError::new(ErrorKind::Capability)
                        .with_format("zip")
                        .with_context("native ZIP zstd encoder is not compiled"))
                }
            },
        }
    }

    fn encode(&mut self, data: &[u8], output: &mut [u8]) -> Result<(usize, usize), ArchiveError> {
        match self {
            Self::Portable(encoder) => {
                let step = encoder
                    .process(data, output, EndOfInput::More)?
                    .validate(data.len(), output.len())?;
                Ok((step.consumed, step.produced))
            },
            #[cfg(feature = "native-codecs")]
            Self::Native(encoder) => {
                let mut source = PartialBuffer::new(data);
                let mut destination = PartialBuffer::new(output);
                encoder.encode(&mut source, &mut destination).map_err(|_| {
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("ZIP zstd encoder failed")
                })?;
                Ok((source.written_len(), destination.written_len()))
            },
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<(usize, bool), ArchiveError> {
        match self {
            Self::Portable(encoder) => {
                let step = encoder
                    .process(&[], output, EndOfInput::End)?
                    .validate(0, output.len())?;
                Ok((step.produced, step.status == CodecStatus::Done))
            },
            #[cfg(feature = "native-codecs")]
            Self::Native(encoder) => {
                let mut destination = PartialBuffer::new(output);
                let done = encoder.finish(&mut destination).map_err(|_| {
                    ArchiveError::new(ErrorKind::Malformed)
                        .with_format("zip")
                        .with_context("ZIP zstd finalization failed")
                })?;
                Ok((destination.written_len(), done))
            },
        }
    }
}

#[derive(Debug)]
struct CentralRecord {
    name: Vec<u8>,
    comment: Vec<u8>,
    extra: Vec<u8>,
    method: u16,
    flags: u16,
    crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    external_attributes: u32,
    dos_time: u16,
    dos_date: u16,
    zip64_size: bool,
    aes_real_method: Option<u16>,
}

#[cfg(feature = "aes")]
enum ZipAesCipher {
    Bits128(ctr::Ctr128LE<aes::Aes128>),
    Bits192(ctr::Ctr128LE<aes::Aes192>),
    Bits256(ctr::Ctr128LE<aes::Aes256>),
}

#[cfg(feature = "aes")]
impl ZipAesCipher {
    fn apply_keystream(&mut self, bytes: &mut [u8]) {
        use ctr::cipher::StreamCipher;

        match self {
            Self::Bits128(cipher) => cipher.apply_keystream(bytes),
            Self::Bits192(cipher) => cipher.apply_keystream(bytes),
            Self::Bits256(cipher) => cipher.apply_keystream(bytes),
        }
    }
}

#[cfg(feature = "aes")]
struct ZipAesEncoder {
    cipher: ZipAesCipher,
    mac: hmac::Hmac<sha1::Sha1>,
}

#[cfg(feature = "aes")]
impl core::fmt::Debug for ZipAesEncoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZipAesEncoder([REDACTED])")
    }
}

#[cfg(feature = "aes")]
impl ZipAesEncoder {
    fn new(password: &[u8], strength: AesStrength) -> Result<(Self, Vec<u8>), ArchiveError> {
        use ctr::cipher::KeyIvInit;
        use hmac::digest::KeyInit;
        use zeroize::Zeroize;

        let (key_len, salt_len) = match strength {
            AesStrength::Bits128 => (16, 8),
            AesStrength::Bits192 => (24, 12),
            AesStrength::Bits256 => (32, 16),
        };
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt[..salt_len]).map_err(|_| {
            ArchiveError::new(ErrorKind::Integrity)
                .with_format("zip")
                .with_context("OS random generator failed for WinZip AES salt")
        })?;
        let mut key_material = [0_u8; 66];
        let material_len = key_len * 2 + 2;
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            password,
            &salt[..salt_len],
            1_000,
            &mut key_material[..material_len],
        );
        let mut counter = [0_u8; 16];
        counter[0] = 1;
        let cipher = match strength {
            AesStrength::Bits128 => {
                ctr::Ctr128LE::<aes::Aes128>::new_from_slices(&key_material[..key_len], &counter)
                    .map(ZipAesCipher::Bits128)
            },
            AesStrength::Bits192 => {
                ctr::Ctr128LE::<aes::Aes192>::new_from_slices(&key_material[..key_len], &counter)
                    .map(ZipAesCipher::Bits192)
            },
            AesStrength::Bits256 => {
                ctr::Ctr128LE::<aes::Aes256>::new_from_slices(&key_material[..key_len], &counter)
                    .map(ZipAesCipher::Bits256)
            },
        }
        .map_err(|_| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("WinZip AES cipher initialization failed")
        })?;
        let mac = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(
            &key_material[key_len..key_len * 2],
        )
        .map_err(|_| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("WinZip AES MAC initialization failed")
        })?;
        let mut framing = Vec::with_capacity(salt_len + 2);
        framing.extend_from_slice(&salt[..salt_len]);
        framing.extend_from_slice(&key_material[key_len * 2..material_len]);
        key_material.zeroize();
        Ok((Self { cipher, mac }, framing))
    }

    fn encrypt(&mut self, bytes: &mut [u8]) {
        use hmac::Mac;

        self.cipher.apply_keystream(bytes);
        self.mac.update(bytes);
    }

    fn authentication(&self) -> [u8; 10] {
        use hmac::Mac;

        let digest = self.mac.clone().finalize().into_bytes();
        let mut authentication = [0_u8; 10];
        authentication.copy_from_slice(&digest[..10]);
        authentication
    }
}

struct OpenEntry {
    name: Vec<u8>,
    comment: Vec<u8>,
    extra: Vec<u8>,
    method: u16,
    payload_method: u16,
    flags: u16,
    crc: Crc32,
    compressed_size: u64,
    uncompressed_size: u64,
    expected_size: Option<u64>,
    metadata_payload: Vec<u8>,
    metadata_payload_position: usize,
    local_offset: u64,
    external_attributes: u32,
    dos_time: u16,
    dos_date: u16,
    zip64_size: bool,
    compressor: Option<RawDeflateEncoder>,
    #[cfg(feature = "bzip2")]
    bz_compress: Option<Compress>,
    #[cfg(feature = "zstd")]
    zstd: Option<ZipZstdEncoder>,
    #[cfg(feature = "xz")]
    lzma: Option<lzma_rust2::LzmaWriter<VecSink>>,
    #[cfg(feature = "xz")]
    lzma_tail: Vec<u8>,
    #[cfg(feature = "xz")]
    xz: Option<lzma_rust2::XzWriter<VecSink>>,
    #[cfg(feature = "xz")]
    xz_tail: Vec<u8>,
    #[cfg(feature = "ppmd")]
    ppmd: Option<ppmd_rust::Ppmd8Encoder<VecSink>>,
    #[cfg(feature = "ppmd")]
    ppmd_tail: Vec<u8>,
    #[cfg(feature = "aes")]
    aes: Option<ZipAesEncoder>,
    #[cfg(feature = "aes")]
    zipcrypto: Option<ZipCrypto>,
}

impl core::fmt::Debug for OpenEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenEntry")
            .field("name", &self.name)
            .field("method", &self.method)
            .field("payload_method", &self.payload_method)
            .field("compressed_size", &self.compressed_size)
            .field("uncompressed_size", &self.uncompressed_size)
            .field(
                "metadata_payload_remaining",
                &self
                    .metadata_payload
                    .len()
                    .saturating_sub(self.metadata_payload_position),
            )
            .field("zip64_size", &self.zip64_size)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum Phase {
    Ready,
    Open(Box<OpenEntry>),
    Central { next: usize, start: u64 },
    FinalBytes,
    Done,
}

#[cfg(feature = "aes")]
#[derive(Debug, Clone, Copy)]
enum ZipStreamEncryption {
    Aes(AesStrength),
    ZipCrypto,
}

#[derive(Debug, Default)]
struct StructuredZipMetadata {
    times: EntryTimes,
    time_covered: [bool; 4],
    owner: Owner,
    owner_covered: bool,
}

fn structured_zip_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("zip")
        .with_context(context)
}

fn body_u16(body: &[u8], offset: usize) -> Result<u16, ArchiveError> {
    let bytes: [u8; 2] = body
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| {
            structured_zip_error(ErrorKind::Malformed, "truncated structured ZIP extra field")
        })?;
    Ok(u16::from_le_bytes(bytes))
}

fn body_u64(body: &[u8], offset: usize) -> Result<u64, ArchiveError> {
    let bytes: [u8; 8] = body
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| {
            structured_zip_error(ErrorKind::Malformed, "truncated structured ZIP extra field")
        })?;
    Ok(u64::from_le_bytes(bytes))
}

fn zip_filetime_timestamp(ticks: u64) -> Option<Timestamp> {
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

fn parse_ntfs_extra(
    value: &[u8],
    structured: &mut StructuredZipMetadata,
) -> Result<(), ArchiveError> {
    if value.len() < 4 {
        return Ok(());
    }
    let mut tags = &value[4..];
    while tags.len() >= 4 {
        let tag = body_u16(tags, 0)?;
        let size = usize::from(body_u16(tags, 2)?);
        let end = 4_usize.checked_add(size).ok_or_else(|| {
            structured_zip_error(ErrorKind::Malformed, "NTFS ZIP tag length overflow")
        })?;
        let body = tags.get(4..end).ok_or_else(|| {
            structured_zip_error(ErrorKind::Malformed, "truncated NTFS ZIP timestamp tag")
        })?;
        if tag == 1 && body.len() >= 24 {
            structured.times.modified = zip_filetime_timestamp(body_u64(body, 0)?);
            structured.times.accessed = zip_filetime_timestamp(body_u64(body, 8)?);
            structured.times.created = zip_filetime_timestamp(body_u64(body, 16)?);
            structured.time_covered[0] = true;
            structured.time_covered[1] = true;
            structured.time_covered[3] = true;
        }
        tags = &tags[end..];
    }
    if !tags.is_empty() {
        return Err(structured_zip_error(
            ErrorKind::Malformed,
            "truncated NTFS ZIP tag header",
        ));
    }
    Ok(())
}

fn parse_structured_zip_metadata(
    metadata: &EntryMetadata,
) -> Result<StructuredZipMetadata, ArchiveError> {
    let mut structured = StructuredZipMetadata::default();
    for extension in metadata.extensions() {
        if extension.namespace() != "zip-extra" {
            continue;
        }
        let [low, high] = extension.key() else {
            continue;
        };
        let id = u16::from_le_bytes([*low, *high]);
        let value = extension.value();
        match id {
            EXTENDED_TIMESTAMP_EXTRA if !value.is_empty() => {
                let mut position = 1;
                for (index, bit) in [0x01_u8, 0x02, 0x04].into_iter().enumerate() {
                    if value[0] & bit == 0 {
                        continue;
                    }
                    let bytes: [u8; 4] = value
                        .get(position..position + 4)
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(|| {
                            structured_zip_error(
                                ErrorKind::Malformed,
                                "truncated extended ZIP timestamp",
                            )
                        })?;
                    let timestamp = Some(Timestamp::from_seconds(i64::from(i32::from_le_bytes(
                        bytes,
                    ))));
                    match index {
                        0 => structured.times.modified = timestamp,
                        1 => structured.times.accessed = timestamp,
                        _ => structured.times.changed = timestamp,
                    }
                    structured.time_covered[index] = true;
                    position += 4;
                }
            },
            NTFS_TIMESTAMP_EXTRA => parse_ntfs_extra(value, &mut structured)?,
            INFOZIP_UNIX_OLD_EXTRA if value.len() >= 8 => {
                let accessed = i32::from_le_bytes(value[..4].try_into().unwrap_or([0; 4]));
                let modified = i32::from_le_bytes(value[4..8].try_into().unwrap_or([0; 4]));
                structured.times.accessed = Some(Timestamp::from_seconds(i64::from(accessed)));
                structured.times.modified = Some(Timestamp::from_seconds(i64::from(modified)));
                structured.time_covered[0] = true;
                structured.time_covered[1] = true;
            },
            INFOZIP_UNIX_NEW_EXTRA if value.len() >= 4 => {
                structured.owner.uid = Some(u64::from(body_u16(value, 0)?));
                structured.owner.gid = Some(u64::from(body_u16(value, 2)?));
                structured.owner_covered = true;
            },
            _ => {},
        }
    }
    Ok(structured)
}

fn validate_zip_typed_metadata(
    metadata: &EntryMetadata,
    structured: &StructuredZipMetadata,
) -> Result<(), ArchiveError> {
    let owner = metadata.owner();
    let owner_ids_supported = if structured.owner_covered {
        owner.uid == structured.owner.uid && owner.gid == structured.owner.gid
    } else {
        match (owner.uid, owner.gid) {
            (None, None) => true,
            (Some(uid), Some(gid)) => u16::try_from(uid).is_ok() && u16::try_from(gid).is_ok(),
            _ => false,
        }
    };
    let times = metadata.times();
    let requested = [times.modified, times.accessed, times.changed, times.created];
    let raw = [
        structured.times.modified,
        structured.times.accessed,
        structured.times.changed,
        structured.times.created,
    ];
    let times_supported = requested.into_iter().enumerate().all(|(index, timestamp)| {
        if structured.time_covered[index] {
            timestamp == raw[index]
        } else if index == 3 {
            timestamp.is_none()
        } else {
            timestamp.is_none_or(|value| {
                value.nanoseconds() == 0 && i32::try_from(value.seconds()).is_ok()
            })
        }
    });
    if !matches!(
        metadata.kind(),
        EntryKind::File | EntryKind::Dir | EntryKind::Symlink
    ) || owner.user.is_some()
        || owner.group.is_some()
        || !owner_ids_supported
        || !times_supported
        || metadata.mode().is_some_and(|mode| mode > 0o7777)
        || metadata.inode().is_some()
        || metadata.links().is_some()
        || metadata.device().is_some()
        || metadata.referenced_device().is_some()
        || !metadata.sparse_extents().is_empty()
        || !metadata.xattrs().is_empty()
        || !metadata.acl().is_empty()
        || metadata.file_flags() & !ZIP_DOS_FILE_FLAGS != 0
        || metadata.checksum().is_some()
        || metadata.is_encrypted()
        || metadata.comment().is_some_and(<[u8]>::is_empty)
    {
        return Err(structured_zip_error(
            ErrorKind::Unsupported,
            "ZIP cannot represent requested typed entry metadata",
        ));
    }
    Ok(())
}

fn validate_applicable_unicode_extra(
    metadata: &EntryMetadata,
    wanted: u16,
    serialized: &[u8],
    require_utf8_path: bool,
) -> Result<(), ArchiveError> {
    for extension in metadata.extensions() {
        if extension.namespace() != "zip-extra" {
            continue;
        }
        let [low, high] = extension.key() else {
            continue;
        };
        if u16::from_le_bytes([*low, *high]) != wanted {
            continue;
        }
        let value = extension.value();
        if value.len() < 5
            || value[0] != 1
            || u32::from_le_bytes(value[1..5].try_into().unwrap_or([0; 4]))
                != crate::filter::crc32(serialized)
        {
            continue;
        }
        core::str::from_utf8(&value[5..]).map_err(|_| {
            structured_zip_error(ErrorKind::Malformed, "Unicode ZIP extra is not UTF-8")
        })?;
        if value[5..] != *serialized
            || (require_utf8_path && !matches!(metadata.path().encoding(), PathEncoding::Utf8))
        {
            return Err(structured_zip_error(
                ErrorKind::Unsupported,
                "Unicode ZIP extra conflicts with typed entry metadata",
            ));
        }
        break;
    }
    Ok(())
}

fn validate_zip_unicode_metadata(
    metadata: &EntryMetadata,
    serialized_path: &[u8],
) -> Result<(), ArchiveError> {
    validate_applicable_unicode_extra(metadata, UNICODE_PATH_EXTRA, serialized_path, true)?;
    let comment = metadata.comment().unwrap_or_default();
    validate_applicable_unicode_extra(metadata, UNICODE_COMMENT_EXTRA, comment, false)
}

/// Data-descriptor ZIP encoder.
///
/// File payload is never retained. Only central-directory metadata is kept,
/// bounded by [`Limits::metadata_bytes`].
#[derive(Debug)]
pub(crate) struct ZipStreamEncoder {
    limits: Limits,
    #[cfg(feature = "zstd")]
    backend: BackendPreference,
    method: StreamZipMethod,
    phase: Phase,
    records: Vec<CentralRecord>,
    metadata_bytes: usize,
    total_input: u64,
    offset: u64,
    pending: Vec<u8>,
    pending_start: usize,
    archive_comment: Vec<u8>,
    #[cfg(feature = "aes")]
    password: Option<SecretBytes>,
    #[cfg(feature = "aes")]
    encryption: Option<ZipStreamEncryption>,
}

impl ZipStreamEncoder {
    pub(crate) fn with_method_and_backend(
        limits: Limits,
        method: StreamZipMethod,
        backend: BackendPreference,
    ) -> Self {
        #[cfg(not(feature = "zstd"))]
        let _ = backend;
        Self {
            limits,
            #[cfg(feature = "zstd")]
            backend,
            method,
            phase: Phase::Ready,
            records: Vec::new(),
            metadata_bytes: 0,
            total_input: 0,
            offset: 0,
            pending: Vec::new(),
            pending_start: 0,
            archive_comment: Vec::new(),
            #[cfg(feature = "aes")]
            password: None,
            #[cfg(feature = "aes")]
            encryption: None,
        }
    }

    pub(crate) fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), ArchiveError> {
        if !matches!(self.phase, Phase::Ready)
            || !self.records.is_empty()
            || self.offset != 0
            || self.pending_start != self.pending.len()
        {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP archive metadata must be set before the first entry",
            ));
        }
        if metadata.volume_name().is_some() || !metadata.extensions().is_empty() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "ZIP archive metadata contains an unrepresentable property",
            ));
        }
        if metadata.comment().is_some_and(<[u8]>::is_empty) {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "ZIP cannot distinguish an empty archive comment from no comment",
            ));
        }
        let comment = metadata.comment().unwrap_or_default();
        if comment.len() > usize::from(U16_SENTINEL) {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP archive comment exceeds format field",
            ));
        }
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| comment.len() > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP archive comment exceeds metadata budget",
            ));
        }
        self.archive_comment.clear();
        self.archive_comment.extend_from_slice(comment);
        Ok(())
    }

    #[cfg(feature = "aes")]
    pub(crate) fn with_password_and_backend(
        limits: Limits,
        method: StreamZipMethod,
        password: SecretBytes,
        strength: AesStrength,
        backend: BackendPreference,
    ) -> Self {
        let mut encoder = Self::with_method_and_backend(limits, method, backend);
        encoder.password = Some(password);
        encoder.encryption = Some(ZipStreamEncryption::Aes(strength));
        encoder
    }

    #[cfg(feature = "aes")]
    pub(crate) fn with_zipcrypto_password_and_backend(
        limits: Limits,
        method: StreamZipMethod,
        password: SecretBytes,
        backend: BackendPreference,
    ) -> Self {
        let mut encoder = Self::with_method_and_backend(limits, method, backend);
        encoder.password = Some(password);
        encoder.encryption = Some(ZipStreamEncryption::ZipCrypto);
        encoder
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("zip")
            .with_context(context)
    }

    fn queue(&mut self, bytes: Vec<u8>) -> Result<(), ArchiveError> {
        if self.pending_start != self.pending.len() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "attempted to replace undrained ZIP output",
            ));
        }
        self.pending = bytes;
        self.pending_start = 0;
        Ok(())
    }

    fn drain_pending(&mut self, output: &mut [u8]) -> Result<usize, ArchiveError> {
        let available = self.pending.len() - self.pending_start;
        let count = available.min(output.len());
        output[..count]
            .copy_from_slice(&self.pending[self.pending_start..self.pending_start + count]);
        self.pending_start += count;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
        if self.pending_start == self.pending.len() {
            self.pending.clear();
            self.pending_start = 0;
        }
        Ok(count)
    }

    fn has_pending(&self) -> bool {
        self.pending_start != self.pending.len()
    }

    #[allow(clippy::too_many_lines)]
    fn begin_entry(&mut self, metadata: &EntryMetadata) -> Result<(), ArchiveError> {
        if !matches!(self.phase, Phase::Ready) {
            return Err(Self::error(
                ErrorKind::Protocol,
                "begin-entry received while another ZIP command is active",
            ));
        }
        #[cfg(feature = "aes")]
        if metadata.kind() == EntryKind::Symlink && self.encryption.is_some() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted ZIP symbolic-link targets cannot be recovered as metadata",
            ));
        }
        if metadata
            .extensions()
            .iter()
            .any(|extension| !zip_entry_extension_supported(extension))
        {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "ZIP entry metadata contains an unrepresentable raw extension",
            ));
        }
        let structured = parse_structured_zip_metadata(metadata)?;
        validate_zip_typed_metadata(metadata, &structured)?;
        if self
            .limits
            .entries()
            .is_some_and(|limit| self.records.len() as u64 >= limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry count exceeds configured limit",
            ));
        }
        let mut name = metadata.path().as_bytes().to_vec();
        if metadata.kind() == EntryKind::Dir && !name.ends_with(b"/") {
            name.push(b'/');
        }
        if self
            .limits
            .path_bytes()
            .is_some_and(|limit| name.len() > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP pathname exceeds configured limit",
            ));
        }
        if name.len() > usize::from(U16_SENTINEL) {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP pathname exceeds format field",
            ));
        }
        validate_zip_unicode_metadata(metadata, &name)?;
        let metadata_payload = if metadata.kind() == EntryKind::Symlink {
            let target = metadata.link_target().ok_or_else(|| {
                Self::error(
                    ErrorKind::Malformed,
                    "ZIP symbolic link is missing its target",
                )
            })?;
            if self
                .limits
                .path_bytes()
                .is_some_and(|limit| target.as_bytes().len() > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP symbolic-link target exceeds configured path limit",
                ));
            }
            if self
                .limits
                .in_flight_bytes()
                .is_some_and(|limit| target.as_bytes().len() > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP symbolic-link target exceeds in-flight memory limit",
                ));
            }
            let target_size = target.as_bytes().len() as u64;
            if metadata.size() != Some(target_size) {
                return Err(Self::error(
                    ErrorKind::Unsupported,
                    "ZIP symbolic-link size must equal its target length",
                ));
            }
            target.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        let comment = metadata.comment().unwrap_or_default().to_vec();
        if comment.len() > usize::from(U16_SENTINEL) {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP file comment exceeds format field",
            ));
        }
        let zip64_size = metadata
            .size()
            .is_none_or(|size| size >= u64::from(U32_SENTINEL));
        let mut preserved_extra = Vec::new();
        for extension in metadata
            .extensions()
            .iter()
            .filter(|extension| extension.namespace() == "zip-extra")
        {
            let [low, high] = extension.key() else {
                continue;
            };
            let id = u16::from_le_bytes([*low, *high]);
            if id == ZIP64_EXTRA || id == AES_EXTRA {
                continue;
            }
            let value_length = u16::try_from(extension.value().len()).map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "preserved ZIP extra field exceeds format field",
                )
            })?;
            push_u16(&mut preserved_extra, id);
            push_u16(&mut preserved_extra, value_length);
            preserved_extra.extend_from_slice(extension.value());
        }
        // Structured raw extras and typed metadata are validated as one logical value above.
        // Preserve the original bytes, then synthesize only fields that no raw extra covers.
        // This permits a raw mtime plus a typed atime without either losing the atime or duplicating the mtime.
        let times = metadata.times();
        push_extended_timestamp(
            &mut preserved_extra,
            EntryTimes {
                modified: (!structured.time_covered[0])
                    .then_some(times.modified)
                    .flatten(),
                accessed: (!structured.time_covered[1])
                    .then_some(times.accessed)
                    .flatten(),
                changed: (!structured.time_covered[2])
                    .then_some(times.changed)
                    .flatten(),
                created: None,
            },
        );
        if !structured.owner_covered {
            push_infozip_unix(&mut preserved_extra, metadata.owner());
        }
        // Reserve room for the ZIP64 extended-information field in BOTH headers.
        // The local header carries only the two sizes (20 bytes), but the central
        // header can also carry the local-header offset when it is >= 4 GiB, so a
        // size+offset entry needs 28 bytes there. Reserving only the local 20 let a
        // maximal preserved-extra block push the central extra past the u16 length
        // field, which `field_u16` would then clamp while the bytes were still
        // written — an 8-byte desync corrupting the central directory. Reserve the
        // larger of the two so the size check refuses the entry instead.
        let offset_zip64 = self.offset >= u64::from(U32_SENTINEL);
        let local_zip64_reserve = if zip64_size { 20 } else { 0 };
        let central_zip64_reserve = zip64_extra_reserve(zip64_size, offset_zip64);
        let maximum_extra =
            usize::from(U16_SENTINEL) - local_zip64_reserve.max(central_zip64_reserve);
        if preserved_extra.len() > maximum_extra {
            return Err(Self::error(
                ErrorKind::Limit,
                "combined ZIP extra fields exceed format field",
            ));
        }
        let added_metadata = name
            .len()
            .checked_add(comment.len())
            .and_then(|value| value.checked_add(preserved_extra.len()))
            .and_then(|value| value.checked_add(core::mem::size_of::<CentralRecord>()))
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP metadata accounting overflow"))?;
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(added_metadata)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| self.metadata_bytes > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP central-directory metadata exceeds configured limit",
            ));
        }

        let payload_method = if matches!(
            metadata.kind(),
            EntryKind::Dir | EntryKind::Symlink | EntryKind::Hardlink
        ) || matches!(self.method, StreamZipMethod::Store)
        {
            0
        } else {
            match self.method {
                #[cfg(feature = "bzip2")]
                StreamZipMethod::Bzip2 => 12,
                #[cfg(feature = "zstd")]
                StreamZipMethod::Zstd => 93,
                #[cfg(feature = "xz")]
                StreamZipMethod::Lzma => 14,
                #[cfg(feature = "xz")]
                StreamZipMethod::Xz => 95,
                #[cfg(feature = "ppmd")]
                StreamZipMethod::Ppmd8 => 98,
                _ => 8,
            }
        };
        #[cfg(feature = "aes")]
        let encryption = self.encryption;
        #[cfg(feature = "aes")]
        let encrypted = encryption.is_some();
        #[cfg(not(feature = "aes"))]
        let encrypted = false;
        #[cfg(feature = "aes")]
        let aes_strength = match encryption {
            Some(ZipStreamEncryption::Aes(strength)) => Some(strength),
            Some(ZipStreamEncryption::ZipCrypto) | None => None,
        };
        #[cfg(feature = "aes")]
        let aes_encrypted = aes_strength.is_some();
        #[cfg(not(feature = "aes"))]
        let aes_encrypted = false;
        let method = if aes_encrypted { 99 } else { payload_method };
        if aes_encrypted {
            #[cfg(feature = "aes")]
            push_aes_extra(
                &mut preserved_extra,
                payload_method,
                aes_strength.ok_or_else(|| {
                    Self::error(ErrorKind::Protocol, "ZIP AES strength disappeared")
                })?,
            );
            self.metadata_bytes = self
                .metadata_bytes
                .checked_add(11)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP metadata accounting overflow"))?;
            if self
                .limits
                .metadata_bytes()
                .is_some_and(|limit| self.metadata_bytes > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP central-directory metadata exceeds configured limit",
                ));
            }
            if preserved_extra.len() > maximum_extra {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "combined ZIP extra fields exceed format field",
                ));
            }
        }
        let utf8 = matches!(metadata.path().encoding(), PathEncoding::Utf8);
        // LZMA members set general-purpose bit 1 (0x0002) to signal the
        // end-of-stream-marker convention. It sits outside the 0x0809
        // local/central cross-check mask, so it never trips consistency checks.
        let lzma_flag = if payload_method == 14 { 0x0002 } else { 0 };
        let flags = 0x0008 | lzma_flag | if utf8 { 0x0800 } else { 0 } | u16::from(encrypted);
        let version_needed = if aes_encrypted {
            51
        } else if payload_method == 12 {
            46
        } else if matches!(payload_method, 14 | 93 | 95 | 98) {
            63
        } else if zip64_size {
            45
        } else {
            20
        };
        let (dos_time, dos_date) = dos_datetime(metadata.times().modified);
        let local_offset = self.offset;
        let mut local = Vec::with_capacity(50 + name.len());
        push_u32(&mut local, LOCAL_SIGNATURE);
        push_u16(&mut local, version_needed);
        push_u16(&mut local, flags);
        push_u16(&mut local, method);
        push_u16(&mut local, dos_time);
        push_u16(&mut local, dos_date);
        push_u32(&mut local, 0);
        push_u32(&mut local, if zip64_size { U32_SENTINEL } else { 0 });
        push_u32(&mut local, if zip64_size { U32_SENTINEL } else { 0 });
        push_u16(&mut local, field_u16(name.len()));
        push_u16(
            &mut local,
            field_u16(preserved_extra.len() + if zip64_size { 20 } else { 0 }),
        );
        local.extend_from_slice(&name);
        if zip64_size {
            push_u16(&mut local, ZIP64_EXTRA);
            push_u16(&mut local, 16);
            push_u64(&mut local, 0);
            push_u64(&mut local, 0);
        }
        local.extend_from_slice(&preserved_extra);
        #[cfg(feature = "aes")]
        let (aes, zipcrypto, encryption_framing) = match (self.password.as_ref(), encryption) {
            (Some(password), Some(ZipStreamEncryption::Aes(strength))) => {
                let (aes, framing) = ZipAesEncoder::new(password.expose(), strength)?;
                (Some(aes), None, framing)
            },
            (Some(password), Some(ZipStreamEncryption::ZipCrypto)) => {
                let mut framing = vec![0_u8; 12];
                getrandom::fill(&mut framing[..11]).map_err(|_| {
                    Self::error(
                        ErrorKind::Integrity,
                        "OS random generator failed for ZipCrypto header",
                    )
                })?;
                framing[11] = (dos_time >> 8) as u8;
                let mut zipcrypto = ZipCrypto::new(password.expose());
                zipcrypto.encrypt(&mut framing);
                (None, Some(zipcrypto), framing)
            },
            (None, None) => (None, None, Vec::new()),
            (Some(_), None) | (None, Some(_)) => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZIP encryption password and mode disagree",
                ));
            },
        };
        #[cfg(feature = "aes")]
        local.extend_from_slice(&encryption_framing);
        self.queue(local)?;
        let compressor = if payload_method == 8 {
            Some(RawDeflateEncoder::with_limits(self.limits)?)
        } else {
            None
        };
        #[cfg(feature = "bzip2")]
        let bz_compress = (payload_method == 12).then(|| Compress::new(Compression::new(6), 0));
        #[cfg(feature = "zstd")]
        let zstd = if payload_method == 93 {
            Some(ZipZstdEncoder::new(self.backend.resolve()?, self.limits)?)
        } else {
            None
        };
        // LZMA: preload the sink with the 9-byte ZIP-LZMA header, then wrap it
        // in a raw-LZMA1 writer (no container) that emits an EOS marker. The
        // header becomes the first bytes of the member payload.
        #[cfg(feature = "xz")]
        let lzma = if payload_method == 14 {
            let options = lzma_rust2::LzmaOptions::with_preset(ZIP_LZMA_PRESET);
            let mut sink = VecSink(Vec::new());
            sink.0.extend_from_slice(&ZIP_LZMA_VERSION);
            sink.0.extend_from_slice(&5_u16.to_le_bytes());
            sink.0.push(options.get_props());
            sink.0.extend_from_slice(&options.dict_size.to_le_bytes());
            Some(
                lzma_rust2::LzmaWriter::new_no_header(sink, &options, true).map_err(|_| {
                    Self::error(ErrorKind::Malformed, "ZIP lzma encoder setup failed")
                })?,
            )
        } else {
            None
        };
        #[cfg(feature = "xz")]
        let xz = if payload_method == 95 {
            let options = lzma_rust2::XzOptions::with_preset(ZIP_LZMA_PRESET);
            let required = u64::from(lzma_rust2::lzma2_get_memory_usage(
                options.lzma_options.dict_size,
            ))
            .checked_mul(1024)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP XZ workspace size overflow"))?;
            if self
                .limits
                .codec_memory()
                .is_some_and(|maximum| required > maximum as u64)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP XZ workspace exceeds codec memory limit",
                ));
            }
            Some(
                lzma_rust2::XzWriter::new(VecSink(Vec::new()), options).map_err(|_| {
                    Self::error(ErrorKind::Malformed, "ZIP XZ encoder setup failed")
                })?,
            )
        } else {
            None
        };
        #[cfg(feature = "ppmd")]
        let ppmd = if payload_method == 98 {
            if self
                .limits
                .codec_memory()
                .is_some_and(|maximum| ZIP_PPMD_MEMORY as usize > maximum)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP PPMd model exceeds codec workspace limit",
                ));
            }
            let memory_mb = u16::try_from(ZIP_PPMD_MEMORY / (1024 * 1024))
                .map_err(|_| Self::error(ErrorKind::Limit, "ZIP PPMd model size exceeds header"))?;
            let order = u16::try_from(ZIP_PPMD_ORDER)
                .map_err(|_| Self::error(ErrorKind::Limit, "ZIP PPMd order exceeds header"))?;
            let parameters = (order - 1)
                | ((memory_mb - 1) << 4)
                | ((ppmd_rust::RestoreMethod::Restart as u16) << 12);
            let mut sink = VecSink(Vec::with_capacity(2));
            sink.0.extend_from_slice(&parameters.to_le_bytes());
            Some(
                ppmd_rust::Ppmd8Encoder::new(
                    sink,
                    ZIP_PPMD_ORDER,
                    ZIP_PPMD_MEMORY,
                    ppmd_rust::RestoreMethod::Restart,
                )
                .map_err(|error| ppmd_error(&error, "ZIP PPMd encoder setup failed"))?,
            )
        } else {
            None
        };
        #[cfg(feature = "aes")]
        let initial_compressed_size = encryption_framing.len() as u64;
        #[cfg(not(feature = "aes"))]
        let initial_compressed_size = 0;
        self.phase = Phase::Open(Box::new(OpenEntry {
            name,
            comment,
            extra: preserved_extra,
            method,
            payload_method,
            flags,
            crc: Crc32::new(),
            compressed_size: initial_compressed_size,
            uncompressed_size: 0,
            expected_size: metadata.size(),
            metadata_payload,
            metadata_payload_position: 0,
            local_offset,
            external_attributes: external_attributes(
                metadata.kind(),
                metadata.mode().unwrap_or(0o644),
                metadata.file_flags(),
            ),
            dos_time,
            dos_date,
            zip64_size,
            compressor,
            #[cfg(feature = "bzip2")]
            bz_compress,
            #[cfg(feature = "zstd")]
            zstd,
            #[cfg(feature = "xz")]
            lzma,
            #[cfg(feature = "xz")]
            lzma_tail: Vec::new(),
            #[cfg(feature = "xz")]
            xz,
            #[cfg(feature = "xz")]
            xz_tail: Vec::new(),
            #[cfg(feature = "ppmd")]
            ppmd,
            #[cfg(feature = "ppmd")]
            ppmd_tail: Vec::new(),
            #[cfg(feature = "aes")]
            aes,
            #[cfg(feature = "aes")]
            zipcrypto,
        }));
        Ok(())
    }

    fn account_input(&mut self, count: usize) -> Result<(), ArchiveError> {
        self.total_input = self
            .total_input
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|limit| self.total_input > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP total input exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn deflate_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        let compressor = entry
            .compressor
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP deflate state is missing"))?;
        let step = compressor.process(data, output, EndOfInput::More)?;
        match step.status {
            CodecStatus::Done => Err(Self::error(
                ErrorKind::Protocol,
                "ZIP deflate ended before end-entry",
            )),
            CodecStatus::NeedInput | CodecStatus::NeedOutput => Ok((step.consumed, step.produced)),
            _ => Err(Self::error(
                ErrorKind::Protocol,
                "ZIP deflate encoder returned an unknown status",
            )),
        }
    }

    #[cfg(feature = "bzip2")]
    fn bzip2_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        let compressor = entry
            .bz_compress
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP bzip2 state is missing"))?;
        let before_in = compressor.total_in();
        let before_out = compressor.total_out();
        compressor
            .compress(data, output, Action::Run)
            .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP bzip2 encoder failed"))?;
        let consumed = usize::try_from(compressor.total_in() - before_in)
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP bzip2 consumed overflow"))?;
        let produced = usize::try_from(compressor.total_out() - before_out)
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP bzip2 output overflow"))?;
        Ok((consumed, produced))
    }

    // A native Zstandard encoder may buffer input internally and emit zero
    // output for small members; `(consumed, 0)` is valid back-pressure.
    #[cfg(feature = "zstd")]
    fn zstd_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        let encoder = entry
            .zstd
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP zstd state is missing"))?;
        encoder.encode(data, output)
    }

    // LZMA drives a pull-free sink: `write_all` consumes ALL input (filling the
    // LZ window, possibly emitting zero compressed bytes), then buffered
    // compressed bytes are drained into `output`. Leftover bytes are drained
    // first on the next step, before any new input is fed.
    #[cfg(feature = "xz")]
    fn lzma_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        use std::io::Write as _;

        let writer = entry
            .lzma
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP lzma state is missing"))?;
        if !writer.inner().0.is_empty() {
            let n = writer.inner().0.len().min(output.len());
            output[..n].copy_from_slice(&writer.inner().0[..n]);
            writer.inner_mut().0.drain(..n);
            return Ok((0, n));
        }
        writer
            .write_all(data)
            .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP lzma encoder failed"))?;
        let n = writer.inner().0.len().min(output.len());
        output[..n].copy_from_slice(&writer.inner().0[..n]);
        writer.inner_mut().0.drain(..n);
        Ok((data.len(), n))
    }

    #[cfg(feature = "xz")]
    fn xz_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        use std::io::Write as _;

        let writer = entry
            .xz
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP XZ state is missing"))?;
        if !writer.inner().0.is_empty() {
            let n = writer.inner().0.len().min(output.len());
            output[..n].copy_from_slice(&writer.inner().0[..n]);
            writer.inner_mut().0.drain(..n);
            return Ok((0, n));
        }
        writer
            .write_all(data)
            .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP XZ encoder failed"))?;
        let n = writer.inner().0.len().min(output.len());
        output[..n].copy_from_slice(&writer.inner().0[..n]);
        writer.inner_mut().0.drain(..n);
        Ok((data.len(), n))
    }

    #[cfg(feature = "ppmd")]
    fn ppmd_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        use std::io::Write as _;

        let writer = entry
            .ppmd
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP PPMd state is missing"))?;
        if !writer.get_ref().0.is_empty() {
            let n = writer.get_ref().0.len().min(output.len());
            output[..n].copy_from_slice(&writer.get_ref().0[..n]);
            writer.get_mut().0.drain(..n);
            return Ok((0, n));
        }
        writer
            .write_all(data)
            .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP PPMd encoder failed"))?;
        let n = writer.get_ref().0.len().min(output.len());
        output[..n].copy_from_slice(&writer.get_ref().0[..n]);
        writer.get_mut().0.drain(..n);
        Ok((data.len(), n))
    }

    fn compress_step(
        entry: &mut OpenEntry,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        #[cfg(feature = "bzip2")]
        if entry.payload_method == 12 {
            return Self::bzip2_step(entry, data, output);
        }
        #[cfg(feature = "zstd")]
        if entry.payload_method == 93 {
            return Self::zstd_step(entry, data, output);
        }
        #[cfg(feature = "xz")]
        if entry.payload_method == 14 {
            return Self::lzma_step(entry, data, output);
        }
        #[cfg(feature = "xz")]
        if entry.payload_method == 95 {
            return Self::xz_step(entry, data, output);
        }
        #[cfg(feature = "ppmd")]
        if entry.payload_method == 98 {
            return Self::ppmd_step(entry, data, output);
        }
        Self::deflate_step(entry, data, output)
    }

    #[cfg(feature = "aes")]
    fn encrypt_entry_output(entry: &mut OpenEntry, output: &mut [u8]) {
        if let Some(aes) = &mut entry.aes {
            aes.encrypt(output);
        } else if let Some(zipcrypto) = &mut entry.zipcrypto {
            zipcrypto.encrypt(output);
        }
    }

    #[cfg(not(feature = "aes"))]
    fn encrypt_entry_output(_entry: &mut OpenEntry, _output: &mut [u8]) {}

    fn write_data(&mut self, data: &[u8], output: &mut [u8]) -> Result<EncodeStep, ArchiveError> {
        let Phase::Open(entry) = &mut self.phase else {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP data received outside an entry",
            ));
        };
        if !entry.metadata_payload.is_empty() && !data.is_empty() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP symbolic-link payload is owned by link-target metadata",
            ));
        }
        if data.is_empty() {
            return Ok(EncodeStep {
                consumed: 0,
                produced: 0,
                status: EncodeStatus::NeedCommand,
            });
        }
        let (consumed, produced) = if entry.payload_method == 0 {
            let count = data.len().min(output.len());
            output[..count].copy_from_slice(&data[..count]);
            (count, count)
        } else {
            Self::compress_step(entry, data, output)?
        };
        #[cfg(feature = "aes")]
        Self::encrypt_entry_output(entry, &mut output[..produced]);
        entry.crc.update(&data[..consumed]);
        entry.uncompressed_size = entry
            .uncompressed_size
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP entry size overflow"))?;
        entry.compressed_size = entry
            .compressed_size
            .checked_add(produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed size overflow"))?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|limit| entry.uncompressed_size > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry exceeds configured size limit",
            ));
        }
        self.account_input(consumed)?;
        self.offset = self
            .offset
            .checked_add(produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
        if consumed == 0 && produced == 0 && !output.is_empty() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP encoder made no data progress",
            ));
        }
        Ok(EncodeStep {
            consumed,
            produced,
            status: if consumed == data.len() {
                EncodeStatus::NeedCommand
            } else {
                EncodeStatus::NeedOutput
            },
        })
    }

    /// Drives one streaming-finalization step for the non-deflate codecs.
    ///
    /// Returns `(bytes_written, done)`; `done == false` means the codec needs
    /// another output buffer before its terminal record is complete. Store and
    /// directory entries (and feature-off fallbacks) report `(0, true)`.
    #[allow(unused_variables)]
    fn finish_step(
        entry: &mut OpenEntry,
        output: &mut [u8],
    ) -> Result<(usize, bool), ArchiveError> {
        #[cfg(feature = "bzip2")]
        if entry.payload_method == 12 {
            let compressor = entry
                .bz_compress
                .as_mut()
                .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP bzip2 state is missing"))?;
            let before_out = compressor.total_out();
            let status = compressor
                .compress(&[], output, Action::Finish)
                .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP bzip2 finalization failed"))?;
            let written = usize::try_from(compressor.total_out() - before_out)
                .map_err(|_| Self::error(ErrorKind::Limit, "ZIP bzip2 output overflow"))?;
            return match status {
                BzStatus::StreamEnd => Ok((written, true)),
                BzStatus::FinishOk => Ok((written, false)),
                _ => Err(Self::error(
                    ErrorKind::Malformed,
                    "ZIP bzip2 finalization failed",
                )),
            };
        }
        #[cfg(feature = "zstd")]
        if entry.payload_method == 93 {
            let encoder = entry
                .zstd
                .as_mut()
                .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP zstd state is missing"))?;
            return encoder.finish(output);
        }
        #[cfg(feature = "xz")]
        if entry.payload_method == 14 {
            if let Some(writer) = entry.lzma.as_mut() {
                if !writer.inner().0.is_empty() {
                    // Flush any buffered stream bytes before finalizing.
                    let n = drain_into(&mut writer.inner_mut().0, output);
                    return Ok((n, false));
                }
                // Sink drained: finalize (writes the EOS marker) and stash the
                // remaining bytes in `lzma_tail` for draining.
                let writer = entry
                    .lzma
                    .take()
                    .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP lzma state is missing"))?;
                entry.lzma_tail = writer
                    .finish()
                    .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP lzma finalization failed"))?
                    .0;
            }
            let n = drain_into(&mut entry.lzma_tail, output);
            return Ok((n, entry.lzma_tail.is_empty()));
        }
        #[cfg(feature = "xz")]
        if entry.payload_method == 95 {
            if let Some(writer) = entry.xz.as_mut() {
                if !writer.inner().0.is_empty() {
                    let n = drain_into(&mut writer.inner_mut().0, output);
                    return Ok((n, false));
                }
                let writer = entry
                    .xz
                    .take()
                    .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP XZ state is missing"))?;
                entry.xz_tail = writer
                    .finish()
                    .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP XZ finalization failed"))?
                    .0;
            }
            let n = drain_into(&mut entry.xz_tail, output);
            return Ok((n, entry.xz_tail.is_empty()));
        }
        #[cfg(feature = "ppmd")]
        if entry.payload_method == 98 {
            if let Some(writer) = entry.ppmd.as_mut() {
                if !writer.get_ref().0.is_empty() {
                    let n = drain_into(&mut writer.get_mut().0, output);
                    return Ok((n, false));
                }
                let writer = entry
                    .ppmd
                    .take()
                    .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP PPMd state is missing"))?;
                entry.ppmd_tail = writer
                    .finish(true)
                    .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP PPMd finalization failed"))?
                    .0;
            }
            let n = drain_into(&mut entry.ppmd_tail, output);
            return Ok((n, entry.ppmd_tail.is_empty()));
        }
        if entry.payload_method != 0 {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP entry has no finalizer for its payload method",
            ));
        }
        Ok((0, true))
    }

    #[allow(clippy::too_many_lines)]
    fn end_entry(&mut self, output: &mut [u8]) -> Result<EncodeStep, ArchiveError> {
        let Phase::Open(entry) = &mut self.phase else {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP end-entry received outside an entry",
            ));
        };
        let mut prefix_produced = 0;
        if entry.metadata_payload_position < entry.metadata_payload.len() {
            let remaining = &entry.metadata_payload[entry.metadata_payload_position..];
            let count = remaining.len().min(output.len());
            output[..count].copy_from_slice(&remaining[..count]);
            entry.crc.update(&output[..count]);
            Self::encrypt_entry_output(entry, &mut output[..count]);
            entry.metadata_payload_position += count;
            entry.uncompressed_size = entry
                .uncompressed_size
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP entry size overflow"))?;
            entry.compressed_size = entry
                .compressed_size
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed size overflow"))?;
            if self
                .limits
                .entry_bytes()
                .is_some_and(|limit| entry.uncompressed_size > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP entry exceeds configured size limit",
                ));
            }
            self.total_input = self
                .total_input
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP decoded total overflow"))?;
            if self
                .limits
                .decoded_total()
                .is_some_and(|limit| self.total_input > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP total input exceeds configured limit",
                ));
            }
            self.offset = self
                .offset
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
            if entry.metadata_payload_position < entry.metadata_payload.len() {
                return Ok(EncodeStep {
                    consumed: 0,
                    produced: count,
                    status: EncodeStatus::NeedOutput,
                });
            }
            prefix_produced = count;
        }
        let output = &mut output[prefix_produced..];
        let finalized = if entry.payload_method == 8 {
            let compressor = entry
                .compressor
                .as_mut()
                .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP deflate state is missing"))?;
            let step = compressor.process(&[], output, EndOfInput::End)?;
            #[cfg(feature = "aes")]
            Self::encrypt_entry_output(entry, &mut output[..step.produced]);
            entry.compressed_size = entry
                .compressed_size
                .checked_add(step.produced as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed size overflow"))?;
            self.offset = self
                .offset
                .checked_add(step.produced as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
            match step.status {
                CodecStatus::Done => step.produced,
                CodecStatus::NeedOutput => {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: prefix_produced + step.produced,
                        status: EncodeStatus::NeedOutput,
                    });
                },
                CodecStatus::NeedInput => {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "ZIP deflate requested input while finalizing",
                    ));
                },
                _ => {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "ZIP deflate returned an unknown final status",
                    ));
                },
            }
        } else {
            let (written, done) = Self::finish_step(entry, output)?;
            Self::encrypt_entry_output(entry, &mut output[..written]);
            entry.compressed_size = entry
                .compressed_size
                .checked_add(written as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed size overflow"))?;
            self.offset = self
                .offset
                .checked_add(written as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
            if done {
                written
            } else {
                return Ok(EncodeStep {
                    consumed: 0,
                    produced: prefix_produced + written,
                    status: EncodeStatus::NeedOutput,
                });
            }
        };
        let produced = prefix_produced + finalized;

        let Phase::Open(entry) = core::mem::replace(&mut self.phase, Phase::Ready) else {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP entry state changed while finalizing",
            ));
        };
        #[allow(unused_mut)]
        let mut entry = *entry;
        if entry
            .expected_size
            .is_some_and(|expected| expected != entry.uncompressed_size)
        {
            return Err(Self::error(
                ErrorKind::Integrity,
                "ZIP entry size differs from declared metadata",
            ));
        }
        if !entry.zip64_size
            && (entry.uncompressed_size >= u64::from(U32_SENTINEL)
                || entry.compressed_size >= u64::from(U32_SENTINEL))
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry exceeded its non-ZIP64 local header",
            ));
        }
        #[cfg(feature = "aes")]
        let aes_real_method = entry.aes.as_ref().map(|_| entry.payload_method);
        #[cfg(not(feature = "aes"))]
        let aes_real_method = None;
        let crc = if aes_real_method.is_some() {
            0
        } else {
            entry.crc.finalize()
        };
        let mut descriptor = Vec::with_capacity(if entry.zip64_size { 34 } else { 26 });
        #[cfg(feature = "aes")]
        if let Some(aes) = &entry.aes {
            descriptor.extend_from_slice(&aes.authentication());
            entry.compressed_size = entry
                .compressed_size
                .checked_add(10)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP AES compressed size overflow"))?;
        }
        if !entry.zip64_size
            && (entry.uncompressed_size >= u64::from(U32_SENTINEL)
                || entry.compressed_size >= u64::from(U32_SENTINEL))
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry exceeded its non-ZIP64 local header",
            ));
        }
        push_u32(&mut descriptor, DESCRIPTOR_SIGNATURE);
        push_u32(&mut descriptor, crc);
        if entry.zip64_size {
            push_u64(&mut descriptor, entry.compressed_size);
            push_u64(&mut descriptor, entry.uncompressed_size);
        } else {
            push_u32(&mut descriptor, field_u32(entry.compressed_size));
            push_u32(&mut descriptor, field_u32(entry.uncompressed_size));
        }
        self.records.push(CentralRecord {
            name: entry.name,
            comment: entry.comment,
            extra: entry.extra,
            method: entry.method,
            flags: entry.flags,
            crc,
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.uncompressed_size,
            local_offset: entry.local_offset,
            external_attributes: entry.external_attributes,
            dos_time: entry.dos_time,
            dos_date: entry.dos_date,
            zip64_size: entry.zip64_size,
            aes_real_method,
        });
        self.queue(descriptor)?;
        Ok(EncodeStep {
            consumed: 1,
            produced,
            status: EncodeStatus::NeedOutput,
        })
    }

    fn central_record(record: &CentralRecord) -> Vec<u8> {
        let size_zip64 = record.zip64_size
            || record.compressed_size >= u64::from(U32_SENTINEL)
            || record.uncompressed_size >= u64::from(U32_SENTINEL);
        let offset_zip64 = record.local_offset >= u64::from(U32_SENTINEL);
        let mut extra = Vec::new();
        if size_zip64 || offset_zip64 {
            let mut body = Vec::new();
            if size_zip64 {
                push_u64(&mut body, record.uncompressed_size);
                push_u64(&mut body, record.compressed_size);
            }
            if offset_zip64 {
                push_u64(&mut body, record.local_offset);
            }
            push_u16(&mut extra, ZIP64_EXTRA);
            push_u16(&mut extra, field_u16(body.len()));
            extra.extend_from_slice(&body);
        }
        extra.extend_from_slice(&record.extra);
        let mut central =
            Vec::with_capacity(46 + record.name.len() + extra.len() + record.comment.len());
        push_u32(&mut central, CENTRAL_SIGNATURE);
        push_u16(&mut central, 0x031e);
        push_u16(
            &mut central,
            if record.aes_real_method.is_some() {
                51
            } else if record.method == 12 {
                46
            } else if matches!(record.method, 14 | 93 | 95 | 98) {
                63
            } else if size_zip64 || offset_zip64 {
                45
            } else {
                20
            },
        );
        push_u16(&mut central, record.flags);
        push_u16(&mut central, record.method);
        push_u16(&mut central, record.dos_time);
        push_u16(&mut central, record.dos_date);
        push_u32(&mut central, record.crc);
        push_u32(
            &mut central,
            if size_zip64 {
                U32_SENTINEL
            } else {
                field_u32(record.compressed_size)
            },
        );
        push_u32(
            &mut central,
            if size_zip64 {
                U32_SENTINEL
            } else {
                field_u32(record.uncompressed_size)
            },
        );
        push_u16(&mut central, field_u16(record.name.len()));
        push_u16(&mut central, field_u16(extra.len()));
        push_u16(&mut central, field_u16(record.comment.len()));
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, record.external_attributes);
        push_u32(
            &mut central,
            if offset_zip64 {
                U32_SENTINEL
            } else {
                field_u32(record.local_offset)
            },
        );
        central.extend_from_slice(&record.name);
        central.extend_from_slice(&extra);
        central.extend_from_slice(&record.comment);
        central
    }

    fn final_records(&self, start: u64) -> Vec<u8> {
        let size = self.offset - start;
        let count = self.records.len() as u64;
        let zip64 = count >= u64::from(U16_SENTINEL)
            || size >= u64::from(U32_SENTINEL)
            || start >= u64::from(U32_SENTINEL);
        let mut output =
            Vec::with_capacity((if zip64 { 98 } else { 22 }) + self.archive_comment.len());
        if zip64 {
            let zip64_offset = self.offset;
            push_u32(&mut output, ZIP64_EOCD_SIGNATURE);
            push_u64(&mut output, 44);
            push_u16(&mut output, 0x031e);
            push_u16(&mut output, 45);
            push_u32(&mut output, 0);
            push_u32(&mut output, 0);
            push_u64(&mut output, count);
            push_u64(&mut output, count);
            push_u64(&mut output, size);
            push_u64(&mut output, start);
            push_u32(&mut output, ZIP64_LOCATOR_SIGNATURE);
            push_u32(&mut output, 0);
            push_u64(&mut output, zip64_offset);
            push_u32(&mut output, 1);
        }
        push_u32(&mut output, EOCD_SIGNATURE);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(
            &mut output,
            if count >= u64::from(U16_SENTINEL) {
                U16_SENTINEL
            } else {
                u16::try_from(count).unwrap_or(U16_SENTINEL)
            },
        );
        push_u16(
            &mut output,
            if count >= u64::from(U16_SENTINEL) {
                U16_SENTINEL
            } else {
                u16::try_from(count).unwrap_or(U16_SENTINEL)
            },
        );
        push_u32(
            &mut output,
            if size >= u64::from(U32_SENTINEL) {
                U32_SENTINEL
            } else {
                field_u32(size)
            },
        );
        push_u32(
            &mut output,
            if start >= u64::from(U32_SENTINEL) {
                U32_SENTINEL
            } else {
                field_u32(start)
            },
        );
        push_u16(
            &mut output,
            u16::try_from(self.archive_comment.len()).unwrap_or(U16_SENTINEL),
        );
        output.extend_from_slice(&self.archive_comment);
        output
    }

    fn finish_archive(&mut self, output: &mut [u8]) -> Result<EncodeStep, ArchiveError> {
        loop {
            if self.has_pending() {
                let produced = self.drain_pending(output)?;
                return Ok(EncodeStep {
                    consumed: 0,
                    produced,
                    status: EncodeStatus::NeedOutput,
                });
            }
            match self.phase {
                Phase::Ready => {
                    self.phase = Phase::Central {
                        next: 0,
                        start: self.offset,
                    };
                },
                Phase::Central { next, start } => {
                    if next < self.records.len() {
                        let record = Self::central_record(&self.records[next]);
                        self.phase = Phase::Central {
                            next: next + 1,
                            start,
                        };
                        self.queue(record)?;
                    } else {
                        let final_bytes = self.final_records(start);
                        self.phase = Phase::FinalBytes;
                        self.queue(final_bytes)?;
                    }
                },
                Phase::FinalBytes => {
                    self.phase = Phase::Done;
                    return Ok(EncodeStep {
                        consumed: 1,
                        produced: 0,
                        status: EncodeStatus::Done,
                    });
                },
                Phase::Done => {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: 0,
                        status: EncodeStatus::Done,
                    });
                },
                Phase::Open(_) => {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "ZIP finish received with an open entry",
                    ));
                },
            }
        }
    }
}

pub(crate) fn zip_entry_extension_supported(extension: &Extension) -> bool {
    if extension.namespace() != "zip-extra" {
        return false;
    }
    let [low, high] = extension.key() else {
        return false;
    };
    !matches!(u16::from_le_bytes([*low, *high]), ZIP64_EXTRA | AES_EXTRA)
}

impl ArchiveEncoder for ZipStreamEncoder {
    #[allow(clippy::too_many_lines)]
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        if matches!(self.phase, Phase::Done) {
            return match command {
                EncodeCommand::Finish => Ok(EncodeStep {
                    consumed: 0,
                    produced: 0,
                    status: EncodeStatus::Done,
                }),
                _ => Err(Self::error(
                    ErrorKind::Protocol,
                    "command supplied after ZIP completion",
                )),
            };
        }
        if self.has_pending() {
            let produced = self.drain_pending(output)?;
            return Ok(EncodeStep {
                consumed: 0,
                produced,
                status: EncodeStatus::NeedOutput,
            });
        }
        match command {
            EncodeCommand::BeginEntry(metadata) => {
                self.begin_entry(metadata)?;
                let produced = self.drain_pending(output)?;
                Ok(EncodeStep {
                    consumed: 1,
                    produced,
                    status: if self.has_pending() {
                        EncodeStatus::NeedOutput
                    } else {
                        EncodeStatus::NeedCommand
                    },
                })
            },
            EncodeCommand::Data(data) => self.write_data(data, output),
            EncodeCommand::EndEntry => self.end_entry(output),
            EncodeCommand::Finish => self.finish_archive(output),
            _ => Err(Self::error(
                ErrorKind::Unsupported,
                "unknown ZIP encoder command",
            )),
        }
    }
}

fn external_attributes(kind: EntryKind, mode: u32, file_flags: u64) -> u32 {
    let type_bits = match kind {
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        EntryKind::Char => 0o020_000,
        EntryKind::Block => 0o060_000,
        EntryKind::Fifo => 0o010_000,
        _ => 0o100_000,
    };
    let dos_attributes = u32::try_from(file_flags & ZIP_DOS_FILE_FLAGS).unwrap_or_default();
    let mut attributes = ((type_bits | (mode & 0o7777)) << 16) | dos_attributes;
    if kind == EntryKind::Dir {
        attributes |= 0x10;
    }
    attributes
}

fn dos_datetime(timestamp: Option<Timestamp>) -> (u16, u16) {
    const DOS_EPOCH: i64 = 315_532_800;
    let seconds = match timestamp {
        Some(value) if value.seconds() >= DOS_EPOCH => value.seconds(),
        _ => return (0, 0x21),
    };
    let days = seconds.div_euclid(86_400);
    let remaining = seconds.rem_euclid(86_400);
    let hour = remaining / 3600;
    let minute = (remaining % 3600) / 60;
    let second = remaining % 60;
    let (year, month, day) = civil_from_days(days);
    let year = (year - 1980).clamp(0, 127);
    let year = u16::try_from(year).unwrap_or(0);
    let month = u16::try_from(month).unwrap_or(1);
    let day = u16::try_from(day).unwrap_or(1);
    let hour = u16::try_from(hour).unwrap_or(0);
    let minute = u16::try_from(minute).unwrap_or(0);
    let second = u16::try_from(second).unwrap_or(0);
    let date = (year << 9) | (month << 5) | day;
    let time = (hour << 11) | (minute << 5) | (second / 2);
    (time, date)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Copies as much of `source`'s front into `output` as fits, removing the
/// copied bytes from `source`, and returns the count written.
#[cfg(any(feature = "xz", feature = "ppmd"))]
fn drain_into(source: &mut Vec<u8>, output: &mut [u8]) -> usize {
    let n = source.len().min(output.len());
    output[..n].copy_from_slice(&source[..n]);
    source.drain(..n);
    n
}

#[cfg(feature = "ppmd")]
fn ppmd_error(error: &ppmd_rust::Error, context: &'static str) -> ArchiveError {
    let kind = match error {
        ppmd_rust::Error::MemoryAllocation => ErrorKind::Limit,
        ppmd_rust::Error::RangeDecoderInitialization
        | ppmd_rust::Error::InvalidParameter
        | ppmd_rust::Error::IoError(_) => ErrorKind::Malformed,
    };
    ArchiveError::new(kind)
        .with_format("zip")
        .with_context(context)
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Appends an Info-ZIP Extended Timestamp (`UT`, 0x5455) built from `times`.
///
/// The flag byte marks which of modification/access/change times follow, each a
/// signed 32-bit Unix second count. A time whose seconds do not fit `i32` is
/// dropped rather than truncated; an all-empty field is not emitted.
fn push_extended_timestamp(output: &mut Vec<u8>, times: EntryTimes) {
    let mut flags = 0_u8;
    let mut body = Vec::new();
    for (bit, timestamp) in [
        (0x01_u8, times.modified),
        (0x02, times.accessed),
        (0x04, times.changed),
    ] {
        if let Some(timestamp) = timestamp
            && let Ok(seconds) = i32::try_from(timestamp.seconds())
        {
            flags |= bit;
            body.extend_from_slice(&seconds.to_le_bytes());
        }
    }
    if flags == 0 {
        return;
    }
    push_u16(output, EXTENDED_TIMESTAMP_EXTRA);
    push_u16(output, field_u16(1 + body.len()));
    output.push(flags);
    output.extend_from_slice(&body);
}

/// Appends an Info-ZIP New Unix (`Ux`, 0x7855) field carrying numeric uid/gid.
///
/// Emitted only when both ids are present and fit the 16-bit form; an id that
/// overflows `u16` is left unrepresented rather than silently wrapped. Info-ZIP's
/// strict `Ux` form is empty in the central directory (uid/gid live only in the
/// local header), but arca's seek reader indexes the central directory, so the
/// uid/gid body is written into both headers to keep ownership recoverable from
/// the central directory on an arca round trip. Independent readers that only
/// expect the local form ignore the extra field for content.
fn push_infozip_unix(output: &mut Vec<u8>, owner: &Owner) {
    let (Some(uid), Some(gid)) = (owner.uid, owner.gid) else {
        return;
    };
    let (Ok(uid), Ok(gid)) = (u16::try_from(uid), u16::try_from(gid)) else {
        return;
    };
    push_u16(output, INFOZIP_UNIX_NEW_EXTRA);
    push_u16(output, 4);
    push_u16(output, uid);
    push_u16(output, gid);
}

#[cfg(feature = "aes")]
fn push_aes_extra(output: &mut Vec<u8>, real_method: u16, strength: AesStrength) {
    push_u16(output, AES_EXTRA);
    push_u16(output, 7);
    push_u16(output, 2);
    output.extend_from_slice(b"AE");
    output.push(match strength {
        AesStrength::Bits128 => 1,
        AesStrength::Bits192 => 2,
        AesStrength::Bits256 => 3,
    });
    push_u16(output, real_method);
}

/// Bytes a ZIP64 extended-information extra field occupies in the central
/// directory: a 4-byte tag+size header plus one `u64` per selected field. The
/// size flag covers both the uncompressed and compressed sizes (16 bytes); a
/// local-header offset >= 4 GiB adds one more `u64` (8 bytes). Returns 0 when no
/// ZIP64 field is written. Used to reserve extra-field headroom so a maximal
/// preserved-extra block cannot overflow the u16 length field.
fn zip64_extra_reserve(size_zip64: bool, offset_zip64: bool) -> usize {
    if !size_zip64 && !offset_zip64 {
        return 0;
    }
    let size_body = if size_zip64 { 16 } else { 0 };
    let offset_body = if offset_zip64 { 8 } else { 0 };
    4 + size_body + offset_body
}

fn field_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(U16_SENTINEL)
}

fn field_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(U32_SENTINEL)
}

#[cfg(test)]
mod tests {
    use super::{U16_SENTINEL, zip64_extra_reserve};

    #[test]
    fn every_built_in_zip_method_has_a_capability_record() {
        use libarchive_oxide_core::{FormatId, MethodId};

        for code in [0, 8, 9, 12, 14, 93, 99] {
            assert!(
                libarchive_oxide_core::capability::method_capability(
                    FormatId::Zip,
                    MethodId::Numeric(code),
                )
                .is_some(),
                "missing capability record for ZIP method {code}"
            );
        }
    }

    #[test]
    fn zip64_extra_reserve_covers_every_field_combination() {
        assert_eq!(zip64_extra_reserve(false, false), 0);
        assert_eq!(zip64_extra_reserve(true, false), 20); // header + 2 sizes
        assert_eq!(zip64_extra_reserve(false, true), 12); // header + offset
        assert_eq!(zip64_extra_reserve(true, true), 28); // header + 2 sizes + offset
    }

    #[test]
    fn maximum_extra_reserves_the_worst_case_zip64_field() {
        // The extra-length budget must leave room for the LARGER of the local
        // header's ZIP64 field (two sizes, 20 bytes) and the central header's
        // (sizes plus the local-offset, up to 28 bytes), so a maximal preserved
        // extra block can never push either header past the u16 extra-length field
        // and desync it through a silent `field_u16` clamp.
        for (size_zip64, offset_zip64) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let local = if size_zip64 { 20 } else { 0 };
            let central = zip64_extra_reserve(size_zip64, offset_zip64);
            let maximum_extra = usize::from(U16_SENTINEL) - local.max(central);
            assert!(local + maximum_extra <= usize::from(U16_SENTINEL));
            assert!(central + maximum_extra <= usize::from(U16_SENTINEL));
        }
    }
}
