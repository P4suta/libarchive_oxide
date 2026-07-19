// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Incremental ZIP writer used by the common sync and async drivers.

use libarchive_oxide_core::{
    ArchiveEncoder, ArchiveError, ArchiveMetadata, EncodeCommand, EncodeStatus, EncodeStep,
    EntryKind, EntryMetadata, ErrorKind, Limits, PathEncoding, Timestamp,
};
use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::{MZError, MZFlush, MZStatus};

#[cfg(feature = "aes")]
use crate::SecretBytes;
use crate::filter::gzip::Crc32;

const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 0x0001;
const AES_EXTRA: u16 = 0x9901;
const U16_SENTINEL: u16 = u16::MAX;
const U32_SENTINEL: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
pub(crate) enum StreamZipMethod {
    Store,
    Deflate,
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
struct ZipAesEncoder {
    cipher: ctr::Ctr128LE<aes::Aes256>,
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
    fn new(password: &[u8]) -> Result<(Self, [u8; 18]), ArchiveError> {
        use ctr::cipher::KeyIvInit;
        use hmac::digest::KeyInit;
        use zeroize::Zeroize;

        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt).map_err(|_| {
            ArchiveError::new(ErrorKind::Integrity)
                .with_format("zip")
                .with_context("OS random generator failed for WinZip AES salt")
        })?;
        let mut key_material = [0_u8; 66];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt, 1_000, &mut key_material);
        let mut counter = [0_u8; 16];
        counter[0] = 1;
        let cipher = ctr::Ctr128LE::<aes::Aes256>::new_from_slices(&key_material[..32], &counter)
            .map_err(|_| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("zip")
                .with_context("WinZip AES cipher initialization failed")
        })?;
        let mac = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&key_material[32..64])
            .map_err(|_| {
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("zip")
                    .with_context("WinZip AES MAC initialization failed")
            })?;
        let mut framing = [0_u8; 18];
        framing[..16].copy_from_slice(&salt);
        framing[16..].copy_from_slice(&key_material[64..]);
        key_material.zeroize();
        Ok((Self { cipher, mac }, framing))
    }

    fn encrypt(&mut self, bytes: &mut [u8]) {
        use ctr::cipher::StreamCipher;
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
    local_offset: u64,
    external_attributes: u32,
    dos_time: u16,
    dos_date: u16,
    zip64_size: bool,
    compressor: Option<Box<CompressorOxide>>,
    #[cfg(feature = "aes")]
    aes: Option<ZipAesEncoder>,
}

impl core::fmt::Debug for OpenEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenEntry")
            .field("name", &self.name)
            .field("method", &self.method)
            .field("payload_method", &self.payload_method)
            .field("compressed_size", &self.compressed_size)
            .field("uncompressed_size", &self.uncompressed_size)
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

/// Data-descriptor ZIP encoder.
///
/// File payload is never retained. Only central-directory metadata is kept,
/// bounded by [`Limits::metadata_bytes`].
#[derive(Debug)]
pub(crate) struct ZipStreamEncoder {
    limits: Limits,
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
}

impl ZipStreamEncoder {
    pub(crate) fn new(limits: Limits) -> Self {
        Self::with_method(limits, StreamZipMethod::Deflate)
    }

    pub(crate) fn with_method(limits: Limits, method: StreamZipMethod) -> Self {
        Self {
            limits,
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
    pub(crate) fn with_password(
        limits: Limits,
        method: StreamZipMethod,
        password: SecretBytes,
    ) -> Self {
        let mut encoder = Self::with_method(limits, method);
        encoder.password = Some(password);
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
        if metadata.kind() == EntryKind::Dir && !name.ends_with(b"/") {
            name.push(b'/');
        }
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
        let maximum_extra = usize::from(U16_SENTINEL) - if zip64_size { 20 } else { 0 };
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
            8
        };
        #[cfg(feature = "aes")]
        let encrypted = self.password.is_some();
        #[cfg(not(feature = "aes"))]
        let encrypted = false;
        let method = if encrypted { 99 } else { payload_method };
        if encrypted {
            push_aes_extra(&mut preserved_extra, payload_method);
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
        let flags = 0x0008 | if utf8 { 0x0800 } else { 0 } | u16::from(encrypted);
        let version_needed = if encrypted {
            51
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
        let (aes, aes_framing) = if let Some(password) = &self.password {
            let (aes, framing) = ZipAesEncoder::new(password.expose())?;
            (Some(aes), Some(framing))
        } else {
            (None, None)
        };
        #[cfg(feature = "aes")]
        if let Some(framing) = aes_framing {
            local.extend_from_slice(&framing);
        }
        self.queue(local)?;
        let compressor = (payload_method == 8).then(|| {
            let flags = create_comp_flags_from_zip_params(6, 0, 0);
            Box::new(CompressorOxide::new(flags))
        });
        self.phase = Phase::Open(Box::new(OpenEntry {
            name,
            comment,
            extra: preserved_extra,
            method,
            payload_method,
            flags,
            crc: Crc32::new(),
            compressed_size: if encrypted { 18 } else { 0 },
            uncompressed_size: 0,
            expected_size: metadata.size(),
            local_offset,
            external_attributes: external_attributes(
                metadata.kind(),
                metadata.mode().unwrap_or(0o644),
            ),
            dos_time,
            dos_date,
            zip64_size,
            compressor,
            #[cfg(feature = "aes")]
            aes,
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

    fn write_data(&mut self, data: &[u8], output: &mut [u8]) -> Result<EncodeStep, ArchiveError> {
        let Phase::Open(entry) = &mut self.phase else {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP data received outside an entry",
            ));
        };
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
            let compressor = entry
                .compressor
                .as_mut()
                .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP deflate state is missing"))?;
            let result = deflate(compressor, data, output, MZFlush::None);
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "ZIP deflate ended before end-entry",
                    ));
                },
                Ok(_) => (result.bytes_consumed, result.bytes_written),
                Err(MZError::Buf) if output.is_empty() => (0, 0),
                Err(_) => {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "ZIP deflate encoder failed",
                    ));
                },
            }
        };
        #[cfg(feature = "aes")]
        if let Some(aes) = &mut entry.aes {
            aes.encrypt(&mut output[..produced]);
        }
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

    #[allow(clippy::too_many_lines)]
    fn end_entry(&mut self, output: &mut [u8]) -> Result<EncodeStep, ArchiveError> {
        let Phase::Open(entry) = &mut self.phase else {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP end-entry received outside an entry",
            ));
        };
        let produced = if entry.payload_method == 8 {
            let compressor = entry
                .compressor
                .as_mut()
                .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP deflate state is missing"))?;
            let result = deflate(compressor, &[], output, MZFlush::Finish);
            #[cfg(feature = "aes")]
            if let Some(aes) = &mut entry.aes {
                aes.encrypt(&mut output[..result.bytes_written]);
            }
            entry.compressed_size = entry
                .compressed_size
                .checked_add(result.bytes_written as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed size overflow"))?;
            self.offset = self
                .offset
                .checked_add(result.bytes_written as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP archive offset overflow"))?;
            match result.status {
                Ok(MZStatus::StreamEnd) => result.bytes_written,
                Ok(_) => {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: result.bytes_written,
                        status: EncodeStatus::NeedOutput,
                    });
                },
                Err(MZError::Buf) if output.is_empty() => {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: 0,
                        status: EncodeStatus::NeedOutput,
                    });
                },
                Err(_) => {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "ZIP deflate finalization failed",
                    ));
                },
            }
        } else {
            0
        };

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

fn external_attributes(kind: EntryKind, mode: u32) -> u32 {
    let type_bits = match kind {
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        EntryKind::Char => 0o020_000,
        EntryKind::Block => 0o060_000,
        EntryKind::Fifo => 0o010_000,
        _ => 0o100_000,
    };
    let mut attributes = (type_bits | (mode & 0o7777)) << 16;
    if kind == EntryKind::Dir {
        attributes |= 0x10;
    }
    attributes
}

fn dos_datetime(timestamp: Option<Timestamp>) -> (u16, u16) {
    const DOS_EPOCH: i64 = 315_532_800;
    let seconds = match timestamp {
        Some(value) if value.secs >= DOS_EPOCH => value.secs,
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

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_aes_extra(output: &mut Vec<u8>, real_method: u16) {
    push_u16(output, AES_EXTRA);
    push_u16(output, 7);
    push_u16(output, 2);
    output.extend_from_slice(b"AE");
    output.push(3);
    push_u16(output, real_method);
}

fn field_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(U16_SENTINEL)
}

fn field_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(U32_SENTINEL)
}
