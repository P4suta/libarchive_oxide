// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared bounded ZIP central-directory reader for package profiles.
//!
//! Both [`super::zip_profile`] (JAR, `NuGet`, wheel, EPUB) and
//! [`super::app_profile`] (APK, IPA, MSIX) validate ZIP-container packages
//! *without ever extracting them*: they read the central directory to collect
//! each member's name, order, compression method, encryption flag, declared
//! uncompressed size, and local-header offset. This module holds the reader they
//! share so the parser lives in exactly one place. No entry payload is ever
//! decompressed, so a decompression bomb is refused by budget rather than
//! expanded. Central-directory size, entry count, and per-entry path length are
//! all bounded by the caller's [`Limits`].

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use libarchive_oxide_core::{ArchivePath, Limits, PathEncoding};

use super::finding::{PackageFinding, PackageFindingCode};
use crate::path::sanitize_archive_path;

/// Store compression method (no compression).
pub(crate) const METHOD_STORE: u16 = 0;

/// Deflate compression method.
pub(crate) const METHOD_DEFLATE: u16 = 8;

/// `WinZip` AES compression method (the payload is encrypted).
const METHOD_AES: u16 = 99;

/// Bit 0 of the ZIP general-purpose flags: the entry is encrypted.
const FLAG_ENCRYPTED: u16 = 0x0001;

/// Bit 11 of the ZIP general-purpose flags: names and comments are UTF-8.
const FLAG_UTF8: u16 = 0x0800;

/// Fixed size of a ZIP local file header, before the variable name and extra.
pub(crate) const LOCAL_HEADER_LEN: usize = 30;

/// Fixed size of a ZIP central-directory file header.
const CENTRAL_HEADER_LEN: usize = 46;

/// Minimum size of an end-of-central-directory record.
const EOCD_MIN: usize = 22;

/// Size of a ZIP64 end-of-central-directory locator.
const ZIP64_LOCATOR_LEN: usize = 20;

/// Largest tail scanned for the end-of-central-directory signature: the maximum
/// 16-bit archive comment plus the fixed record.
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;

/// One collected central-directory member.
///
/// Fields are crate-visible so both ZIP-container profile modules can inspect
/// member names, order, compression, and offsets without re-parsing.
#[derive(Debug, Clone)]
pub(crate) struct ZipEntry {
    /// Archive-native member name bytes.
    pub(crate) name: Vec<u8>,
    /// Encoding the name bytes should be interpreted with.
    pub(crate) encoding: PathEncoding,
    /// Declared compression method.
    pub(crate) method: u16,
    /// General-purpose bit flags.
    pub(crate) flags: u16,
    /// Declared uncompressed size.
    pub(crate) uncompressed_size: u64,
    /// Offset of the member's local file header.
    pub(crate) local_offset: u64,
}

impl ZipEntry {
    /// Whether the member is encrypted (traditional or `WinZip` AES).
    pub(crate) fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == METHOD_AES
    }
}

/// Locates and parses the central directory into collected members.
///
/// Errors carry a human-readable detail used for a `ContainerUnreadable`
/// finding. Every allocation is bounded by `limits`.
pub(crate) fn read_central_directory<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<Vec<ZipEntry>, String> {
    Ok(read_central_directory_with_offset(reader, limits)?.0)
}

/// Parses the central directory and also returns its absolute start offset.
///
/// The APK profile needs the central-directory start offset to locate the APK
/// Signing Block, which sits immediately before it, so this variant exposes the
/// offset the members were read from alongside the members themselves.
pub(crate) fn read_central_directory_with_offset<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<(Vec<ZipEntry>, u64), String> {
    let end = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("cannot measure ZIP length: {error}"))?;
    let tail_length = end.min(EOCD_SEARCH);
    let tail_start = end - tail_length;
    let tail_len =
        usize::try_from(tail_length).map_err(|_| "EOCD search range exceeds address space")?;
    let mut tail = vec![0_u8; tail_len];
    read_exact_at(reader, tail_start, &mut tail)
        .map_err(|error| format!("cannot read ZIP tail: {error}"))?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or("end-of-central-directory record not found")?;
    if tail.len() - eocd < EOCD_MIN {
        return Err("truncated end-of-central-directory record".to_string());
    }
    let record = &tail[eocd..];
    let mut count = u64::from(le_u16(record, 10));
    let mut central_offset = u64::from(le_u32(record, 16));
    let eocd_absolute = tail_start + eocd as u64;

    if count == u64::from(u16::MAX) || central_offset == u64::from(u32::MAX) {
        let (zip64_count, zip64_offset) = read_zip64_directory(reader, eocd_absolute)?;
        count = zip64_count;
        central_offset = zip64_offset;
    }

    if limits.entries().is_some_and(|limit| count > limit) {
        return Err("central-directory entry count exceeds limit".to_string());
    }

    reader
        .seek(SeekFrom::Start(central_offset))
        .map_err(|error| format!("cannot seek to central directory: {error}"))?;
    let capacity = usize::try_from(count.min(4096)).unwrap_or(4096);
    let mut entries = Vec::with_capacity(capacity);
    let mut metadata_used: usize = 0;
    for _ in 0..count {
        let mut fixed = [0_u8; CENTRAL_HEADER_LEN];
        reader
            .read_exact(&mut fixed)
            .map_err(|error| format!("cannot read central-directory header: {error}"))?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err("bad central-directory signature".to_string());
        }
        let flags = le_u16(&fixed, 8);
        let method = le_u16(&fixed, 10);
        let uncompressed32 = le_u32(&fixed, 24);
        let compressed32 = le_u32(&fixed, 20);
        let name_length = usize::from(le_u16(&fixed, 28));
        let extra_length = usize::from(le_u16(&fixed, 30));
        let comment_length = usize::from(le_u16(&fixed, 32));
        let local32 = le_u32(&fixed, 42);
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or("central variable fields overflow")?;
        metadata_used = metadata_used
            .checked_add(variable_length)
            .and_then(|value| value.checked_add(core::mem::size_of::<ZipEntry>()))
            .ok_or("metadata accounting overflow")?;
        if limits
            .metadata_bytes()
            .is_some_and(|limit| metadata_used > limit)
        {
            return Err("central-directory metadata exceeds limit".to_string());
        }
        let mut variable = vec![0_u8; variable_length];
        reader
            .read_exact(&mut variable)
            .map_err(|error| format!("cannot read central-directory record: {error}"))?;
        let raw_name = &variable[..name_length];
        let extra = &variable[name_length..name_length + extra_length];
        let (uncompressed_size, local_offset) =
            zip64_sizes(extra, uncompressed32, compressed32, local32)?;
        if limits
            .path_bytes()
            .is_some_and(|limit| raw_name.len() > limit)
        {
            return Err("ZIP pathname exceeds configured limit".to_string());
        }
        let encoding = if flags & FLAG_UTF8 != 0 || core::str::from_utf8(raw_name).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        entries.push(ZipEntry {
            name: raw_name.to_vec(),
            encoding,
            method,
            flags,
            uncompressed_size,
            local_offset,
        });
    }
    Ok((entries, central_offset))
}

/// Follows the ZIP64 locator and record to recover the true entry count and
/// central-directory offset.
fn read_zip64_directory<R: Read + Seek>(
    reader: &mut R,
    eocd_absolute: u64,
) -> Result<(u64, u64), String> {
    if eocd_absolute < ZIP64_LOCATOR_LEN as u64 {
        return Err("ZIP64 locator is missing".to_string());
    }
    let mut locator = [0_u8; ZIP64_LOCATOR_LEN];
    read_exact_at(
        reader,
        eocd_absolute - ZIP64_LOCATOR_LEN as u64,
        &mut locator,
    )
    .map_err(|error| format!("cannot read ZIP64 locator: {error}"))?;
    if &locator[..4] != b"PK\x06\x07" {
        return Err("bad ZIP64 locator".to_string());
    }
    let record_offset = le_u64(&locator, 8);
    let mut record = [0_u8; 56];
    read_exact_at(reader, record_offset, &mut record)
        .map_err(|error| format!("cannot read ZIP64 end record: {error}"))?;
    if &record[..4] != b"PK\x06\x06" {
        return Err("bad ZIP64 end record".to_string());
    }
    Ok((le_u64(&record, 32), le_u64(&record, 48)))
}

/// Resolves the declared uncompressed size and local-header offset, following a
/// ZIP64 extra field whenever the 32-bit central-directory field is the `0xFFFF...`
/// sentinel.
fn zip64_sizes(
    extra: &[u8],
    uncompressed: u32,
    compressed: u32,
    local: u32,
) -> Result<(u64, u64), String> {
    let mut zip64: &[u8] = &[];
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = le_u16(extra, cursor);
        let length = usize::from(le_u16(extra, cursor + 2));
        let start = cursor + 4;
        let finish = start
            .checked_add(length)
            .ok_or("ZIP64 extra length overflow")?;
        let value = extra
            .get(start..finish)
            .ok_or("truncated ZIP extra field")?;
        if id == 0x0001 {
            zip64 = value;
            break;
        }
        cursor = finish;
    }
    let mut take = || -> Result<u64, String> {
        if zip64.len() < 8 {
            return Err("truncated ZIP64 value".to_string());
        }
        let value = le_u64(zip64, 0);
        zip64 = &zip64[8..];
        Ok(value)
    };
    let uncompressed_size = if uncompressed == u32::MAX {
        take()?
    } else {
        u64::from(uncompressed)
    };
    // The compressed size follows the uncompressed size in the ZIP64 record, so
    // it must be consumed even though this validator never decompresses.
    if compressed == u32::MAX {
        take()?;
    }
    let local_offset = if local == u32::MAX {
        take()?
    } else {
        u64::from(local)
    };
    Ok((uncompressed_size, local_offset))
}

/// Applies the ZIP-structure checks shared by every ZIP-container profile:
/// unsafe paths, duplicate members, unexpected encryption, unsupported
/// compression method, and the summed-uncompressed-size decompression bomb.
pub(crate) fn check_common_structure(
    label: &'static str,
    entries: &[ZipEntry],
    limits: Limits,
    findings: &mut Vec<PackageFinding>,
) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut decoded_total: u64 = 0;
    let mut bomb_reported = false;
    for entry in entries {
        let path = ArchivePath::from_encoded(entry.name.clone(), entry.encoding);
        match sanitize_archive_path(&path) {
            None => findings.push(PackageFinding::new(
                label,
                Some(entry.name.clone()),
                PackageFindingCode::UnsafeEntryPath,
                "member name is absolute, traversing, or unrepresentable",
            )),
            Some(safe) => {
                if !seen.insert(safe) {
                    findings.push(PackageFinding::new(
                        label,
                        Some(entry.name.clone()),
                        PackageFindingCode::DuplicateEntryPath,
                        "member path repeats within the archive",
                    ));
                }
            },
        }

        if entry.is_encrypted() {
            findings.push(PackageFinding::new(
                label,
                Some(entry.name.clone()),
                PackageFindingCode::UnexpectedEncryption,
                "member is encrypted, which this profile forbids",
            ));
        } else if entry.method != METHOD_STORE && entry.method != METHOD_DEFLATE {
            findings.push(PackageFinding::unsupported_method(
                label,
                Some(entry.name.clone()),
                format!(
                    "member uses compression method {} this build cannot decode",
                    entry.method
                ),
            ));
        }

        decoded_total = decoded_total.saturating_add(entry.uncompressed_size);
        if !bomb_reported
            && limits
                .decoded_total()
                .is_some_and(|limit| decoded_total > limit)
        {
            bomb_reported = true;
            findings.push(PackageFinding::new(
                label,
                None,
                PackageFindingCode::DecompressionBomb,
                "declared uncompressed size exceeds the decompression budget",
            ));
        }
    }
}

/// Reads exactly `buffer.len()` bytes starting at `offset`.
pub(crate) fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> std::io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer)
}

/// Reads a little-endian `u16` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 2` bytes.
pub(crate) fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Reads a little-endian `u32` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 4` bytes.
pub(crate) fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Reads a little-endian `u64` at `offset` within `bytes`.
///
/// The caller guarantees `bytes` holds at least `offset + 8` bytes.
pub(crate) fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
