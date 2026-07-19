// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! cpio format (SVR4 "newc"/"crc" and POSIX "odc").
//!
//! Supports `newc`, `crc`, and `odc` ASCII headers plus legacy binary headers
//! in both byte orders. `TRAILER!!!` terminates the archive.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::Limits;
use crate::error::{ArchiveError, Error, ErrorKind, Result};
use crate::meta::{EntryKind, Timestamp, default_mode};
use crate::metadata::{ArchivePath, Device, EntryMetadata, EntryTimes, Owner};
use crate::protocol::{
    ArchiveDecoder, ArchiveEncoder, Chunk, DecodeEvent, DecodeStep, EncodeCommand, EncodeStatus,
    EncodeStep, EndOfInput, ProbeResult,
};

const NEWC_MAGIC: &[u8] = b"070701";
const NEWC_CRC_MAGIC: &[u8] = b"070702";
const ODC_MAGIC: &[u8] = b"070707";
const NEWC_HEADER: usize = 110;
const ODC_HEADER: usize = 76;
const TRAILER: &[u8] = b"TRAILER!!!";

/// Legacy binary format magic (both host byte orders).
const BIN_MAGIC_LE: [u8; 2] = [0xc7, 0x71];
const BIN_MAGIC_BE: [u8; 2] = [0x71, 0xc7];

/// Output dialect selected for a cpio encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpioDialect {
    /// SVR4 new ASCII format.
    Newc,
    /// SVR4 new ASCII format with payload byte-sum verification.
    Crc,
    /// POSIX portable ASCII format.
    Odc,
    /// Legacy binary format in little-endian byte order.
    BinaryLittleEndian,
    /// Legacy binary format in big-endian byte order.
    BinaryBigEndian,
}

/// Maps a typed kind to its `S_IFMT` bits for writing.
fn mode_bits(kind: EntryKind) -> u64 {
    match kind {
        EntryKind::Dir => S_IFDIR,
        EntryKind::Symlink => S_IFLNK,
        EntryKind::Char => S_IFCHR,
        EntryKind::Block => S_IFBLK,
        EntryKind::Fifo => S_IFIFO,
        EntryKind::Socket => S_IFSOCK,
        _ => S_IFREG,
    }
}

/// The low 32 bits of `v` (newc fields are 32-bit).
fn lo32(v: u64) -> u32 {
    u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0)
}

/// Writes `val` as 8 uppercase hex digits into `field`.
fn put_hex8(field: &mut [u8], val: u32) {
    let mut v = val;
    for slot in field.iter_mut().rev() {
        let d = u8::try_from(v & 0xf).unwrap_or(0);
        *slot = if d < 10 { b'0' + d } else { b'A' + (d - 10) };
        v >>= 4;
    }
}

fn put_octal(field: &mut [u8], mut value: u64) -> core::result::Result<(), ArchiveError> {
    for slot in field.iter_mut().rev() {
        *slot = b'0' + u8::try_from(value & 7).unwrap_or(0);
        value >>= 3;
    }
    if value != 0 {
        return Err(ArchiveError::new(ErrorKind::Unsupported)
            .with_format("cpio")
            .with_context("odc numeric value exceeds its field"));
    }
    Ok(())
}

fn cpio_u32(value: u64, context: &'static str) -> core::result::Result<u32, ArchiveError> {
    u32::try_from(value).map_err(|_| {
        ArchiveError::new(ErrorKind::Unsupported)
            .with_format("cpio")
            .with_context(context)
    })
}

fn cpio_u16(value: u64, context: &'static str) -> core::result::Result<u16, ArchiveError> {
    u16::try_from(value).map_err(|_| {
        ArchiveError::new(ErrorKind::Unsupported)
            .with_format("cpio")
            .with_context(context)
    })
}

fn write_binary_word(header: &mut [u8], index: usize, value: u16, little: bool) {
    let bytes = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    let offset = index * 2;
    header[offset..offset + 2].copy_from_slice(&bytes);
}

/// Reads the `i`-th 8-hex-digit field of a newc header (0-based, after the 6-byte magic).
fn newc_field(data: &[u8], pos: usize, i: usize) -> Result<u64> {
    let start = pos + 6 + i * 8;
    let field = data
        .get(start..start + 8)
        .ok_or(Error::Malformed("cpio: truncated newc field"))?;
    parse_radix(field, 16)
}

/// Reads an octal field of the given width at `pos + off` in an odc header.
fn odc_field(data: &[u8], pos: usize, off: usize, width: usize) -> Result<u64> {
    let start = pos + off;
    let field = data
        .get(start..start + width)
        .ok_or(Error::Malformed("cpio: truncated odc field"))?;
    parse_radix(field, 8)
}

/// Parses ASCII digits in base 8 or 16 into a `u64`. Spaces and NULs are ignored.
fn parse_radix(field: &[u8], radix: u32) -> Result<u64> {
    let mut val: u64 = 0;
    for &b in field {
        if b == b' ' || b == 0 {
            continue;
        }
        let digit = u64::from(
            (b as char)
                .to_digit(radix)
                .ok_or(Error::Malformed("cpio: invalid digit"))?,
        );
        val = val
            .checked_mul(u64::from(radix))
            .and_then(|v| v.checked_add(digit))
            .ok_or(Error::Malformed("cpio: numeric overflow"))?;
    }
    Ok(val)
}

// File-type bits (`S_IFMT`) of a UNIX mode.
const S_IFMT: u64 = 0o170_000;
const S_IFREG: u64 = 0o100_000;
const S_IFDIR: u64 = 0o040_000;
const S_IFCHR: u64 = 0o020_000;
const S_IFBLK: u64 = 0o060_000;
const S_IFIFO: u64 = 0o010_000;
const S_IFLNK: u64 = 0o120_000;
const S_IFSOCK: u64 = 0o140_000;

/// Maps the `S_IFMT` bits of `mode` to a typed [`EntryKind`].
fn kind_from_mode(mode: u64) -> EntryKind {
    match mode & S_IFMT {
        S_IFDIR => EntryKind::Dir,
        S_IFLNK => EntryKind::Symlink,
        S_IFCHR => EntryKind::Char,
        S_IFBLK => EntryKind::Block,
        S_IFIFO => EntryKind::Fifo,
        S_IFSOCK => EntryKind::Socket,
        _ => EntryKind::File,
    }
}

/// `u64` to `usize`, rejecting oversized values on 32-bit targets.
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("cpio: size exceeds usize"))
}

#[derive(Debug)]
enum DecoderState {
    Header,
    Data {
        remaining: u64,
        padding: usize,
        checksum: Option<u32>,
        checksum_actual: u32,
        emit_end: bool,
    },
    EndEntry {
        padding: usize,
        checksum: Option<u32>,
        checksum_actual: u32,
        emit_end: bool,
    },
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HardlinkKey {
    device_major: u64,
    device_minor: u64,
    inode: u64,
}

#[derive(Debug)]
struct HardlinkGroup {
    expected: u64,
    seen: u64,
    target: Option<ArchivePath>,
    pending: Vec<EntryMetadata>,
}

#[derive(Debug)]
enum QueuedEvent {
    Entry(Box<EntryMetadata>),
    EndEntry,
}

#[derive(Debug)]
struct ParsedHeader {
    metadata: EntryMetadata,
    size: u64,
    padding: usize,
    checksum: Option<u32>,
    trailer: bool,
}

/// Incremental cpio decoder supporting newc, crc, odc and binary LE/BE.
///
/// Only the fixed header and pathname are retained. Regular payload bytes are
/// borrowed directly from caller input.
#[derive(Debug)]
pub struct CpioDecoder {
    limits: Limits,
    state: DecoderState,
    header: Vec<u8>,
    header_target: Option<usize>,
    entries: u64,
    total: u64,
    hardlinks: BTreeMap<HardlinkKey, HardlinkGroup>,
    queued: VecDeque<QueuedEvent>,
    hardlink_metadata: usize,
}

impl CpioDecoder {
    /// Creates a decoder with mandatory resource limits.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: DecoderState::Header,
            header: Vec::new(),
            header_target: None,
            entries: 0,
            total: 0,
            hardlinks: BTreeMap::new(),
            queued: VecDeque::new(),
            hardlink_metadata: 0,
        }
    }

    /// Incrementally probes a cpio prefix.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() < 2 {
            return ProbeResult::NeedMore { minimum: 2 };
        }
        if prefix.starts_with(&BIN_MAGIC_LE) || prefix.starts_with(&BIN_MAGIC_BE) {
            return ProbeResult::Match(());
        }
        if prefix.len() < 6 {
            return ProbeResult::NeedMore { minimum: 6 };
        }
        if prefix.starts_with(NEWC_MAGIC)
            || prefix.starts_with(NEWC_CRC_MAGIC)
            || prefix.starts_with(ODC_MAGIC)
        {
            ProbeResult::Match(())
        } else {
            ProbeResult::NoMatch
        }
    }

    fn target_from_prefix(&self) -> core::result::Result<Option<usize>, ArchiveError> {
        if self.header.len() < 2 {
            return Ok(None);
        }
        let (fixed, namesize, alignment) =
            if self.header.starts_with(&BIN_MAGIC_LE) || self.header.starts_with(&BIN_MAGIC_BE) {
                if self.header.len() < 26 {
                    return Ok(Some(26));
                }
                let little = self.header.starts_with(&BIN_MAGIC_LE);
                let namesize = usize::from(binary_word(&self.header, 10, little)?);
                (26, namesize, 2)
            } else {
                if self.header.len() < 6 {
                    return Ok(Some(6));
                }
                if self.header.starts_with(NEWC_MAGIC) || self.header.starts_with(NEWC_CRC_MAGIC) {
                    if self.header.len() < NEWC_HEADER {
                        return Ok(Some(NEWC_HEADER));
                    }
                    let namesize = usize_of(newc_field(&self.header, 0, 11)?)?;
                    (NEWC_HEADER, namesize, 4)
                } else if self.header.starts_with(ODC_MAGIC) {
                    if self.header.len() < ODC_HEADER {
                        return Ok(Some(ODC_HEADER));
                    }
                    let namesize = usize_of(odc_field(&self.header, 0, 59, 6)?)?;
                    (ODC_HEADER, namesize, 1)
                } else {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format("cpio")
                        .with_context("unrecognized cpio magic"));
                }
            };
        if namesize == 0 {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("zero-length pathname"));
        }
        if self
            .limits
            .path_bytes()
            .is_some_and(|limit| namesize.saturating_sub(1) > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("pathname exceeds configured limit"));
        }
        let unaligned = fixed.checked_add(namesize).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("header size overflow")
        })?;
        let target = match alignment {
            4 => unaligned.checked_add(3).map(|value| value & !3),
            2 => unaligned.checked_add(1).map(|value| value & !1),
            _ => Some(unaligned),
        }
        .ok_or_else(|| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("header alignment overflow")
        })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| target > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("header metadata exceeds configured limit"));
        }
        Ok(Some(target))
    }

    #[allow(clippy::too_many_lines)]
    fn parse_header(&self) -> core::result::Result<ParsedHeader, ArchiveError> {
        let bytes = &self.header;
        let (
            fixed,
            namesize,
            size,
            mode,
            uid,
            gid,
            mtime,
            inode,
            links,
            device,
            referenced_device,
            checksum,
            data_alignment,
        ) = if bytes.starts_with(NEWC_MAGIC) || bytes.starts_with(NEWC_CRC_MAGIC) {
            let namesize = usize_of(newc_field(bytes, 0, 11)?)?;
            let size = newc_field(bytes, 0, 6)?;
            let device = Device {
                major: newc_field(bytes, 0, 7)?,
                minor: newc_field(bytes, 0, 8)?,
            };
            let referenced = Device {
                major: newc_field(bytes, 0, 9)?,
                minor: newc_field(bytes, 0, 10)?,
            };
            (
                NEWC_HEADER,
                namesize,
                size,
                newc_field(bytes, 0, 1)?,
                newc_field(bytes, 0, 2)?,
                newc_field(bytes, 0, 3)?,
                newc_field(bytes, 0, 5)?,
                newc_field(bytes, 0, 0)?,
                newc_field(bytes, 0, 4)?,
                Some(device),
                Some(referenced),
                bytes
                    .starts_with(NEWC_CRC_MAGIC)
                    .then(|| newc_field(bytes, 0, 12))
                    .transpose()?
                    .map(lo32),
                4,
            )
        } else if bytes.starts_with(ODC_MAGIC) {
            (
                ODC_HEADER,
                usize_of(odc_field(bytes, 0, 59, 6)?)?,
                odc_field(bytes, 0, 65, 11)?,
                odc_field(bytes, 0, 18, 6)?,
                odc_field(bytes, 0, 24, 6)?,
                odc_field(bytes, 0, 30, 6)?,
                odc_field(bytes, 0, 48, 11)?,
                odc_field(bytes, 0, 12, 6)?,
                odc_field(bytes, 0, 36, 6)?,
                Some(Device {
                    major: 0,
                    minor: odc_field(bytes, 0, 6, 6)?,
                }),
                Some(Device {
                    major: 0,
                    minor: odc_field(bytes, 0, 42, 6)?,
                }),
                None,
                1,
            )
        } else {
            let little = bytes.starts_with(&BIN_MAGIC_LE);
            let word = |index| binary_word(bytes, index, little);
            (
                26,
                usize::from(word(10)?),
                (u64::from(word(11)?) << 16) | u64::from(word(12)?),
                u64::from(word(3)?),
                u64::from(word(4)?),
                u64::from(word(5)?),
                (u64::from(word(8)?) << 16) | u64::from(word(9)?),
                u64::from(word(2)?),
                u64::from(word(6)?),
                Some(Device {
                    major: 0,
                    minor: u64::from(word(1)?),
                }),
                Some(Device {
                    major: 0,
                    minor: u64::from(word(7)?),
                }),
                None,
                2,
            )
        };
        if self.limits.entry_bytes().is_some_and(|limit| size > limit) {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("entry exceeds configured size limit"));
        }
        let name = bytes
            .get(fixed..fixed + namesize)
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("cpio")
                    .with_context("truncated pathname")
            })?
            .strip_suffix(&[0])
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("cpio")
                    .with_context("pathname is not NUL terminated")
            })?;
        let metadata =
            EntryMetadata::builder(kind_from_mode(mode), ArchivePath::from_bytes(name.to_vec()))
                .size(Some(size))
                .mode(Some(u32::try_from(mode & 0o7777).unwrap_or(0)))
                .owner(Owner {
                    uid: Some(uid),
                    gid: Some(gid),
                    user: None,
                    group: None,
                })
                .times(EntryTimes {
                    modified: Some(Timestamp {
                        secs: i64::try_from(mtime).unwrap_or(i64::MAX),
                        nanos: 0,
                    }),
                    ..EntryTimes::default()
                })
                .inode_and_links(Some(inode), Some(links))
                .devices(device, referenced_device)
                .checksum(checksum.map(u32::to_be_bytes).map(Vec::from))
                .build();
        let size_usize = usize::try_from(size).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("entry size exceeds address space")
        })?;
        let padding = match data_alignment {
            4 => (4 - (size_usize & 3)) & 3,
            2 => size_usize & 1,
            _ => 0,
        };
        Ok(ParsedHeader {
            trailer: name == TRAILER,
            metadata,
            size,
            padding,
            checksum,
        })
    }

    fn hardlink_metadata(metadata: EntryMetadata, target: ArchivePath) -> EntryMetadata {
        metadata
            .into_builder()
            .kind(EntryKind::Hardlink)
            .size(Some(0))
            .link_target(Some(target))
            .build()
    }

    fn queue_entry(&mut self, metadata: EntryMetadata) {
        self.queued
            .push_back(QueuedEvent::Entry(Box::new(metadata)));
        self.queued.push_back(QueuedEvent::EndEntry);
    }

    fn charge_hardlink_metadata(
        &mut self,
        metadata: &EntryMetadata,
    ) -> core::result::Result<(), ArchiveError> {
        let charge = core::mem::size_of::<EntryMetadata>()
            .checked_add(metadata.path().as_bytes().len())
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("cpio")
                    .with_context("hardlink metadata accounting overflow")
            })?;
        self.hardlink_metadata = self.hardlink_metadata.checked_add(charge).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("hardlink metadata accounting overflow")
        })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| self.hardlink_metadata > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("hardlink metadata exceeds configured limit"));
        }
        Ok(())
    }

    fn classify_hardlink(
        &mut self,
        metadata: EntryMetadata,
        size: u64,
    ) -> core::result::Result<Option<EntryMetadata>, ArchiveError> {
        let links = metadata.links().unwrap_or(1);
        if metadata.kind() != EntryKind::File || links <= 1 {
            return Ok(Some(metadata));
        }
        self.charge_hardlink_metadata(&metadata)?;
        let device = metadata.device().unwrap_or_default();
        let key = HardlinkKey {
            device_major: device.major,
            device_minor: device.minor,
            inode: metadata.inode().unwrap_or(0),
        };
        let mut group = self.hardlinks.remove(&key).unwrap_or(HardlinkGroup {
            expected: links,
            seen: 0,
            target: None,
            pending: Vec::new(),
        });
        if group.expected != links {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("hardlink group disagrees on link count"));
        }
        group.seen = group.seen.checked_add(1).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("hardlink count overflow")
        })?;
        if group.seen > group.expected {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("hardlink group has more records than nlink"));
        }

        let result = if size != 0 {
            if group.target.is_some() {
                return Err(ArchiveError::new(ErrorKind::Malformed)
                    .with_format("cpio")
                    .with_context("hardlink group contains multiple payload records"));
            }
            let target = metadata.path().clone();
            group.target = Some(target.clone());
            for pending in core::mem::take(&mut group.pending) {
                self.queue_entry(Self::hardlink_metadata(pending, target.clone()));
            }
            Some(metadata)
        } else if let Some(target) = group.target.clone() {
            Some(Self::hardlink_metadata(metadata, target))
        } else {
            group.pending.push(metadata);
            if group.seen == group.expected {
                let mut pending = core::mem::take(&mut group.pending).into_iter();
                let first = pending.next().ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("empty hardlink group lost its first record")
                })?;
                let target = first.path().clone();
                group.target = Some(target.clone());
                self.queue_entry(first);
                for metadata in pending {
                    self.queue_entry(Self::hardlink_metadata(metadata, target.clone()));
                }
            }
            None
        };
        self.hardlinks.insert(key, group);
        Ok(result)
    }

    fn resolve_incomplete_hardlinks(&mut self) -> core::result::Result<(), ArchiveError> {
        let mut queued = Vec::new();
        for group in self.hardlinks.values_mut() {
            if group.target.is_some() || group.pending.is_empty() {
                continue;
            }
            let mut pending = core::mem::take(&mut group.pending).into_iter();
            let first = pending.next().ok_or_else(|| {
                ArchiveError::new(ErrorKind::Protocol)
                    .with_format("cpio")
                    .with_context("pending hardlink group disappeared")
            })?;
            let target = first.path().clone();
            group.target = Some(target.clone());
            queued.push(first);
            for metadata in pending {
                queued.push(Self::hardlink_metadata(metadata, target.clone()));
            }
        }
        for metadata in queued {
            self.queue_entry(metadata);
        }
        Ok(())
    }

    fn pop_queued<'a>(&mut self, consumed: usize) -> Option<DecodeStep<'a>> {
        self.queued.pop_front().map(|event| DecodeStep {
            consumed,
            produced: 0,
            event: match event {
                QueuedEvent::Entry(metadata) => DecodeEvent::Entry(*metadata),
                QueuedEvent::EndEntry => DecodeEvent::EndEntry,
            },
        })
    }
}

impl ArchiveDecoder for CpioDecoder {
    #[allow(clippy::too_many_lines)]
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        _output: &'a mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<DecodeStep<'a>, ArchiveError> {
        if matches!(self.state, DecoderState::Header | DecoderState::Done) {
            if let Some(step) = self.pop_queued(0) {
                return Ok(step);
            }
        }
        match self.state {
            DecoderState::Done => {
                if !input.is_empty() {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("input supplied after archive completion"));
                }
                return Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::Done,
                });
            },
            DecoderState::Data {
                remaining,
                padding,
                checksum,
                checksum_actual,
                emit_end,
            } => {
                if remaining == 0 {
                    self.state = DecoderState::EndEntry {
                        padding,
                        checksum,
                        checksum_actual,
                        emit_end,
                    };
                    return self.step(input, &mut [], end);
                }
                if input.is_empty() {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("cpio")
                            .with_context("truncated entry data"));
                    }
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                let count = input
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let bytes = &input[..count];
                let actual = bytes.iter().fold(checksum_actual, |sum, byte| {
                    sum.wrapping_add(u32::from(*byte))
                });
                self.total = self.total.checked_add(count as u64).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("decoded byte count overflow")
                })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|limit| self.total > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("decoded total exceeds configured limit"));
                }
                self.state = DecoderState::Data {
                    remaining: remaining - count as u64,
                    padding,
                    checksum,
                    checksum_actual: actual,
                    emit_end,
                };
                return Ok(DecodeStep {
                    consumed: count,
                    produced: 0,
                    event: DecodeEvent::Data(Chunk::new(bytes)),
                });
            },
            DecoderState::EndEntry {
                padding,
                checksum,
                checksum_actual,
                emit_end,
            } => {
                if input.len() < padding {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("cpio")
                            .with_context("truncated entry padding"));
                    }
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                if checksum.is_some_and(|expected| expected != checksum_actual) {
                    return Err(ArchiveError::new(ErrorKind::Integrity)
                        .with_format("cpio")
                        .with_context("crc payload checksum mismatch"));
                }
                self.state = DecoderState::Header;
                if emit_end {
                    return Ok(DecodeStep {
                        consumed: padding,
                        produced: 0,
                        event: DecodeEvent::EndEntry,
                    });
                }
                let mut step = self.step(&input[padding..], &mut [], end)?;
                step.consumed = step.consumed.checked_add(padding).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("decoder progress overflow")
                })?;
                return Ok(step);
            },
            DecoderState::Header => {},
        }

        let mut consumed = 0;
        loop {
            let target = self.header_target.unwrap_or_else(|| {
                if self.header.len() < 2 {
                    2
                } else if self.header.starts_with(&BIN_MAGIC_LE)
                    || self.header.starts_with(&BIN_MAGIC_BE)
                {
                    26
                } else if self.header.len() < 6 {
                    6
                } else if self.header.starts_with(ODC_MAGIC) {
                    ODC_HEADER
                } else {
                    NEWC_HEADER
                }
            });
            if self.header.len() < target {
                let count = (target - self.header.len()).min(input.len() - consumed);
                self.header
                    .extend_from_slice(&input[consumed..consumed + count]);
                consumed += count;
                if self.header.len() < target {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("cpio")
                            .with_context("truncated entry header"));
                    }
                    return Ok(DecodeStep {
                        consumed,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
            }
            let next = self.target_from_prefix()?;
            self.header_target = next;
            if next.is_some_and(|needed| self.header.len() < needed) {
                if consumed == input.len() {
                    return Ok(DecodeStep {
                        consumed,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                continue;
            }
            break;
        }

        let parsed = self.parse_header()?;
        self.header.clear();
        self.header_target = None;
        if parsed.trailer {
            self.resolve_incomplete_hardlinks()?;
            self.state = DecoderState::Done;
            if let Some(step) = self.pop_queued(consumed) {
                return Ok(step);
            }
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::Done,
            });
        }
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("entry count overflow")
        })?;
        if self
            .limits
            .entries()
            .is_some_and(|limit| self.entries > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("cpio")
                .with_context("entry count exceeds configured limit"));
        }
        let metadata = self.classify_hardlink(parsed.metadata, parsed.size)?;
        self.state = DecoderState::Data {
            remaining: parsed.size,
            padding: parsed.padding,
            checksum: parsed.checksum,
            checksum_actual: 0,
            emit_end: metadata.is_some(),
        };
        if let Some(metadata) = metadata {
            Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::Entry(metadata),
            })
        } else {
            let mut step = self.step(&input[consumed..], &mut [], end)?;
            step.consumed = step.consumed.checked_add(consumed).ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("cpio")
                    .with_context("decoder progress overflow")
            })?;
            Ok(step)
        }
    }
}

fn binary_word(
    bytes: &[u8],
    index: usize,
    little: bool,
) -> core::result::Result<u16, ArchiveError> {
    let offset = index.checked_mul(2).ok_or_else(|| {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("cpio")
            .with_context("binary header offset overflow")
    })?;
    let pair: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("cpio")
                .with_context("truncated binary header")
        })?;
    Ok(if little {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    })
}

/// Identity shared by the records in one cpio hardlink group.
#[derive(Debug, Clone, Copy)]
struct LinkIdentity {
    inode: u64,
    links: u64,
    device: Device,
}

#[derive(Debug, Clone, Copy)]
struct StagedHeader {
    size: u64,
    identity: LinkIdentity,
    alignment: usize,
    checksum: Option<u32>,
}

/// Streaming cpio encoder driven by [`EncodeCommand`].
#[derive(Debug)]
pub struct CpioEncoder {
    limits: Limits,
    dialect: CpioDialect,
    pending: Vec<u8>,
    pending_pos: usize,
    inode: u32,
    open: bool,
    entry_size: u64,
    entry_alignment: usize,
    remaining: u64,
    expected_checksum: Option<u32>,
    checksum_actual: u32,
    finishing: bool,
    done: bool,
    entries: u64,
    link_targets: BTreeMap<Vec<u8>, LinkIdentity>,
}

impl CpioEncoder {
    /// Creates an empty newc encoder.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            dialect: CpioDialect::Newc,
            pending: Vec::new(),
            pending_pos: 0,
            inode: 0,
            open: false,
            entry_size: 0,
            entry_alignment: 4,
            remaining: 0,
            expected_checksum: None,
            checksum_actual: 0,
            finishing: false,
            done: false,
            entries: 0,
            link_targets: BTreeMap::new(),
        }
    }

    /// Creates an empty encoder for an explicit cpio dialect.
    #[must_use]
    pub const fn with_dialect(limits: Limits, dialect: CpioDialect) -> Self {
        let mut encoder = Self::new(limits);
        encoder.dialect = dialect;
        encoder
    }

    fn drain_pending(&mut self, output: &mut [u8]) -> usize {
        let count = (self.pending.len() - self.pending_pos).min(output.len());
        output[..count].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + count]);
        self.pending_pos += count;
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        count
    }

    #[allow(clippy::too_many_lines)]
    fn stage_header(
        &mut self,
        name: &[u8],
        metadata: Option<&EntryMetadata>,
    ) -> core::result::Result<StagedHeader, ArchiveError> {
        let size = metadata.and_then(EntryMetadata::size).unwrap_or(0);
        let namesize = u64::try_from(name.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("cpio")
                    .with_context("pathname size overflow")
            })?;
        let mode = metadata.map_or(0, |meta| {
            mode_bits(meta.kind())
                | u64::from(meta.mode().unwrap_or_else(|| default_mode(meta.kind())) & 0o7777)
        });
        let uid = metadata.and_then(|meta| meta.owner().uid).unwrap_or(0);
        let gid = metadata.and_then(|meta| meta.owner().gid).unwrap_or(0);
        let links = metadata.and_then(EntryMetadata::links).unwrap_or(1);
        let mtime = metadata
            .and_then(|meta| meta.times().modified)
            .map_or(0, |time| u64::try_from(time.secs.max(0)).unwrap_or(0));
        let device = metadata.and_then(EntryMetadata::device).unwrap_or_default();
        let referenced = metadata
            .and_then(EntryMetadata::referenced_device)
            .unwrap_or_default();
        let inode = metadata
            .and_then(EntryMetadata::inode)
            .unwrap_or(u64::from(self.inode));
        let checksum = if self.dialect == CpioDialect::Crc {
            match metadata.and_then(EntryMetadata::checksum) {
                Some(bytes) if bytes.len() == 4 => {
                    Some(u32::from_be_bytes(bytes.try_into().map_err(|_| {
                        ArchiveError::new(ErrorKind::Protocol)
                            .with_format("cpio")
                            .with_context("CRC checksum conversion failed")
                    })?))
                },
                None if size == 0 => Some(0),
                _ => {
                    return Err(ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("cpio")
                        .with_context(
                            "crc output requires a four-byte big-endian payload byte sum",
                        ));
                },
            }
        } else {
            None
        };
        let alignment = match self.dialect {
            CpioDialect::Newc | CpioDialect::Crc => {
                let fields = [
                    cpio_u32(inode, "newc inode exceeds 32-bit field")?,
                    cpio_u32(mode, "newc mode exceeds 32-bit field")?,
                    cpio_u32(uid, "newc uid exceeds 32-bit field")?,
                    cpio_u32(gid, "newc gid exceeds 32-bit field")?,
                    cpio_u32(links, "newc nlink exceeds 32-bit field")?,
                    cpio_u32(mtime, "newc mtime exceeds 32-bit field")?,
                    cpio_u32(size, "newc entry size exceeds 32-bit field")?,
                    cpio_u32(device.major, "newc device major exceeds 32-bit field")?,
                    cpio_u32(device.minor, "newc device minor exceeds 32-bit field")?,
                    cpio_u32(
                        referenced.major,
                        "newc referenced device major exceeds 32-bit field",
                    )?,
                    cpio_u32(
                        referenced.minor,
                        "newc referenced device minor exceeds 32-bit field",
                    )?,
                    cpio_u32(namesize, "newc pathname exceeds 32-bit field")?,
                    checksum.unwrap_or(0),
                ];
                self.pending.resize(NEWC_HEADER, 0);
                self.pending[..6].copy_from_slice(if self.dialect == CpioDialect::Crc {
                    NEWC_CRC_MAGIC
                } else {
                    NEWC_MAGIC
                });
                for (index, value) in fields.iter().enumerate() {
                    let offset = 6 + index * 8;
                    put_hex8(&mut self.pending[offset..offset + 8], *value);
                }
                4
            },
            CpioDialect::Odc => {
                if device.major != 0 || referenced.major != 0 {
                    return Err(ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("cpio")
                        .with_context("odc cannot preserve split device major numbers"));
                }
                self.pending.resize(ODC_HEADER, b'0');
                self.pending[..6].copy_from_slice(ODC_MAGIC);
                for (offset, width, value) in [
                    (6, 6, device.minor),
                    (12, 6, inode),
                    (18, 6, mode),
                    (24, 6, uid),
                    (30, 6, gid),
                    (36, 6, links),
                    (42, 6, referenced.minor),
                    (48, 11, mtime),
                    (59, 6, namesize),
                    (65, 11, size),
                ] {
                    put_octal(&mut self.pending[offset..offset + width], value)?;
                }
                1
            },
            CpioDialect::BinaryLittleEndian | CpioDialect::BinaryBigEndian => {
                if device.major != 0 || referenced.major != 0 {
                    return Err(ArchiveError::new(ErrorKind::Unsupported)
                        .with_format("cpio")
                        .with_context("binary cpio cannot preserve split device major numbers"));
                }
                let little = self.dialect == CpioDialect::BinaryLittleEndian;
                let mtime = cpio_u32(mtime, "binary cpio mtime exceeds 32 bits")?;
                let size = cpio_u32(size, "binary cpio size exceeds 32 bits")?;
                let fields = [
                    0o070_707,
                    cpio_u16(device.minor, "binary cpio device exceeds 16 bits")?,
                    cpio_u16(inode, "binary cpio inode exceeds 16 bits")?,
                    cpio_u16(mode, "binary cpio mode exceeds 16 bits")?,
                    cpio_u16(uid, "binary cpio uid exceeds 16 bits")?,
                    cpio_u16(gid, "binary cpio gid exceeds 16 bits")?,
                    cpio_u16(links, "binary cpio nlink exceeds 16 bits")?,
                    cpio_u16(
                        referenced.minor,
                        "binary cpio referenced device exceeds 16 bits",
                    )?,
                    u16::try_from(mtime >> 16).unwrap_or(0),
                    u16::try_from(mtime & 0xffff).unwrap_or(0),
                    cpio_u16(namesize, "binary cpio pathname exceeds 16 bits")?,
                    u16::try_from(size >> 16).unwrap_or(0),
                    u16::try_from(size & 0xffff).unwrap_or(0),
                ];
                self.pending.resize(26, 0);
                for (index, value) in fields.iter().enumerate() {
                    write_binary_word(&mut self.pending, index, *value, little);
                }
                2
            },
        };
        self.pending.extend_from_slice(name);
        self.pending.push(0);
        let aligned = self
            .pending
            .len()
            .checked_add(alignment - 1)
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("cpio")
                    .with_context("header size overflow")
            })?
            / alignment
            * alignment;
        self.pending.resize(aligned, 0);
        self.inode = self.inode.wrapping_add(1);
        Ok(StagedHeader {
            size,
            identity: LinkIdentity {
                inode,
                links,
                device,
            },
            alignment,
            checksum,
        })
    }
}

impl ArchiveEncoder for CpioEncoder {
    #[allow(clippy::too_many_lines)]
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> core::result::Result<EncodeStep, ArchiveError> {
        if self.done {
            return match command {
                EncodeCommand::Finish => Ok(EncodeStep {
                    consumed: 0,
                    produced: 0,
                    status: EncodeStatus::Done,
                }),
                _ => Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("cpio")
                    .with_context("command supplied after finish")),
            };
        }
        if !self.pending.is_empty() {
            let produced = self.drain_pending(output);
            if self.pending.is_empty() && self.finishing {
                self.done = true;
                return Ok(EncodeStep {
                    consumed: 0,
                    produced,
                    status: EncodeStatus::Done,
                });
            }
            return Ok(EncodeStep {
                consumed: 0,
                produced,
                status: if self.pending.is_empty() {
                    EncodeStatus::NeedCommand
                } else {
                    EncodeStatus::NeedOutput
                },
            });
        }
        match command {
            EncodeCommand::BeginEntry(metadata) => {
                if self.open {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("previous entry is still open"));
                }
                if metadata.size().is_none() {
                    return Err(ArchiveError::new(ErrorKind::SizeRequired)
                        .with_format("cpio")
                        .with_context("cpio requires a declared entry size"));
                }
                let size = metadata.size().unwrap_or(0);
                if self
                    .limits
                    .path_bytes()
                    .is_some_and(|limit| metadata.path().as_bytes().len() > limit)
                    || self.limits.entry_bytes().is_some_and(|limit| size > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("entry exceeds configured limits"));
                }
                let next_entries = self.entries.checked_add(1).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("entry count overflow")
                })?;
                if self
                    .limits
                    .entries()
                    .is_some_and(|limit| next_entries > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("entry count exceeds configured limit"));
                }
                let effective;
                let metadata = if metadata.kind() == EntryKind::Hardlink {
                    if size != 0 {
                        return Err(ArchiveError::new(ErrorKind::Protocol)
                            .with_format("cpio")
                            .with_context("cpio hardlink entries must have zero size"));
                    }
                    let target = metadata.link_target().ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Protocol)
                            .with_format("cpio")
                            .with_context("cpio hardlink is missing its target")
                    })?;
                    let identity = self
                        .link_targets
                        .get(target.as_bytes())
                        .copied()
                        .ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_format("cpio")
                                .with_context("cpio hardlink target must precede the link entry")
                        })?;
                    if identity.links <= 1 {
                        return Err(ArchiveError::new(ErrorKind::Protocol)
                            .with_format("cpio")
                            .with_context(
                                "cpio hardlink target must declare nlink greater than one",
                            ));
                    }
                    effective = metadata
                        .clone()
                        .into_builder()
                        .kind(EntryKind::File)
                        .size(Some(0))
                        .inode_and_links(Some(identity.inode), Some(identity.links))
                        .devices(Some(identity.device), metadata.referenced_device())
                        .build();
                    &effective
                } else {
                    metadata
                };
                let staged = self.stage_header(metadata.path().as_bytes(), Some(metadata))?;
                if metadata.kind() == EntryKind::File && staged.identity.links > 1 {
                    self.link_targets
                        .insert(metadata.path().as_bytes().to_vec(), staged.identity);
                }
                self.entries = next_entries;
                self.entry_size = staged.size;
                self.entry_alignment = staged.alignment;
                self.remaining = staged.size;
                self.expected_checksum = staged.checksum;
                self.checksum_actual = 0;
                self.open = true;
                let produced = self.drain_pending(output);
                Ok(EncodeStep {
                    consumed: 1,
                    produced,
                    status: if self.pending.is_empty() {
                        EncodeStatus::NeedCommand
                    } else {
                        EncodeStatus::NeedOutput
                    },
                })
            },
            EncodeCommand::Data(input) => {
                if !self.open {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("entry data supplied without an open entry"));
                }
                if input.len() as u64 > self.remaining {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("entry data exceeds declared size"));
                }
                let count = input.len().min(output.len());
                output[..count].copy_from_slice(&input[..count]);
                self.checksum_actual = input[..count]
                    .iter()
                    .fold(self.checksum_actual, |sum, byte| {
                        sum.wrapping_add(u32::from(*byte))
                    });
                self.remaining -= count as u64;
                Ok(EncodeStep {
                    consumed: count,
                    produced: count,
                    status: if count == input.len() {
                        EncodeStatus::NeedCommand
                    } else {
                        EncodeStatus::NeedOutput
                    },
                })
            },
            EncodeCommand::EndEntry => {
                if !self.open || self.remaining != 0 {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("entry ended before its declared size"));
                }
                let size = usize::try_from(self.entry_size).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("cpio")
                        .with_context("entry size exceeds address space")
                })?;
                if self
                    .expected_checksum
                    .is_some_and(|expected| expected != self.checksum_actual)
                {
                    return Err(ArchiveError::new(ErrorKind::Integrity)
                        .with_format("cpio")
                        .with_context("written payload does not match declared crc byte sum"));
                }
                let remainder = size % self.entry_alignment;
                let padding = if remainder == 0 {
                    0
                } else {
                    self.entry_alignment - remainder
                };
                self.pending.resize(padding, 0);
                self.open = false;
                let produced = self.drain_pending(output);
                Ok(EncodeStep {
                    consumed: 1,
                    produced,
                    status: if self.pending.is_empty() {
                        EncodeStatus::NeedCommand
                    } else {
                        EncodeStatus::NeedOutput
                    },
                })
            },
            EncodeCommand::Finish => {
                if self.open {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("cpio")
                        .with_context("cannot finish with an open entry"));
                }
                let _ = self.stage_header(TRAILER, None)?;
                self.finishing = true;
                let produced = self.drain_pending(output);
                if self.pending.is_empty() {
                    self.done = true;
                }
                Ok(EncodeStep {
                    consumed: 1,
                    produced,
                    status: if self.done {
                        EncodeStatus::Done
                    } else {
                        EncodeStatus::NeedOutput
                    },
                })
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn radix_parsing() {
        assert_eq!(parse_radix(b"000000ff", 16).unwrap(), 255);
        assert_eq!(parse_radix(b"000644", 8).unwrap(), 0o644);
    }
}
