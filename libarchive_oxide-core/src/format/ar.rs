// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unix `ar` archive format (used by `.deb`, static libraries).
//!
//! Handles the three name conventions: plain `SysV` names (trailing `/` terminator), the GNU
//! extended-name string table (`//` member plus `/N` offset references), and BSD long names
//! (`#1/LEN` with the real name stored at the start of the member data). The special GNU symbol
//! tables (`/` and 64-bit `/SYM64/`) are skipped. Every member is a regular file (`ar` carries no
//! type info).

use alloc::vec::Vec;

use crate::Limits;
use crate::error::{ArchiveError, Error, ErrorKind, Result};
use crate::meta::{EntryKind, Timestamp, default_mode};
use crate::metadata::{ArchivePath, EntryMetadata, EntryTimes, Extension, Owner};
use crate::protocol::{
    ArchiveDecoder, ArchiveEncoder, Chunk, DecodeEvent, DecodeStep, EncodeCommand, EncodeStatus,
    EncodeStep, EndOfInput, ProbeResult,
};

const MAGIC: &[u8] = b"!<arch>\n";
const THIN_MAGIC: &[u8] = b"!<thin>\n";
const HEADER: usize = 60;
const F_NAME: (usize, usize) = (0, 16);
const F_MTIME: (usize, usize) = (16, 28);
const F_UID: (usize, usize) = (28, 34);
const F_GID: (usize, usize) = (34, 40);
const F_MODE: (usize, usize) = (40, 48);
const F_SIZE: (usize, usize) = (48, 58);
const F_MAGIC: (usize, usize) = (58, 60);

/// Left-aligns `value` into `field`, space-padding the remainder (ar's ASCII header fields).
fn put_field(field: &mut [u8], value: &[u8]) {
    field.fill(b' ');
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
}

/// Formats `val` in the given radix (8 or 10) into `buf`, returning the written slice.
fn radix_bytes(val: u64, radix: u64, buf: &mut [u8; 24]) -> &[u8] {
    if val == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    let mut v = val;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + u8::try_from(v % radix).unwrap_or(0);
        v /= radix;
    }
    &buf[i..]
}

/// Extracts a fixed header field.
fn field(hdr: &[u8], (start, end): (usize, usize)) -> &[u8] {
    &hdr[start..end]
}

/// Trims trailing occurrences of `b` from a slice.
fn rtrim(mut s: &[u8], b: u8) -> &[u8] {
    while let [rest @ .., last] = s {
        if *last == b {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Looks up a name at `offset` in the GNU string table (names are `\n`-terminated, `/`-suffixed).
fn gnu_table_name(table: &[u8], offset: usize) -> Result<&[u8]> {
    let rest = table
        .get(offset..)
        .ok_or(Error::Malformed("ar: // offset out of range"))?;
    let end = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
    Ok(rest[..end].strip_suffix(b"/").unwrap_or(&rest[..end]))
}

/// Parses ASCII decimal digits into a `u64`.
fn parse_decimal(field: &[u8]) -> Result<u64> {
    if field.is_empty() {
        return Err(Error::Malformed("ar: empty numeric field"));
    }
    let mut val: u64 = 0;
    for &b in field {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed("ar: invalid decimal digit"));
        }
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(Error::Malformed("ar: numeric overflow"))?;
    }
    Ok(val)
}

/// Parses ASCII octal digits into a `u64` (empty yields 0).
fn parse_octal(field: &[u8]) -> Result<u64> {
    let mut val: u64 = 0;
    for &b in field {
        if !(b'0'..=b'7').contains(&b) {
            return Err(Error::Malformed("ar: invalid octal digit"));
        }
        val = val
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(Error::Malformed("ar: numeric overflow"))?;
    }
    Ok(val)
}

/// `u64` to `usize`, rejecting oversized values on 32-bit targets.
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("ar: size exceeds usize"))
}

#[derive(Debug, Clone, Copy)]
struct ArFields {
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: Option<Timestamp>,
}

#[derive(Debug)]
enum ArDecoderState {
    Magic,
    Header,
    Special {
        remaining: usize,
        padding: usize,
        string_table: bool,
    },
    BsdName {
        remaining: usize,
        body_size: u64,
        padding: usize,
        fields: ArFields,
    },
    Data {
        remaining: u64,
        padding: usize,
    },
    EndEntry {
        padding: usize,
    },
    Done,
}

/// Incremental SysV/GNU/BSD ar decoder, including thin-archive metadata.
#[derive(Debug)]
pub struct ArDecoder {
    limits: Limits,
    state: ArDecoderState,
    pending: Vec<u8>,
    string_table: Vec<u8>,
    thin: bool,
    entries: u64,
    total: u64,
}

impl ArDecoder {
    /// Creates a decoder with mandatory resource limits.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: ArDecoderState::Magic,
            pending: Vec::new(),
            string_table: Vec::new(),
            thin: false,
            entries: 0,
            total: 0,
        }
    }

    /// Incrementally probes regular and thin ar archives.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() < MAGIC.len() {
            return ProbeResult::NeedMore {
                minimum: MAGIC.len(),
            };
        }
        if prefix.starts_with(MAGIC) || prefix.starts_with(THIN_MAGIC) {
            ProbeResult::Match(())
        } else {
            ProbeResult::NoMatch
        }
    }

    fn fill(pending: &mut Vec<u8>, target: usize, input: &[u8]) -> usize {
        let count = (target - pending.len()).min(input.len());
        pending.extend_from_slice(&input[..count]);
        count
    }

    fn fields(header: &[u8]) -> core::result::Result<ArFields, ArchiveError> {
        if field(header, F_MAGIC) != b"`\n" {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("ar")
                .with_context("bad member header terminator"));
        }
        Ok(ArFields {
            mode: u32::try_from(parse_octal(rtrim(field(header, F_MODE), b' '))? & 0o7777)
                .unwrap_or(0),
            uid: parse_decimal(rtrim(field(header, F_UID), b' ')).unwrap_or(0),
            gid: parse_decimal(rtrim(field(header, F_GID), b' ')).unwrap_or(0),
            mtime: parse_decimal(rtrim(field(header, F_MTIME), b' '))
                .ok()
                .map(|seconds| Timestamp {
                    secs: i64::try_from(seconds).unwrap_or(i64::MAX),
                    nanos: 0,
                }),
        })
    }

    fn metadata(
        &self,
        name: Vec<u8>,
        size: u64,
        fields: ArFields,
    ) -> core::result::Result<EntryMetadata, ArchiveError> {
        if self
            .limits
            .path_bytes()
            .is_some_and(|limit| name.len() > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("ar")
                .with_context("pathname exceeds configured limit"));
        }
        if self.limits.entry_bytes().is_some_and(|limit| size > limit) {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("ar")
                .with_context("member exceeds configured size limit"));
        }
        let mut builder = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name))
            .size(Some(size))
            .mode(Some(fields.mode))
            .owner(Owner {
                uid: Some(fields.uid),
                gid: Some(fields.gid),
                user: None,
                group: None,
            })
            .times(EntryTimes {
                modified: fields.mtime,
                ..EntryTimes::default()
            });
        if self.thin {
            builder = builder.extension(Extension::new(
                "ar-thin",
                b"external-reference".to_vec(),
                Vec::new(),
            ));
        }
        Ok(builder.build())
    }

    fn count_entry(&mut self) -> core::result::Result<(), ArchiveError> {
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("ar")
                .with_context("entry count overflow")
        })?;
        if self
            .limits
            .entries()
            .is_some_and(|limit| self.entries > limit)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("ar")
                .with_context("entry count exceeds configured limit"));
        }
        Ok(())
    }

    fn resolve_gnu_name(&self, offset: usize) -> core::result::Result<Vec<u8>, ArchiveError> {
        Ok(gnu_table_name(&self.string_table, offset)?.to_vec())
    }
}

impl ArchiveDecoder for ArDecoder {
    #[allow(clippy::too_many_lines, clippy::only_used_in_recursion)]
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<DecodeStep<'a>, ArchiveError> {
        match self.state {
            ArDecoderState::Done => {
                if !input.is_empty() {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("ar")
                        .with_context("input supplied after archive completion"));
                }
                return Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::Done,
                });
            },
            ArDecoderState::Data { remaining, padding } => {
                if remaining == 0 {
                    self.state = ArDecoderState::EndEntry { padding };
                    return self.step(input, output, end);
                }
                if input.is_empty() {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("ar")
                            .with_context("truncated member data"));
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
                self.total = self.total.checked_add(count as u64).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("decoded byte count overflow")
                })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|limit| self.total > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("decoded total exceeds configured limit"));
                }
                self.state = ArDecoderState::Data {
                    remaining: remaining - count as u64,
                    padding,
                };
                return Ok(DecodeStep {
                    consumed: count,
                    produced: 0,
                    event: DecodeEvent::Data(Chunk::new(&input[..count])),
                });
            },
            ArDecoderState::EndEntry { padding } => {
                if input.len() < padding {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("ar")
                            .with_context("truncated member padding"));
                    }
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                self.state = ArDecoderState::Header;
                return Ok(DecodeStep {
                    consumed: padding,
                    produced: 0,
                    event: DecodeEvent::EndEntry,
                });
            },
            ArDecoderState::Special {
                remaining,
                padding,
                string_table,
            } => {
                let count = remaining.min(input.len());
                if string_table {
                    self.string_table.extend_from_slice(&input[..count]);
                }
                let left = remaining - count;
                if left != 0 {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("ar")
                            .with_context("truncated special member"));
                    }
                    self.state = ArDecoderState::Special {
                        remaining: left,
                        padding,
                        string_table,
                    };
                    return Ok(DecodeStep {
                        consumed: count,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                if input.len() - count < padding {
                    self.state = ArDecoderState::Special {
                        remaining: 0,
                        padding,
                        string_table,
                    };
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("ar")
                            .with_context("truncated special-member padding"));
                    }
                    return Ok(DecodeStep {
                        consumed: count,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                self.state = ArDecoderState::Header;
                return Ok(DecodeStep {
                    consumed: count + padding,
                    produced: 0,
                    event: DecodeEvent::NeedInput,
                });
            },
            ArDecoderState::BsdName {
                remaining,
                body_size,
                padding,
                ..
            } => {
                let count = remaining.min(input.len());
                self.pending.extend_from_slice(&input[..count]);
                let left = remaining - count;
                if left != 0 {
                    if matches!(end, EndOfInput::End) {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("ar")
                            .with_context("truncated BSD inline name"));
                    }
                    let ArDecoderState::BsdName { fields, .. } =
                        core::mem::replace(&mut self.state, ArDecoderState::Done)
                    else {
                        return Err(ArchiveError::new(ErrorKind::Protocol)
                            .with_format("ar")
                            .with_context("BSD name state changed unexpectedly"));
                    };
                    self.state = ArDecoderState::BsdName {
                        remaining: left,
                        body_size,
                        padding,
                        fields,
                    };
                    return Ok(DecodeStep {
                        consumed: count,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                let ArDecoderState::BsdName { fields, .. } =
                    core::mem::replace(&mut self.state, ArDecoderState::Done)
                else {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("ar")
                        .with_context("BSD name state changed unexpectedly"));
                };
                let name = core::mem::take(&mut self.pending);
                let metadata = self.metadata(name, body_size, fields)?;
                self.count_entry()?;
                self.state = if self.thin {
                    ArDecoderState::EndEntry { padding: 0 }
                } else {
                    ArDecoderState::Data {
                        remaining: body_size,
                        padding,
                    }
                };
                return Ok(DecodeStep {
                    consumed: count,
                    produced: 0,
                    event: DecodeEvent::Entry(metadata),
                });
            },
            ArDecoderState::Magic | ArDecoderState::Header => {},
        }

        let mut consumed = 0;
        if matches!(self.state, ArDecoderState::Magic) {
            consumed += Self::fill(&mut self.pending, MAGIC.len(), input);
            if self.pending.len() < MAGIC.len() {
                if matches!(end, EndOfInput::End) {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format("ar")
                        .with_context("truncated global magic"));
                }
                return Ok(DecodeStep {
                    consumed,
                    produced: 0,
                    event: DecodeEvent::NeedInput,
                });
            }
            self.thin = self.pending.as_slice() == THIN_MAGIC;
            if self.pending.as_slice() != MAGIC && !self.thin {
                return Err(ArchiveError::new(ErrorKind::Malformed)
                    .with_format("ar")
                    .with_context("bad global magic"));
            }
            self.pending.clear();
            self.state = ArDecoderState::Header;
        }

        if self.pending.is_empty() && consumed == input.len() && matches!(end, EndOfInput::End) {
            self.state = ArDecoderState::Done;
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::Done,
            });
        }

        consumed += Self::fill(&mut self.pending, HEADER, &input[consumed..]);
        if self.pending.len() < HEADER {
            if matches!(end, EndOfInput::End) {
                return Err(ArchiveError::new(ErrorKind::Malformed)
                    .with_format("ar")
                    .with_context("truncated member header"));
            }
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::NeedInput,
            });
        }

        let header = core::mem::take(&mut self.pending);
        let fields = Self::fields(&header)?;
        let size = usize_of(parse_decimal(rtrim(field(&header, F_SIZE), b' '))?)?;
        let padding = size & 1;
        let raw_name = rtrim(field(&header, F_NAME), b' ');
        if raw_name == b"//" || raw_name == b"/" || raw_name == b"/SYM64/" {
            if raw_name == b"//" {
                if self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|limit| size > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("GNU string table exceeds metadata budget"));
                }
                self.string_table.clear();
                self.string_table.reserve(size);
            }
            self.state = ArDecoderState::Special {
                remaining: size,
                padding,
                string_table: raw_name == b"//",
            };
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::NeedInput,
            });
        }

        if let Some(length) = raw_name.strip_prefix(b"#1/") {
            let name_length = usize_of(parse_decimal(length)?)?;
            let body_size = size.checked_sub(name_length).ok_or_else(|| {
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("ar")
                    .with_context("BSD name is longer than member")
            })?;
            if self
                .limits
                .path_bytes()
                .is_some_and(|limit| name_length > limit)
            {
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("ar")
                    .with_context("BSD pathname exceeds configured limit"));
            }
            self.pending.clear();
            self.pending.reserve(name_length);
            self.state = ArDecoderState::BsdName {
                remaining: name_length,
                body_size: body_size as u64,
                padding,
                fields,
            };
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::NeedInput,
            });
        }

        let name = if raw_name.len() >= 2 && raw_name[0] == b'/' && raw_name[1].is_ascii_digit() {
            let offset = usize_of(parse_decimal(&raw_name[1..])?)?;
            self.resolve_gnu_name(offset)?
        } else {
            raw_name.strip_suffix(b"/").unwrap_or(raw_name).to_vec()
        };
        let metadata = self.metadata(name, size as u64, fields)?;
        self.count_entry()?;
        self.state = if self.thin {
            ArDecoderState::EndEntry { padding: 0 }
        } else {
            ArDecoderState::Data {
                remaining: size as u64,
                padding,
            }
        };
        Ok(DecodeStep {
            consumed,
            produced: 0,
            event: DecodeEvent::Entry(metadata),
        })
    }
}

/// Streaming BSD-compatible ar encoder.
#[derive(Debug)]
pub struct ArEncoder {
    limits: Limits,
    pending: Vec<u8>,
    pending_pos: usize,
    started: bool,
    open: bool,
    remaining: u64,
    padding: usize,
    done: bool,
    entries: u64,
}

impl ArEncoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            pending: Vec::new(),
            pending_pos: 0,
            started: false,
            open: false,
            remaining: 0,
            padding: 0,
            done: false,
            entries: 0,
        }
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

    fn stage_entry(&mut self, metadata: &EntryMetadata) -> core::result::Result<(), ArchiveError> {
        let size = metadata.size().ok_or_else(|| {
            ArchiveError::new(ErrorKind::SizeRequired)
                .with_format("ar")
                .with_context("ar requires a declared entry size")
        })?;
        if !self.started {
            self.pending.extend_from_slice(MAGIC);
            self.started = true;
        }
        let name = metadata.path().as_bytes();
        let mut name_field = Vec::new();
        let inline_name = name.len() > 15;
        if inline_name {
            name_field.extend_from_slice(b"#1/");
            let mut buffer = [0_u8; 24];
            name_field.extend_from_slice(radix_bytes(name.len() as u64, 10, &mut buffer));
        } else {
            name_field.extend_from_slice(name);
            name_field.push(b'/');
        }
        let total = size
            .checked_add(if inline_name { name.len() as u64 } else { 0 })
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("ar")
                    .with_context("member size overflow")
            })?;
        let mut header = [b' '; HEADER];
        let mut buffer = [0_u8; 24];
        put_field(&mut header[F_NAME.0..F_NAME.1], &name_field);
        let mtime = metadata
            .times()
            .modified
            .map_or(0, |time| u64::try_from(time.secs.max(0)).unwrap_or(0));
        put_field(
            &mut header[F_MTIME.0..F_MTIME.1],
            radix_bytes(mtime, 10, &mut buffer),
        );
        put_field(
            &mut header[F_UID.0..F_UID.1],
            radix_bytes(metadata.owner().uid.unwrap_or(0), 10, &mut buffer),
        );
        put_field(
            &mut header[F_GID.0..F_GID.1],
            radix_bytes(metadata.owner().gid.unwrap_or(0), 10, &mut buffer),
        );
        put_field(
            &mut header[F_MODE.0..F_MODE.1],
            radix_bytes(
                0o100_000
                    | u64::from(
                        metadata
                            .mode()
                            .unwrap_or_else(|| default_mode(metadata.kind()))
                            & 0o7777,
                    ),
                8,
                &mut buffer,
            ),
        );
        put_field(
            &mut header[F_SIZE.0..F_SIZE.1],
            radix_bytes(total, 10, &mut buffer),
        );
        header[F_MAGIC.0] = b'`';
        header[F_MAGIC.0 + 1] = b'\n';
        self.pending.extend_from_slice(&header);
        if inline_name {
            self.pending.extend_from_slice(name);
        }
        self.remaining = size;
        self.padding = usize::from(total & 1 != 0);
        self.open = true;
        Ok(())
    }
}

impl ArchiveEncoder for ArEncoder {
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
                    .with_format("ar")
                    .with_context("command supplied after finish")),
            };
        }
        if !self.pending.is_empty() {
            let produced = self.drain_pending(output);
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
                        .with_format("ar")
                        .with_context("previous entry is still open"));
                }
                let size = metadata.size().ok_or_else(|| {
                    ArchiveError::new(ErrorKind::SizeRequired)
                        .with_format("ar")
                        .with_context("ar requires a declared entry size")
                })?;
                if self
                    .limits
                    .path_bytes()
                    .is_some_and(|limit| metadata.path().as_bytes().len() > limit)
                    || self.limits.entry_bytes().is_some_and(|limit| size > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("entry exceeds configured limits"));
                }
                let next_entries = self.entries.checked_add(1).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("entry count overflow")
                })?;
                if self
                    .limits
                    .entries()
                    .is_some_and(|limit| next_entries > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("ar")
                        .with_context("entry count exceeds configured limit"));
                }
                self.stage_entry(metadata)?;
                self.entries = next_entries;
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
                        .with_format("ar")
                        .with_context("entry data supplied without an open entry"));
                }
                if input.len() as u64 > self.remaining {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("ar")
                        .with_context("entry data exceeds declared size"));
                }
                let count = input.len().min(output.len());
                output[..count].copy_from_slice(&input[..count]);
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
                        .with_format("ar")
                        .with_context("entry ended before its declared size"));
                }
                self.pending.resize(self.padding, b'\n');
                self.padding = 0;
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
                        .with_format("ar")
                        .with_context("cannot finish with an open entry"));
                }
                if !self.started {
                    self.pending.extend_from_slice(MAGIC);
                    self.started = true;
                    let produced = self.drain_pending(output);
                    if self.pending.is_empty() {
                        self.done = true;
                    }
                    return Ok(EncodeStep {
                        consumed: 1,
                        produced,
                        status: if self.done {
                            EncodeStatus::Done
                        } else {
                            EncodeStatus::NeedOutput
                        },
                    });
                }
                self.done = true;
                Ok(EncodeStep {
                    consumed: 1,
                    produced: 0,
                    status: EncodeStatus::Done,
                })
            },
        }
    }
}
