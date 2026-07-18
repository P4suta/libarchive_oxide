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

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{
    ArchiveFormat, Detection, Entry, EntryDataSink, EntryReader, EntrySink, EntryWriter, SliceData,
};
use crate::io::Sink;
use crate::meta::{EntryKind, EntryMeta, Timestamp};

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER: usize = 60;
const F_NAME: (usize, usize) = (0, 16);
const F_MTIME: (usize, usize) = (16, 28);
const F_UID: (usize, usize) = (28, 34);
const F_GID: (usize, usize) = (34, 40);
const F_MODE: (usize, usize) = (40, 48);
const F_SIZE: (usize, usize) = (48, 58);
const F_MAGIC: (usize, usize) = (58, 60);

/// The `ar` format detection anchor (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ar;

impl ArchiveFormat for Ar {
    const NAME: &'static str = "ar";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < MAGIC.len() {
            return Detection::NeedMore;
        }
        if prefix.starts_with(MAGIC) {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// `ar` streaming reader (over an in-memory slice).
#[derive(Debug)]
pub struct ArReader<'a> {
    data: &'a [u8],
    pos: usize,
    payload: SliceData<'a>,
    /// GNU extended-name string table (the `//` member's data), once seen.
    strtab: Option<&'a [u8]>,
    started: bool,
    ended: bool,
}

impl<'a> ArReader<'a> {
    /// Builds a reader from the entire post-filter archive byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            payload: SliceData::default(),
            strtab: None,
            started: false,
            ended: false,
        }
    }

    /// Resolves a raw 16-byte name field into the effective name and the data sub-range.
    ///
    /// Returns `(name, data_start, data_len)`, accounting for GNU `/N` table references and
    /// BSD `#1/LEN` inline names (which consume the first `LEN` bytes of the member data).
    fn resolve_name(
        &self,
        raw: &'a [u8],
        data_start: usize,
        data_len: usize,
    ) -> Result<(Cow<'a, [u8]>, usize, usize)> {
        let trimmed = rtrim(raw, b' ');

        // GNU extended name reference: "/N" where N is a decimal offset into the string table.
        if trimmed.len() >= 2 && trimmed[0] == b'/' && trimmed[1].is_ascii_digit() {
            let offset = usize_of(parse_decimal(&trimmed[1..])?)?;
            let table = self
                .strtab
                .ok_or(Error::Malformed("ar: missing // table"))?;
            let name = gnu_table_name(table, offset)?;
            return Ok((Cow::Borrowed(name), data_start, data_len));
        }

        // BSD long name: "#1/LEN", real name is the first LEN bytes of the data.
        if let Some(rest) = trimmed.strip_prefix(b"#1/") {
            let len = usize_of(parse_decimal(rest)?)?;
            let name = self
                .data
                .get(data_start..data_start + len)
                .ok_or(Error::Malformed("ar: truncated BSD name"))?;
            let data_len = data_len
                .checked_sub(len)
                .ok_or(Error::Malformed("ar: BSD name longer than data"))?;
            return Ok((Cow::Borrowed(name), data_start + len, data_len));
        }

        // Plain SysV name: strip a single trailing '/' terminator.
        let name = trimmed.strip_suffix(b"/").unwrap_or(trimmed);
        Ok((Cow::Borrowed(name), data_start, data_len))
    }
}

impl<'a> EntryReader for ArReader<'a> {
    type Data = SliceData<'a>;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, SliceData<'a>>>> {
        if self.ended {
            return Ok(None);
        }
        let data = self.data;

        if !self.started {
            if !data.starts_with(MAGIC) {
                return Err(Error::Malformed("ar: bad global magic"));
            }
            self.pos = MAGIC.len();
            self.started = true;
        }

        loop {
            if self.pos + HEADER > data.len() {
                self.ended = true;
                return Ok(None);
            }
            let hdr = &data[self.pos..self.pos + HEADER];
            if field(hdr, F_MAGIC) != [0x60, 0x0a] {
                return Err(Error::Malformed("ar: bad header terminator"));
            }

            let size = usize_of(parse_decimal(rtrim(field(hdr, F_SIZE), b' '))?)?;
            let data_start = self.pos + HEADER;
            let member = data
                .get(data_start..data_start + size)
                .ok_or(Error::Malformed("ar: truncated member data"))?;
            // Members are padded to an even offset with a trailing '\n'.
            self.pos = data_start + size + (size & 1);

            let raw = field(hdr, F_NAME);
            let trimmed = rtrim(raw, b' ');

            // The GNU string table: keep it for later "/N" references, then skip.
            if trimmed == b"//" {
                self.strtab = Some(member);
                continue;
            }
            // The GNU 32-bit ("/") and 64-bit ("/SYM64/") symbol tables: skip.
            if trimmed == b"/" || trimmed == b"/SYM64/" {
                continue;
            }

            let (name, body_start, body_len) = self.resolve_name(raw, data_start, size)?;
            let meta = EntryMeta {
                kind: EntryKind::File,
                path: name,
                mode: u32::try_from(parse_octal(rtrim(field(hdr, F_MODE), b' '))? & 0o7777)
                    .unwrap_or(0),
                uid: parse_decimal(rtrim(field(hdr, F_UID), b' ')).unwrap_or(0),
                gid: parse_decimal(rtrim(field(hdr, F_GID), b' ')).unwrap_or(0),
                mtime: parse_decimal(rtrim(field(hdr, F_MTIME), b' '))
                    .ok()
                    .map(|secs| Timestamp {
                        secs: i64::try_from(secs).unwrap_or(i64::MAX),
                        nanos: 0,
                    }),
                size: body_len as u64,
                link_target: None,
                pax: crate::meta::PaxMap::new(),
            };

            self.payload = SliceData::new(data, body_start, body_len);
            return Ok(Some(Entry::new(meta, &mut self.payload)));
        }
    }
}

/// `ar` streaming writer — the dual of [`ArReader`]. Writes the global magic once, then a 60-byte
/// header per member (BSD `#1/LEN` inline names for names longer than 15 bytes) and an even-byte
/// pad. Every member is a regular file.
#[derive(Debug)]
pub struct ArWriter<W: Sink> {
    sink: W,
    remaining: u64,
    pad: bool,
    open: bool,
    started: bool,
}

impl<W: Sink> ArWriter<W> {
    /// Builds a writer over a byte sink.
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            remaining: 0,
            pad: false,
            open: false,
            started: false,
        }
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Writes the global `!<arch>\n` magic if it has not been written yet.
    fn ensure_started(&mut self) -> Result<()> {
        if !self.started {
            self.sink.write_all(MAGIC)?;
            self.started = true;
        }
        Ok(())
    }

    /// Emits a 60-byte member header.
    fn emit_header(
        &mut self,
        name_field: &[u8],
        mode: u64,
        meta: &EntryMeta<'_>,
        size: u64,
    ) -> Result<()> {
        let mtime = meta
            .mtime
            .map_or(0, |t| u64::try_from(t.secs.max(0)).unwrap_or(0));
        let mut h = [b' '; HEADER];
        let mut buf = [0u8; 24];
        put_field(&mut h[F_NAME.0..F_NAME.1], name_field);
        put_field(
            &mut h[F_MTIME.0..F_MTIME.1],
            radix_bytes(mtime, 10, &mut buf),
        );
        put_field(
            &mut h[F_UID.0..F_UID.1],
            radix_bytes(meta.uid, 10, &mut buf),
        );
        put_field(
            &mut h[F_GID.0..F_GID.1],
            radix_bytes(meta.gid, 10, &mut buf),
        );
        put_field(&mut h[F_MODE.0..F_MODE.1], radix_bytes(mode, 8, &mut buf));
        put_field(&mut h[F_SIZE.0..F_SIZE.1], radix_bytes(size, 10, &mut buf));
        h[F_MAGIC.0] = b'`';
        h[F_MAGIC.0 + 1] = b'\n';
        self.sink.write_all(&h)
    }
}

impl<W: Sink> EntryWriter for ArWriter<W> {
    type Sink = Self;

    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self>> {
        if self.open {
            return Err(Error::InvalidState("ar: previous entry not closed"));
        }
        self.ensure_started()?;

        // Names up to 15 bytes fit "name/" in the 16-byte field; longer names use BSD "#1/LEN"
        // with the name stored inline at the front of the member data.
        let name = &meta.path;
        let mut prefix: &[u8] = &[];
        let name_field: Vec<u8> = if name.len() <= 15 {
            let mut nf = Vec::with_capacity(name.len() + 1);
            nf.extend_from_slice(name);
            nf.push(b'/');
            nf
        } else {
            prefix = name;
            let mut nf = Vec::new();
            nf.extend_from_slice(b"#1/");
            let mut buf = [0u8; 24];
            nf.extend_from_slice(radix_bytes(name.len() as u64, 10, &mut buf));
            nf
        };

        let total = prefix.len() as u64 + meta.size;
        let mode = 0o100_000 | u64::from(meta.mode & 0o7777);
        self.emit_header(&name_field, mode, meta, total)?;
        if !prefix.is_empty() {
            self.sink.write_all(prefix)?;
        }

        self.remaining = meta.size;
        self.pad = total % 2 == 1;
        self.open = true;
        Ok(EntrySink::new(self))
    }

    fn finish(&mut self) -> Result<()> {
        if self.open {
            return Err(Error::InvalidState("ar: entry open at finish"));
        }
        // An empty archive is still just the magic.
        self.ensure_started()
    }
}

impl<W: Sink> EntryDataSink for ArWriter<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.remaining {
            return Err(Error::InvalidState("ar: payload exceeds declared size"));
        }
        self.sink.write_all(data)?;
        self.remaining -= data.len() as u64;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::InvalidState(
                "ar: payload shorter than declared size",
            ));
        }
        if self.pad {
            self.sink.write_all(b"\n")?;
            self.pad = false;
        }
        self.open = false;
        Ok(())
    }
}

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
