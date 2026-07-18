//! Unix `ar` archive format (used by `.deb`, static libraries).
//!
//! Handles the three name conventions: plain `SysV` names (trailing `/` terminator), the GNU
//! extended-name string table (`//` member plus `/N` offset references), and BSD long names
//! (`#1/LEN` with the real name stored at the start of the member data). The special GNU symbol
//! tables (`/` and 64-bit `/SYM64/`) are skipped. Every member is a regular file (`ar` carries no
//! type info).

use alloc::borrow::Cow;

use crate::error::{Error, Result};
use crate::format::{ArchiveFormat, Detection, Entry, EntryReader, SliceData};
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

impl EntryReader for ArReader<'_> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
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
