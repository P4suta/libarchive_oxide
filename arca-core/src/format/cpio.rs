//! cpio format (SVR4 "newc"/"crc" and POSIX "odc").
//!
//! **Orthogonality proof, realized**: adding a new format is just adding a type that implements
//! the same [`EntryReader`], with no change to the existing traits or the tar implementation.
//!
//! Supports the two ASCII header variants used in practice: `newc`/`crc` (SVR4, 8-hex-digit
//! fields, 4-byte-aligned) and `odc` (POSIX, 6/11-octal-digit fields, unaligned). The legacy
//! binary format is out of P4 scope. The archive ends at the `TRAILER!!!` entry.

use alloc::borrow::Cow;

use crate::error::{Error, Result};
use crate::format::{ArchiveFormat, Detection, Entry, EntryReader, SliceData};
use crate::meta::{EntryKind, EntryMeta, Timestamp};

const NEWC_MAGIC: &[u8] = b"070701";
const NEWC_CRC_MAGIC: &[u8] = b"070702";
const ODC_MAGIC: &[u8] = b"070707";
const NEWC_HEADER: usize = 110;
const ODC_HEADER: usize = 76;
const TRAILER: &[u8] = b"TRAILER!!!";

/// Legacy binary format magic (both host byte orders).
const BIN_MAGIC_LE: [u8; 2] = [0xc7, 0x71];
const BIN_MAGIC_BE: [u8; 2] = [0x71, 0xc7];

/// The cpio format detection anchor (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpio;

impl ArchiveFormat for Cpio {
    const NAME: &'static str = "cpio";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < 2 {
            return Detection::NeedMore;
        }
        let head2 = [prefix[0], prefix[1]];
        if head2 == BIN_MAGIC_LE || head2 == BIN_MAGIC_BE {
            return Detection::Match;
        }
        if prefix.len() < 6 {
            return Detection::NeedMore;
        }
        let head6 = &prefix[..6];
        if head6 == NEWC_MAGIC || head6 == NEWC_CRC_MAGIC || head6 == ODC_MAGIC {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// Which ASCII header layout an entry uses.
#[derive(Clone, Copy)]
enum Variant {
    /// SVR4: 8-hex-digit fields, name and data padded to 4 bytes.
    Newc,
    /// POSIX: 6/11-octal-digit fields, no padding.
    Odc,
}

/// The parsed, format-independent view of a cpio header.
struct Header {
    mode: u64,
    uid: u64,
    gid: u64,
    mtime: u64,
    filesize: usize,
    name_start: usize,
    name_len: usize, // excludes the trailing NUL
    data_start: usize,
    next_pos: usize,
}

/// cpio streaming reader (over an in-memory slice).
#[derive(Debug)]
pub struct CpioReader<'a> {
    data: &'a [u8],
    pos: usize,
    payload: SliceData<'a>,
    ended: bool,
}

impl<'a> CpioReader<'a> {
    /// Builds a reader from the entire post-filter archive byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            payload: SliceData::default(),
            ended: false,
        }
    }

    /// Parses the header at `self.pos`, returning the format-independent [`Header`].
    fn parse_header(data: &[u8], pos: usize) -> Result<Header> {
        let magic = data
            .get(pos..pos + 6)
            .ok_or(Error::Malformed("cpio: truncated header"))?;
        let variant = match magic {
            NEWC_MAGIC | NEWC_CRC_MAGIC => Variant::Newc,
            ODC_MAGIC => Variant::Odc,
            _ => return Err(Error::Malformed("cpio: bad magic")),
        };

        match variant {
            Variant::Newc => {
                let f = |i: usize| newc_field(data, pos, i);
                let mode = f(1)?;
                let uid = f(2)?;
                let gid = f(3)?;
                let mtime = f(5)?;
                let filesize = usize_of(f(6)?)?;
                let name_len = usize_of(f(11)?)?;
                let name_start = pos + NEWC_HEADER;
                let data_start = round4(add(name_start, name_len)?)?;
                let next_pos = add(data_start, round4(filesize)?)?;
                Ok(Header {
                    mode,
                    uid,
                    gid,
                    mtime,
                    filesize,
                    name_start,
                    name_len: name_len.saturating_sub(1),
                    data_start,
                    next_pos,
                })
            }
            Variant::Odc => {
                let mode = odc_field(data, pos, 18, 6)?;
                let uid = odc_field(data, pos, 24, 6)?;
                let gid = odc_field(data, pos, 30, 6)?;
                let mtime = odc_field(data, pos, 48, 11)?;
                let name_len = usize_of(odc_field(data, pos, 59, 6)?)?;
                let filesize = usize_of(odc_field(data, pos, 65, 11)?)?;
                let name_start = pos + ODC_HEADER;
                let data_start = add(name_start, name_len)?;
                let next_pos = add(data_start, filesize)?;
                Ok(Header {
                    mode,
                    uid,
                    gid,
                    mtime,
                    filesize,
                    name_start,
                    name_len: name_len.saturating_sub(1),
                    data_start,
                    next_pos,
                })
            }
        }
    }
}

impl EntryReader for CpioReader<'_> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if self.ended {
            return Ok(None);
        }
        let data = self.data;

        let header = Self::parse_header(data, self.pos)?;
        let name = data
            .get(header.name_start..)
            .and_then(|s| s.get(..header.name_len))
            .ok_or(Error::Malformed("cpio: truncated name"))?;

        if name == TRAILER {
            self.ended = true;
            return Ok(None);
        }

        let kind = kind_from_mode(header.mode);
        let body = data
            .get(header.data_start..)
            .and_then(|s| s.get(..header.filesize))
            .ok_or(Error::Malformed("cpio: truncated data"))?;
        let link_target = matches!(kind, EntryKind::Symlink).then(|| Cow::Borrowed(body));

        let meta = EntryMeta {
            kind,
            path: Cow::Borrowed(name),
            mode: u32::try_from(header.mode & 0o7777).unwrap_or(0),
            uid: header.uid,
            gid: header.gid,
            mtime: Some(Timestamp {
                secs: i64::try_from(header.mtime).unwrap_or(i64::MAX),
                nanos: 0,
            }),
            size: header.filesize as u64,
            link_target,
            pax: crate::meta::PaxMap::new(),
        };

        self.payload = SliceData::new(data, header.data_start, header.filesize);
        self.pos = header.next_pos;
        Ok(Some(Entry::new(meta, &mut self.payload)))
    }
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

/// Rounds up to the next 4-byte boundary (newc alignment). Errors on overflow (32-bit targets).
fn round4(n: usize) -> Result<usize> {
    Ok(add(n, 3)? & !3)
}

/// Checked `usize` addition, mapped to a malformed-archive error on overflow.
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Malformed("cpio: size overflow"))
}

/// `u64` to `usize`, rejecting oversized values on 32-bit targets.
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("cpio: size exceeds usize"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radix_parsing() {
        assert_eq!(parse_radix(b"000000ff", 16).unwrap(), 255);
        assert_eq!(parse_radix(b"000644", 8).unwrap(), 0o644);
    }

    #[test]
    fn round4_alignment() {
        assert_eq!(round4(0).unwrap(), 0);
        assert_eq!(round4(1).unwrap(), 4);
        assert_eq!(round4(110).unwrap(), 112);
        assert!(round4(usize::MAX).is_err());
    }
}
