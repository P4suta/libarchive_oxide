//! zip reader (central-directory based, store + deflate).
//!
//! zip differs in shape from tar/cpio/ar: its authoritative metadata lives in a *central
//! directory* at the end of the file, and each entry is *individually* compressed rather than the
//! whole stream being wrapped by an external filter. It therefore does not compose with the
//! `Filter` pipeline; instead its `EntryData` decompresses per entry. This reader lives in the std
//! crate (it needs a DEFLATE codec) yet still implements the same [`arca_core::EntryReader`],
//! demonstrating that a format impl can live anywhere and still plug into detection and extraction.
//!
//! Scope: the common case — the "store" (0) and "deflate" (8) methods, Unix modes and symlinks via
//! external attributes. Not handled: zip64 (> 4 GiB / > 65535 entries), encryption, and other
//! compression methods.

use std::borrow::Cow;

use arca_core::format::{Entry, EntryData, EntryReader};
use arca_core::{EntryKind, EntryMeta, Error, Result};

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LOCAL_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const EOCD_MIN: usize = 22;
const MAX_COMMENT: usize = 0xFFFF;

/// Returns `true` if `data` looks like a zip archive (local header or empty-archive EOCD magic).
#[must_use]
pub fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&LOCAL_SIG) || data.starts_with(&EOCD_SIG)
}

/// A parsed central-directory entry (all `Copy`, so it can be lifted out before borrowing `owned`).
#[derive(Debug, Clone, Copy)]
struct CdEntry {
    name_start: usize,
    name_len: usize,
    method: u16,
    comp_size: usize,
    uncomp_size: usize,
    local_offset: usize,
    external_attrs: u32,
}

/// An `EntryData` over an owned, already-decompressed buffer.
#[derive(Debug, Default)]
struct OwnedData {
    buf: Vec<u8>,
    pos: usize,
}

impl EntryData for OwnedData {
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        let remaining = self.buf.len() - self.pos;
        if remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let n = remaining.min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// zip streaming reader (over an in-memory slice).
#[derive(Debug)]
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<CdEntry>,
    index: usize,
    parsed: bool,
    owned: OwnedData,
}

impl<'a> ZipReader<'a> {
    /// Builds a reader over the whole zip archive bytes.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            entries: Vec::new(),
            index: 0,
            parsed: false,
            owned: OwnedData::default(),
        }
    }

    /// Parses the central directory into `self.entries`.
    fn parse_central_directory(&mut self) -> Result<()> {
        let data = self.data;
        let eocd = find_eocd(data)?;
        let count = usize::from(u16le(data, eocd + 10)?);
        let mut pos = usize_of(u32le(data, eocd + 16)?)?; // central directory offset

        for _ in 0..count {
            if !data.get(pos..).is_some_and(|s| s.starts_with(&CD_SIG)) {
                return Err(Error::Malformed("zip: bad central directory signature"));
            }
            let method = u16le(data, add(pos, 10)?)?;
            let comp_size = usize_of(u32le(data, add(pos, 20)?)?)?;
            let uncomp_size = usize_of(u32le(data, add(pos, 24)?)?)?;
            let name_len = usize::from(u16le(data, add(pos, 28)?)?);
            let extra_len = usize::from(u16le(data, add(pos, 30)?)?);
            let comment_len = usize::from(u16le(data, add(pos, 32)?)?);
            let external_attrs = u32le(data, add(pos, 38)?)?;
            let local_offset = usize_of(u32le(data, add(pos, 42)?)?)?;
            let name_start = add(pos, 46)?;
            if data
                .get(name_start..)
                .is_none_or(|rest| rest.len() < name_len)
            {
                return Err(Error::Malformed("zip: truncated central directory name"));
            }
            self.entries.push(CdEntry {
                name_start,
                name_len,
                method,
                comp_size,
                uncomp_size,
                local_offset,
                external_attrs,
            });
            pos = add(add(add(name_start, name_len)?, extra_len)?, comment_len)?;
        }
        Ok(())
    }

    /// Locates and decompresses one entry's content into `self.owned`.
    fn load_content(&mut self, entry: CdEntry) -> Result<()> {
        let data = self.data;
        let lo = entry.local_offset;
        if !data.get(lo..).is_some_and(|s| s.starts_with(&LOCAL_SIG)) {
            return Err(Error::Malformed("zip: bad local header signature"));
        }
        let local_name = usize::from(u16le(data, add(lo, 26)?)?);
        let local_extra = usize::from(u16le(data, add(lo, 28)?)?);
        let start = add(add(add(lo, 30)?, local_name)?, local_extra)?;
        let compressed = data
            .get(start..)
            .and_then(|s| s.get(..entry.comp_size))
            .ok_or(Error::Malformed("zip: truncated entry data"))?;

        let content = match entry.method {
            0 => compressed.to_vec(),
            8 => arca_filter::inflate(compressed, entry.uncomp_size)?,
            _ => return Err(Error::Unsupported("zip: unsupported compression method")),
        };
        self.owned = OwnedData {
            buf: content,
            pos: 0,
        };
        Ok(())
    }
}

impl EntryReader for ZipReader<'_> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        if !self.parsed {
            self.parse_central_directory()?;
            self.parsed = true;
        }
        if self.index >= self.entries.len() {
            return Ok(None);
        }
        let entry = self.entries[self.index];
        self.index += 1;

        let data = self.data;
        let name = &data[entry.name_start..entry.name_start + entry.name_len];
        let unix_mode = entry.external_attrs >> 16;
        let is_dir = name.last() == Some(&b'/');
        let kind = if is_dir {
            EntryKind::Dir
        } else if unix_mode & 0o170_000 == 0o120_000 {
            EntryKind::Symlink
        } else {
            EntryKind::File
        };

        self.load_content(entry)?;

        let mode = if unix_mode & 0o7777 != 0 {
            unix_mode & 0o7777
        } else if is_dir {
            0o755
        } else {
            0o644
        };
        let link_target =
            matches!(kind, EntryKind::Symlink).then(|| Cow::Owned(self.owned.buf.clone()));

        let meta = EntryMeta {
            kind,
            path: Cow::Borrowed(name),
            mode,
            uid: 0,
            gid: 0,
            mtime: None,
            size: self.owned.buf.len() as u64,
            link_target,
            pax: arca_core::PaxMap::new(),
        };
        Ok(Some(Entry::new(meta, &mut self.owned)))
    }
}

/// Finds the End Of Central Directory record by scanning backward from the end.
fn find_eocd(data: &[u8]) -> Result<usize> {
    if data.len() < EOCD_MIN {
        return Err(Error::Malformed("zip: too small for EOCD"));
    }
    let last = data.len() - EOCD_MIN;
    let first = last.saturating_sub(MAX_COMMENT);
    for i in (first..=last).rev() {
        if data[i..i + 4] == EOCD_SIG {
            return Ok(i);
        }
    }
    Err(Error::Malformed("zip: no EOCD record"))
}

/// Reads a little-endian `u16` at `off`, bounds- and overflow-checked.
fn u16le(data: &[u8], off: usize) -> Result<u16> {
    let end = off
        .checked_add(2)
        .ok_or(Error::Malformed("zip: offset overflow"))?;
    let b = data
        .get(off..end)
        .ok_or(Error::Malformed("zip: truncated field"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a little-endian `u32` at `off`, bounds- and overflow-checked.
fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or(Error::Malformed("zip: offset overflow"))?;
    let b = data
        .get(off..end)
        .ok_or(Error::Malformed("zip: truncated field"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Checked `usize` addition, mapped to a malformed-archive error on overflow.
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Malformed("zip: offset overflow"))
}

/// `u32` to `usize` (infallible on 32/64-bit, but explicit for clarity).
fn usize_of(v: u32) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("zip: offset exceeds usize"))
}
