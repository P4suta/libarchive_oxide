//! zip reader and writer (central-directory based, store + deflate, zip64, AES-256 AE-2).
//!
//! zip differs in shape from tar/cpio/ar: its authoritative metadata lives in a *central
//! directory* at the end of the file, and each entry is *individually* compressed rather than the
//! whole stream being wrapped by an external filter. It therefore does not compose with the
//! `Filter` pipeline; instead its `EntryData` decompresses per entry. This lives in the std crate
//! (it needs a DEFLATE codec) yet still implements the same [`libarchive_oxide_core::EntryReader`] /
//! [`libarchive_oxide_core::EntryWriter`], demonstrating that a format impl can live anywhere and still plug
//! into detection, extraction, and creation.
//!
//! Scope: the "store" (0) and "deflate" (8) methods, Unix modes and symlinks via external
//! attributes, zip64 (> 4 GiB sizes / offsets, > 65535 entries), and `WinZip` AES-256 (AE-2)
//! encryption (behind the `aes` feature). Other compression methods are `Unsupported`.
//!
//! ## AE-2 and SHA-1
//!
//! The AES layer follows the `WinZip` AE-2 specification, which mandates PBKDF2-**HMAC-SHA1** for key
//! derivation and HMAC-SHA1 for authentication. SHA-1 here is an interoperability requirement of the
//! on-disk format, **not** a choice of "modern strength": a reader/writer that wants to interoperate
//! with `WinZip`/7-Zip/`zip`-crate AES entries has no other option.

use std::borrow::Cow;

use libarchive_oxide_core::format::{
    Entry, EntryDataSink, EntryReader, EntrySink, EntryWriter, OwnedData,
};
use libarchive_oxide_core::io::Sink;
use libarchive_oxide_core::{EntryKind, EntryMeta, Error, Result, Timestamp};

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const EOCD64_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
const LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LOCAL_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const EOCD_MIN: usize = 22;
const LOCATOR_LEN: usize = 20;
const MAX_COMMENT: usize = 0xFFFF;

/// The 32-bit sentinel that signals "the real value lives in the zip64 extra field".
const U32_SENTINEL: u32 = 0xFFFF_FFFF;
/// The 16-bit sentinel (entry count in the classic EOCD).
const U16_SENTINEL: u16 = 0xFFFF;

/// zip64 extra field header id.
const EXTRA_ZIP64: u16 = 0x0001;
/// `WinZip` AES extra field header id.
const EXTRA_AES: u16 = 0x9901;
/// AES pseudo-compression method.
const METHOD_AES: u16 = 99;

/// Cap on a single entry's declared uncompressed size, applied before decoding (bomb defense).
///
/// zip is not wrapped by an external filter, so the CLI's outer [`decompress_capped`] boundary never
/// sees a zip entry's inflation; without this the per-entry inflate would be bounded only by the
/// entry's own (attacker-controlled) declared size. This mirrors the 7z reader's `MAX_UNPACK` and the
/// CLI's 4 GiB transparent-decompression cap, so every tool's bomb defense holds at the same ceiling.
///
/// [`decompress_capped`]: crate::decompress_capped
const MAX_UNCOMP: u64 = 4 * 1024 * 1024 * 1024;

/// Returns `true` if `data` looks like a zip archive (local header or empty-archive EOCD magic).
#[must_use]
pub fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&LOCAL_SIG) || data.starts_with(&EOCD_SIG)
}

/// A parsed central-directory entry (all `Copy`, so it can be lifted out before borrowing `owned`).
///
/// Sizes and the local-header offset are `u64`: zip64 widens each 32-bit slot when it holds the
/// [`U32_SENTINEL`], and the real value is read from the entry's zip64 extra field.
#[derive(Debug, Clone, Copy)]
struct CdEntry {
    name_start: usize,
    name_len: usize,
    method: u16,
    comp_size: u64,
    uncomp_size: u64,
    local_offset: u64,
    external_attrs: u32,
    /// The real compression method carried inside the AES extra field (only meaningful when
    /// `method == METHOD_AES`). `8`/`0` for deflate/store. Only read when the `aes` feature decodes.
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    aes_real_method: u16,
    /// The AES strength code from the AES extra field (`0x03` = AES-256). `0` when not AES.
    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    aes_strength: u8,
}

/// zip streaming reader (over an in-memory slice).
#[derive(Debug)]
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<CdEntry>,
    index: usize,
    parsed: bool,
    owned: OwnedData,
    /// Optional password for AES (method 99) entries.
    password: Option<Vec<u8>>,
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
            password: None,
        }
    }

    /// Builds a reader that can decrypt `WinZip` AES (method 99) entries with `password`.
    #[must_use]
    pub fn with_password(data: &'a [u8], password: &[u8]) -> Self {
        let mut r = Self::new(data);
        r.password = Some(password.to_vec());
        r
    }

    /// Parses the central directory into `self.entries`, resolving zip64 sentinels.
    fn parse_central_directory(&mut self) -> Result<()> {
        let data = self.data;
        let (count, cd_offset) = locate_central_directory(data)?;
        let mut pos = usize_of(cd_offset)?;

        for _ in 0..count {
            if !data.get(pos..).is_some_and(|s| s.starts_with(&CD_SIG)) {
                return Err(Error::Malformed("zip: bad central directory signature"));
            }
            let method = u16le(data, add(pos, 10)?)?;
            let comp32 = u32le(data, add(pos, 20)?)?;
            let uncomp32 = u32le(data, add(pos, 24)?)?;
            let name_len = usize::from(u16le(data, add(pos, 28)?)?);
            let extra_len = usize::from(u16le(data, add(pos, 30)?)?);
            let comment_len = usize::from(u16le(data, add(pos, 32)?)?);
            let disk16 = u16le(data, add(pos, 34)?)?;
            let external_attrs = u32le(data, add(pos, 38)?)?;
            let offset32 = u32le(data, add(pos, 42)?)?;
            let name_start = add(pos, 46)?;
            let extra_start = add(name_start, name_len)?;
            if data
                .get(name_start..)
                .is_none_or(|rest| rest.len() < name_len)
            {
                return Err(Error::Malformed("zip: truncated central directory name"));
            }
            let extra = data
                .get(extra_start..)
                .and_then(|s| s.get(..extra_len))
                .ok_or(Error::Malformed("zip: truncated central directory extra"))?;

            // Resolve zip64 sentinels (order: uncomp, comp, offset, disk) from the 0x0001 extra.
            let z = parse_zip64_extra(extra, uncomp32, comp32, offset32, disk16)?;
            // Parse AES parameters if this is a method-99 entry.
            let (aes_real_method, aes_strength) = if method == METHOD_AES {
                parse_aes_extra(extra)?
            } else {
                (0, 0)
            };

            self.entries.push(CdEntry {
                name_start,
                name_len,
                method,
                comp_size: z.comp,
                uncomp_size: z.uncomp,
                local_offset: z.offset,
                external_attrs,
                aes_real_method,
                aes_strength,
            });
            pos = add(add(extra_start, extra_len)?, comment_len)?;
        }
        Ok(())
    }

    /// Locates and decompresses (and decrypts, if needed) one entry's content into `self.owned`.
    fn load_content(&mut self, entry: CdEntry) -> Result<()> {
        let data = self.data;
        let lo = usize_of(entry.local_offset)?;
        if !data.get(lo..).is_some_and(|s| s.starts_with(&LOCAL_SIG)) {
            return Err(Error::Malformed("zip: bad local header signature"));
        }
        let local_name = usize::from(u16le(data, add(lo, 26)?)?);
        let local_extra = usize::from(u16le(data, add(lo, 28)?)?);
        let start = add(add(add(lo, 30)?, local_name)?, local_extra)?;
        let comp_size = usize_of(entry.comp_size)?;
        let stored = data
            .get(start..)
            .and_then(|s| s.get(..comp_size))
            .ok_or(Error::Malformed("zip: truncated entry data"))?;

        if entry.uncomp_size > MAX_UNCOMP {
            return Err(Error::LimitExceeded(
                "zip: entry uncompressed size exceeds decompression cap",
            ));
        }
        let uncomp = usize_of(entry.uncomp_size)?;
        let content = if entry.method == METHOD_AES {
            self.decrypt_aes(entry, stored, uncomp)?
        } else {
            decode_method(entry.method, stored, uncomp)?
        };
        self.owned = OwnedData::new(content);
        Ok(())
    }

    /// Decrypts and then decodes an AES (method 99) entry's stored blob.
    #[cfg(feature = "aes")]
    fn decrypt_aes(&self, entry: CdEntry, stored: &[u8], uncomp: usize) -> Result<Vec<u8>> {
        let password = self
            .password
            .as_deref()
            .ok_or(Error::Unsupported("zip: AES entry requires a password"))?;
        if entry.aes_strength != 0x03 {
            return Err(Error::Unsupported(
                "zip: only AES-256 (strength 3) is supported",
            ));
        }
        let plain_compressed = aes::decrypt(stored, password)?;
        decode_method(entry.aes_real_method, &plain_compressed, uncomp)
    }

    /// Without the `aes` feature, method-99 entries cannot be decrypted.
    #[cfg(not(feature = "aes"))]
    #[allow(clippy::unused_self)]
    fn decrypt_aes(&self, _entry: CdEntry, _stored: &[u8], _uncomp: usize) -> Result<Vec<u8>> {
        Err(Error::Unsupported(
            "zip: AES encryption (rebuild with the `aes` feature)",
        ))
    }
}

impl EntryReader for ZipReader<'_> {
    type Data = OwnedData;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, OwnedData>>> {
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
            matches!(kind, EntryKind::Symlink).then(|| Cow::Owned(self.owned.as_bytes().to_vec()));

        let meta = EntryMeta {
            kind,
            path: Cow::Borrowed(name),
            mode,
            uid: 0,
            gid: 0,
            mtime: None,
            size: self.owned.as_bytes().len() as u64,
            link_target,
            pax: libarchive_oxide_core::PaxMap::new(),
        };
        Ok(Some(Entry::new(meta, &mut self.owned)))
    }
}

/// Decodes a stored blob per compression method (store=0, deflate=8), capped at `uncomp`.
fn decode_method(method: u16, stored: &[u8], uncomp: usize) -> Result<Vec<u8>> {
    match method {
        0 => Ok(stored.to_vec()),
        8 => crate::filter::inflate(stored, uncomp),
        _ => Err(Error::Unsupported("zip: unsupported compression method")),
    }
}

/// The zip64-resolved sizes/offset of a central-directory entry.
#[derive(Debug, Clone, Copy)]
struct Zip64 {
    uncomp: u64,
    comp: u64,
    offset: u64,
}

/// Walks the extra-field TLV and applies the zip64 (0x0001) block, replacing **only** the 32-bit
/// fields that hold [`U32_SENTINEL`], in the fixed order uncomp, comp, offset, disk.
fn parse_zip64_extra(
    extra: &[u8],
    uncomp32: u32,
    comp32: u32,
    offset32: u32,
    disk16: u16,
) -> Result<Zip64> {
    let mut out = Zip64 {
        uncomp: u64::from(uncomp32),
        comp: u64::from(comp32),
        offset: u64::from(offset32),
    };
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = usize::from(u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]));
        let body_start = pos + 4;
        let body_end = body_start
            .checked_add(len)
            .filter(|&e| e <= extra.len())
            .ok_or(Error::Malformed("zip: truncated extra field"))?;
        if id == EXTRA_ZIP64 {
            let body = &extra[body_start..body_end];
            let mut c = 0usize;
            let next_u64 = |c: &mut usize| -> Result<u64> {
                let end = c
                    .checked_add(8)
                    .ok_or(Error::Malformed("zip: zip64 overflow"))?;
                let b = body
                    .get(*c..end)
                    .ok_or(Error::Malformed("zip: truncated zip64 extra"))?;
                *c = end;
                Ok(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            };
            if uncomp32 == U32_SENTINEL {
                out.uncomp = next_u64(&mut c)?;
            }
            if comp32 == U32_SENTINEL {
                out.comp = next_u64(&mut c)?;
            }
            if offset32 == U32_SENTINEL {
                out.offset = next_u64(&mut c)?;
            }
            if disk16 == U16_SENTINEL {
                // A 4-byte disk-start field would follow; we do not use it, but bounds-check it.
                let end = c
                    .checked_add(4)
                    .filter(|&e| e <= body.len())
                    .ok_or(Error::Malformed("zip: truncated zip64 disk field"))?;
                c = end;
                let _ = c;
            }
            return Ok(out);
        }
        pos = body_end;
    }
    Ok(out)
}

/// Extracts `(real_method, strength)` from the `WinZip` AES (0x9901) extra field.
fn parse_aes_extra(extra: &[u8]) -> Result<(u16, u8)> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = usize::from(u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]));
        let body_start = pos + 4;
        let body_end = body_start
            .checked_add(len)
            .filter(|&e| e <= extra.len())
            .ok_or(Error::Malformed("zip: truncated extra field"))?;
        if id == EXTRA_AES {
            let body = &extra[body_start..body_end];
            if body.len() < 7 {
                return Err(Error::Malformed("zip: truncated AES extra field"));
            }
            // vendor version (2) | vendor id "AE" (2) | strength (1) | real method (2)
            let strength = body[4];
            let real_method = u16::from_le_bytes([body[5], body[6]]);
            return Ok((real_method, strength));
        }
        pos = body_end;
    }
    Err(Error::Malformed("zip: method 99 without AES extra field"))
}

/// Resolves `(entry_count, cd_offset)`, following the zip64 EOCD record + locator when the classic
/// EOCD fields are sentinels.
fn locate_central_directory(data: &[u8]) -> Result<(u64, u64)> {
    let eocd = find_eocd(data)?;
    let count16 = u16le(data, eocd + 10)?;
    let cd_size32 = u32le(data, eocd + 12)?;
    let cd_offset32 = u32le(data, eocd + 16)?;

    let needs_zip64 =
        count16 == U16_SENTINEL || cd_size32 == U32_SENTINEL || cd_offset32 == U32_SENTINEL;

    if needs_zip64 {
        // The zip64 EOCD locator sits immediately before the classic EOCD.
        if let Some(loc) = eocd.checked_sub(LOCATOR_LEN) {
            if data.get(loc..).is_some_and(|s| s.starts_with(&LOCATOR_SIG)) {
                let eocd64_off = usize_of(u64le(data, loc + 8)?)?;
                if data
                    .get(eocd64_off..)
                    .is_some_and(|s| s.starts_with(&EOCD64_SIG))
                {
                    let count = u64le(data, eocd64_off + 32)?;
                    let cd_offset = u64le(data, eocd64_off + 48)?;
                    return Ok((count, cd_offset));
                }
                return Err(Error::Malformed("zip: bad zip64 EOCD record"));
            }
        }
        return Err(Error::Malformed("zip: missing zip64 EOCD locator"));
    }

    Ok((u64::from(count16), u64::from(cd_offset32)))
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

// ── Little-endian field readers (bounds- and overflow-checked) ──────────────────────────────────

/// Reads a little-endian `u16` at `off`.
fn u16le(data: &[u8], off: usize) -> Result<u16> {
    let end = off
        .checked_add(2)
        .ok_or(Error::Malformed("zip: offset overflow"))?;
    let b = data
        .get(off..end)
        .ok_or(Error::Malformed("zip: truncated field"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a little-endian `u32` at `off`.
fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or(Error::Malformed("zip: offset overflow"))?;
    let b = data
        .get(off..end)
        .ok_or(Error::Malformed("zip: truncated field"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a little-endian `u64` at `off`.
fn u64le(data: &[u8], off: usize) -> Result<u64> {
    let end = off
        .checked_add(8)
        .ok_or(Error::Malformed("zip: offset overflow"))?;
    let b = data
        .get(off..end)
        .ok_or(Error::Malformed("zip: truncated field"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Checked `usize` addition, mapped to a malformed-archive error on overflow.
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Malformed("zip: offset overflow"))
}

/// `u64` to `usize`, mapped to a limit error where it would truncate (32-bit hosts).
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("zip: value exceeds usize"))
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Writer
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// The compression method a [`ZipWriter`] applies to a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipMethod {
    /// No compression.
    Store,
    /// DEFLATE, falling back to store when it would not shrink the data.
    Deflate,
}

/// Where a [`ZipWriter`] draws AES salt bytes from.
#[derive(Debug, Clone)]
pub enum SaltSource {
    /// The operating-system CSPRNG (via `getrandom`).
    System,
    /// A fixed 16-byte salt, for deterministic tests. **Never** use in production.
    Fixed([u8; 16]),
}

/// Options controlling zip creation.
#[derive(Debug, Clone)]
pub struct ZipOptions {
    /// Compression method for regular files.
    pub method: ZipMethod,
    /// If set, every entry is encrypted with `WinZip` AES-256 (AE-2) using this password.
    pub password: Option<Vec<u8>>,
    /// Salt source for AES.
    pub salt_source: SaltSource,
    /// A value `> zip64_threshold` triggers a zip64 sentinel for that size/offset field. Defaults to
    /// `U32_SENTINEL` (real 4 GiB boundary); tests lower it to force zip64 without huge data.
    pub zip64_threshold: u64,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self {
            method: ZipMethod::Deflate,
            password: None,
            salt_source: SaltSource::System,
            zip64_threshold: u64::from(U32_SENTINEL),
        }
    }
}

/// A finalized entry's central-directory record, held until [`ZipWriter::finish`].
#[derive(Debug)]
struct CentralRecord {
    name: Vec<u8>,
    method: u16,
    gp_flag: u16,
    crc: u32,
    comp_size: u64,
    uncomp_size: u64,
    local_offset: u64,
    external_attrs: u32,
    dos_time: u16,
    dos_date: u16,
    version_needed: u16,
    /// The real method recorded in the AES extra field, when the entry is encrypted.
    aes_real_method: Option<u16>,
}

/// The metadata captured when an entry is opened (payload is buffered until `close`).
#[derive(Debug)]
struct Pending {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    plain: Vec<u8>,
}

/// zip streaming writer — the dual of [`ZipReader`]. Buffers each entry's plaintext, then at
/// `close` chooses the method, (optionally) encrypts, and emits the local header + data; the whole
/// central directory and EOCD (with zip64 records when needed) are emitted at `finish`.
///
/// The deferred-local-header strategy is exact because the sole DEFLATE encoder is one-shot: it
/// already buffers the whole plaintext, so by `close` the CRC and compressed size are known and a
/// complete local header can be written up front (no data descriptor).
#[derive(Debug)]
pub struct ZipWriter<W: Sink> {
    sink: W,
    options: ZipOptions,
    offset: u64,
    records: Vec<CentralRecord>,
    pending: Option<Pending>,
}

impl<W: Sink> ZipWriter<W> {
    /// Builds a writer with default options (deflate, no encryption).
    pub fn new(sink: W) -> Self {
        Self::with_options(sink, ZipOptions::default())
    }

    /// Builds a writer with explicit [`ZipOptions`].
    pub fn with_options(sink: W, options: ZipOptions) -> Self {
        Self {
            sink,
            options,
            offset: 0,
            records: Vec::new(),
            pending: None,
        }
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Appends `bytes` to the sink and advances the running offset.
    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
        self.sink.write_all(bytes)?;
        self.offset = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::LimitExceeded("zip: archive offset overflow"))?;
        Ok(())
    }

    /// Whether `v` must be represented with a zip64 sentinel. Two independent reasons:
    /// the (test-tunable) `zip64_threshold` is exceeded, or `v` reaches the fixed 32-bit sentinel
    /// value itself — which the classic field physically cannot hold without being read back as
    /// "see the zip64 extra". The second clause is format-mandated and holds at any threshold, so
    /// the writer emits a zip64 record for *exactly* the values [`size32`] would stamp as sentinels.
    fn over(&self, v: u64) -> bool {
        v > self.options.zip64_threshold || v >= u64::from(U32_SENTINEL)
    }

    /// Finalizes the currently open entry: pick method, (encrypt), write LFH + name + extra + body.
    fn close_entry(&mut self) -> Result<()> {
        let Some(p) = self.pending.take() else {
            return Err(Error::InvalidState("zip: no open entry"));
        };

        // Symlink content is its target; directories and files use the buffered payload.
        let content: Vec<u8> = match p.kind {
            EntryKind::Symlink => p.link_target.clone().unwrap_or_default(),
            _ => p.plain,
        };
        let uncomp_size = content.len() as u64;
        let crc = crate::filter::crc32(&content);

        // Method selection: dirs/symlinks/empty store; otherwise deflate if it shrinks.
        let force_store = matches!(p.kind, EntryKind::Dir | EntryKind::Symlink)
            || content.is_empty()
            || self.options.method == ZipMethod::Store;
        let (base_method, body_pre): (u16, Vec<u8>) = if force_store {
            (0, content.clone())
        } else {
            let deflated = crate::filter::deflate(&content);
            if deflated.len() < content.len() {
                (8, deflated)
            } else {
                (0, content.clone())
            }
        };

        // Optional AES-256 (AE-2) wrapping happens AFTER compression.
        let (stored_method, gp_flag, crc_field, body, aes_real_method) =
            match self.options.password.clone() {
                Some(password) => {
                    let salt = self.next_salt()?;
                    let blob = encrypt_aes(&body_pre, &password, salt)?;
                    (METHOD_AES, 0x0001u16, 0u32, blob, Some(base_method))
                },
                None => (base_method, 0u16, crc, body_pre, None),
            };
        let comp_size = body.len() as u64;
        let local_offset = self.offset;

        // zip64 decisions for this entry.
        let uc_over = self.over(uncomp_size);
        let c_over = self.over(comp_size);
        let off_over = self.over(local_offset);
        let lfh_zip64 = uc_over || c_over;

        let mut version_needed = 20u16;
        if lfh_zip64 || off_over {
            version_needed = version_needed.max(45);
        }
        if aes_real_method.is_some() {
            version_needed = version_needed.max(51);
        }

        let (dos_time, dos_date) = dos_datetime(p.mtime);
        let external_attrs = external_attrs(p.kind, p.mode);

        // Build the local extra field: zip64 (both sizes, 16B) then AES.
        let mut lfh_extra = Vec::new();
        if lfh_zip64 {
            push_u16(&mut lfh_extra, EXTRA_ZIP64);
            push_u16(&mut lfh_extra, 16);
            push_u64(&mut lfh_extra, uncomp_size);
            push_u64(&mut lfh_extra, comp_size);
        }
        if let Some(real) = aes_real_method {
            push_aes_extra(&mut lfh_extra, real);
        }

        // Local file header.
        let mut lfh = Vec::with_capacity(30);
        lfh.extend_from_slice(&LOCAL_SIG);
        push_u16(&mut lfh, version_needed);
        push_u16(&mut lfh, gp_flag);
        push_u16(&mut lfh, stored_method);
        push_u16(&mut lfh, dos_time);
        push_u16(&mut lfh, dos_date);
        push_u32(&mut lfh, crc_field);
        push_u32(&mut lfh, size32(comp_size, lfh_zip64));
        push_u32(&mut lfh, size32(uncomp_size, lfh_zip64));
        push_u16(
            &mut lfh,
            u16::try_from(p.name.len()).unwrap_or(U16_SENTINEL),
        );
        push_u16(&mut lfh, u16::try_from(lfh_extra.len()).unwrap_or(0));

        self.emit(&lfh)?;
        self.emit(&p.name)?;
        self.emit(&lfh_extra)?;
        self.emit(&body)?;

        self.records.push(CentralRecord {
            name: p.name,
            method: stored_method,
            gp_flag,
            crc: crc_field,
            comp_size,
            uncomp_size,
            local_offset,
            external_attrs,
            dos_time,
            dos_date,
            version_needed,
            aes_real_method,
        });
        Ok(())
    }

    /// Produces the next AES salt from the configured source.
    fn next_salt(&self) -> Result<[u8; 16]> {
        match self.options.salt_source {
            SaltSource::Fixed(s) => Ok(s),
            SaltSource::System => system_salt(),
        }
    }

    /// Emits one central-directory header for a finalized record.
    fn write_central(&mut self, r: &CentralRecord) -> Result<()> {
        let uc_over = self.over(r.uncomp_size);
        let c_over = self.over(r.comp_size);
        let off_over = self.over(r.local_offset);

        // CDH zip64 extra: only the sentineled fields, in order uncomp, comp, offset.
        let mut extra = Vec::new();
        if uc_over || c_over || off_over {
            let mut body = Vec::new();
            if uc_over {
                push_u64(&mut body, r.uncomp_size);
            }
            if c_over {
                push_u64(&mut body, r.comp_size);
            }
            if off_over {
                push_u64(&mut body, r.local_offset);
            }
            push_u16(&mut extra, EXTRA_ZIP64);
            push_u16(&mut extra, u16::try_from(body.len()).unwrap_or(0));
            extra.extend_from_slice(&body);
        }
        if let Some(real) = r.aes_real_method {
            push_aes_extra(&mut extra, real);
        }

        let mut h = Vec::with_capacity(46);
        h.extend_from_slice(&CD_SIG);
        push_u16(&mut h, 0x031E); // version made by: unix host (0x03), spec 3.0 (0x1E)
        push_u16(&mut h, r.version_needed);
        push_u16(&mut h, r.gp_flag);
        push_u16(&mut h, r.method);
        push_u16(&mut h, r.dos_time);
        push_u16(&mut h, r.dos_date);
        push_u32(&mut h, r.crc);
        push_u32(&mut h, size32(r.comp_size, c_over));
        push_u32(&mut h, size32(r.uncomp_size, uc_over));
        push_u16(&mut h, u16::try_from(r.name.len()).unwrap_or(U16_SENTINEL));
        push_u16(&mut h, u16::try_from(extra.len()).unwrap_or(0));
        push_u16(&mut h, 0); // comment length
        push_u16(&mut h, 0); // disk number start
        push_u16(&mut h, 0); // internal attributes
        push_u32(&mut h, r.external_attrs);
        push_u32(&mut h, size32(r.local_offset, off_over));

        self.emit(&h)?;
        let name = r.name.clone();
        self.emit(&name)?;
        self.emit(&extra)?;
        Ok(())
    }
}

impl<W: Sink> EntryWriter for ZipWriter<W> {
    type Sink = Self;

    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self>> {
        if self.pending.is_some() {
            return Err(Error::InvalidState("zip: previous entry not closed"));
        }
        // Directory names must end with '/', symmetric with the reader's dir detection.
        let mut name = meta.path.to_vec();
        if meta.kind == EntryKind::Dir && name.last() != Some(&b'/') {
            name.push(b'/');
        }
        self.pending = Some(Pending {
            name,
            kind: meta.kind,
            mode: meta.mode & 0o7777,
            mtime: meta.mtime,
            link_target: meta.link_target.as_ref().map(|t| t.to_vec()),
            plain: Vec::new(),
        });
        Ok(EntrySink::new(self))
    }

    fn finish(&mut self) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::InvalidState("zip: entry open at finish"));
        }

        let cd_start = self.offset;
        let records = core::mem::take(&mut self.records);
        for r in &records {
            self.write_central(r)?;
        }
        let cd_end = self.offset;
        let cd_size = cd_end - cd_start;
        let count = records.len() as u64;

        // `>=`: at exactly 0xFFFF the classic count16 field already becomes the sentinel value, so
        // the zip64 EOCD record must be emitted (the reader treats count16 == 0xFFFF as zip64).
        let count_over = count >= u64::from(U16_SENTINEL);
        let cd_size_over = self.over(cd_size);
        let cd_off_over = self.over(cd_start);
        let need_zip64 = count_over || cd_size_over || cd_off_over;

        if need_zip64 {
            let eocd64_off = self.offset;
            // zip64 EOCD record (fixed 56 bytes; the size field counts the 44 bytes after it).
            let mut rec = Vec::with_capacity(56);
            rec.extend_from_slice(&EOCD64_SIG);
            push_u64(&mut rec, 44);
            push_u16(&mut rec, 0x031E); // version made by
            push_u16(&mut rec, 45); // version needed
            push_u32(&mut rec, 0); // this disk
            push_u32(&mut rec, 0); // disk with CD
            push_u64(&mut rec, count); // entries on this disk
            push_u64(&mut rec, count); // total entries
            push_u64(&mut rec, cd_size);
            push_u64(&mut rec, cd_start);
            self.emit(&rec)?;

            // zip64 EOCD locator (20 bytes).
            let mut loc = Vec::with_capacity(20);
            loc.extend_from_slice(&LOCATOR_SIG);
            push_u32(&mut loc, 0); // disk with zip64 EOCD
            push_u64(&mut loc, eocd64_off);
            push_u32(&mut loc, 1); // total disks
            self.emit(&loc)?;
        }

        // Classic EOCD (with sentinels where zip64 applies).
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG);
        push_u16(&mut eocd, 0); // this disk
        push_u16(&mut eocd, 0); // disk with CD
        let count16 = if count_over {
            U16_SENTINEL
        } else {
            u16::try_from(count).unwrap_or(U16_SENTINEL)
        };
        push_u16(&mut eocd, count16);
        push_u16(&mut eocd, count16);
        push_u32(&mut eocd, size32(cd_size, cd_size_over));
        push_u32(&mut eocd, size32(cd_start, cd_off_over));
        push_u16(&mut eocd, 0); // comment length
        self.emit(&eocd)?;
        Ok(())
    }
}

impl<W: Sink> EntryDataSink for ZipWriter<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.pending {
            Some(p) => {
                p.plain.extend_from_slice(data);
                Ok(())
            },
            None => Err(Error::InvalidState("zip: write without an open entry")),
        }
    }

    fn close(&mut self) -> Result<()> {
        self.close_entry()
    }
}

// ── Writer helpers ──────────────────────────────────────────────────────────────────────────────

/// Pushes a little-endian `u16`.
fn push_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Pushes a little-endian `u32`.
fn push_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Pushes a little-endian `u64`.
fn push_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// A 32-bit size field: the real value, or [`U32_SENTINEL`] when zip64 carries it in the extra.
fn size32(v: u64, over: bool) -> u32 {
    if over {
        U32_SENTINEL
    } else {
        u32::try_from(v).unwrap_or(U32_SENTINEL)
    }
}

/// Appends a `WinZip` AES (0x9901) extra field recording `real_method` (AE-2, AES-256).
fn push_aes_extra(extra: &mut Vec<u8>, real_method: u16) {
    push_u16(extra, EXTRA_AES);
    push_u16(extra, 7); // body length
    push_u16(extra, 0x0002); // vendor version: AE-2
    extra.extend_from_slice(b"AE"); // vendor id
    extra.push(0x03); // strength: AES-256
    push_u16(extra, real_method);
}

/// Computes the external-attributes word: the Unix mode (type bits + permissions) in the high 16
/// bits, plus the DOS directory bit so DOS-only tools still see directories.
fn external_attrs(kind: EntryKind, mode: u32) -> u32 {
    let type_bits = match kind {
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        _ => 0o100_000,
    };
    let unix = type_bits | (mode & 0o7777);
    let mut attrs = unix << 16;
    if kind == EntryKind::Dir {
        attrs |= 0x10; // FILE_ATTRIBUTE_DIRECTORY
    }
    attrs
}

/// Converts an optional timestamp into a DOS `(time, date)` pair. Times before the DOS epoch
/// (1980-01-01) or absent clamp to that epoch.
fn dos_datetime(ts: Option<Timestamp>) -> (u16, u16) {
    const DOS_EPOCH: i64 = 315_532_800; // 1980-01-01T00:00:00Z
    let secs = match ts {
        Some(t) if t.secs >= DOS_EPOCH => t.secs,
        _ => return (0, 0x21), // 1980-01-01 00:00:00
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (y, m, d) = civil_from_days(days);
    let year = (y - 1980).clamp(0, 127);
    let dos_date = (u16::try_from(year).unwrap_or(0) << 9)
        | (u16::try_from(m).unwrap_or(1) << 5)
        | u16::try_from(d).unwrap_or(1);
    let dos_time = (u16::try_from(hour).unwrap_or(0) << 11)
        | (u16::try_from(min).unwrap_or(0) << 5)
        | u16::try_from(sec / 2).unwrap_or(0);
    (dos_time, dos_date)
}

/// Civil date `(year, month, day)` from days since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ── AES-256 `WinZip` AE-2 ─────────────────────────────────────────────────────────────────────────

/// Draws a 16-byte salt from the OS CSPRNG.
#[cfg(feature = "aes")]
fn system_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Malformed("zip: OS RNG failure"))?;
    Ok(salt)
}

/// Without the `aes` feature there is no CSPRNG dependency; a system salt cannot be produced.
#[cfg(not(feature = "aes"))]
fn system_salt() -> Result<[u8; 16]> {
    Err(Error::Unsupported(
        "zip: AES encryption (rebuild with the `aes` feature)",
    ))
}

/// Encrypts `compressed` as a `WinZip` AE-2 blob: `salt(16) | pwverify(2) | ciphertext | auth(10)`.
#[cfg(feature = "aes")]
fn encrypt_aes(compressed: &[u8], password: &[u8], salt: [u8; 16]) -> Result<Vec<u8>> {
    aes::encrypt(compressed, password, salt)
}

/// Without the `aes` feature, a writer configured with a password cannot proceed.
#[cfg(not(feature = "aes"))]
fn encrypt_aes(_compressed: &[u8], _password: &[u8], _salt: [u8; 16]) -> Result<Vec<u8>> {
    Err(Error::Unsupported(
        "zip: AES encryption (rebuild with the `aes` feature)",
    ))
}

/// `WinZip` AES-256 AE-2 primitives (PBKDF2-HMAC-SHA1, AES-256-CTR little-endian, HMAC-SHA1 auth).
#[cfg(feature = "aes")]
mod aes {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use hmac::{Hmac, Mac};
    use libarchive_oxide_core::{Error, Result};
    use sha1::Sha1;
    use subtle::ConstantTimeEq;

    type Aes256Ctr = ctr::Ctr128LE<::aes::Aes256>;
    type HmacSha1 = Hmac<Sha1>;

    const KEY_LEN: usize = 32;
    const MAC_LEN: usize = 32;
    const PWVERIFY_LEN: usize = 2;
    const AUTH_LEN: usize = 10;
    const SALT_LEN: usize = 16;
    const ITERATIONS: u32 = 1000;

    /// Derives `aes_key(32) | mac_key(32) | pwverify(2)` via PBKDF2-HMAC-SHA1, 1000 iterations.
    fn derive(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN + MAC_LEN + PWVERIFY_LEN] {
        let mut km = [0u8; KEY_LEN + MAC_LEN + PWVERIFY_LEN];
        pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, ITERATIONS, &mut km);
        km
    }

    /// Builds the AES-256-CTR cipher with a 128-bit little-endian counter starting at 1.
    fn cipher(key: &[u8]) -> Result<Aes256Ctr> {
        let mut iv = [0u8; 16];
        iv[0] = 1; // little-endian counter initialized to 1
        Aes256Ctr::new_from_slices(key, &iv).map_err(|_| Error::Malformed("zip: AES key setup"))
    }

    /// Encrypts `compressed` into `salt | pwverify | ciphertext | auth`.
    pub(super) fn encrypt(
        compressed: &[u8],
        password: &[u8],
        salt: [u8; SALT_LEN],
    ) -> Result<Vec<u8>> {
        let km = derive(password, &salt);
        let aes_key = &km[..KEY_LEN];
        let mac_key = &km[KEY_LEN..KEY_LEN + MAC_LEN];
        let pwverify = &km[KEY_LEN + MAC_LEN..];

        let mut ct = compressed.to_vec();
        cipher(aes_key)?.apply_keystream(&mut ct);

        let mut mac = <HmacSha1 as Mac>::new_from_slice(mac_key)
            .map_err(|_| Error::Malformed("zip: HMAC key setup"))?;
        mac.update(&ct);
        let auth = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(SALT_LEN + PWVERIFY_LEN + ct.len() + AUTH_LEN);
        out.extend_from_slice(&salt);
        out.extend_from_slice(pwverify);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&auth[..AUTH_LEN]);
        Ok(out)
    }

    /// Decrypts a `WinZip` AE-2 blob, verifying the password check bytes and the HMAC in constant
    /// time. Returns the (still-compressed) plaintext.
    pub(super) fn decrypt(blob: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        let min = SALT_LEN + PWVERIFY_LEN + AUTH_LEN;
        if blob.len() < min {
            return Err(Error::Malformed("zip: AES blob too short"));
        }
        let salt = &blob[..SALT_LEN];
        let stored_verify = &blob[SALT_LEN..SALT_LEN + PWVERIFY_LEN];
        let ct = &blob[SALT_LEN + PWVERIFY_LEN..blob.len() - AUTH_LEN];
        let stored_auth = &blob[blob.len() - AUTH_LEN..];

        let km = derive(password, salt);
        let aes_key = &km[..KEY_LEN];
        let mac_key = &km[KEY_LEN..KEY_LEN + MAC_LEN];
        let pwverify = &km[KEY_LEN + MAC_LEN..];

        // Constant-time password-verifier check.
        if pwverify.ct_eq(stored_verify).unwrap_u8() != 1 {
            return Err(Error::Malformed("zip: AES wrong password"));
        }

        // Constant-time HMAC authentication over the ciphertext.
        let mut mac = <HmacSha1 as Mac>::new_from_slice(mac_key)
            .map_err(|_| Error::Malformed("zip: HMAC key setup"))?;
        mac.update(ct);
        let auth = mac.finalize().into_bytes();
        if auth[..AUTH_LEN].ct_eq(stored_auth).unwrap_u8() != 1 {
            return Err(Error::Malformed("zip: AES authentication failed"));
        }

        let mut plain = ct.to_vec();
        cipher(aes_key)?.apply_keystream(&mut plain);
        Ok(plain)
    }
}
