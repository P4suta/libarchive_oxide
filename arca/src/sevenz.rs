//! 7z reader and writer — a deliberately narrow, fully interoperable subset.
//!
//! 7z, like zip, keeps its authoritative metadata in a header (here at the *end* of the file,
//! pointed to by a 32-byte signature header at the front) and compresses payloads independently of
//! the outer stream. It therefore does not compose with the [`Filter`](arca_core::filter) pipeline;
//! instead each entry's [`EntryData`](arca_core::EntryData) is a window into the decompressed folder
//! buffer. It lives in the std crate (it needs an LZMA2 codec) yet implements the same
//! [`arca_core::EntryReader`] / [`arca_core::EntryWriter`], so it plugs into detection, extraction,
//! and creation exactly like every other format.
//!
//! ## Scope (explicit, tested)
//!
//! Read and write are restricted to the **single-folder, single-pack, single-coder** subset: one
//! solid block holding any number of files as substreams, plus directories and empty files (which
//! carry no stream). The **writer** always emits LZMA2 (method id `0x21`). The **reader** accepts
//! either LZMA2 or plain **LZMA** (method id `03 01 01`) as the folder coder, including for a
//! compressed (`kEncodedHeader`) next header — which is what mainstream 7-Zip and `sevenz-rust2`
//! produce once an archive has more than a trivial number of entries. Anything outside that —
//! BCJ/delta filters, AES, `PPMd`, multiple folders/coders, or complex coder graphs — is reported
//! as [`Error::Unsupported`], never a panic. This is a genuine format-shape limitation, not a
//! shortcut: the byte layout produced here is standard 7z and round-trips through independent 7z
//! implementations.

use std::borrow::Cow;
use std::io::{Cursor, Read, Write};

use arca_core::format::{ArchiveFormat, Detection};
use arca_core::format::{Entry, EntryDataSink, EntryReader, EntrySink, EntryWriter, OwnedData};
use arca_core::io::Sink;
use arca_core::{EntryKind, EntryMeta, Error, Result, Timestamp};

/// The 6-byte 7z signature magic (`'7' 'z' 0xBC 0xAF 0x27 0x1C`).
const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
/// Size of the fixed signature header at the start of every 7z file.
const SIGNATURE_HEADER_SIZE: usize = 32;

// 7z header property ids (a self-describing tag-length-ish structure).
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_NAME: u8 = 0x11;
const K_MTIME: u8 = 0x14;
const K_WIN_ATTRIBUTES: u8 = 0x15;
const K_ENCODED_HEADER: u8 = 0x17;

/// LZMA2 coder method id (1 byte).
const METHOD_LZMA2: u8 = 0x21;
/// LZMA (v1) coder method id (3 bytes) — how mainstream 7-Zip compresses encoded headers and folders.
const METHOD_LZMA: [u8; 3] = [0x03, 0x01, 0x01];

/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTR_DIRECTORY: u32 = 0x10;
/// 7-Zip's "the high 16 bits carry a Unix `st_mode`" marker.
const ATTR_UNIX_EXTENSION: u32 = 0x8000;

/// Seconds between the Windows `FILETIME` epoch (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;

/// Cap on a folder's declared uncompressed size, applied before allocating (bomb defense).
const MAX_UNPACK: u64 = 4 * 1024 * 1024 * 1024;
/// Cap on the file count declared in `FilesInfo`, applied before allocating.
const MAX_FILES: u64 = 1 << 24;

/// The LZMA2 dictionary size the writer uses (matches `lzma_rust2` preset 6 = 8 MiB).
const WRITER_DICT_SIZE: u32 = 1 << 23;
/// The LZMA2 encoder preset the writer uses.
const WRITER_PRESET: u32 = 6;

/// Returns `true` if `data` begins with the 7z signature magic.
#[must_use]
pub fn is_7z(data: &[u8]) -> bool {
    data.starts_with(&SIGNATURE)
}

/// Detection anchor for the 7z format.
#[derive(Debug)]
pub struct SevenZ;

impl ArchiveFormat for SevenZ {
    const NAME: &'static str = "7z";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < SIGNATURE.len() {
            return Detection::NeedMore;
        }
        if prefix.starts_with(&SIGNATURE) {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Parsed structures
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// The single-coder codec of a folder. Reading supports both LZMA2 (what arca writes) and plain
/// LZMA (what 7-Zip and `sevenz-rust2` use for compressed/encoded headers and folders).
#[derive(Debug, Clone, Copy)]
enum FolderCoder {
    /// LZMA2, carrying its one-byte dictionary-size property.
    Lzma2 { dict_prop: u8 },
    /// LZMA (v1), carrying its 5 property bytes: `lc/lp/pb` byte + little-endian `u32` dict size.
    Lzma { props: [u8; 5] },
}

/// The restricted single-folder description parsed from a `StreamsInfo`.
#[derive(Debug, Clone)]
struct FolderInfo {
    /// Absolute offset of the packed stream within the archive bytes.
    pack_offset: usize,
    /// Length of the packed stream.
    pack_size: usize,
    /// Uncompressed size of the whole folder.
    unpack_size: u64,
    /// The folder's single coder and its properties.
    coder: FolderCoder,
    /// Per-substream (per content file) uncompressed sizes, in file order.
    substream_sizes: Vec<u64>,
}

/// A parsed directory-entry-like record: name, kind, permissions, mtime, and (for content files)
/// the window into the decompressed folder buffer.
#[derive(Debug, Clone)]
struct FileRec {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    has_stream: bool,
    stream_offset: usize,
    size: usize,
}

/// 7z streaming reader over an in-memory archive slice.
///
/// Following the zip `OwnedData` pattern, the whole folder is decompressed once into
/// [`Self::unpacked`] and each content file is handed a fresh owned window; directories and empty
/// files get an empty window.
#[derive(Debug)]
pub struct SevenZReader<'a> {
    data: &'a [u8],
    files: Vec<FileRec>,
    folder: Option<FolderInfo>,
    index: usize,
    parsed: bool,
    unpacked: Option<Vec<u8>>,
    owned: OwnedData,
}

impl<'a> SevenZReader<'a> {
    /// Builds a reader over the whole 7z archive bytes.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            files: Vec::new(),
            folder: None,
            index: 0,
            parsed: false,
            unpacked: None,
            owned: OwnedData::default(),
        }
    }

    /// Parses the signature header and the (possibly LZMA2-encoded) next header.
    fn parse(&mut self) -> Result<()> {
        let data = self.data;
        if data.len() < SIGNATURE_HEADER_SIZE || !data.starts_with(&SIGNATURE) {
            return Err(Error::Malformed("7z: bad signature header"));
        }
        // The start-header CRC covers bytes 12..32 (the NextHeader offset/size/CRC triple).
        let start_crc = u32_le(data, 8)?;
        if arca_filter::crc32(&data[12..32]) != start_crc {
            return Err(Error::Malformed("7z: bad start header CRC"));
        }
        let nh_offset = u64_le(data, 12)?;
        let nh_size = u64_le(data, 20)?;
        let nh_crc = u32_le(data, 28)?;

        // An empty archive has no next header.
        if nh_size == 0 {
            return Ok(());
        }

        let header_start = SIGNATURE_HEADER_SIZE
            .checked_add(usize_of(nh_offset)?)
            .ok_or(Error::Malformed("7z: header offset overflow"))?;
        let header_end = header_start
            .checked_add(usize_of(nh_size)?)
            .ok_or(Error::Malformed("7z: header size overflow"))?;
        let header = data
            .get(header_start..header_end)
            .ok_or(Error::Malformed("7z: truncated next header"))?;
        if arca_filter::crc32(header) != nh_crc {
            return Err(Error::Malformed("7z: bad next header CRC"));
        }

        let mut r = ByteReader::new(header);
        match r.u8()? {
            K_HEADER => self.parse_header(&mut r),
            K_ENCODED_HEADER => {
                // The header itself is a compressed stream; decode it, then re-parse as a plain
                // kHeader. The decode path is the same restricted LZMA2 single-folder pipeline.
                let folder = parse_streams_info(&mut r)?;
                let decoded = self.decode_folder(&folder)?;
                let mut r2 = ByteReader::new(&decoded);
                if r2.u8()? != K_HEADER {
                    return Err(Error::Unsupported(
                        "7z: encoded header is not a plain kHeader",
                    ));
                }
                self.parse_header(&mut r2)
            }
            _ => Err(Error::Malformed("7z: unexpected next-header id")),
        }
    }

    /// Parses a plain `kHeader` body: optional main streams info, then files info.
    fn parse_header(&mut self, r: &mut ByteReader<'_>) -> Result<()> {
        let mut folder: Option<FolderInfo> = None;
        loop {
            match r.u8()? {
                K_END => break,
                K_ARCHIVE_PROPERTIES => skip_archive_properties(r)?,
                K_MAIN_STREAMS_INFO => folder = Some(parse_streams_info(r)?),
                K_FILES_INFO => self.parse_files_info(r, folder.as_ref())?,
                _ => return Err(Error::Unsupported("7z: unsupported header property")),
            }
        }
        self.folder = folder;
        Ok(())
    }

    /// Parses `FilesInfo`, assembling [`FileRec`]s and assigning content-file windows in order.
    #[allow(clippy::too_many_lines, clippy::needless_range_loop)]
    fn parse_files_info(
        &mut self,
        r: &mut ByteReader<'_>,
        folder: Option<&FolderInfo>,
    ) -> Result<()> {
        let num_files = usize_of(r.number()?)?;
        if num_files as u64 > MAX_FILES {
            return Err(Error::LimitExceeded("7z: too many files"));
        }
        // Bomb defense: the entire next-header is already resident, so no honest archive can declare
        // more files than there are header bytes left to describe them (each file carries at least a
        // 2-byte UTF-16 name terminator, and usually attributes and a timestamp besides). Capping
        // against the remaining bytes keeps the per-file allocations below proportional to the input
        // and blocks a tiny header from forcing a multi-hundred-megabyte allocation up front.
        if num_files > r.remaining() {
            return Err(Error::Malformed("7z: file count exceeds header size"));
        }

        let mut empty_stream = vec![false; num_files];
        let mut empty_file: Vec<bool> = Vec::new();
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut mtimes: Vec<Option<Timestamp>> = vec![None; num_files];
        let mut modes: Vec<Option<u32>> = vec![None; num_files];

        loop {
            let prop = r.number()?;
            if prop == u64::from(K_END) {
                break;
            }
            let size = usize_of(r.number()?)?;
            let body = r.bytes(size)?;
            let mut br = ByteReader::new(body);
            match u8::try_from(prop).unwrap_or(0xFF) {
                K_EMPTY_STREAM => empty_stream = br.bit_vector(num_files)?,
                K_EMPTY_FILE => {
                    let num_empty = empty_stream.iter().filter(|&&b| b).count();
                    empty_file = br.bit_vector(num_empty)?;
                }
                K_NAME => names = parse_names(&mut br, num_files)?,
                K_MTIME => mtimes = parse_times(&mut br, num_files)?,
                K_WIN_ATTRIBUTES => modes = parse_attributes(&mut br, num_files)?,
                // kCTime/kATime/kAnti/kStartPos/kDummy and any other property: body already skipped.
                _ => {}
            }
        }

        // Assemble records. Content files consume substream windows in file order; empty-stream
        // files are directories unless flagged as empty files.
        let sizes = folder.map_or(&[][..], |f| f.substream_sizes.as_slice());
        let mut content_index = 0usize;
        let mut running = 0usize;
        let mut empty_index = 0usize;

        for i in 0..num_files {
            let name = names.get(i).cloned().unwrap_or_default();
            let full_mode = modes.get(i).copied().flatten();
            let has_stream = !empty_stream[i];

            let (kind, offset, size) = if has_stream {
                let size = usize_of(
                    *sizes
                        .get(content_index)
                        .ok_or(Error::Malformed("7z: content stream index out of range"))?,
                )?;
                let offset = running;
                running = running
                    .checked_add(size)
                    .ok_or(Error::Malformed("7z: folder offset overflow"))?;
                content_index += 1;
                let kind = if full_mode.is_some_and(|m| m & 0o170_000 == 0o120_000) {
                    EntryKind::Symlink
                } else {
                    EntryKind::File
                };
                (kind, offset, size)
            } else {
                let is_empty_file = empty_file.get(empty_index).copied().unwrap_or(false);
                empty_index += 1;
                let kind = if is_empty_file {
                    EntryKind::File
                } else {
                    EntryKind::Dir
                };
                (kind, 0, 0)
            };

            let mode = permission_bits(full_mode, kind);
            self.files.push(FileRec {
                name,
                kind,
                mode,
                mtime: mtimes.get(i).copied().flatten(),
                has_stream,
                stream_offset: offset,
                size,
            });
        }
        Ok(())
    }

    /// Decompresses a folder's packed stream into a fresh buffer, capping the size first.
    fn decode_folder(&self, f: &FolderInfo) -> Result<Vec<u8>> {
        if f.unpack_size > MAX_UNPACK {
            return Err(Error::LimitExceeded("7z: folder unpack size exceeds cap"));
        }
        let end = f
            .pack_offset
            .checked_add(f.pack_size)
            .ok_or(Error::Malformed("7z: pack range overflow"))?;
        let packed = self
            .data
            .get(f.pack_offset..end)
            .ok_or(Error::Malformed("7z: truncated packed stream"))?;

        let cap = usize_of(f.unpack_size)?;
        match f.coder {
            FolderCoder::Lzma2 { dict_prop } => {
                let dict = lzma2_dict_size(dict_prop)?;
                let reader = lzma_rust2::Lzma2Reader::new(Cursor::new(packed.to_vec()), dict, None);
                drain_exact(reader, cap)
            }
            FolderCoder::Lzma { props } => {
                let dict = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
                let reader = lzma_rust2::LzmaReader::new_with_props(
                    Cursor::new(packed.to_vec()),
                    f.unpack_size,
                    props[0],
                    dict,
                    None,
                )
                .map_err(|_| Error::Malformed("7z: LZMA stream setup failed"))?;
                drain_exact(reader, cap)
            }
        }
    }
}

/// Reads exactly `cap` decompressed bytes from `reader` into a fresh buffer.
///
/// Bomb defense: unlike a `vec![0u8; cap]` pre-fill, the buffer grows only with bytes actually
/// produced, so a tiny packed stream that *declares* a near-`MAX_UNPACK` size but decodes to little
/// (or errors early) never forces a multi-gigabyte allocation. A short or over-long decode is an
/// error, matching the strict `read_exact` contract the format requires.
fn drain_exact<R: Read>(mut reader: R, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while out.len() < cap {
        let want = (cap - out.len()).min(buf.len());
        let n = reader
            .read(&mut buf[..want])
            .map_err(|_| Error::Malformed("7z: LZMA decode failed"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    if out.len() != cap {
        return Err(Error::Malformed(
            "7z: decoded size does not match declared unpack size",
        ));
    }
    Ok(out)
}

impl EntryReader for SevenZReader<'_> {
    type Data = OwnedData;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, OwnedData>>> {
        if !self.parsed {
            self.parse()?;
            self.parsed = true;
        }
        if self.index >= self.files.len() {
            return Ok(None);
        }
        let idx = self.index;
        self.index += 1;

        // Copy the scalar fields out before mutating `self` (decode buffer + owned slot).
        let rec = self.files[idx].clone();

        let content: Vec<u8> = if rec.has_stream {
            if self.unpacked.is_none() {
                let folder = self
                    .folder
                    .clone()
                    .ok_or(Error::Malformed("7z: content stream without a folder"))?;
                self.unpacked = Some(self.decode_folder(&folder)?);
            }
            let buf = self
                .unpacked
                .as_ref()
                .ok_or(Error::Malformed("7z: folder not decoded"))?;
            let end = rec
                .stream_offset
                .checked_add(rec.size)
                .ok_or(Error::Malformed("7z: stream window overflow"))?;
            buf.get(rec.stream_offset..end)
                .ok_or(Error::Malformed("7z: stream window out of range"))?
                .to_vec()
        } else {
            Vec::new()
        };
        self.owned = OwnedData::new(content);

        let link_target = matches!(rec.kind, EntryKind::Symlink)
            .then(|| Cow::Owned(self.owned.as_bytes().to_vec()));
        let meta = EntryMeta {
            kind: rec.kind,
            path: Cow::Owned(rec.name),
            mode: rec.mode,
            uid: 0,
            gid: 0,
            mtime: rec.mtime,
            size: self.owned.as_bytes().len() as u64,
            link_target,
            pax: arca_core::PaxMap::new(),
        };
        Ok(Some(Entry::new(meta, &mut self.owned)))
    }
}

/// Skips a `kArchiveProperties` block (a sequence of typed property blobs ended by `kEnd`).
fn skip_archive_properties(r: &mut ByteReader<'_>) -> Result<()> {
    loop {
        if r.u8()? == K_END {
            return Ok(());
        }
        let size = usize_of(r.number()?)?;
        let _ = r.bytes(size)?;
    }
}

/// Parses a `StreamsInfo` (`PackInfo`, `UnpackInfo`, `SubStreamsInfo`) restricted to one pack, one folder,
/// and one LZMA2 coder.
fn parse_streams_info(r: &mut ByteReader<'_>) -> Result<FolderInfo> {
    let mut pack_pos = 0u64;
    let mut pack_size: Option<u64> = None;
    let mut coder: Option<FolderCoder> = None;
    let mut unpack_size = 0u64;
    let mut num_substreams = 1usize;
    let mut substream_sizes: Option<Vec<u64>> = None;
    // Whether the folder's UnpackInfo carried a CRC. Mainstream 7-Zip and `sevenz-rust2` do NOT put
    // the folder CRC here — they store it only in SubStreamsInfo — so a single-substream folder still
    // carries a digest in SubStreamsInfo. Tracking this is what makes real compressed headers parse.
    let mut folder_has_crc = false;

    loop {
        match r.u8()? {
            K_END => break,
            K_PACK_INFO => {
                pack_pos = r.number()?;
                let num_pack = r.number()?;
                if num_pack != 1 {
                    return Err(Error::Unsupported(
                        "7z: only a single pack stream is supported",
                    ));
                }
                loop {
                    match r.u8()? {
                        K_END => break,
                        K_SIZE => pack_size = Some(r.number()?),
                        K_CRC => read_digests(r, 1)?,
                        _ => return Err(Error::Unsupported("7z: unsupported pack-info property")),
                    }
                }
            }
            K_UNPACK_INFO => {
                if r.u8()? != K_FOLDER {
                    return Err(Error::Malformed("7z: unpack info missing kFolder"));
                }
                if r.number()? != 1 {
                    return Err(Error::Unsupported("7z: only a single folder is supported"));
                }
                if r.u8()? != 0 {
                    return Err(Error::Unsupported("7z: external folder definitions"));
                }
                coder = Some(read_folder(r)?);
                if r.u8()? != K_CODERS_UNPACK_SIZE {
                    return Err(Error::Malformed("7z: missing coders-unpack-size"));
                }
                unpack_size = r.number()?;
                loop {
                    match r.u8()? {
                        K_END => break,
                        K_CRC => {
                            folder_has_crc = true;
                            read_digests(r, 1)?;
                        }
                        _ => {
                            return Err(Error::Unsupported("7z: unsupported unpack-info property"))
                        }
                    }
                }
            }
            K_SUBSTREAMS_INFO => {
                let (n, sizes) = parse_substreams_info(r, unpack_size, folder_has_crc)?;
                num_substreams = n;
                substream_sizes = Some(sizes);
            }
            _ => return Err(Error::Unsupported("7z: unsupported streams-info property")),
        }
    }

    let pack_size = pack_size.ok_or(Error::Malformed("7z: missing pack size"))?;
    let coder = coder.ok_or(Error::Malformed("7z: missing coder properties"))?;
    let substream_sizes = match substream_sizes {
        Some(s) => s,
        None => vec![unpack_size],
    };
    let _ = num_substreams;
    let pack_offset = SIGNATURE_HEADER_SIZE
        .checked_add(usize_of(pack_pos)?)
        .ok_or(Error::Malformed("7z: pack offset overflow"))?;

    Ok(FolderInfo {
        pack_offset,
        pack_size: usize_of(pack_size)?,
        unpack_size,
        coder,
        substream_sizes,
    })
}

/// Parses a single folder definition, returning its coder (LZMA2 or plain LZMA) and properties.
fn read_folder(r: &mut ByteReader<'_>) -> Result<FolderCoder> {
    if r.number()? != 1 {
        return Err(Error::Unsupported("7z: only a single coder is supported"));
    }
    let flags = r.u8()?;
    let id_size = usize::from(flags & 0x0F);
    let is_complex = flags & 0x10 != 0;
    let has_attributes = flags & 0x20 != 0;
    if flags & 0x80 != 0 {
        return Err(Error::Unsupported("7z: reserved coder flag set"));
    }
    let codec = r.bytes(id_size)?;
    if is_complex {
        return Err(Error::Unsupported("7z: complex coders are not supported"));
    }
    if !has_attributes {
        return Err(Error::Unsupported("7z: coder without properties"));
    }
    let prop_size = usize_of(r.number()?)?;
    let props = r.bytes(prop_size)?;
    if codec == [METHOD_LZMA2] {
        if prop_size != 1 {
            return Err(Error::Unsupported("7z: unexpected LZMA2 property size"));
        }
        Ok(FolderCoder::Lzma2 {
            dict_prop: props[0],
        })
    } else if codec == METHOD_LZMA {
        if prop_size != 5 {
            return Err(Error::Unsupported("7z: unexpected LZMA property size"));
        }
        let mut p = [0u8; 5];
        p.copy_from_slice(props);
        Ok(FolderCoder::Lzma { props: p })
    } else {
        Err(Error::Unsupported(
            "7z: only the LZMA2 and LZMA coders are supported",
        ))
    }
}

/// Parses a `SubStreamsInfo` block for the single folder, returning `(num_substreams, sizes)`.
///
/// `folder_has_crc` says whether the folder's `UnpackInfo` already defined a CRC: a single-substream
/// folder repeats no digest here only when it did, matching the 7z rule
/// `numDigests = Σ folders where (numSubstreams != 1 || !folderCrcDefined)`.
fn parse_substreams_info(
    r: &mut ByteReader<'_>,
    folder_unpack: u64,
    folder_has_crc: bool,
) -> Result<(usize, Vec<u64>)> {
    let mut num = 1usize;
    let mut sizes: Vec<u64> = Vec::new();
    let mut have_sizes = false;

    loop {
        match r.u8()? {
            K_END => break,
            K_NUM_UNPACK_STREAM => num = usize_of(r.number()?)?,
            K_SIZE => {
                let mut sum = 0u64;
                for _ in 0..num.saturating_sub(1) {
                    let s = r.number()?;
                    sum = sum
                        .checked_add(s)
                        .ok_or(Error::Malformed("7z: substream size overflow"))?;
                    sizes.push(s);
                }
                let last = folder_unpack
                    .checked_sub(sum)
                    .ok_or(Error::Malformed("7z: substream sizes exceed folder"))?;
                sizes.push(last);
                have_sizes = true;
            }
            K_CRC => {
                // A digest is present for every substream except the single-substream case whose CRC
                // is already defined on the folder (then it is not repeated).
                let unknown = if num == 1 && folder_has_crc { 0 } else { num };
                read_digests(r, unknown)?;
            }
            _ => return Err(Error::Unsupported("7z: unsupported substreams property")),
        }
    }

    if !have_sizes {
        if num == 1 {
            sizes = vec![folder_unpack];
        } else {
            return Err(Error::Malformed("7z: missing substream sizes"));
        }
    }
    if sizes.len() != num {
        return Err(Error::Malformed("7z: substream count mismatch"));
    }
    Ok((num, sizes))
}

/// Reads a `Digests` structure (`AllAreDefined` byte + optional bit vector + one CRC per defined
/// item), discarding the values after bounds-checking them.
fn read_digests(r: &mut ByteReader<'_>, count: usize) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let all_defined = r.u8()?;
    let defined = if all_defined != 0 {
        count
    } else {
        r.bit_vector(count)?.iter().filter(|&&b| b).count()
    };
    for _ in 0..defined {
        let _ = r.u32()?;
    }
    Ok(())
}

/// Parses the `kName` property: an external byte (must be 0) then null-terminated UTF-16LE names.
fn parse_names(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Vec<u8>>> {
    if r.u8()? != 0 {
        return Err(Error::Unsupported("7z: names in an external stream"));
    }
    let mut names = Vec::with_capacity(num_files);
    for _ in 0..num_files {
        let start = r.pos;
        loop {
            if r.u16()? == 0 {
                break;
            }
        }
        let raw = r
            .data
            .get(start..r.pos - 2)
            .ok_or(Error::Malformed("7z: bad name range"))?;
        names.push(utf16le_to_bytes(raw));
    }
    Ok(names)
}

/// Parses the `kMTime` property into a per-file list of optional timestamps.
fn parse_times(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Option<Timestamp>>> {
    let defined = read_all_defined(r, num_files)?;
    if r.u8()? != 0 {
        return Err(Error::Unsupported("7z: times in an external stream"));
    }
    let mut out = vec![None; num_files];
    for (i, &is_def) in defined.iter().enumerate() {
        if is_def {
            out[i] = Some(filetime_to_timestamp(r.u64()?));
        }
    }
    Ok(out)
}

/// Parses the `kWinAttributes` property into a per-file optional full Unix mode (with type bits),
/// present only when the entry carries the Unix-extension marker.
fn parse_attributes(r: &mut ByteReader<'_>, num_files: usize) -> Result<Vec<Option<u32>>> {
    let defined = read_all_defined(r, num_files)?;
    if r.u8()? != 0 {
        return Err(Error::Unsupported("7z: attributes in an external stream"));
    }
    let mut out = vec![None; num_files];
    for (i, &is_def) in defined.iter().enumerate() {
        if is_def {
            let attr = r.u32()?;
            if attr & ATTR_UNIX_EXTENSION != 0 {
                out[i] = Some(attr >> 16);
            }
        }
    }
    Ok(out)
}

/// Reads an "`AllAreDefined`" boolean vector: a flag byte, and when it is zero, a following bit vector.
fn read_all_defined(r: &mut ByteReader<'_>, n: usize) -> Result<Vec<bool>> {
    if r.u8()? != 0 {
        Ok(vec![true; n])
    } else {
        r.bit_vector(n)
    }
}

/// The permission bits to expose for an entry: the stored `mode & 0o7777`, or a sensible default.
fn permission_bits(full_mode: Option<u32>, kind: EntryKind) -> u32 {
    match full_mode {
        Some(m) if m & 0o7777 != 0 => m & 0o7777,
        _ => match kind {
            EntryKind::Dir => 0o755,
            _ => 0o644,
        },
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Writer
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A finalized entry held until [`SevenZWriter::finish`].
#[derive(Debug)]
struct StoredEntry {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    content: Vec<u8>,
    has_stream: bool,
}

/// The metadata captured when an entry is opened (payload buffered until `close`).
#[derive(Debug)]
struct PendingEntry {
    name: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    plain: Vec<u8>,
}

/// 7z streaming writer — the dual of [`SevenZReader`], restricted to the single-folder LZMA2 subset.
///
/// **The whole archive is buffered in memory.** Every content file's plaintext is concatenated into
/// one solid folder that is LZMA2-compressed at `finish`, and the 32-byte signature header must be
/// back-filled with the (then-known) next-header offset/size/CRC. Because a [`Sink`] is append-only
/// (no seek), the writer assembles the entire archive into a single `Vec<u8>` and performs exactly
/// one `sink.write_all` at the end.
#[derive(Debug)]
pub struct SevenZWriter<W: Sink> {
    sink: W,
    entries: Vec<StoredEntry>,
    pending: Option<PendingEntry>,
}

impl<W: Sink> SevenZWriter<W> {
    /// Builds a writer over a byte sink.
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            entries: Vec::new(),
            pending: None,
        }
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Finalizes the currently open entry into a [`StoredEntry`].
    fn close_entry(&mut self) -> Result<()> {
        let Some(p) = self.pending.take() else {
            return Err(Error::InvalidState("7z: no open entry"));
        };
        // A symlink's content is its target; directories carry nothing; files use the buffered bytes.
        let content = match p.kind {
            EntryKind::Symlink => p.link_target.unwrap_or_default(),
            EntryKind::Dir => Vec::new(),
            _ => p.plain,
        };
        let has_stream = !matches!(p.kind, EntryKind::Dir) && !content.is_empty();
        self.entries.push(StoredEntry {
            name: p.name,
            kind: p.kind,
            mode: p.mode,
            mtime: p.mtime,
            content,
            has_stream,
        });
        Ok(())
    }

    /// Assembles the whole archive in memory and writes it with a single `write_all`.
    fn assemble(&mut self) -> Result<()> {
        // Concatenate content streams into one solid folder and record substream sizes/CRCs.
        let mut unpacked: Vec<u8> = Vec::new();
        let mut sub_sizes: Vec<u64> = Vec::new();
        let mut sub_crcs: Vec<u32> = Vec::new();
        for e in &self.entries {
            if e.has_stream {
                sub_sizes.push(e.content.len() as u64);
                sub_crcs.push(arca_filter::crc32(&e.content));
                unpacked.extend_from_slice(&e.content);
            }
        }
        let num_content = sub_sizes.len();
        let folder_crc = arca_filter::crc32(&unpacked);
        let packed = if num_content > 0 {
            lzma2_compress(&unpacked)?
        } else {
            Vec::new()
        };
        let dict_prop = lzma2_dict_prop(WRITER_DICT_SIZE);

        // Build the plain kHeader.
        let mut header = Vec::new();
        header.push(K_HEADER);
        if num_content > 0 {
            header.push(K_MAIN_STREAMS_INFO);
            write_pack_info(&mut header, packed.len() as u64);
            write_unpack_info(&mut header, dict_prop, unpacked.len() as u64, folder_crc);
            write_substreams_info(&mut header, num_content, &sub_sizes, &sub_crcs);
            header.push(K_END);
        }
        self.write_files_info(&mut header);
        header.push(K_END);

        // Layout: [32-byte signature header][packed folder][next header]. Assemble, then back-fill.
        let mut out = vec![0u8; SIGNATURE_HEADER_SIZE];
        out[0..6].copy_from_slice(&SIGNATURE);
        out[6] = 0; // format major version
        out[7] = 4; // format minor version
        out.extend_from_slice(&packed);
        let nh_offset = packed.len() as u64;
        let nh_size = header.len() as u64;
        let nh_crc = arca_filter::crc32(&header);
        out.extend_from_slice(&header);

        out[12..20].copy_from_slice(&nh_offset.to_le_bytes());
        out[20..28].copy_from_slice(&nh_size.to_le_bytes());
        out[28..32].copy_from_slice(&nh_crc.to_le_bytes());
        let start_crc = arca_filter::crc32(&out[12..32]);
        out[8..12].copy_from_slice(&start_crc.to_le_bytes());

        self.sink.write_all(&out)
    }

    /// Emits the `FilesInfo` block (names, empty-stream/empty-file vectors, attributes, mtimes).
    fn write_files_info(&self, header: &mut Vec<u8>) {
        header.push(K_FILES_INFO);
        write_number(header, self.entries.len() as u64);

        // kEmptyStream: files that carry no stream (directories and empty files).
        let empty_stream: Vec<bool> = self.entries.iter().map(|e| !e.has_stream).collect();
        if empty_stream.iter().any(|&b| b) {
            let mut body = Vec::new();
            write_bit_vector(&mut body, &empty_stream);
            header.push(K_EMPTY_STREAM);
            write_number(header, body.len() as u64);
            header.extend_from_slice(&body);

            // kEmptyFile: among empty-stream files, which are empty regular files (not directories).
            let empty_file: Vec<bool> = self
                .entries
                .iter()
                .filter(|e| !e.has_stream)
                .map(|e| !matches!(e.kind, EntryKind::Dir))
                .collect();
            if empty_file.iter().any(|&b| b) {
                let mut fbody = Vec::new();
                write_bit_vector(&mut fbody, &empty_file);
                header.push(K_EMPTY_FILE);
                write_number(header, fbody.len() as u64);
                header.extend_from_slice(&fbody);
            }
        }

        // kName: external byte (0) then null-terminated UTF-16LE names.
        let mut name_body = vec![0u8];
        for e in &self.entries {
            bytes_to_utf16le(&e.name, &mut name_body);
        }
        header.push(K_NAME);
        write_number(header, name_body.len() as u64);
        header.extend_from_slice(&name_body);

        // kWinAttributes: always defined, carrying the Unix mode + directory bit.
        let mut attr_body = vec![1u8, 0u8]; // AllAreDefined = 1, external = 0
        for e in &self.entries {
            attr_body.extend_from_slice(&windows_attributes(e.kind, e.mode).to_le_bytes());
        }
        header.push(K_WIN_ATTRIBUTES);
        write_number(header, attr_body.len() as u64);
        header.extend_from_slice(&attr_body);

        // kMTime: only when at least one entry has a timestamp.
        let defined: Vec<bool> = self.entries.iter().map(|e| e.mtime.is_some()).collect();
        if defined.iter().any(|&b| b) {
            let mut time_body = Vec::new();
            if defined.iter().all(|&b| b) {
                time_body.push(1u8);
            } else {
                time_body.push(0u8);
                write_bit_vector(&mut time_body, &defined);
            }
            time_body.push(0u8); // external
            for e in &self.entries {
                if let Some(ts) = e.mtime {
                    time_body.extend_from_slice(&timestamp_to_filetime(ts).to_le_bytes());
                }
            }
            header.push(K_MTIME);
            write_number(header, time_body.len() as u64);
            header.extend_from_slice(&time_body);
        }

        header.push(K_END); // end of FilesInfo (property id kEnd)
    }
}

impl<W: Sink> EntryWriter for SevenZWriter<W> {
    type Sink = Self;

    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self>> {
        if self.pending.is_some() {
            return Err(Error::InvalidState("7z: previous entry not closed"));
        }
        // Directory names never carry a trailing '/' in 7z (unlike zip); strip it if present.
        let mut name = meta.path.to_vec();
        if meta.kind == EntryKind::Dir {
            while name.last() == Some(&b'/') {
                name.pop();
            }
        }
        self.pending = Some(PendingEntry {
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
            return Err(Error::InvalidState("7z: entry open at finish"));
        }
        self.assemble()
    }
}

impl<W: Sink> EntryDataSink for SevenZWriter<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.pending {
            Some(p) => {
                p.plain.extend_from_slice(data);
                Ok(())
            }
            None => Err(Error::InvalidState("7z: write without an open entry")),
        }
    }

    fn close(&mut self) -> Result<()> {
        self.close_entry()
    }
}

/// Emits a `PackInfo` block for a single pack stream at pack position 0.
fn write_pack_info(header: &mut Vec<u8>, pack_size: u64) {
    header.push(K_PACK_INFO);
    write_number(header, 0); // PackPos (relative to the end of the signature header)
    write_number(header, 1); // NumPackStreams
    header.push(K_SIZE);
    write_number(header, pack_size);
    header.push(K_END);
}

/// Emits an `UnpackInfo` block for a single LZMA2 folder with a known CRC.
fn write_unpack_info(header: &mut Vec<u8>, dict_prop: u8, unpack_size: u64, folder_crc: u32) {
    header.push(K_UNPACK_INFO);
    header.push(K_FOLDER);
    write_number(header, 1); // NumFolders
    header.push(0); // External = 0
                    // One coder: flags = idSize(1) | kAttributes(0x20) = 0x21; codec id = LZMA2 (0x21); 1 prop byte.
    write_number(header, 1); // NumCoders
    header.push(0x21);
    header.push(METHOD_LZMA2);
    write_number(header, 1); // property size
    header.push(dict_prop);
    header.push(K_CODERS_UNPACK_SIZE);
    write_number(header, unpack_size);
    header.push(K_CRC);
    header.push(1); // AllAreDefined
    header.extend_from_slice(&folder_crc.to_le_bytes());
    header.push(K_END);
}

/// Emits a `SubStreamsInfo` block for the single folder's content substreams.
fn write_substreams_info(header: &mut Vec<u8>, num: usize, sizes: &[u64], crcs: &[u32]) {
    header.push(K_SUBSTREAMS_INFO);
    header.push(K_NUM_UNPACK_STREAM);
    write_number(header, num as u64);
    if num > 1 {
        header.push(K_SIZE);
        // Sizes for all but the last substream; the last is derived from the folder size.
        for &s in &sizes[..num - 1] {
            write_number(header, s);
        }
        // Per-substream CRCs (the single-substream case reuses the folder CRC and is omitted).
        header.push(K_CRC);
        header.push(1); // AllAreDefined
        for &c in crcs {
            header.extend_from_slice(&c.to_le_bytes());
        }
    }
    header.push(K_END);
}

/// Computes a 7z `WinAttributes` word carrying the directory bit and the Unix mode extension.
fn windows_attributes(kind: EntryKind, mode: u32) -> u32 {
    let type_bits = match kind {
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        _ => 0o100_000,
    };
    let unix = type_bits | (mode & 0o7777);
    let mut attr = ATTR_UNIX_EXTENSION | (unix << 16);
    if kind == EntryKind::Dir {
        attr |= ATTR_DIRECTORY;
    }
    attr
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// LZMA2 glue
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// LZMA2-compresses `plain` into a raw LZMA2 stream (exactly what a 7z folder stores).
fn lzma2_compress(plain: &[u8]) -> Result<Vec<u8>> {
    let options = lzma_rust2::Lzma2Options::with_preset(WRITER_PRESET);
    let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), options);
    writer
        .write_all(plain)
        .map_err(|_| Error::Malformed("7z: LZMA2 encode failed"))?;
    writer
        .finish()
        .map_err(|_| Error::Malformed("7z: LZMA2 finish failed"))
}

/// Decodes an LZMA2 dictionary-size property byte into a dictionary size in bytes.
///
/// `dict_size = (2 | (p & 1)) << (p / 2 + 11)`, with `40` reserved for `u32::MAX`.
fn lzma2_dict_size(prop: u8) -> Result<u32> {
    if prop > 40 {
        return Err(Error::Unsupported("7z: invalid LZMA2 dictionary property"));
    }
    if prop == 40 {
        return Ok(u32::MAX);
    }
    let base = 2 | u32::from(prop & 1);
    let shift = u32::from(prop) / 2 + 11;
    Ok(base << shift)
}

/// Encodes a dictionary size into the smallest LZMA2 property byte whose size is `>= dict`.
fn lzma2_dict_prop(dict: u32) -> u8 {
    if dict == u32::MAX {
        return 40;
    }
    let mut prop = 0u8;
    while prop < 40 {
        if lzma2_dict_size(prop).is_ok_and(|d| d >= dict) {
            break;
        }
        prop += 1;
    }
    prop
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// 7z number / bit-vector / time / name primitives
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A bounds-checked cursor over a byte slice for parsing the 7z header grammar.
struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(Error::Malformed("7z: unexpected end of header"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Number of unconsumed bytes — an upper bound on how much more this reader can yield.
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Malformed("7z: header length overflow"))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(Error::Malformed("7z: truncated header field"))?;
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a 7z variable-length number (`ReadNumber`).
    fn number(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let mut value = 0u64;
        let mut mask = 0x80u8;
        for i in 0..8u32 {
            if first & mask == 0 {
                value |= u64::from(first & (mask.wrapping_sub(1))) << (8 * i);
                return Ok(value);
            }
            value |= u64::from(self.u8()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// Reads `n` bits (MSB-first) into a boolean vector, consuming `ceil(n/8)` bytes.
    fn bit_vector(&mut self, n: usize) -> Result<Vec<bool>> {
        let mut bits = Vec::with_capacity(n);
        let mut cur = 0u8;
        let mut mask = 0u8;
        for _ in 0..n {
            if mask == 0 {
                cur = self.u8()?;
                mask = 0x80;
            }
            bits.push(cur & mask != 0);
            mask >>= 1;
        }
        Ok(bits)
    }
}

/// Writes a 7z variable-length number (`WriteNumber`). The `as u8` casts deliberately keep the low
/// byte at each step, which is exactly the little-endian serialization the format prescribes.
#[allow(clippy::cast_possible_truncation)]
fn write_number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0u32;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    let mut v = value;
    for _ in 0..i {
        out.push(v as u8);
        v >>= 8;
    }
}

/// Writes an MSB-first bit vector, emitting `ceil(bits.len()/8)` bytes.
fn write_bit_vector(out: &mut Vec<u8>, bits: &[bool]) {
    let mut cur = 0u8;
    let mut mask = 0x80u8;
    for &bit in bits {
        if bit {
            cur |= mask;
        }
        mask >>= 1;
        if mask == 0 {
            out.push(cur);
            cur = 0;
            mask = 0x80;
        }
    }
    if mask != 0x80 {
        out.push(cur);
    }
}

/// Converts a Unix timestamp to a Windows `FILETIME` (100-ns ticks since 1601-01-01).
fn timestamp_to_filetime(ts: Timestamp) -> u64 {
    let secs = ts.secs.saturating_add(FILETIME_EPOCH_DIFF);
    let ticks = secs
        .saturating_mul(10_000_000)
        .saturating_add(i64::from(ts.nanos / 100));
    u64::try_from(ticks).unwrap_or(0)
}

/// Converts a Windows `FILETIME` to a Unix [`Timestamp`].
fn filetime_to_timestamp(ft: u64) -> Timestamp {
    let ticks = i64::try_from(ft).unwrap_or(i64::MAX);
    let secs = ticks.div_euclid(10_000_000) - FILETIME_EPOCH_DIFF;
    let rem = ticks.rem_euclid(10_000_000);
    Timestamp {
        secs,
        nanos: u32::try_from(rem).unwrap_or(0).saturating_mul(100),
    }
}

/// Decodes null-stripped UTF-16LE code units into raw UTF-8 bytes (lossy for unpaired surrogates).
fn utf16le_to_bytes(raw: &[u8]) -> Vec<u8> {
    let units = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    let s: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    s.into_bytes()
}

/// Encodes `name` (interpreted as UTF-8) as null-terminated UTF-16LE code units.
fn bytes_to_utf16le(name: &[u8], out: &mut Vec<u8>) {
    for unit in String::from_utf8_lossy(name).encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

// ── Little-endian slice readers over the fixed signature header ──────────────────────────────────

/// Reads a little-endian `u32` at `off` within `data`.
fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(Error::Malformed("7z: truncated signature field"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a little-endian `u64` at `off` within `data`.
fn u64_le(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or(Error::Malformed("7z: truncated signature field"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// `u64` to `usize`, mapped to a limit error where it would truncate (32-bit hosts).
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("7z: value exceeds usize"))
}
