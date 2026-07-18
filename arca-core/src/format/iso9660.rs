//! ISO 9660 (ECMA-119) with the Joliet extension — reader and writer.
//!
//! Unlike the container formats that keep compressed payloads (zip/7z), an ISO image stores every
//! file **uncompressed and LBA-contiguous**: a file's bytes are exactly `image[lba*2048 ..][..size]`.
//! That makes the read path genuinely zero-copy — the reader lends a [`SliceData`] window straight
//! into the backing image, so `Data = SliceData<'a>` exactly like tar/cpio/ar. Because there is no
//! codec involved, the whole format lives in `arca-core` (`no_std`, `alloc` + `core` only) and stays
//! green on `thumbv7em-none-eabi`.
//!
//! ## Scope (explicit, tested)
//!
//! **Read**: 2048-byte sectors; the volume-descriptor set from sector 16 (`0x8000`); the Primary
//! Volume Descriptor (type 1, both-endian numeric fields, 34-byte root directory record) and — when
//! present — the Joliet Supplementary Volume Descriptor (type 2, escape `25 2F {40,43,45}`), whose
//! UCS-2BE names are **preferred**. Directory records are walked recursively (`.`/`..` skipped, the
//! `;1` version suffix stripped, both-endian LBA/size read), with recursion-depth and record-count
//! caps against malformed loops. No Rock Ridge: only files and directories, with default modes
//! (`0o755` for directories, `0o644` for files).
//!
//! **Write**: ISO mastering, buffered fully in memory. Entry paths accumulate into a tree; `finish`
//! assigns LBAs, lays out the path tables (both L- and M-endian) and directory extents for **both**
//! the ISO 9660 and Joliet trees, writes the PVD, the Joliet SVD and the terminator, sector-aligns
//! the (shared) file data, and performs a single [`Sink::write_all`]. Single volume, ≤ 4 GiB per
//! file, no El Torito boot record.

use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{
    ArchiveFormat, Detection, Entry, EntryDataSink, EntryReader, EntrySink, EntryWriter, SliceData,
};
use crate::io::Sink;
use crate::meta::{EntryKind, EntryMeta, PaxMap};

/// Logical sector size. ISO 9660 permits others, but 2048 is universal for CD/DVD images and the
/// only size this implementation reads or writes.
const SECTOR: usize = 2048;
/// The same sector size as a `u16`, for the volume descriptor's logical-block-size field.
const SECTOR_U16: u16 = 2048;
/// The first volume descriptor lives at sector 16 (`0x8000`); the 15 sectors before it are the
/// "system area", conventionally all zero.
const VD_START_SECTOR: usize = 16;
/// Byte offset of the standard identifier `CD001` within a volume descriptor (sector base + 1).
const STD_ID_OFFSET: usize = VD_START_SECTOR * SECTOR + 1;

/// Volume-descriptor type codes.
const VD_PRIMARY: u8 = 1;
const VD_SUPPLEMENTARY: u8 = 2;
const VD_TERMINATOR: u8 = 255;

/// The directory-record file-flag bit marking a subdirectory.
const FLAG_DIRECTORY: u8 = 0x02;

/// Fixed base size of a directory record (offsets `0..33`), before the identifier and its padding.
const DIR_REC_BASE: usize = 33;
/// Fixed base size of a path-table record (offsets `0..8`), before the identifier and its padding.
const PT_REC_BASE: usize = 8;

/// Safety caps applied while walking a (possibly malformed) directory tree.
const MAX_DEPTH: usize = 64;
const MAX_RECORDS: usize = 1 << 20;
/// Upper bound on volume descriptors scanned before giving up (a malformed image could omit the
/// terminator entirely).
const MAX_VDS: usize = 64;

/// Detection anchor for the ISO 9660 format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Iso9660;

impl ArchiveFormat for Iso9660 {
    const NAME: &'static str = "iso9660";

    fn sniff(prefix: &[u8]) -> Detection {
        // The standard identifier `CD001` sits at offset 1 of sector 16 (0x8001).
        match prefix.get(STD_ID_OFFSET..STD_ID_OFFSET + 5) {
            None => Detection::NeedMore,
            Some(b"CD001") => Detection::Match,
            Some(_) => Detection::NoMatch,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Reader
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A directory entry recovered from the walk: an owned path plus the extent needed to lend the body.
#[derive(Debug, Clone)]
struct IsoRec {
    path: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    /// File byte length (0 for directories).
    size: u32,
    /// Logical block address of the file extent (unused for directories).
    lba: u32,
}

/// ISO 9660 streaming reader over an in-memory image slice.
///
/// The image is parsed once (on the first [`next_entry`](EntryReader::next_entry)) into a flat list
/// of entries in pre-order (each directory before its contents); each file entry then lends a
/// [`SliceData`] window directly into the backing image — no copy, no decode.
#[derive(Debug)]
pub struct IsoReader<'a> {
    data: &'a [u8],
    entries: Vec<IsoRec>,
    index: usize,
    parsed: bool,
    payload: SliceData<'a>,
}

impl<'a> IsoReader<'a> {
    /// Builds a reader over the whole ISO image bytes.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            entries: Vec::new(),
            index: 0,
            parsed: false,
            payload: SliceData::default(),
        }
    }

    /// Scans the volume-descriptor set, chooses the Joliet tree when present, and walks it.
    fn parse(&mut self) -> Result<()> {
        let mut pvd_root: Option<(u32, u32)> = None;
        let mut joliet_root: Option<(u32, u32)> = None;

        for i in 0..MAX_VDS {
            let base = (VD_START_SECTOR + i)
                .checked_mul(SECTOR)
                .ok_or(Error::Malformed("iso: sector offset overflow"))?;
            let vd = self
                .data
                .get(base..base + SECTOR)
                .ok_or(Error::Malformed("iso: truncated volume descriptor"))?;
            if &vd[1..6] != b"CD001" {
                return Err(Error::Malformed("iso: bad standard identifier"));
            }
            match vd[0] {
                VD_PRIMARY => {
                    let bs = read_u16_le(vd, 128)
                        .ok_or(Error::Malformed("iso: truncated block size"))?;
                    if usize::from(bs) != SECTOR {
                        return Err(Error::Unsupported("iso: logical block size is not 2048"));
                    }
                    pvd_root = Some(root_from_vd(vd)?);
                }
                VD_SUPPLEMENTARY => {
                    if is_joliet_escape(&vd[88..120]) {
                        joliet_root = Some(root_from_vd(vd)?);
                    }
                }
                VD_TERMINATOR => break,
                _ => {}
            }
        }

        // Prefer the Joliet tree (faithful long/Unicode names); fall back to the primary tree.
        let (root_lba, root_size, joliet) = match (joliet_root, pvd_root) {
            (Some((l, s)), _) => (l, s, true),
            (None, Some((l, s))) => (l, s, false),
            _ => return Err(Error::Malformed("iso: no primary volume descriptor")),
        };
        self.walk(root_lba, root_size, joliet)
    }

    /// Iterative pre-order walk of the directory tree, appending entries. Depth and record counts
    /// are capped so a malformed image (self-referential or absurdly deep) errors instead of looping.
    fn walk(&mut self, root_lba: u32, root_size: u32, joliet: bool) -> Result<()> {
        // (extent lba, extent size, path prefix incl. trailing '/', depth). A stack yields a valid
        // pre-order: a directory's own entry is pushed before its extent is expanded.
        let mut stack: Vec<(u32, u32, Vec<u8>, usize)> = vec![(root_lba, root_size, Vec::new(), 0)];
        let mut records_seen = 0usize;

        while let Some((lba, size, prefix, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                return Err(Error::LimitExceeded("iso: directory nesting too deep"));
            }
            let base = (lba as usize)
                .checked_mul(SECTOR)
                .ok_or(Error::Malformed("iso: directory lba overflow"))?;
            let end = base
                .checked_add(size as usize)
                .ok_or(Error::Malformed("iso: directory extent overflow"))?;
            let extent = self
                .data
                .get(base..end)
                .ok_or(Error::Malformed("iso: truncated directory extent"))?;

            let mut pos = 0usize;
            while pos < extent.len() {
                records_seen += 1;
                if records_seen > MAX_RECORDS {
                    return Err(Error::LimitExceeded("iso: too many directory records"));
                }
                let rlen = extent[pos] as usize;
                if rlen == 0 {
                    // A zero length pads the rest of the sector; jump to the next sector boundary.
                    let next = (pos / SECTOR + 1) * SECTOR;
                    if next <= pos {
                        break;
                    }
                    pos = next;
                    continue;
                }
                if rlen < DIR_REC_BASE + 1 || pos + rlen > extent.len() {
                    return Err(Error::Malformed("iso: bad directory record length"));
                }
                let rec = &extent[pos..pos + rlen];
                let child_lba =
                    read_u32_le(rec, 2).ok_or(Error::Malformed("iso: bad record lba"))?;
                let child_size =
                    read_u32_le(rec, 10).ok_or(Error::Malformed("iso: bad record size"))?;
                let flags = rec[25];
                let ilen = rec[32] as usize;
                if DIR_REC_BASE + ilen > rlen {
                    return Err(Error::Malformed("iso: identifier exceeds record"));
                }
                let ident = &rec[DIR_REC_BASE..DIR_REC_BASE + ilen];
                pos += rlen;

                // Skip the `.` (0x00) and `..` (0x01) self/parent records.
                if ilen == 1 && (ident[0] == 0 || ident[0] == 1) {
                    continue;
                }
                let is_dir = flags & FLAG_DIRECTORY != 0;
                let name = decode_name(ident, joliet, is_dir);

                let mut path = prefix.clone();
                path.extend_from_slice(&name);
                if is_dir {
                    let mut dir_path = path.clone();
                    dir_path.push(b'/');
                    self.entries.push(IsoRec {
                        path: dir_path,
                        kind: EntryKind::Dir,
                        mode: 0o755,
                        size: 0,
                        lba: 0,
                    });
                    let mut child_prefix = path;
                    child_prefix.push(b'/');
                    stack.push((child_lba, child_size, child_prefix, depth + 1));
                } else {
                    self.entries.push(IsoRec {
                        path,
                        kind: EntryKind::File,
                        mode: 0o644,
                        size: child_size,
                        lba: child_lba,
                    });
                }
            }
        }
        Ok(())
    }
}

impl<'a> EntryReader for IsoReader<'a> {
    type Data = SliceData<'a>;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, SliceData<'a>>>> {
        if !self.parsed {
            self.parse()?;
            self.parsed = true;
        }
        if self.index >= self.entries.len() {
            return Ok(None);
        }
        let rec = self.entries[self.index].clone();
        self.index += 1;

        let (start, len) = if rec.kind == EntryKind::File {
            let start = (rec.lba as usize)
                .checked_mul(SECTOR)
                .ok_or(Error::Malformed("iso: file lba overflow"))?;
            let len = rec.size as usize;
            let end = start
                .checked_add(len)
                .ok_or(Error::Malformed("iso: file extent overflow"))?;
            if end > self.data.len() {
                return Err(Error::Malformed("iso: file extent out of range"));
            }
            (start, len)
        } else {
            (0, 0)
        };
        self.payload = SliceData::new(self.data, start, len);

        let meta = EntryMeta {
            kind: rec.kind,
            path: Cow::Owned(rec.path),
            mode: rec.mode,
            uid: 0,
            gid: 0,
            mtime: None,
            size: u64::from(rec.size),
            link_target: None,
            pax: PaxMap::new(),
        };
        Ok(Some(Entry::new(meta, &mut self.payload)))
    }
}

/// Reads the (lba, size) of the root directory from the 34-byte root record at offset 156 of a
/// volume descriptor.
fn root_from_vd(vd: &[u8]) -> Result<(u32, u32)> {
    let lba = read_u32_le(vd, 156 + 2).ok_or(Error::Malformed("iso: bad root lba"))?;
    let size = read_u32_le(vd, 156 + 10).ok_or(Error::Malformed("iso: bad root size"))?;
    Ok((lba, size))
}

/// Whether a supplementary descriptor's 32-byte escape-sequence field selects Joliet (UCS-2 levels
/// 1/2/3, escapes `25 2F 40`, `25 2F 43`, `25 2F 45`).
fn is_joliet_escape(esc: &[u8]) -> bool {
    esc.windows(3)
        .any(|w| w[0] == 0x25 && w[1] == 0x2F && matches!(w[2], 0x40 | 0x43 | 0x45))
}

/// Decodes a directory-record identifier into a display name: UCS-2BE for Joliet, raw bytes
/// otherwise, with the `;1` version suffix stripped (and, for the primary tree, a trailing dot).
fn decode_name(ident: &[u8], joliet: bool, is_dir: bool) -> Vec<u8> {
    if joliet {
        strip_version(utf16be_to_bytes(ident))
    } else {
        let mut v = strip_version(ident.to_vec());
        if !is_dir && v.last() == Some(&b'.') {
            v.pop();
        }
        v
    }
}

/// Truncates a name at its `;` version separator, if any.
fn strip_version(mut v: Vec<u8>) -> Vec<u8> {
    if let Some(p) = v.iter().position(|&b| b == b';') {
        v.truncate(p);
    }
    v
}

/// Decodes UCS-2BE (Joliet) code units into UTF-8 bytes (lossy for unpaired surrogates).
fn utf16be_to_bytes(raw: &[u8]) -> Vec<u8> {
    let units = raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]));
    let s: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    s.into_bytes()
}

/// Reads a little-endian `u32` at `off`, or `None` if out of range.
fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Reads a little-endian `u16` at `off`, or `None` if out of range.
fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Writer
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A node in the in-memory mastering tree (a directory or a file).
#[derive(Debug)]
struct Node {
    /// The single path component (raw bytes), empty for the root.
    name: Vec<u8>,
    is_dir: bool,
    /// File content (empty for directories).
    content: Vec<u8>,
    /// Child node indices into the writer's arena.
    children: Vec<usize>,
    /// Arena index of the parent (the root is its own parent).
    parent_idx: usize,
    // ── Layout, assigned in `assemble` ──
    /// 1-based path-table number (directories only; root = 1).
    dir_number: u16,
    /// Path-table number of the parent (root = 1).
    parent_number: u16,
    iso_lba: u32,
    iso_size: u32,
    joliet_lba: u32,
    joliet_size: u32,
    file_lba: u32,
    file_size: u32,
}

impl Node {
    fn new(name: Vec<u8>, is_dir: bool, content: Vec<u8>, parent_idx: usize) -> Self {
        Self {
            name,
            is_dir,
            content,
            children: Vec::new(),
            parent_idx,
            dir_number: 0,
            parent_number: 0,
            iso_lba: 0,
            iso_size: 0,
            joliet_lba: 0,
            joliet_size: 0,
            file_lba: 0,
            file_size: 0,
        }
    }
}

/// The metadata captured when an entry is opened (payload buffered until `close`).
#[derive(Debug)]
struct PendingEntry {
    path: Vec<u8>,
    kind: EntryKind,
    content: Vec<u8>,
}

/// ISO 9660 + Joliet streaming writer — the dual of [`IsoReader`].
///
/// **The whole image is mastered in memory.** Entries accumulate into a tree as they are written;
/// `finish` performs the full layout (LBA assignment, path tables, directory extents for both trees,
/// sector-aligned file data) and emits the image with a single [`Sink::write_all`]. This mirrors the
/// other buffered writers (zip/7z): an append-only [`Sink`] cannot seek, and ISO fields (volume-space
/// size, root extents, path-table locations) are only known once the whole tree has been laid out.
#[derive(Debug)]
pub struct IsoWriter<W: Sink> {
    sink: W,
    /// Arena of tree nodes; index 0 is always the root directory.
    nodes: Vec<Node>,
    pending: Option<PendingEntry>,
}

impl<W: Sink> IsoWriter<W> {
    /// Builds a writer over a byte sink, seeded with an empty root directory.
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            nodes: vec![Node::new(Vec::new(), true, Vec::new(), 0)],
            pending: None,
        }
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Finalizes the currently open entry, inserting it into the tree.
    fn close_entry(&mut self) -> Result<()> {
        let Some(p) = self.pending.take() else {
            return Err(Error::InvalidState("iso: no open entry"));
        };
        let is_dir = matches!(p.kind, EntryKind::Dir);
        self.insert(&p.path, is_dir, p.content);
        Ok(())
    }

    /// Inserts a path into the tree, creating intermediate directories as needed. Only files and
    /// directories are represented; other kinds are dropped by the caller before reaching here.
    fn insert(&mut self, path: &[u8], is_dir: bool, content: Vec<u8>) {
        let comps: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        let Some((leaf, dirs)) = comps.split_last() else {
            return; // The path is the root itself (or empty); nothing to add.
        };

        let mut cur = 0usize;
        for comp in dirs {
            cur = self.child_dir(cur, comp);
        }

        if let Some(ci) = self.find_child(cur, leaf) {
            if is_dir {
                self.nodes[ci].is_dir = true;
            } else {
                self.nodes[ci].is_dir = false;
                self.nodes[ci].content = content;
            }
        } else {
            let node = Node::new(
                leaf.to_vec(),
                is_dir,
                if is_dir { Vec::new() } else { content },
                cur,
            );
            let idx = self.nodes.len();
            self.nodes.push(node);
            self.nodes[cur].children.push(idx);
        }
    }

    /// Finds an existing child of `parent` with the given name.
    fn find_child(&self, parent: usize, name: &[u8]) -> Option<usize> {
        self.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|&c| self.nodes[c].name == name)
    }

    /// Returns the index of a child directory named `name` under `parent`, creating it if absent.
    fn child_dir(&mut self, parent: usize, name: &[u8]) -> usize {
        if let Some(ci) = self.find_child(parent, name) {
            self.nodes[ci].is_dir = true;
            return ci;
        }
        let node = Node::new(name.to_vec(), true, Vec::new(), parent);
        let idx = self.nodes.len();
        self.nodes.push(node);
        self.nodes[parent].children.push(idx);
        idx
    }

    /// The (lba, size) of a directory's extent in the requested tree.
    fn extent_of(&self, di: usize, joliet: bool) -> (u32, u32) {
        let n = &self.nodes[di];
        if joliet {
            (n.joliet_lba, n.joliet_size)
        } else {
            (n.iso_lba, n.iso_size)
        }
    }

    /// The on-disk identifier for a child node in the requested tree (Joliet UCS-2BE names, or the
    /// mangled primary-tree name with a `;1` version suffix on files).
    fn child_ident(&self, ci: usize, joliet: bool) -> Vec<u8> {
        let n = &self.nodes[ci];
        if joliet {
            joliet_name(&n.name)
        } else if n.is_dir {
            mangle(&n.name)
        } else {
            let mut v = mangle(&n.name);
            v.extend_from_slice(b";1");
            v
        }
    }

    /// The path-table identifier for a directory (`0x00` for the root).
    fn dir_ident(&self, di: usize, joliet: bool) -> Vec<u8> {
        if di == 0 {
            return vec![0u8];
        }
        if joliet {
            joliet_name(&self.nodes[di].name)
        } else {
            mangle(&self.nodes[di].name)
        }
    }

    /// Builds the ordered directory records of one directory in one tree (`.`, `..`, then children
    /// sorted by name). Called twice: once during sizing (LBAs still zero — only lengths matter) and
    /// once during emission (LBAs resolved).
    fn build_dir_records(&self, di: usize, joliet: bool) -> Vec<Vec<u8>> {
        let mut recs = Vec::new();
        let (self_lba, self_size) = self.extent_of(di, joliet);
        recs.push(dir_record(&[0u8], self_lba, self_size, true));
        let (p_lba, p_size) = self.extent_of(self.nodes[di].parent_idx, joliet);
        recs.push(dir_record(&[1u8], p_lba, p_size, true));

        for ci in self.sorted_children(di) {
            let ident = self.child_ident(ci, joliet);
            if self.nodes[ci].is_dir {
                let (lba, size) = self.extent_of(ci, joliet);
                recs.push(dir_record(&ident, lba, size, true));
            } else {
                recs.push(dir_record(
                    &ident,
                    self.nodes[ci].file_lba,
                    self.nodes[ci].file_size,
                    false,
                ));
            }
        }
        recs
    }

    /// A directory's children, sorted by raw name (a stable, deterministic layout order).
    fn sorted_children(&self, di: usize) -> Vec<usize> {
        let mut kids = self.nodes[di].children.clone();
        kids.sort_by(|&a, &b| self.nodes[a].name.cmp(&self.nodes[b].name));
        kids
    }

    /// Builds a path table for one tree in the requested endianness. Records are ordered by the BFS
    /// `order` (root first, then by ascending parent number, then by name), as ISO 9660 requires.
    fn build_path_table(&self, order: &[usize], joliet: bool, big_endian: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for &di in order {
            let ident = self.dir_ident(di, joliet);
            let (lba, _) = self.extent_of(di, joliet);
            let parent = self.nodes[di].parent_number;
            out.push(u8::try_from(ident.len()).unwrap_or(u8::MAX));
            out.push(0); // extended attribute record length
            if big_endian {
                out.extend_from_slice(&lba.to_be_bytes());
                out.extend_from_slice(&parent.to_be_bytes());
            } else {
                out.extend_from_slice(&lba.to_le_bytes());
                out.extend_from_slice(&parent.to_le_bytes());
            }
            out.extend_from_slice(&ident);
            if ident.len() % 2 == 1 {
                out.push(0);
            }
        }
        out
    }

    /// Lays out the whole image and writes it with a single `write_all`.
    // The L/M path-table location pairs are inherently similar names (little/big endian of the same
    // table), so the similar-names lint is silenced for this layout routine.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn assemble(&mut self) -> Result<()> {
        // 1. Order directories breadth-first, assigning path-table numbers and parent numbers.
        let order = self.order_directories()?;

        // 2. Validate identifier lengths (the record length field is a single byte).
        self.validate_identifiers(&order)?;

        // 3. File sizes (≤ 4 GiB each), assigned to the file nodes.
        let files = self.collect_files()?;

        // 4. Directory extent sizes for both trees (independent of LBA values).
        for &di in &order {
            let iso = layout_len(&self.build_dir_records(di, false));
            let jol = layout_len(&self.build_dir_records(di, true));
            self.nodes[di].iso_size = u32::try_from(iso)
                .map_err(|_| Error::LimitExceeded("iso: directory extent too large"))?;
            self.nodes[di].joliet_size = u32::try_from(jol)
                .map_err(|_| Error::LimitExceeded("iso: directory extent too large"))?;
        }

        // 5. Path-table byte sizes (both trees; identical for L and M).
        let iso_pt_size = self.path_table_size(&order, false);
        let joliet_pt_size = self.path_table_size(&order, true);

        // 6. Assign LBAs in a fixed, sector-aligned order (after PVD(16), SVD(17), terminator(18)).
        let mut lba: u32 = u32::try_from(VD_START_SECTOR + 3)
            .map_err(|_| Error::LimitExceeded("iso: image too large"))?;
        let iso_l_pt = lba;
        lba = advance(lba, iso_pt_size)?;
        let iso_m_pt = lba;
        lba = advance(lba, iso_pt_size)?;
        let joliet_l_pt = lba;
        lba = advance(lba, joliet_pt_size)?;
        let joliet_m_pt = lba;
        lba = advance(lba, joliet_pt_size)?;

        for &di in &order {
            self.nodes[di].iso_lba = lba;
            lba = advance(lba, self.nodes[di].iso_size as usize)?;
        }
        for &di in &order {
            self.nodes[di].joliet_lba = lba;
            lba = advance(lba, self.nodes[di].joliet_size as usize)?;
        }
        for &fi in &files {
            self.nodes[fi].file_lba = lba;
            lba = advance(lba, self.nodes[fi].file_size as usize)?;
        }
        let total_sectors = lba;

        // 7. Emit.
        let total_bytes = (total_sectors as usize)
            .checked_mul(SECTOR)
            .ok_or(Error::LimitExceeded("iso: image too large"))?;
        let mut out = vec![0u8; total_bytes];

        let (root_iso_lba, root_iso_size) = self.extent_of(0, false);
        let (root_jol_lba, root_jol_size) = self.extent_of(0, true);
        write_vd(
            &mut out,
            VD_START_SECTOR,
            VD_PRIMARY,
            false,
            root_iso_lba,
            root_iso_size,
            iso_pt_size,
            iso_l_pt,
            iso_m_pt,
            total_sectors,
        );
        write_vd(
            &mut out,
            VD_START_SECTOR + 1,
            VD_SUPPLEMENTARY,
            true,
            root_jol_lba,
            root_jol_size,
            joliet_pt_size,
            joliet_l_pt,
            joliet_m_pt,
            total_sectors,
        );
        write_terminator(&mut out, VD_START_SECTOR + 2);

        write_at(
            &mut out,
            iso_l_pt,
            &self.build_path_table(&order, false, false),
        );
        write_at(
            &mut out,
            iso_m_pt,
            &self.build_path_table(&order, false, true),
        );
        write_at(
            &mut out,
            joliet_l_pt,
            &self.build_path_table(&order, true, false),
        );
        write_at(
            &mut out,
            joliet_m_pt,
            &self.build_path_table(&order, true, true),
        );

        for &di in &order {
            let iso_recs = self.build_dir_records(di, false);
            write_extent(&mut out, self.nodes[di].iso_lba, &iso_recs);
            let jol_recs = self.build_dir_records(di, true);
            write_extent(&mut out, self.nodes[di].joliet_lba, &jol_recs);
        }
        for &fi in &files {
            let base = self.nodes[fi].file_lba as usize * SECTOR;
            let content = &self.nodes[fi].content;
            out[base..base + content.len()].copy_from_slice(content);
        }

        self.sink.write_all(&out)
    }

    /// Breadth-first directory ordering. Root is number 1; siblings are numbered in name order, so
    /// the sequence is (level, parent number, name) — exactly the ISO 9660 path-table order.
    fn order_directories(&mut self) -> Result<Vec<usize>> {
        self.nodes[0].dir_number = 1;
        self.nodes[0].parent_number = 1;
        let mut order = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(0usize);
        let mut next_number: u16 = 2;

        while let Some(di) = queue.pop_front() {
            order.push(di);
            let mut child_dirs: Vec<usize> = self.nodes[di]
                .children
                .iter()
                .copied()
                .filter(|&c| self.nodes[c].is_dir)
                .collect();
            child_dirs.sort_by(|&a, &b| self.nodes[a].name.cmp(&self.nodes[b].name));
            let parent_number = self.nodes[di].dir_number;
            for c in child_dirs {
                self.nodes[c].dir_number = next_number;
                self.nodes[c].parent_number = parent_number;
                next_number = next_number
                    .checked_add(1)
                    .ok_or(Error::LimitExceeded("iso: too many directories"))?;
                queue.push_back(c);
            }
        }
        Ok(order)
    }

    /// Collects file node indices (creation order) and records each file's size, rejecting any file
    /// larger than 4 GiB (the single-volume 32-bit extent limit).
    fn collect_files(&mut self) -> Result<Vec<usize>> {
        let mut files = Vec::new();
        for idx in 0..self.nodes.len() {
            if !self.nodes[idx].is_dir {
                let len = self.nodes[idx].content.len();
                self.nodes[idx].file_size = u32::try_from(len)
                    .map_err(|_| Error::Unsupported("iso: file exceeds 4 GiB"))?;
                files.push(idx);
            }
        }
        Ok(files)
    }

    /// Rejects identifiers that would overflow the single-byte length field of a record, and rejects
    /// any Joliet identifier still carrying a forbidden character (defense-in-depth: `joliet_name`
    /// sanitizes these away, so this only fires if that sanitization ever regresses).
    fn validate_identifiers(&self, order: &[usize]) -> Result<()> {
        for &di in order {
            for joliet in [false, true] {
                let ident = self.dir_ident(di, joliet);
                if ident.len() > 255 {
                    return Err(Error::Unsupported("iso: directory name too long"));
                }
                if joliet && joliet_ident_has_forbidden(&ident) {
                    return Err(Error::Unsupported(
                        "iso: forbidden character in Joliet name",
                    ));
                }
                for ci in &self.nodes[di].children {
                    let child = self.child_ident(*ci, joliet);
                    if child.len() > 255 {
                        return Err(Error::Unsupported("iso: entry name too long"));
                    }
                    if joliet && joliet_ident_has_forbidden(&child) {
                        return Err(Error::Unsupported(
                            "iso: forbidden character in Joliet name",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Total byte length of a path table for one tree (sum of unpadded record lengths).
    fn path_table_size(&self, order: &[usize], joliet: bool) -> usize {
        order
            .iter()
            .map(|&di| pt_rec_len(self.dir_ident(di, joliet).len()))
            .sum()
    }
}

impl<W: Sink> EntryWriter for IsoWriter<W> {
    type Sink = Self;

    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self>> {
        if self.pending.is_some() {
            return Err(Error::InvalidState("iso: previous entry not closed"));
        }
        // ISO stores only files and directories; anything else (symlink/device/…) has no
        // representation without Rock Ridge, so it is rejected rather than silently mangled.
        if !matches!(meta.kind, EntryKind::File | EntryKind::Dir) {
            return Err(Error::Unsupported(
                "iso: only files and directories are supported",
            ));
        }
        self.pending = Some(PendingEntry {
            path: meta.path.to_vec(),
            kind: meta.kind,
            content: Vec::new(),
        });
        Ok(EntrySink::new(self))
    }

    fn finish(&mut self) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::InvalidState("iso: entry open at finish"));
        }
        self.assemble()
    }
}

impl<W: Sink> EntryDataSink for IsoWriter<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if let Some(p) = &mut self.pending {
            p.content.extend_from_slice(data);
            Ok(())
        } else {
            Err(Error::InvalidState("iso: write without an open entry"))
        }
    }

    fn close(&mut self) -> Result<()> {
        self.close_entry()
    }
}

// ── Writer helpers (free functions) ──────────────────────────────────────────────────────────────

/// Number of sectors needed to hold `bytes`.
fn sectors(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(SECTOR)).unwrap_or(u32::MAX)
}

/// Advances an LBA cursor past a region of `bytes`, sector-aligned, checking for overflow.
fn advance(lba: u32, bytes: usize) -> Result<u32> {
    lba.checked_add(sectors(bytes))
        .ok_or(Error::LimitExceeded("iso: image too large"))
}

/// The padded length of a directory record whose identifier is `ident_len` bytes (base 33, then the
/// identifier, rounded up to an even total).
fn dir_rec_len(ident_len: usize) -> usize {
    let base = DIR_REC_BASE + ident_len;
    base + (base & 1)
}

/// The padded length of a path-table record whose identifier is `ident_len` bytes.
fn pt_rec_len(ident_len: usize) -> usize {
    let base = PT_REC_BASE + ident_len;
    base + (base & 1)
}

/// Serializes one directory record. Numeric fields are stored both-endian per ECMA-119.
fn dir_record(ident: &[u8], lba: u32, size: u32, is_dir: bool) -> Vec<u8> {
    let ilen = ident.len();
    let rlen = dir_rec_len(ilen);
    let mut r = vec![0u8; rlen];
    r[0] = u8::try_from(rlen).unwrap_or(u8::MAX);
    r[1] = 0; // extended attribute record length
    r[2..10].copy_from_slice(&both_endian_u32(lba));
    r[10..18].copy_from_slice(&both_endian_u32(size));
    r[18..25].copy_from_slice(&RECORDING_TIME);
    r[25] = if is_dir { FLAG_DIRECTORY } else { 0 };
    r[26] = 0; // file unit size
    r[27] = 0; // interleave gap size
    r[28..32].copy_from_slice(&both_endian_u16(1)); // volume sequence number
    r[32] = u8::try_from(ilen).unwrap_or(u8::MAX);
    r[DIR_REC_BASE..DIR_REC_BASE + ilen].copy_from_slice(ident);
    r
}

/// A fixed, valid 7-byte recording timestamp (2020-01-01T00:00:00, GMT offset 0). ISO records carry
/// a time; a constant keeps the writer deterministic without threading `mtime` (not round-tripped).
const RECORDING_TIME: [u8; 7] = [120, 1, 1, 0, 0, 0, 0];

/// Lays a directory record list out into a byte length (sector-aligned), applying the rule that a
/// record may not span a sector boundary.
fn layout_len(recs: &[Vec<u8>]) -> usize {
    let mut pos = 0usize;
    for r in recs {
        let off = pos % SECTOR;
        if off + r.len() > SECTOR {
            pos += SECTOR - off;
        }
        pos += r.len();
    }
    pos.div_ceil(SECTOR).max(1) * SECTOR
}

/// Writes a directory record list into `out` at directory LBA `lba`, applying the same
/// no-record-spans-a-sector rule as [`layout_len`]. The surrounding padding stays zero.
fn write_extent(out: &mut [u8], lba: u32, recs: &[Vec<u8>]) {
    let base = lba as usize * SECTOR;
    let mut pos = 0usize;
    for r in recs {
        let off = pos % SECTOR;
        if off + r.len() > SECTOR {
            pos += SECTOR - off;
        }
        out[base + pos..base + pos + r.len()].copy_from_slice(r);
        pos += r.len();
    }
}

/// Writes `bytes` into `out` starting at sector `lba` (the remainder of the sector stays zero).
fn write_at(out: &mut [u8], lba: u32, bytes: &[u8]) {
    let base = lba as usize * SECTOR;
    out[base..base + bytes.len()].copy_from_slice(bytes);
}

/// Writes a volume descriptor (primary or supplementary/Joliet) into sector `sector_index`.
#[allow(clippy::too_many_arguments)]
fn write_vd(
    out: &mut [u8],
    sector_index: usize,
    vtype: u8,
    joliet: bool,
    root_lba: u32,
    root_size: u32,
    pt_size: usize,
    l_pt: u32,
    m_pt: u32,
    total_sectors: u32,
) {
    let base = sector_index * SECTOR;
    let vd = &mut out[base..base + SECTOR];
    vd[0] = vtype;
    vd[1..6].copy_from_slice(b"CD001");
    vd[6] = 1; // volume descriptor version

    // Text fields are a-/d-characters; space padding is what real images use in the primary tree.
    if joliet {
        vd[88] = 0x25;
        vd[89] = 0x2F;
        vd[90] = 0x45; // Joliet UCS-2 level 3 escape
    } else {
        for b in &mut vd[8..40] {
            *b = b' ';
        }
        for b in &mut vd[40..72] {
            *b = b' ';
        }
    }

    let pt = u32::try_from(pt_size).unwrap_or(u32::MAX);
    vd[80..88].copy_from_slice(&both_endian_u32(total_sectors)); // volume space size
    vd[120..124].copy_from_slice(&both_endian_u16(1)); // volume set size
    vd[124..128].copy_from_slice(&both_endian_u16(1)); // volume sequence number
    vd[128..132].copy_from_slice(&both_endian_u16(SECTOR_U16)); // logical block size
    vd[132..140].copy_from_slice(&both_endian_u32(pt)); // path table size
    vd[140..144].copy_from_slice(&l_pt.to_le_bytes()); // type-L path table location
    vd[148..152].copy_from_slice(&m_pt.to_be_bytes()); // type-M path table location
    let root = dir_record(&[0u8], root_lba, root_size, true);
    vd[156..190].copy_from_slice(&root);
    if !joliet {
        for b in &mut vd[190..813] {
            *b = b' ';
        }
    }
    vd[881] = 1; // file structure version
}

/// Writes the volume-descriptor set terminator (type 255) into sector `sector_index`.
fn write_terminator(out: &mut [u8], sector_index: usize) {
    let base = sector_index * SECTOR;
    let vd = &mut out[base..base + SECTOR];
    vd[0] = VD_TERMINATOR;
    vd[1..6].copy_from_slice(b"CD001");
    vd[6] = 1;
}

/// Encodes `v` as an ISO both-endian `u32` (little-endian then big-endian, 8 bytes).
fn both_endian_u32(v: u32) -> [u8; 8] {
    let l = v.to_le_bytes();
    let b = v.to_be_bytes();
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}

/// Encodes `v` as an ISO both-endian `u16` (little-endian then big-endian, 4 bytes).
fn both_endian_u16(v: u16) -> [u8; 4] {
    let l = v.to_le_bytes();
    let b = v.to_be_bytes();
    [l[0], l[1], b[0], b[1]]
}

/// Mangles a name into safe primary-tree d-characters: uppercase ASCII, keeping `A-Z 0-9 _ .`, with
/// everything else replaced by `_`. Faithful long names live in the Joliet tree; the primary tree
/// only needs a valid, deterministic fallback name.
fn mangle(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    for &b in name {
        let c = if b.is_ascii_lowercase() {
            b - 32
        } else if b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'.' {
            b
        } else {
            b'_'
        };
        out.push(c);
    }
    if out.is_empty() {
        out.push(b'_');
    }
    out
}

/// True for the characters Joliet forbids in a file/directory identifier: `* / : ; ? \` and the
/// C0 control range (`0x00..=0x1F`). All are single-byte ASCII, so they can never form part of a
/// multibyte UTF-8 sequence and are safe to test byte-by-byte.
fn is_joliet_forbidden(b: u8) -> bool {
    matches!(b, b'*' | b'/' | b':' | b';' | b'?' | b'\\') || b < 0x20
}

/// True if an encoded UCS-2BE Joliet identifier contains a forbidden code unit. Forbidden characters
/// are all single-byte ASCII, so they encode as a `0x00` high byte followed by the forbidden low byte.
fn joliet_ident_has_forbidden(ident: &[u8]) -> bool {
    ident
        .chunks_exact(2)
        .any(|u| u[0] == 0x00 && is_joliet_forbidden(u[1]))
}

/// Encodes a name (UTF-8, lossy) as a UCS-2BE Joliet identifier, replacing every Joliet-forbidden
/// character with `_`. Without this, a component such as `C:` (drive-letter paths on Windows) or any
/// name containing `* / : ; ? \` would embed an illegal code unit in the Joliet SVD tree, which a
/// conformant reader rejects for the whole volume — mirroring what `mangle` does for the primary tree.
fn joliet_name(name: &[u8]) -> Vec<u8> {
    let mut sanitized = Vec::with_capacity(name.len());
    for &b in name {
        sanitized.push(if is_joliet_forbidden(b) { b'_' } else { b });
    }
    let mut out = Vec::new();
    push_utf16be(&sanitized, &mut out);
    out
}

/// Appends the UCS-2BE encoding of `name` (decoded from UTF-8, with U+FFFD for invalid sequences).
fn push_utf16be(name: &[u8], out: &mut Vec<u8>) {
    let mut input = name;
    loop {
        match core::str::from_utf8(input) {
            Ok(s) => {
                encode_utf16be(s, out);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if let Ok(s) = core::str::from_utf8(&input[..valid]) {
                    encode_utf16be(s, out);
                }
                out.extend_from_slice(&0xFFFDu16.to_be_bytes());
                match e.error_len() {
                    Some(len) => input = &input[valid + len..],
                    None => break, // Unexpected end of input; stop.
                }
            }
        }
    }
}

/// Appends the UCS-2BE encoding of a valid UTF-8 string to `out`.
fn encode_utf16be(s: &str, out: &mut Vec<u8>) {
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn both_endian_layout() {
        assert_eq!(both_endian_u32(0x0102_0304), [4, 3, 2, 1, 1, 2, 3, 4]);
        assert_eq!(both_endian_u16(0x0102), [2, 1, 1, 2]);
    }

    #[test]
    fn record_lengths_are_even() {
        // 1-byte identifier ("." / "..") → base 34 (already even).
        assert_eq!(dir_rec_len(1), 34);
        // 2-byte identifier → base 35 → padded to 36.
        assert_eq!(dir_rec_len(2), 36);
        assert_eq!(pt_rec_len(1), 10); // 8 + 1 → 9 → 10
        assert_eq!(pt_rec_len(2), 10); // 8 + 2 → 10
    }

    #[test]
    fn mangle_uppercases_and_sanitizes() {
        assert_eq!(mangle(b"Hello.txt"), b"HELLO.TXT");
        assert_eq!(mangle(b"a b/c"), b"A_B_C");
        assert_eq!(mangle(b""), b"_");
    }

    #[test]
    fn joliet_roundtrips_unicode() {
        let name = "héllo".as_bytes();
        let encoded = joliet_name(name);
        assert_eq!(utf16be_to_bytes(&encoded), name);
    }

    #[test]
    fn joliet_name_sanitizes_forbidden_chars() {
        // Drive-letter path component and each Joliet-forbidden character map to '_'.
        let encoded = joliet_name(b"C:*/;?\\\x01");
        assert_eq!(utf16be_to_bytes(&encoded), b"C_______");
        assert!(!joliet_ident_has_forbidden(&encoded));
        // A legal name is left untouched.
        let legal = joliet_name(b"Hello.txt");
        assert_eq!(utf16be_to_bytes(&legal), b"Hello.txt");
        assert!(!joliet_ident_has_forbidden(&legal));
    }

    #[test]
    fn joliet_escape_detected() {
        let mut esc = [0u8; 32];
        esc[0..3].copy_from_slice(&[0x25, 0x2F, 0x45]);
        assert!(is_joliet_escape(&esc));
        assert!(!is_joliet_escape(&[0u8; 32]));
    }
}
