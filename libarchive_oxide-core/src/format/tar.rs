// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! tar format (ustar / pax / GNU).
//!
//! Supports ustar, pax extensions, GNU long names and sparse maps, octal and
//! base-256 numbers, and checksum verification.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem;

use crate::error::{Error, Result};
use crate::meta::{EntryKind, Timestamp, default_mode};
use crate::metadata::{
    ArchiveMetadata, ArchivePath, Device, EntryMetadata, EntryMetadataBuilder, EntryTimes,
    Extension, Owner, SparseExtent,
};
use crate::protocol::{
    ArchiveDecoder, ArchiveEncoder, Chunk, DecodeEvent, DecodeStep, EncodeCommand, EncodeStatus,
    EncodeStep, EndOfInput, ProbeResult,
};
use crate::{ArchiveError, ErrorKind, Limits};

/// tar block size. Every header and every payload is aligned to a multiple of this.
const BLOCK: usize = 512;

// ── ustar header field ranges (offsets within the 512B block).
const F_NAME: (usize, usize) = (0, 100);
const F_MODE: (usize, usize) = (100, 108);
const F_UID: (usize, usize) = (108, 116);
const F_GID: (usize, usize) = (116, 124);
const F_SIZE: (usize, usize) = (124, 136);
const F_MTIME: (usize, usize) = (136, 148);
const F_CHKSUM: (usize, usize) = (148, 156);
const O_TYPEFLAG: usize = 156;
const F_LINKNAME: (usize, usize) = (157, 257);
const F_MAGIC: (usize, usize) = (257, 263);
const F_UNAME: (usize, usize) = (265, 297);
const F_GNAME: (usize, usize) = (297, 329);
const F_DEVMAJOR: (usize, usize) = (329, 337);
const F_DEVMINOR: (usize, usize) = (337, 345);
const F_PREFIX: (usize, usize) = (345, 500);
const GNU_SPARSE_START: usize = 386;
const GNU_SPARSE_COUNT: usize = 4;
const GNU_SPARSE_EXTENDED: usize = 482;
const GNU_SPARSE_REALSIZE: (usize, usize) = (483, 495);
const GNU_SPARSE_EXT_COUNT: usize = 21;

/// Overrides that a preceding header (PAX / GNU longname) imposes on the next entry or on all entries.
type RawPaxRecord<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

#[derive(Debug, Default, Clone)]
struct Overrides<'a> {
    path: Option<Cow<'a, [u8]>>,
    linkpath: Option<Cow<'a, [u8]>>,
    size: Option<u64>,
    mtime: Option<Timestamp>,
    atime: Option<Timestamp>,
    ctime: Option<Timestamp>,
    birthtime: Option<Timestamp>,
    uid: Option<u64>,
    gid: Option<u64>,
    uname: Option<Cow<'a, [u8]>>,
    gname: Option<Cow<'a, [u8]>>,
    sparse_realsize: Option<u64>,
    pax: Vec<RawPaxRecord<'a>>,
}

/// Owned overrides for the incremental tar parser.
type OwnedOverrides = Overrides<'static>;

// ── Incremental sans-IO source (Phase 4) ────────────────────────────────────────────────────────

/// Which kind of extended / long header the tar parser is currently accumulating.
#[derive(Debug, Clone, Copy)]
enum MetaKind {
    /// PAX `x`/`X`: extended records applying to the next entry.
    PaxNext,
    /// PAX `g`: global extended records applying to all subsequent entries.
    PaxGlobal,
    /// GNU `L`: the next entry's long name.
    LongName,
    /// GNU `K`: the next entry's long link target.
    LongLink,
}

/// The tar parser driver state. `Copy` so `pull` can read it out of `self`, mutate the other
/// fields, and write the successor back without borrow entanglement.
#[derive(Debug, Clone, Copy)]
enum State {
    /// Awaiting a full 512-byte header block.
    Header,
    /// Streaming a real entry's payload: `remaining` data bytes, then `pad` zero bytes.
    Payload { remaining: u64, pad: usize },
    /// Accumulating an extended / long header record: `data` record bytes, then `pad` zero bytes.
    Meta {
        kind: MetaKind,
        data: usize,
        pad: usize,
    },
    /// Reading one or more old-GNU sparse extension blocks.
    SparseExtensions { remaining: u64, pad: usize },
    /// The archive has ended.
    Done,
}

/// Internal state-machine result.
enum Poll {
    /// The state advanced; loop and drive again.
    Continue,
    /// Starved: waiting for more fed bytes.
    NeedInput,
    /// Archive terminated.
    Done,
    /// The current entry's payload is complete.
    EndEntry,
    /// A real entry header was parsed; its metadata is staged.
    Entry,
    /// A payload window is staged.
    Data,
}

enum TarSourceEvent<'a> {
    NeedInput,
    ArchiveMetadata(ArchiveMetadata),
    Entry {
        metadata: Box<EntryMetadata>,
        sparse: Vec<SparseExtent>,
        is_sparse: bool,
    },
    Data(&'a [u8]),
    EndEntry,
    Done,
}

#[derive(Debug)]
struct ParsedHeader {
    kind: EntryKind,
    path: Vec<u8>,
    mode: u32,
    uid: u64,
    gid: u64,
    modified: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
}

/// Incremental sans-IO tar reader.
///
/// Consumed buffer prefixes are removed between events.
#[derive(Debug)]
struct TarSource {
    /// Input buffer.
    buf: Vec<u8>,
    /// Read position.
    cursor: usize,
    /// Driver state.
    state: State,
    /// End-of-input state.
    finished: bool,
    /// Overrides for the next entry.
    pending: OwnedOverrides,
    /// Global PAX overrides.
    global: OwnedOverrides,
    /// Partial extended header.
    record: Vec<u8>,
    /// Staged entry overrides.
    stage_pending: OwnedOverrides,
    /// Staged entry size.
    stage_size: u64,
    /// Logical entry size (different from stored size for sparse files).
    stage_logical_size: u64,
    /// Staged sparse data extents.
    stage_sparse: Vec<SparseExtent>,
    /// Whether sparse semantics apply even when the extent list is empty.
    stage_is_sparse: bool,
    /// Staged ustar owner names.
    stage_uname: Vec<u8>,
    stage_gname: Vec<u8>,
    /// Staged device numbers.
    stage_device: Option<Device>,
    stage_referenced_device: Option<Device>,
    /// Maximum data window requested by the v0.2 sparse driver.
    payload_chunk_limit: usize,
    /// Whether a global PAX record changed since the v0.2 driver last observed it.
    global_changed: bool,
    /// Staged data length.
    stage_len: usize,
}

impl Default for TarSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TarSource {
    /// A fresh source with an empty buffer.
    #[must_use]
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            state: State::Header,
            finished: false,
            pending: Overrides::default(),
            global: Overrides::default(),
            record: Vec::new(),
            stage_pending: Overrides::default(),
            stage_size: 0,
            stage_logical_size: 0,
            stage_sparse: Vec::new(),
            stage_is_sparse: false,
            stage_uname: Vec::new(),
            stage_gname: Vec::new(),
            stage_device: None,
            stage_referenced_device: None,
            payload_chunk_limit: usize::MAX,
            global_changed: false,
            stage_len: 0,
        }
    }

    /// Bytes available past the cursor.
    fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }

    fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    fn feed(&mut self, input: &[u8]) -> usize {
        self.buf.extend_from_slice(input);
        input.len()
    }

    const fn finish_input(&mut self) {
        self.finished = true;
    }

    /// Removes consumed bytes and resets the cursor.
    fn compact(&mut self) {
        if self.cursor > 0 {
            self.buf.drain(..self.cursor);
            self.cursor = 0;
        }
    }

    /// Apply a completed extended / long header record to the pending / global overrides.
    fn apply_record(&mut self, kind: MetaKind) -> Result<()> {
        match kind {
            MetaKind::LongName => {
                self.pending.path = Some(Cow::Owned(cstr(&self.record).to_vec()));
            },
            MetaKind::LongLink => {
                self.pending.linkpath = Some(Cow::Owned(cstr(&self.record).to_vec()));
            },
            MetaKind::PaxNext => {
                let mut parsed = Overrides::default();
                parse_pax(&self.record, &mut parsed)?;
                merge_owned(&mut self.pending, parsed);
            },
            MetaKind::PaxGlobal => {
                let mut parsed = Overrides::default();
                parse_pax(&self.record, &mut parsed)?;
                merge_owned(&mut self.global, parsed);
                self.global_changed = true;
            },
        }
        Ok(())
    }

    /// Map a starvation point to [`Poll::NeedInput`] (more bytes may still arrive) or a truncation
    /// error (input was already declared finished).
    fn starved(&self, what: &'static str) -> Result<Poll> {
        if self.finished {
            Err(Error::Malformed(what))
        } else {
            Ok(Poll::NeedInput)
        }
    }

    fn stage_header_metadata(
        &mut self,
        hdr: &[u8],
        pending: OwnedOverrides,
        physical_size: u64,
    ) -> Result<()> {
        let typeflag = hdr[O_TYPEFLAG];
        self.stage_uname = pending
            .uname
            .as_ref()
            .or(self.global.uname.as_ref())
            .map_or_else(
                || cstr(field(hdr, F_UNAME)).to_vec(),
                |value| value.to_vec(),
            );
        self.stage_gname = pending
            .gname
            .as_ref()
            .or(self.global.gname.as_ref())
            .map_or_else(
                || cstr(field(hdr, F_GNAME)).to_vec(),
                |value| value.to_vec(),
            );
        let referenced_device = if matches!(typeflag, b'3' | b'4') {
            Some(Device {
                major: parse_numeric(field(hdr, F_DEVMAJOR))?,
                minor: parse_numeric(field(hdr, F_DEVMINOR))?,
            })
        } else {
            None
        };
        self.stage_device = None;
        self.stage_referenced_device = referenced_device;
        self.stage_sparse = pax_sparse_extents(&self.global, &pending)?;
        self.stage_is_sparse = typeflag == b'S'
            || pending.sparse_realsize.is_some()
            || self.global.sparse_realsize.is_some()
            || pending
                .pax
                .iter()
                .chain(&self.global.pax)
                .any(|(key, _)| key.as_ref().starts_with(b"GNU.sparse."));
        self.stage_logical_size = pending
            .sparse_realsize
            .or(self.global.sparse_realsize)
            .unwrap_or(physical_size);
        if typeflag == b'S' {
            self.stage_sparse.extend(parse_gnu_sparse_descriptors(
                hdr,
                GNU_SPARSE_START,
                GNU_SPARSE_COUNT,
            )?);
            self.stage_logical_size = parse_numeric(field(hdr, GNU_SPARSE_REALSIZE))?;
        }
        if self.stage_is_sparse {
            validate_sparse_extents(&self.stage_sparse, self.stage_logical_size, physical_size)?;
        }
        self.stage_pending = pending;
        self.stage_size = physical_size;
        self.payload_chunk_limit = usize::MAX;
        Ok(())
    }

    /// Parse the next header block. Meta/long headers set up the [`State::Meta`] accumulation; a real
    /// entry stages its overrides/size and advances to [`State::Payload`]; a zero/short block ends.
    fn poll_header(&mut self) -> Result<Poll> {
        if self.available() < BLOCK {
            // A short/absent final block is a clean end of archive (mirrors the slice reader
            // returning `None` when a whole header no longer fits).
            if self.finished {
                self.state = State::Done;
                return Ok(Poll::Done);
            }
            return Ok(Poll::NeedInput);
        }
        let hdr = &self.buf[self.cursor..self.cursor + BLOCK];
        if hdr.iter().all(|&b| b == 0) {
            self.state = State::Done;
            return Ok(Poll::Done);
        }
        verify_checksum(hdr)?;
        let typeflag = hdr[O_TYPEFLAG];
        let raw_size = parse_numeric(field(hdr, F_SIZE))?;

        match typeflag {
            // PAX / GNU long headers: their whole payload is a record, not entry data.
            b'x' | b'X' | b'g' | b'L' | b'K' => {
                let data = usize_of(raw_size)?;
                let pad = round_up(raw_size)? - data;
                let kind = match typeflag {
                    b'g' => MetaKind::PaxGlobal,
                    b'L' => MetaKind::LongName,
                    b'K' => MetaKind::LongLink,
                    _ => MetaKind::PaxNext,
                };
                self.cursor += BLOCK;
                self.record.clear();
                self.state = State::Meta { kind, data, pad };
                Ok(Poll::Continue)
            },
            // Real entry: take `pending`, compute the size (respecting overrides), advance to the
            // payload, and stage what [`pull`](Self::pull) needs to build the borrowed metadata.
            _ => {
                let pending = mem::take(&mut self.pending);
                let hdr_start = self.cursor;
                let size = {
                    let hdr = &self.buf[hdr_start..hdr_start + BLOCK];
                    pending
                        .size
                        .or(self.global.size)
                        .map_or_else(|| parse_numeric(field(hdr, F_SIZE)), Ok)?
                };
                let pad = round_up(size)? - usize_of(size)?;
                let header = self.buf[hdr_start..hdr_start + BLOCK].to_vec();
                self.stage_header_metadata(&header, pending, size)?;
                self.cursor = hdr_start + BLOCK;
                self.state = if typeflag == b'S' && header[GNU_SPARSE_EXTENDED] != 0 {
                    State::SparseExtensions {
                        remaining: size,
                        pad,
                    }
                } else {
                    State::Payload {
                        remaining: size,
                        pad,
                    }
                };
                if matches!(self.state, State::SparseExtensions { .. }) {
                    Ok(Poll::Continue)
                } else {
                    Ok(Poll::Entry)
                }
            },
        }
    }

    fn poll_sparse_extension(&mut self, remaining: u64, pad: usize) -> Result<Poll> {
        if self.available() < BLOCK {
            return self.starved("tar: truncated GNU sparse extension header");
        }
        let block = &self.buf[self.cursor..self.cursor + BLOCK];
        self.stage_sparse.extend(parse_gnu_sparse_descriptors(
            block,
            0,
            GNU_SPARSE_EXT_COUNT,
        )?);
        let extended = block[504] != 0;
        self.cursor += BLOCK;
        if extended {
            self.state = State::SparseExtensions { remaining, pad };
            return Ok(Poll::Continue);
        }
        validate_sparse_extents(&self.stage_sparse, self.stage_logical_size, remaining)?;
        self.state = State::Payload { remaining, pad };
        Ok(Poll::Entry)
    }

    /// Accumulate an extended / long header record (data bytes then padding). On completion it is
    /// applied to the pending / global overrides and the driver returns to reading headers.
    fn poll_meta(&mut self, kind: MetaKind, data: usize, pad: usize) -> Result<Poll> {
        if data > 0 {
            let avail = self.available();
            if avail == 0 {
                return self.starved("tar: truncated extended header");
            }
            let n = data.min(avail);
            let from = self.cursor;
            self.record.extend_from_slice(&self.buf[from..from + n]);
            self.cursor += n;
            self.state = State::Meta {
                kind,
                data: data - n,
                pad,
            };
            return Ok(Poll::Continue);
        }
        if pad > 0 {
            let avail = self.available();
            if avail == 0 {
                return self.starved("tar: truncated extended header");
            }
            let n = pad.min(avail);
            self.cursor += n;
            self.state = State::Meta {
                kind,
                data,
                pad: pad - n,
            };
            return Ok(Poll::Continue);
        }
        self.apply_record(kind)?;
        self.record = Vec::new();
        self.state = State::Header;
        Ok(Poll::Continue)
    }

    /// Stream a real entry's payload (data window then padding). Data windows are staged for
    /// [`Poll::Data`]; once payload and padding are consumed the entry ends and the buffer compacts.
    fn poll_payload(&mut self, remaining: u64, pad: usize) -> Result<Poll> {
        if remaining > 0 {
            let avail = self.available();
            if avail == 0 {
                return self.starved("tar: truncated payload");
            }
            let want = usize_of(remaining)?
                .min(avail)
                .min(self.payload_chunk_limit);
            if want == 0 {
                return Ok(Poll::NeedInput);
            }
            self.cursor += want;
            self.state = State::Payload {
                remaining: remaining - want as u64,
                pad,
            };
            self.stage_len = want;
            return Ok(Poll::Data);
        }
        if pad > 0 {
            let avail = self.available();
            if avail == 0 {
                return self.starved("tar: truncated payload padding");
            }
            let n = pad.min(avail);
            self.cursor += n;
            self.state = State::Payload {
                remaining,
                pad: pad - n,
            };
            return Ok(Poll::Continue);
        }
        // Payload and padding consumed: end the entry. The consumed bytes are reclaimed at the
        // top of the next `pull` (a single compaction point), keeping residency bounded.
        self.state = State::Header;
        Ok(Poll::EndEntry)
    }

    fn set_payload_chunk_limit(&mut self, limit: usize) {
        self.payload_chunk_limit = limit;
    }

    fn take_global_metadata(&mut self) -> Option<ArchiveMetadata> {
        if !mem::take(&mut self.global_changed) {
            return None;
        }
        let mut metadata = ArchiveMetadata::new();
        for (key, value) in &self.global.pax {
            metadata = metadata.with_extension(Extension::new(
                "pax",
                key.as_ref().to_vec(),
                value.as_ref().to_vec(),
            ));
        }
        Some(metadata)
    }

    fn rich_metadata(&self, header: ParsedHeader) -> EntryMetadata {
        let pending = &self.stage_pending;
        let global = &self.global;
        let times = EntryTimes {
            modified: pending.mtime.or(global.mtime).or(header.modified),
            accessed: pending.atime.or(global.atime),
            changed: pending.ctime.or(global.ctime),
            created: pending.birthtime.or(global.birthtime),
        };
        let mut builder = EntryMetadata::builder(header.kind, ArchivePath::from_bytes(header.path))
            .size(Some(self.stage_logical_size))
            .mode(Some(header.mode))
            .owner(Owner {
                uid: Some(header.uid),
                gid: Some(header.gid),
                user: (!self.stage_uname.is_empty()).then(|| self.stage_uname.clone()),
                group: (!self.stage_gname.is_empty()).then(|| self.stage_gname.clone()),
            })
            .times(times)
            .devices(self.stage_device, self.stage_referenced_device)
            .link_target(header.link_target.map(ArchivePath::from_bytes));
        for extent in &self.stage_sparse {
            builder = builder.sparse_extent(*extent);
        }
        builder = add_pax_metadata(builder, &global.pax);
        builder = add_pax_metadata(builder, &pending.pax);
        builder.build()
    }

    fn pull_v2(&mut self) -> Result<TarSourceEvent<'_>> {
        self.compact();
        loop {
            if self.global_changed {
                let metadata = self
                    .take_global_metadata()
                    .ok_or(Error::InvalidState("global PAX update disappeared"))?;
                return Ok(TarSourceEvent::ArchiveMetadata(metadata));
            }
            let poll = match self.state {
                State::Done => return Ok(TarSourceEvent::Done),
                State::Header => self.poll_header()?,
                State::Meta { kind, data, pad } => self.poll_meta(kind, data, pad)?,
                State::SparseExtensions { remaining, pad } => {
                    self.poll_sparse_extension(remaining, pad)?
                },
                State::Payload { remaining, pad } => self.poll_payload(remaining, pad)?,
            };
            match poll {
                Poll::Continue => {},
                Poll::NeedInput => return Ok(TarSourceEvent::NeedInput),
                Poll::Done => return Ok(TarSourceEvent::Done),
                Poll::EndEntry => return Ok(TarSourceEvent::EndEntry),
                Poll::Entry => {
                    let start = match self.state {
                        State::Payload { .. } => self
                            .cursor
                            .checked_sub(BLOCK)
                            .filter(|start| {
                                self.buf
                                    .get(*start..*start + BLOCK)
                                    .is_some_and(|header| verify_checksum(header).is_ok())
                            })
                            .unwrap_or_else(|| {
                                self.buf
                                    .get(..self.cursor)
                                    .and_then(|prefix| {
                                        prefix
                                            .windows(BLOCK)
                                            .rposition(|header| verify_checksum(header).is_ok())
                                    })
                                    .unwrap_or(0)
                            }),
                        _ => return Err(Error::InvalidState("tar entry was not staged")),
                    };
                    let header = self
                        .buf
                        .get(start..start + BLOCK)
                        .ok_or(Error::Malformed("staged tar header disappeared"))?;
                    let header = parse_source_header(header, &self.stage_pending, &self.global)?;
                    let metadata = self.rich_metadata(header);
                    return Ok(TarSourceEvent::Entry {
                        metadata: Box::new(metadata),
                        sparse: self.stage_sparse.clone(),
                        is_sparse: self.stage_is_sparse,
                    });
                },
                Poll::Data => {
                    let from = self.cursor - self.stage_len;
                    return Ok(TarSourceEvent::Data(&self.buf[from..self.cursor]));
                },
            }
        }
    }
}

/// v0.2 incremental tar decoder.
///
/// This is the first format implementation of the unified [`ArchiveDecoder`]
/// contract. It wraps the proven tar state machine while the old entry-cursor
/// surface is removed from the remaining formats.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct TarDecoder {
    source: TarSource,
    limits: Limits,
    needs_input: bool,
    input_finished: bool,
    done: bool,
    entries: u64,
    entry_bytes: u64,
    total_bytes: u64,
    metadata_bytes: usize,
    sparse_active: bool,
    sparse: Vec<SparseExtent>,
    sparse_index: usize,
    logical_position: u64,
    logical_size: u64,
}

impl TarDecoder {
    /// Creates a decoder with explicit resource budgets.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            source: TarSource::new(),
            limits,
            needs_input: true,
            input_finished: false,
            done: false,
            entries: 0,
            entry_bytes: 0,
            total_bytes: 0,
            metadata_bytes: 0,
            sparse_active: false,
            sparse: Vec::new(),
            sparse_index: 0,
            logical_position: 0,
            logical_size: 0,
        }
    }

    /// Incrementally probes for a ustar/PAX/GNU tar header.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() < BLOCK {
            ProbeResult::NeedMore { minimum: BLOCK }
        } else if prefix[..BLOCK].iter().all(|byte| *byte == 0) {
            // Empty tar begins with zero blocks, but so do ISO images before
            // their sector-16 descriptor. Runtime detection must defer the
            // ambiguous all-zero prefix long enough to check that signature.
            const ISO_PROBE: usize = 16 * 2048 + 6;
            if prefix.len() < ISO_PROBE {
                ProbeResult::NeedMore { minimum: ISO_PROBE }
            } else {
                ProbeResult::Match(())
            }
        } else if verify_checksum(&prefix[..BLOCK]).is_ok() {
            ProbeResult::Match(())
        } else {
            ProbeResult::NoMatch
        }
    }

    fn check_limit_u64(
        actual: u64,
        limit: Option<u64>,
        message: &'static str,
    ) -> core::result::Result<(), ArchiveError> {
        if limit.is_some_and(|limit| actual > limit) {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("tar")
                .with_context(message));
        }
        Ok(())
    }

    fn account_data(&mut self, length: usize) -> core::result::Result<(), ArchiveError> {
        let length = u64::try_from(length).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("tar")
                .with_context("data window length exceeds u64")
        })?;
        self.entry_bytes = self.entry_bytes.checked_add(length).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("tar")
                .with_context("entry byte count overflow")
        })?;
        self.total_bytes = self.total_bytes.checked_add(length).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("tar")
                .with_context("decoded byte count overflow")
        })?;
        Self::check_limit_u64(
            self.entry_bytes,
            self.limits.entry_bytes(),
            "entry bytes exceed limit",
        )?;
        Self::check_limit_u64(
            self.total_bytes,
            self.limits.decoded_total(),
            "decoded bytes exceed limit",
        )
    }

    fn entry_metadata_cost(metadata: &EntryMetadata) -> core::result::Result<usize, ArchiveError> {
        metadata
            .path()
            .as_bytes()
            .len()
            .checked_add(
                metadata
                    .link_target()
                    .map_or(0, |target| target.as_bytes().len()),
            )
            .and_then(|value| {
                value.checked_add(
                    metadata
                        .extensions()
                        .iter()
                        .map(|extension| extension.key().len() + extension.value().len())
                        .sum::<usize>(),
                )
            })
            .and_then(|value| {
                value.checked_add(
                    metadata
                        .xattrs()
                        .iter()
                        .map(|(name, value)| name.len() + value.len())
                        .sum::<usize>(),
                )
            })
            .and_then(|value| value.checked_add(metadata.acl().iter().map(Vec::len).sum::<usize>()))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("tar")
                    .with_context("metadata accounting overflow")
            })
    }

    fn sparse_hole<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> core::result::Result<Option<DecodeStep<'a>>, ArchiveError> {
        if !self.sparse_active {
            self.source.set_payload_chunk_limit(usize::MAX);
            return Ok(None);
        }
        while self.sparse.get(self.sparse_index).is_some_and(|extent| {
            extent
                .offset
                .checked_add(extent.length)
                .is_some_and(|end| self.logical_position == end)
        }) {
            self.sparse_index += 1;
        }
        let next_data = self
            .sparse
            .get(self.sparse_index)
            .map_or(self.logical_size, |extent| extent.offset);
        if self.logical_position < next_data {
            if output.is_empty() {
                return Ok(Some(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::NeedOutput,
                }));
            }
            let hole = next_data - self.logical_position;
            let count = usize::try_from(hole.min(output.len() as u64)).map_err(|_| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("tar")
                    .with_context("sparse hole exceeds address space")
            })?;
            output[..count].fill(0);
            self.logical_position += count as u64;
            self.account_data(count)?;
            return Ok(Some(DecodeStep {
                consumed: 0,
                produced: count,
                event: DecodeEvent::Data(Chunk::new(&output[..count])),
            }));
        }
        if let Some(extent) = self.sparse.get(self.sparse_index) {
            let end = extent.offset.checked_add(extent.length).ok_or_else(|| {
                ArchiveError::new(ErrorKind::Malformed)
                    .with_format("tar")
                    .with_context("sparse extent overflow")
            })?;
            let remaining = end.saturating_sub(self.logical_position);
            self.source
                .set_payload_chunk_limit(usize::try_from(remaining).unwrap_or(usize::MAX));
        } else {
            self.source.set_payload_chunk_limit(usize::MAX);
        }
        Ok(None)
    }
}

impl Default for TarDecoder {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl ArchiveDecoder for TarDecoder {
    #[allow(clippy::too_many_lines)]
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<DecodeStep<'a>, ArchiveError> {
        if self.done {
            if !input.is_empty() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("tar")
                    .with_context("input supplied after archive end"));
            }
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::Done,
            });
        }
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|limit| limit < BLOCK)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("tar")
                .with_context("in-flight limit is smaller than one tar block"));
        }
        if let Some(step) = self.sparse_hole(output)? {
            return Ok(step);
        }

        let mut consumed = 0;
        if self.needs_input && !input.is_empty() {
            let accepted_limit = self.limits.in_flight_bytes().map_or(input.len(), |limit| {
                limit
                    .saturating_sub(self.source.buffered_len())
                    .min(input.len())
            });
            if accepted_limit == 0 {
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("tar")
                    .with_context("in-flight buffer budget was exhausted"));
            }
            let accepted = self.source.feed(&input[..accepted_limit]);
            if accepted > input.len() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("tar")
                    .with_context("tar source over-consumed input"));
            }
            consumed = accepted;
            self.needs_input = false;
        }
        if matches!(end, EndOfInput::End) && consumed == input.len() && !self.input_finished {
            self.source.finish_input();
            self.input_finished = true;
        }

        let event = self.source.pull_v2().map_err(ArchiveError::from)?;
        let event = match event {
            TarSourceEvent::NeedInput => {
                self.needs_input = true;
                if self.input_finished {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format("tar")
                        .with_context("unexpected end of tar input"));
                }
                DecodeEvent::NeedInput
            },
            TarSourceEvent::ArchiveMetadata(metadata) => DecodeEvent::ArchiveMetadata(metadata),
            TarSourceEvent::Entry {
                metadata,
                sparse,
                is_sparse,
            } => {
                let metadata = *metadata;
                self.entries = self.entries.checked_add(1).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry count overflow")
                })?;
                Self::check_limit_u64(
                    self.entries,
                    self.limits.entries(),
                    "entry count exceeds limit",
                )?;
                if self
                    .limits
                    .path_bytes()
                    .is_some_and(|limit| metadata.path().as_bytes().len() > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_entry(self.entries - 1, metadata.path().as_bytes())
                        .with_context("entry path exceeds limit"));
                }
                let logical_size = metadata.size().unwrap_or(0);
                Self::check_limit_u64(
                    logical_size,
                    self.limits.entry_bytes(),
                    "entry size exceeds limit",
                )?;
                let metadata_cost = Self::entry_metadata_cost(&metadata)?;
                self.metadata_bytes =
                    self.metadata_bytes
                        .checked_add(metadata_cost)
                        .ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("tar")
                                .with_context("metadata accounting overflow")
                        })?;
                if self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|limit| self.metadata_bytes > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("metadata exceeds configured limit"));
                }
                self.entry_bytes = 0;
                self.sparse_active = is_sparse;
                self.sparse = sparse;
                self.sparse_index = 0;
                self.logical_position = 0;
                self.logical_size = logical_size;
                DecodeEvent::Entry(metadata)
            },
            TarSourceEvent::Data(data) => {
                if self.sparse_active {
                    let extent = self.sparse.get(self.sparse_index).ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("tar")
                            .with_context("sparse payload exceeds declared extents")
                    })?;
                    let end = extent.offset.checked_add(extent.length).ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_format("tar")
                            .with_context("sparse extent overflow")
                    })?;
                    let next = self
                        .logical_position
                        .checked_add(data.len() as u64)
                        .ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("tar")
                                .with_context("sparse logical position overflow")
                        })?;
                    if self.logical_position < extent.offset || next > end {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("tar")
                            .with_context("sparse payload does not match extent map"));
                    }
                    self.logical_position = next;
                }
                let length = u64::try_from(data.len()).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("data window length exceeds u64")
                })?;
                self.entry_bytes = self.entry_bytes.checked_add(length).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry byte count overflow")
                })?;
                self.total_bytes = self.total_bytes.checked_add(length).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("decoded byte count overflow")
                })?;
                Self::check_limit_u64(
                    self.entry_bytes,
                    self.limits.entry_bytes(),
                    "entry bytes exceed limit",
                )?;
                Self::check_limit_u64(
                    self.total_bytes,
                    self.limits.decoded_total(),
                    "decoded bytes exceed limit",
                )?;
                DecodeEvent::Data(Chunk::new(data))
            },
            TarSourceEvent::EndEntry => {
                if self.sparse_active && self.logical_position != self.logical_size {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format("tar")
                        .with_context("sparse payload ended before logical size"));
                }
                self.sparse_active = false;
                DecodeEvent::EndEntry
            },
            TarSourceEvent::Done => {
                self.done = true;
                DecodeEvent::Done
            },
        };
        Ok(DecodeStep {
            consumed,
            produced: 0,
            event,
        })
    }
}

/// v0.2 sequential tar encoder.
///
/// Headers and alignment bytes are staged in a small metadata buffer; entry
/// payload bytes are copied directly from caller input to caller output.
#[derive(Debug)]
pub struct TarEncoder {
    limits: Limits,
    pending: Vec<u8>,
    pending_pos: usize,
    open: bool,
    entry_size: u64,
    remaining: u64,
    finishing: bool,
    done: bool,
    entries: u64,
    total_bytes: u64,
    sparse: Vec<SparseExtent>,
    sparse_index: usize,
    logical_position: u64,
}

#[derive(Clone, Copy)]
struct HeaderView<'a> {
    kind: EntryKind,
    path: &'a [u8],
    mode: u32,
    uid: u64,
    gid: u64,
    modified: Option<Timestamp>,
    size: u64,
    link_target: Option<&'a [u8]>,
}

impl<'a> HeaderView<'a> {
    fn from_metadata(metadata: &'a EntryMetadata, size: u64) -> Self {
        Self {
            kind: metadata.kind(),
            path: metadata.path().as_bytes(),
            mode: metadata
                .mode()
                .unwrap_or_else(|| default_mode(metadata.kind())),
            uid: metadata.owner().uid.unwrap_or(0),
            gid: metadata.owner().gid.unwrap_or(0),
            modified: metadata.times().modified,
            size,
            link_target: metadata.link_target().map(ArchivePath::as_bytes),
        }
    }
}

impl TarEncoder {
    /// Creates a fresh encoder.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            pending: Vec::new(),
            pending_pos: 0,
            open: false,
            entry_size: 0,
            remaining: 0,
            finishing: false,
            done: false,
            entries: 0,
            total_bytes: 0,
            sparse: Vec::new(),
            sparse_index: 0,
            logical_position: 0,
        }
    }

    /// Queues archive-level global PAX metadata before the first entry.
    pub fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> core::result::Result<(), ArchiveError> {
        if self.open || self.entries != 0 || !self.pending.is_empty() || self.finishing || self.done
        {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format("tar")
                .with_context("archive metadata must be set before the first entry"));
        }
        let mut records = Vec::new();
        for extension in metadata
            .extensions()
            .iter()
            .filter(|extension| extension.namespace() == "pax")
        {
            push_pax_record(&mut records, extension.key(), extension.value())
                .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
        }
        if let Some(comment) = metadata.comment() {
            if !metadata.extensions().iter().any(|extension| {
                extension.namespace() == "pax" && extension.key() == b"LIBARCHIVE.comment"
            }) {
                push_pax_record(&mut records, b"LIBARCHIVE.comment", comment)
                    .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
            }
        }
        if !records.is_empty() {
            write_pax_header(&mut self.pending, &records, b'g')
                .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
            if self
                .limits
                .metadata_bytes()
                .is_some_and(|limit| self.pending.len() > limit)
            {
                self.pending.clear();
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("tar")
                    .with_context("global PAX metadata exceeds configured limit"));
            }
        }
        Ok(())
    }

    fn drain_pending(&mut self, output: &mut [u8]) -> usize {
        let remaining = self.pending.len().saturating_sub(self.pending_pos);
        let n = remaining.min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
            self.pending_pos += n;
        }
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        n
    }
}

impl ArchiveEncoder for TarEncoder {
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
                    .with_format("tar")
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
            EncodeCommand::BeginEntry(meta) => {
                if self.open {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("tar")
                        .with_context("previous entry is still open"));
                }
                let logical_size = meta.size().ok_or_else(|| {
                    ArchiveError::new(ErrorKind::SizeRequired)
                        .with_format("tar")
                        .with_context("tar requires a declared entry size")
                })?;
                if self
                    .limits
                    .path_bytes()
                    .is_some_and(|limit| meta.path().as_bytes().len() > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry path exceeds configured limit"));
                }
                if self
                    .limits
                    .entry_bytes()
                    .is_some_and(|limit| logical_size > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry size exceeds configured limit"));
                }
                let next_entries = self.entries.checked_add(1).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry count overflow")
                })?;
                if self
                    .limits
                    .entries()
                    .is_some_and(|limit| next_entries > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("entry count exceeds configured limit"));
                }
                let sparse = meta.sparse_extents();
                let is_sparse = !sparse.is_empty();
                let stored_size = if is_sparse {
                    let stored = sparse.iter().try_fold(0_u64, |total, extent| {
                        total.checked_add(extent.length).ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("tar")
                                .with_context("sparse stored size overflow")
                        })
                    })?;
                    validate_sparse_extents(sparse, logical_size, stored)
                        .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
                    stored
                } else {
                    logical_size
                };
                let stored_meta = HeaderView::from_metadata(meta, stored_size);
                write_v2_header(&mut self.pending, meta, stored_meta, is_sparse)
                    .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
                if self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|limit| self.pending.len() > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("tar header metadata exceeds configured limit"));
                }
                self.entries = next_entries;
                self.remaining = logical_size;
                self.entry_size = stored_size;
                self.sparse.clear();
                self.sparse.extend_from_slice(sparse);
                self.sparse_index = 0;
                self.logical_position = 0;
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
                        .with_format("tar")
                        .with_context("entry data supplied without an open entry"));
                }
                if input.len() as u64 > self.remaining {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("tar")
                        .with_context("entry data exceeds declared size"));
                }
                if input.is_empty() {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: 0,
                        status: EncodeStatus::NeedCommand,
                    });
                }
                let (consumed, produced) = if self.sparse.is_empty() {
                    if output.is_empty() {
                        return Ok(EncodeStep {
                            consumed: 0,
                            produced: 0,
                            status: EncodeStatus::NeedOutput,
                        });
                    }
                    let count = input.len().min(output.len());
                    output[..count].copy_from_slice(&input[..count]);
                    self.logical_position += count as u64;
                    (count, count)
                } else {
                    write_sparse_data(
                        &self.sparse,
                        &mut self.sparse_index,
                        &mut self.logical_position,
                        input,
                        output,
                    )?
                };
                let next_total =
                    self.total_bytes
                        .checked_add(consumed as u64)
                        .ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Limit)
                                .with_format("tar")
                                .with_context("encoded byte count overflow")
                        })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|limit| next_total > limit)
                {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("encoded total exceeds configured limit"));
                }
                self.remaining -= consumed as u64;
                self.total_bytes = next_total;
                Ok(EncodeStep {
                    consumed,
                    produced,
                    status: if consumed == input.len() {
                        EncodeStatus::NeedCommand
                    } else {
                        EncodeStatus::NeedOutput
                    },
                })
            },
            EncodeCommand::EndEntry => {
                if !self.open {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("tar")
                        .with_context("end-entry supplied without an open entry"));
                }
                if self.remaining != 0 {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_format("tar")
                        .with_context("entry data is shorter than declared size"));
                }
                let pad = round_up(self.entry_size)
                    .map_err(|error| ArchiveError::from(error).with_format("tar"))?
                    - usize_of(self.entry_size)
                        .map_err(|error| ArchiveError::from(error).with_format("tar"))?;
                self.pending.resize(pad, 0);
                self.open = false;
                self.sparse.clear();
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
                        .with_format("tar")
                        .with_context("cannot finish with an open entry"));
                }
                self.pending.resize(2 * BLOCK, 0);
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

fn parse_source_header(
    hdr: &[u8],
    pending: &OwnedOverrides,
    global: &OwnedOverrides,
) -> Result<ParsedHeader> {
    let kind = kind_from_typeflag(hdr[O_TYPEFLAG]);

    let name = cstr(field(hdr, F_NAME));
    let prefix = cstr(field(hdr, F_PREFIX));
    let is_ustar = field(hdr, F_MAGIC).starts_with(b"ustar");

    let path = match pending.path.as_ref().or(global.path.as_ref()) {
        Some(path) => path.to_vec(),
        None => {
            if is_ustar && !prefix.is_empty() {
                join_prefix_name(prefix, name).into_owned()
            } else {
                name.to_vec()
            }
        },
    };

    let link_target = match kind {
        EntryKind::Symlink | EntryKind::Hardlink => Some(
            pending
                .linkpath
                .as_ref()
                .or(global.linkpath.as_ref())
                .map_or_else(
                    || cstr(field(hdr, F_LINKNAME)).to_vec(),
                    |link| link.to_vec(),
                ),
        ),
        _ => None,
    };

    let mtime = pending.mtime.or(global.mtime).or_else(|| {
        parse_numeric(field(hdr, F_MTIME))
            .ok()
            .map(|secs| Timestamp {
                secs: i64::try_from(secs).unwrap_or(i64::MAX),
                nanos: 0,
            })
    });

    let uid = pending
        .uid
        .or(global.uid)
        .map_or_else(|| parse_numeric(field(hdr, F_UID)), Ok)?;
    let gid = pending
        .gid
        .or(global.gid)
        .map_or_else(|| parse_numeric(field(hdr, F_GID)), Ok)?;
    let mode = u32::try_from(parse_numeric(field(hdr, F_MODE))? & 0o7777).unwrap_or(0);

    Ok(ParsedHeader {
        kind,
        path,
        mode,
        uid,
        gid,
        modified: mtime,
        link_target,
    })
}

/// Merges the set fields of a freshly parsed (buffer-borrowing) `Overrides` into an
/// [`OwnedOverrides`], cloning each present byte string so it survives buffer compaction. Only set
/// fields overwrite, so a GNU `L`/`K` header and a PAX `x` header can both contribute to the same
/// next entry.
fn merge_owned(dst: &mut OwnedOverrides, src: Overrides<'_>) {
    if let Some(v) = src.path {
        dst.path = Some(Cow::Owned(v.into_owned()));
    }
    if let Some(v) = src.linkpath {
        dst.linkpath = Some(Cow::Owned(v.into_owned()));
    }
    if let Some(v) = src.size {
        dst.size = Some(v);
    }
    if let Some(v) = src.mtime {
        dst.mtime = Some(v);
    }
    if let Some(v) = src.atime {
        dst.atime = Some(v);
    }
    if let Some(v) = src.ctime {
        dst.ctime = Some(v);
    }
    if let Some(v) = src.birthtime {
        dst.birthtime = Some(v);
    }
    if let Some(v) = src.uid {
        dst.uid = Some(v);
    }
    if let Some(v) = src.gid {
        dst.gid = Some(v);
    }
    if let Some(v) = src.uname {
        dst.uname = Some(Cow::Owned(v.into_owned()));
    }
    if let Some(v) = src.gname {
        dst.gname = Some(Cow::Owned(v.into_owned()));
    }
    if let Some(v) = src.sparse_realsize {
        dst.sparse_realsize = Some(v);
    }
    dst.pax.extend(
        src.pax
            .into_iter()
            .map(|(key, value)| (Cow::Owned(key.into_owned()), Cow::Owned(value.into_owned()))),
    );
}

// ── Helpers (free functions; they don't borrow self, avoiding borrow entanglement) ─────────────

/// Slices out a fixed field from the header.
fn field(hdr: &[u8], (start, end): (usize, usize)) -> &[u8] {
    &hdr[start..end]
}

/// Returns up to the first NUL (tar's C-string field).
fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// Joins `prefix` + "/" + `name` (ustar's 255B path).
fn join_prefix_name<'a>(prefix: &'a [u8], name: &'a [u8]) -> Cow<'a, [u8]> {
    let mut joined = Vec::with_capacity(prefix.len() + 1 + name.len());
    joined.extend_from_slice(prefix);
    joined.push(b'/');
    joined.extend_from_slice(name);
    Cow::Owned(joined)
}

/// Maps a typeflag to a typed kind. `'0'`/`'\0'`/`'7'` and unknown values are treated as regular files (tar convention).
fn kind_from_typeflag(tf: u8) -> EntryKind {
    match tf {
        b'5' => EntryKind::Dir,
        b'1' => EntryKind::Hardlink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::Char,
        b'4' => EntryKind::Block,
        b'6' => EntryKind::Fifo,
        _ => EntryKind::File,
    }
}

/// Parses a tar numeric field (octal ASCII, or base-256 with the high bit set).
fn parse_numeric(field: &[u8]) -> Result<u64> {
    match field.first() {
        None => Ok(0),
        // base-256 (GNU extension, for large values). The high bit of the first byte is set.
        Some(&first) if first & 0x80 != 0 => {
            let mut val: u64 = u64::from(first & 0x7f);
            for &b in &field[1..] {
                // `checked_mul(256)` (not `checked_shl(8)`) is what actually detects value
                // overflow: shl only errors when the shift count reaches the bit width.
                val = val
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(u64::from(b)))
                    .ok_or(Error::Malformed("base-256 numeric overflow"))?;
            }
            Ok(val)
        },
        // Octal ASCII. Leading/trailing spaces / NULs are ignored.
        _ => {
            let mut val: u64 = 0;
            let mut seen = false;
            for &b in field {
                match b {
                    b' ' | 0 => {
                        if seen {
                            break;
                        }
                    },
                    b'0'..=b'7' => {
                        val = val
                            .checked_mul(8)
                            .and_then(|v| v.checked_add(u64::from(b - b'0')))
                            .ok_or(Error::Malformed("octal numeric overflow"))?;
                        seen = true;
                    },
                    _ => return Err(Error::Malformed("invalid octal digit")),
                }
            }
            Ok(val)
        },
    }
}

/// Verifies the header checksum (supports both unsigned and signed).
fn verify_checksum(hdr: &[u8]) -> Result<()> {
    let stored = parse_numeric(field(hdr, F_CHKSUM))?;
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in hdr.iter().enumerate() {
        // The checksum field itself is computed as spaces (0x20).
        let byte = if (F_CHKSUM.0..F_CHKSUM.1).contains(&i) {
            b' '
        } else {
            b
        };
        unsigned += u64::from(byte);
        signed += i64::from(i8::from_ne_bytes([byte]));
    }
    if stored == unsigned || u64::try_from(signed).is_ok_and(|s| s == stored) {
        Ok(())
    } else {
        Err(Error::Malformed("header checksum mismatch"))
    }
}

/// Converts u64 to usize (rejects oversized values on 32-bit platforms).
fn usize_of(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::LimitExceeded("size exceeds usize"))
}

/// Rounds a byte length up to the next block boundary.
fn round_up(size: u64) -> Result<usize> {
    let size = usize_of(size)?;
    let blocks = size
        .checked_add(BLOCK - 1)
        .ok_or(Error::Malformed("size overflow"))?
        / BLOCK;
    blocks
        .checked_mul(BLOCK)
        .ok_or(Error::Malformed("size overflow"))
}

/// Parses a set of PAX extended records `"LEN KEY=VALUE\n"...` and applies them to `into`.
fn parse_pax<'a>(mut records: &'a [u8], into: &mut Overrides<'a>) -> Result<()> {
    while !records.is_empty() {
        // The head is the decimal total record length (including its own digits + space + KEY=VALUE + newline).
        let sp = records
            .iter()
            .position(|&b| b == b' ')
            .ok_or(Error::Malformed("pax: missing length separator"))?;
        let len = ascii_decimal(&records[..sp])?;
        // Need room for "LEN" + space + at least an empty body + newline, i.e. len >= sp + 2,
        // otherwise `record[sp + 1..len - 1]` below would have start > end and panic.
        if len < sp + 2 || len > records.len() {
            return Err(Error::Malformed("pax: bad record length"));
        }
        let record = &records[..len];
        // The KEY=VALUE part of "LEN KEY=VALUE\n" (excluding the trailing newline).
        let body = &record[sp + 1..record.len() - 1];
        let eq = body
            .iter()
            .position(|&b| b == b'=')
            .ok_or(Error::Malformed("pax: missing '='"))?;
        let key = &body[..eq];
        let value = &body[eq + 1..];
        apply_pax(key, value, into)?;
        records = &records[len..];
    }
    Ok(())
}

/// Applies a single PAX key-value to the overrides (unknown keys are ignored).
fn apply_pax<'a>(key: &[u8], value: &'a [u8], into: &mut Overrides<'a>) -> Result<()> {
    into.pax
        .push((Cow::Owned(key.to_vec()), Cow::Borrowed(value)));
    match key {
        b"path" => into.path = Some(Cow::Borrowed(value)),
        b"linkpath" => into.linkpath = Some(Cow::Borrowed(value)),
        b"size" => into.size = Some(ascii_decimal_u64(value)?),
        b"uid" => into.uid = Some(ascii_decimal_u64(value)?),
        b"gid" => into.gid = Some(ascii_decimal_u64(value)?),
        b"mtime" => into.mtime = Some(parse_pax_time(value)?),
        b"atime" => into.atime = Some(parse_pax_time(value)?),
        b"ctime" => into.ctime = Some(parse_pax_time(value)?),
        b"LIBARCHIVE.creationtime" | b"SCHILY.birthtime" => {
            into.birthtime = Some(parse_pax_time(value)?);
        },
        b"uname" => into.uname = Some(Cow::Borrowed(value)),
        b"gname" => into.gname = Some(Cow::Borrowed(value)),
        b"GNU.sparse.size" | b"GNU.sparse.realsize" => {
            into.sparse_realsize = Some(ascii_decimal_u64(value)?);
        },
        _ => {},
    }
    Ok(())
}

fn pax_sparse_extents(
    global: &OwnedOverrides,
    pending: &OwnedOverrides,
) -> Result<Vec<SparseExtent>> {
    let records = global.pax.iter().chain(&pending.pax);
    let mut map = None;
    let mut pairs = Vec::new();
    let mut offset = None;
    for (key, value) in records {
        match key.as_ref() {
            b"GNU.sparse.map" => map = Some(value.as_ref()),
            b"GNU.sparse.offset" => offset = Some(ascii_decimal_u64(value.as_ref())?),
            b"GNU.sparse.numbytes" => {
                let Some(offset) = offset.take() else {
                    return Err(Error::Malformed("GNU sparse length without offset"));
                };
                pairs.push(SparseExtent {
                    offset,
                    length: ascii_decimal_u64(value.as_ref())?,
                });
            },
            _ => {},
        }
    }
    if offset.is_some() {
        return Err(Error::Malformed("GNU sparse offset without length"));
    }
    if let Some(map) = map {
        pairs.clear();
        let mut fields = map.split(|byte| *byte == b',');
        while let Some(offset) = fields.next() {
            let length = fields
                .next()
                .ok_or(Error::Malformed("GNU sparse map has an odd field count"))?;
            pairs.push(SparseExtent {
                offset: ascii_decimal_u64(trim_ascii_space(offset))?,
                length: ascii_decimal_u64(trim_ascii_space(length))?,
            });
        }
    }
    Ok(pairs)
}

fn parse_gnu_sparse_descriptors(
    block: &[u8],
    start: usize,
    count: usize,
) -> Result<Vec<SparseExtent>> {
    let mut extents = Vec::new();
    for index in 0..count {
        let offset = start
            .checked_add(index * 24)
            .ok_or(Error::Malformed("GNU sparse descriptor offset overflow"))?;
        let descriptor = block
            .get(offset..offset + 24)
            .ok_or(Error::Malformed("truncated GNU sparse descriptor"))?;
        let sparse_offset = parse_numeric(&descriptor[..12])?;
        let length = parse_numeric(&descriptor[12..])?;
        if length != 0 {
            extents.push(SparseExtent {
                offset: sparse_offset,
                length,
            });
        }
    }
    Ok(extents)
}

fn validate_sparse_extents(
    extents: &[SparseExtent],
    logical_size: u64,
    stored_size: u64,
) -> Result<()> {
    let mut previous_end = 0_u64;
    let mut stored = 0_u64;
    for extent in extents {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(Error::Malformed("GNU sparse extent overflow"))?;
        if extent.offset < previous_end || end > logical_size {
            return Err(Error::Malformed(
                "GNU sparse extents overlap or exceed logical size",
            ));
        }
        previous_end = end;
        stored = stored
            .checked_add(extent.length)
            .ok_or(Error::Malformed("GNU sparse stored size overflow"))?;
    }
    if stored != stored_size {
        return Err(Error::Malformed(
            "GNU sparse extent bytes differ from stored size",
        ));
    }
    Ok(())
}

fn add_pax_metadata(
    mut builder: EntryMetadataBuilder,
    records: &[RawPaxRecord<'_>],
) -> EntryMetadataBuilder {
    for (key, value) in records {
        if let Some(name) = key.as_ref().strip_prefix(b"SCHILY.xattr.") {
            builder = builder.xattr(name.to_vec(), value.as_ref().to_vec());
        } else if matches!(
            key.as_ref(),
            b"SCHILY.acl.access"
                | b"SCHILY.acl.default"
                | b"LIBARCHIVE.acl.access"
                | b"LIBARCHIVE.acl.default"
        ) {
            builder = builder.acl(value.as_ref().to_vec());
        }
        builder = builder.extension(Extension::new(
            "pax",
            key.as_ref().to_vec(),
            value.as_ref().to_vec(),
        ));
    }
    builder
}

fn trim_ascii_space(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Converts ASCII decimal to usize.
fn ascii_decimal(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() {
        return Err(Error::Malformed("empty decimal"));
    }
    let mut val: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed("invalid decimal digit"));
        }
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(b - b'0')))
            .ok_or(Error::LimitExceeded("decimal overflow"))?;
    }
    Ok(val)
}

fn ascii_decimal_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Err(Error::Malformed("empty decimal"));
    }
    let mut value = 0_u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(Error::Malformed("invalid decimal digit"));
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
            .ok_or(Error::LimitExceeded("decimal overflow"))?;
    }
    Ok(value)
}

/// Parses a PAX mtime (`"secs"` or `"secs.nanos"`).
fn parse_pax_time(value: &[u8]) -> Result<Timestamp> {
    let negative = value.first() == Some(&b'-');
    let value = if negative { &value[1..] } else { value };
    let (secs_part, frac_part) = match value.iter().position(|&b| b == b'.') {
        Some(dot) => (&value[..dot], &value[dot + 1..]),
        None => (value, &b""[..]),
    };
    let magnitude = i64::try_from(ascii_decimal_u64(secs_part)?)
        .map_err(|_| Error::LimitExceeded("PAX timestamp exceeds i64"))?;
    // Convert up to 9 fractional digits into nanoseconds (pad with 0 if short, truncate if longer).
    let mut nanos: u32 = 0;
    for i in 0..9 {
        nanos *= 10;
        if let Some(&b) = frac_part.get(i) {
            if !b.is_ascii_digit() {
                return Err(Error::Malformed("invalid fractional second"));
            }
            nanos += u32::from(b - b'0');
        }
    }
    let (secs, nanos) = if negative && nanos != 0 {
        (
            magnitude
                .checked_neg()
                .and_then(|seconds| seconds.checked_sub(1))
                .ok_or(Error::LimitExceeded("PAX timestamp underflow"))?,
            1_000_000_000 - nanos,
        )
    } else if negative {
        (
            magnitude
                .checked_neg()
                .ok_or(Error::LimitExceeded("PAX timestamp underflow"))?,
            0,
        )
    } else {
        (magnitude, nanos)
    };
    Ok(Timestamp { secs, nanos })
}

// ── Writer helpers (dual of the reader's field parsing) ────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn write_v2_header(
    sink: &mut Vec<u8>,
    metadata: &EntryMetadata,
    stored: HeaderView<'_>,
    sparse: bool,
) -> Result<()> {
    let mut pax = Vec::new();
    for extension in metadata
        .extensions()
        .iter()
        .filter(|extension| extension.namespace() == "pax")
    {
        if sparse
            && matches!(
                extension.key(),
                b"GNU.sparse.map" | b"GNU.sparse.size" | b"GNU.sparse.realsize"
            )
        {
            continue;
        }
        push_pax_record(&mut pax, extension.key(), extension.value())?;
    }
    if let Some(user) = metadata.owner().user.as_deref() {
        push_pax_record(&mut pax, b"uname", user)?;
    }
    if let Some(group) = metadata.owner().group.as_deref() {
        push_pax_record(&mut pax, b"gname", group)?;
    }
    let times = metadata.times();
    for (key, timestamp) in [
        (b"mtime".as_slice(), times.modified),
        (b"atime".as_slice(), times.accessed),
        (b"ctime".as_slice(), times.changed),
        (b"LIBARCHIVE.creationtime".as_slice(), times.created),
    ] {
        if let Some(timestamp) = timestamp {
            let value = format_pax_timestamp(timestamp);
            push_pax_record(&mut pax, key, value.as_bytes())?;
        }
    }
    for (name, value) in metadata.xattrs() {
        let mut key = b"SCHILY.xattr.".to_vec();
        key.extend_from_slice(name);
        if !metadata
            .extensions()
            .iter()
            .any(|extension| extension.namespace() == "pax" && extension.key() == key)
        {
            push_pax_record(&mut pax, &key, value)?;
        }
    }
    if !metadata.acl().is_empty()
        && !metadata.extensions().iter().any(|extension| {
            extension.namespace() == "pax"
                && (extension.key().starts_with(b"SCHILY.acl.")
                    || extension.key().starts_with(b"LIBARCHIVE.acl."))
        })
    {
        for acl in metadata.acl() {
            push_pax_record(&mut pax, b"SCHILY.acl.access", acl)?;
        }
    }
    if let Some(comment) = metadata.comment() {
        push_pax_record(&mut pax, b"LIBARCHIVE.comment", comment)?;
    }
    if sparse {
        let mut map = String::new();
        for (index, extent) in metadata.sparse_extents().iter().enumerate() {
            if index != 0 {
                map.push(',');
            }
            map.push_str(&extent.offset.to_string());
            map.push(',');
            map.push_str(&extent.length.to_string());
        }
        push_pax_record(&mut pax, b"GNU.sparse.map", map.as_bytes())?;
        push_pax_record(
            &mut pax,
            b"GNU.sparse.realsize",
            metadata.size().unwrap_or(0).to_string().as_bytes(),
        )?;
    }
    if !pax.is_empty() {
        write_pax_header(sink, &pax, b'x')?;
    }
    write_header(sink, stored)?;

    let header_start = sink
        .len()
        .checked_sub(BLOCK)
        .ok_or(Error::InvalidState("tar header was not emitted"))?;
    let header = sink
        .get_mut(header_start..)
        .ok_or(Error::InvalidState("tar header cannot be patched"))?;
    if let Some(user) = metadata.owner().user.as_deref() {
        copy_field(&mut header[F_UNAME.0..F_UNAME.1], user);
    }
    if let Some(group) = metadata.owner().group.as_deref() {
        copy_field(&mut header[F_GNAME.0..F_GNAME.1], group);
    }
    if matches!(metadata.kind(), EntryKind::Char | EntryKind::Block) {
        if let Some(device) = metadata.referenced_device() {
            put_octal(&mut header[F_DEVMAJOR.0..F_DEVMAJOR.1], device.major)?;
            put_octal(&mut header[F_DEVMINOR.0..F_DEVMINOR.1], device.minor)?;
        }
    }
    let header: &mut [u8; BLOCK] = header
        .try_into()
        .map_err(|_| Error::InvalidState("tar header patch length changed"))?;
    write_checksum(header)
}

fn write_sparse_data(
    extents: &[SparseExtent],
    sparse_index: &mut usize,
    logical_position: &mut u64,
    input: &[u8],
    output: &mut [u8],
) -> core::result::Result<(usize, usize), ArchiveError> {
    let mut consumed = 0;
    let mut produced = 0;
    while consumed < input.len() {
        while extents.get(*sparse_index).is_some_and(|extent| {
            extent
                .offset
                .checked_add(extent.length)
                .is_some_and(|end| *logical_position == end)
        }) {
            *sparse_index += 1;
        }
        let Some(extent) = extents.get(*sparse_index) else {
            let count = input.len() - consumed;
            *logical_position = logical_position.checked_add(count as u64).ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("tar")
                    .with_context("sparse logical position overflow")
            })?;
            consumed += count;
            break;
        };
        if *logical_position < extent.offset {
            let hole = extent.offset - *logical_position;
            let count =
                usize::try_from(hole.min((input.len() - consumed) as u64)).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("tar")
                        .with_context("sparse hole exceeds address space")
                })?;
            *logical_position += count as u64;
            consumed += count;
            continue;
        }
        if produced == output.len() {
            break;
        }
        let end = extent.offset.checked_add(extent.length).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Malformed)
                .with_format("tar")
                .with_context("sparse extent overflow")
        })?;
        let remaining = end.saturating_sub(*logical_position);
        let count = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len() - consumed)
            .min(output.len() - produced);
        output[produced..produced + count].copy_from_slice(&input[consumed..consumed + count]);
        *logical_position += count as u64;
        consumed += count;
        produced += count;
    }
    Ok((consumed, produced))
}

fn push_pax_record(output: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<()> {
    if key.is_empty() || key.iter().any(|byte| matches!(byte, b'=' | b'\n' | 0)) {
        return Err(Error::Malformed("invalid PAX key"));
    }
    let body_length = 1_usize
        .checked_add(key.len())
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(value.len()))
        .and_then(|length| length.checked_add(1))
        .ok_or(Error::LimitExceeded("PAX record length overflow"))?;
    let mut length = body_length + 1;
    loop {
        let digits = length.to_string();
        let exact = body_length
            .checked_add(digits.len())
            .ok_or(Error::LimitExceeded("PAX record length overflow"))?;
        if exact == length {
            output.extend_from_slice(digits.as_bytes());
            output.push(b' ');
            output.extend_from_slice(key);
            output.push(b'=');
            output.extend_from_slice(value);
            output.push(b'\n');
            return Ok(());
        }
        length = exact;
    }
}

fn write_pax_header(sink: &mut Vec<u8>, records: &[u8], typeflag: u8) -> Result<()> {
    let mut header = [0_u8; BLOCK];
    let name = b"././@PaxHeader";
    header[..name.len()].copy_from_slice(name);
    put_octal(&mut header[F_MODE.0..F_MODE.1], 0o644)?;
    put_octal(&mut header[F_UID.0..F_UID.1], 0)?;
    put_octal(&mut header[F_GID.0..F_GID.1], 0)?;
    put_octal(&mut header[F_SIZE.0..F_SIZE.1], records.len() as u64)?;
    put_octal(&mut header[F_MTIME.0..F_MTIME.1], 0)?;
    header[O_TYPEFLAG] = typeflag;
    header[F_MAGIC.0..F_MAGIC.0 + 5].copy_from_slice(b"ustar");
    header[263] = b'0';
    header[264] = b'0';
    write_checksum(&mut header)?;
    sink.extend_from_slice(&header);
    sink.extend_from_slice(records);
    write_zeros(sink, round_up(records.len() as u64)? - records.len())
}

fn format_pax_timestamp(timestamp: Timestamp) -> String {
    if timestamp.nanos == 0 {
        return timestamp.secs.to_string();
    }
    if timestamp.secs < 0 {
        let integral = timestamp.secs.saturating_add(1).saturating_neg();
        let fraction = 1_000_000_000 - timestamp.nanos;
        alloc::format!("-{integral}.{fraction:09}")
    } else {
        alloc::format!("{}.{:09}", timestamp.secs, timestamp.nanos)
    }
}

fn copy_field(field: &mut [u8], value: &[u8]) {
    field.fill(0);
    let count = field.len().min(value.len());
    field[..count].copy_from_slice(&value[..count]);
}

/// Writes a full ustar header for `meta`, emitting GNU longname/longlink extension entries first
/// when the path or link target exceeds the 100-byte fields.
fn write_header(sink: &mut Vec<u8>, meta: HeaderView<'_>) -> Result<()> {
    let typeflag = typeflag_for(meta.kind)?;

    if meta.path.len() > 100 {
        write_gnu_ext(sink, b'L', meta.path)?;
    }
    if let Some(link) = meta.link_target {
        if link.len() > 100 {
            write_gnu_ext(sink, b'K', link)?;
        }
    }

    let mut h = [0u8; BLOCK];
    let name = &meta.path[..meta.path.len().min(100)];
    h[..name.len()].copy_from_slice(name);
    put_octal(&mut h[F_MODE.0..F_MODE.1], u64::from(meta.mode & 0o7777))?;
    put_octal(&mut h[F_UID.0..F_UID.1], meta.uid)?;
    put_octal(&mut h[F_GID.0..F_GID.1], meta.gid)?;
    put_octal(&mut h[F_SIZE.0..F_SIZE.1], meta.size)?;
    let mtime = meta
        .modified
        .map_or(0, |t| u64::try_from(t.secs.max(0)).unwrap_or(0));
    put_octal(&mut h[F_MTIME.0..F_MTIME.1], mtime)?;
    h[O_TYPEFLAG] = typeflag;
    if let Some(link) = meta.link_target {
        let l = &link[..link.len().min(100)];
        h[F_LINKNAME.0..F_LINKNAME.0 + l.len()].copy_from_slice(l);
    }
    h[F_MAGIC.0..F_MAGIC.0 + 5].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    write_checksum(&mut h)?;
    sink.extend_from_slice(&h);
    Ok(())
}

/// Writes a GNU extension entry (`'L'` longname / `'K'` longlink) carrying `data` as its payload.
fn write_gnu_ext(sink: &mut Vec<u8>, flag: u8, data: &[u8]) -> Result<()> {
    let mut h = [0u8; BLOCK];
    let magic_name = b"././@LongLink";
    h[..magic_name.len()].copy_from_slice(magic_name);
    put_octal(&mut h[F_MODE.0..F_MODE.1], 0)?;
    put_octal(&mut h[F_UID.0..F_UID.1], 0)?;
    put_octal(&mut h[F_GID.0..F_GID.1], 0)?;
    let size = data.len() as u64 + 1; // include the trailing NUL
    put_octal(&mut h[F_SIZE.0..F_SIZE.1], size)?;
    put_octal(&mut h[F_MTIME.0..F_MTIME.1], 0)?;
    h[O_TYPEFLAG] = flag;
    h[F_MAGIC.0..F_MAGIC.0 + 5].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    write_checksum(&mut h)?;
    sink.extend_from_slice(&h);

    sink.extend_from_slice(data);
    sink.push(0); // NUL terminator
    let total = data.len() + 1;
    write_zeros(sink, round_up(size)? - total)
}

/// Computes and writes the ustar header checksum (6 octal digits + NUL + space).
fn write_checksum(h: &mut [u8; BLOCK]) -> Result<()> {
    for b in &mut h[F_CHKSUM.0..F_CHKSUM.1] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    put_octal(&mut h[F_CHKSUM.0..F_CHKSUM.1 - 1], sum)?;
    h[F_CHKSUM.1 - 1] = b' ';
    Ok(())
}

/// Writes `val` as a numeric field: zero-padded octal + NUL when it fits, otherwise the GNU
/// base-256 encoding (dual of [`parse_numeric`]'s two branches), so any value the reader accepts
/// can be written back.
fn put_octal(field: &mut [u8], val: u64) -> Result<()> {
    let n = field.len();
    // `n - 1` octal digits fit if the value needs at most that many.
    if fits_octal(val, n - 1) {
        field[n - 1] = 0;
        let mut v = val;
        for slot in field[..n - 1].iter_mut().rev() {
            *slot = b'0' + u8::try_from(v & 7).unwrap_or(0);
            v >>= 3;
        }
        Ok(())
    } else {
        put_base256(field, val)
    }
}

/// Whether `val` fits in `digits` octal digits.
fn fits_octal(val: u64, digits: usize) -> bool {
    digits >= 22 || val < 1u64 << (3 * digits)
}

/// Encodes `val` as GNU base-256: the first byte's high bit marks it, the value is stored
/// big-endian in the remaining bytes.
fn put_base256(field: &mut [u8], val: u64) -> Result<()> {
    let n = field.len();
    let capacity = n - 1; // bytes available after the marker byte
    let bytes = val.to_be_bytes();
    if capacity < 8 && bytes[..8 - capacity].iter().any(|&b| b != 0) {
        return Err(Error::Unsupported("tar: value too large for numeric field"));
    }
    field.fill(0);
    field[0] = 0x80;
    let take = capacity.min(8);
    field[n - take..].copy_from_slice(&bytes[8 - take..]);
    Ok(())
}

/// Maps a typed [`EntryKind`] to a ustar typeflag byte.
fn typeflag_for(kind: EntryKind) -> Result<u8> {
    Ok(match kind {
        EntryKind::File => b'0',
        EntryKind::Dir => b'5',
        EntryKind::Symlink => b'2',
        EntryKind::Hardlink => b'1',
        EntryKind::Char => b'3',
        EntryKind::Block => b'4',
        EntryKind::Fifo => b'6',
        _ => return Err(Error::Unsupported("tar: unsupported entry kind for write")),
    })
}

/// Appends `count` zero bytes to an encoder staging buffer.
fn write_zeros(sink: &mut Vec<u8>, count: usize) -> Result<()> {
    let new_len = sink
        .len()
        .checked_add(count)
        .ok_or(Error::LimitExceeded("tar output length overflow"))?;
    sink.resize(new_len, 0);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn octal_and_base256() {
        assert_eq!(parse_numeric(b"0000644\0").unwrap(), 0o644);
        assert_eq!(parse_numeric(b"        ").unwrap(), 0);
        assert_eq!(parse_numeric(b"00000000144\0").unwrap(), 0o144);
        // base-256: 0x80 marker + big-endian 0x00000100 = 256.
        assert_eq!(parse_numeric(&[0x80, 0, 0, 1, 0]).unwrap(), 256);
    }

    #[test]
    fn round_up_blocks() {
        assert_eq!(round_up(0).unwrap(), 0);
        assert_eq!(round_up(1).unwrap(), 512);
        assert_eq!(round_up(512).unwrap(), 512);
        assert_eq!(round_up(513).unwrap(), 1024);
    }

    #[test]
    fn pax_time_fractional() {
        let t = parse_pax_time(b"1700000000.5").unwrap();
        assert_eq!(t.secs, 1_700_000_000);
        assert_eq!(t.nanos, 500_000_000);
    }

    #[test]
    fn base256_overflow_is_rejected() {
        // 0x80 marker, then 0x01 followed by zeros = 1 << (8*n), which overflows u64.
        let field = [0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_numeric(&field).is_err());
    }

    #[test]
    fn put_octal_falls_back_to_base256() {
        // 10 GiB does not fit the 12-byte octal size field, so base-256 is used and round-trips.
        let mut size = [0u8; 12];
        put_octal(&mut size, 10_737_418_240).unwrap();
        assert_eq!(size[0] & 0x80, 0x80, "base-256 marker set");
        assert_eq!(parse_numeric(&size).unwrap(), 10_737_418_240);

        // A small value still uses plain octal.
        let mut mode = [0u8; 8];
        put_octal(&mut mode, 0o644).unwrap();
        assert_eq!(mode[0], b'0');
        assert_eq!(parse_numeric(&mode).unwrap(), 0o644);

        // A uid beyond 7 octal digits round-trips via base-256.
        let mut uid = [0u8; 8];
        put_octal(&mut uid, 3_000_000).unwrap();
        assert_eq!(parse_numeric(&uid).unwrap(), 3_000_000);
    }

    #[test]
    fn pax_malformed_record_does_not_panic() {
        let mut o = Overrides::default();
        // len == sp + 1: the off-by-one that used to panic in `record[sp + 1..len - 1]`.
        assert!(parse_pax(b"2 ", &mut o).is_err());
        assert!(parse_pax(b"1 ", &mut o).is_err());
        // A well-formed record still parses.
        assert!(parse_pax(b"11 path=ab\n", &mut o).is_ok());
        assert_eq!(o.path.as_deref(), Some(&b"ab"[..]));
    }
}
