//! tar format (ustar / pax / GNU).
//!
//! **P1**: Implements slice-based reading. Establishes here the borrow-checked
//! `Entry` model frozen in P0 (`Entry<'r>` mutably borrows the reader and cannot
//! advance until the payload is fully read) together with `EntryData` (sans-IO
//! pull of the payload).
//!
//! Supported: ustar (`prefix`+`name` join), octal / base-256 numerics, checksum
//! verification, PAX extensions (`x` for the next entry / `g` global), GNU
//! longname/longlink (`L`/`K`), archive end (zero blocks). GNU sparse (`S`) is
//! currently `Unsupported` (out of scope for P1).
//!
//! Two source models coexist, both additive over the same frozen traits:
//! [`TarReader`] over an **in-memory slice** (`&[u8]`) — the std layer typically
//! mmaps a file and hands over a `&[u8]` — and [`TarSource`], the incremental,
//! caller-fed sans-IO [`EntrySource`] that accepts the
//! archive in arbitrarily small pushes and reuses every field/record parser here.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::mem;

use crate::error::{Error, Result};
use crate::format::{
    ArchiveFormat, Detection, Entry, EntryDataSink, EntryReader, EntrySink, EntrySource,
    EntryWriter, SliceData, SourceEvent,
};
use crate::io::Sink;
use crate::meta::{EntryKind, EntryMeta, Timestamp};

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
const F_PREFIX: (usize, usize) = (345, 500);

/// Detection anchor for the tar format (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct Tar;

impl ArchiveFormat for Tar {
    const NAME: &'static str = "tar";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < F_MAGIC.1 {
            // v7 tar has no magic, so here we can only be certain about ustar/pax/GNU.
            return Detection::NeedMore;
        }
        if prefix[F_MAGIC.0..F_MAGIC.0 + 5] == *b"ustar" {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// Overrides that a preceding header (PAX / GNU longname) imposes on the next entry or on all entries.
#[derive(Debug, Default, Clone)]
struct Overrides<'a> {
    path: Option<Cow<'a, [u8]>>,
    linkpath: Option<Cow<'a, [u8]>>,
    size: Option<u64>,
    mtime: Option<Timestamp>,
    uid: Option<u64>,
    gid: Option<u64>,
}

/// Owned overrides for the incremental [`TarSource`]: the same struct instantiated at `'static`.
///
/// `Overrides` is already generic over the `Cow` lifetime, so pinning it to `'static` yields an
/// owned-only variant with **zero duplicated code** — the cleaner of the two options in the plan
/// (a hand-written twin struct would just re-list the same six fields). The slice [`TarReader`]
/// borrows PAX/long-name bytes straight from the archive slice (`Overrides<'a>`); the source cannot,
/// because its accumulation buffer is compacted between entries, so it merges each parsed record's
/// values into `OwnedOverrides` via an explicit `into_owned` clone (see [`merge_owned`]).
type OwnedOverrides = Overrides<'static>;

/// tar streaming reader (over an in-memory slice).
#[derive(Debug)]
pub struct TarReader<'a> {
    data: &'a [u8],
    pos: usize,
    payload: SliceData<'a>,
    pending: Overrides<'a>,
    global: Overrides<'a>,
    ended: bool,
}

impl<'a> TarReader<'a> {
    /// Builds a reader from the entire post-filter archive byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            payload: SliceData::default(),
            pending: Overrides::default(),
            global: Overrides::default(),
            ended: false,
        }
    }

    /// Slices out `len` bytes of payload/record starting at `start`, with bounds checking.
    fn slice(data: &'a [u8], start: usize, len: usize) -> Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or(Error::Malformed("offset overflow"))?;
        data.get(start..end)
            .ok_or(Error::Malformed("truncated data"))
    }

    /// Builds the metadata for a real entry from the given header. Consumes `pending`.
    fn build_meta(&mut self, hdr: &'a [u8], typeflag: u8) -> Result<EntryMeta<'a>> {
        let kind = kind_from_typeflag(typeflag)?;

        let name = cstr(field(hdr, F_NAME));
        let prefix = cstr(field(hdr, F_PREFIX));
        let is_ustar = field(hdr, F_MAGIC).starts_with(b"ustar");

        let path =
            take_first(&mut self.pending.path, self.global.path.as_ref()).unwrap_or_else(|| {
                if is_ustar && !prefix.is_empty() {
                    join_prefix_name(prefix, name)
                } else {
                    Cow::Borrowed(name)
                }
            });

        let link_target = match kind {
            EntryKind::Symlink | EntryKind::Hardlink => Some(
                take_first(&mut self.pending.linkpath, self.global.linkpath.as_ref())
                    .unwrap_or_else(|| Cow::Borrowed(cstr(field(hdr, F_LINKNAME)))),
            ),
            _ => None,
        };

        let size = self
            .pending
            .size
            .or(self.global.size)
            .map_or_else(|| parse_numeric(field(hdr, F_SIZE)), Ok)?;

        let mtime = self.pending.mtime.or(self.global.mtime).or_else(|| {
            parse_numeric(field(hdr, F_MTIME))
                .ok()
                .map(|secs| Timestamp {
                    secs: i64::try_from(secs).unwrap_or(i64::MAX),
                    nanos: 0,
                })
        });

        let uid = self
            .pending
            .uid
            .or(self.global.uid)
            .map_or_else(|| parse_numeric(field(hdr, F_UID)), Ok)?;
        let gid = self
            .pending
            .gid
            .or(self.global.gid)
            .map_or_else(|| parse_numeric(field(hdr, F_GID)), Ok)?;

        let mode = u32::try_from(parse_numeric(field(hdr, F_MODE))? & 0o7777).unwrap_or(0);

        Ok(EntryMeta {
            kind,
            path,
            mode,
            uid,
            gid,
            mtime,
            size,
            link_target,
            pax: crate::meta::PaxMap::new(),
        })
    }
}

impl<'a> EntryReader for TarReader<'a> {
    type Data = SliceData<'a>;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, SliceData<'a>>>> {
        if self.ended {
            return Ok(None);
        }
        // `&'a [u8]` is Copy. Because it can be treated as a 'a slice independent of self,
        // the header-derived borrow (metadata) does not conflict with the mutable borrow of self.payload.
        let data = self.data;

        loop {
            // If a single header block does not fit, treat it as the end.
            if self.pos + BLOCK > data.len() {
                self.ended = true;
                return Ok(None);
            }
            let hdr = &data[self.pos..self.pos + BLOCK];

            // Zero block = archive end.
            if hdr.iter().all(|&b| b == 0) {
                self.ended = true;
                return Ok(None);
            }

            verify_checksum(hdr)?;

            let typeflag = hdr[O_TYPEFLAG];
            let raw_size = parse_numeric(field(hdr, F_SIZE))?;
            let data_start = self.pos + BLOCK;
            let next_pos = data_start
                .checked_add(round_up(raw_size)?)
                .ok_or(Error::Malformed("size overflow"))?;

            match typeflag {
                // PAX extended header (x = for the next entry / g = global).
                b'x' | b'X' | b'g' => {
                    let records = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    let target = if typeflag == b'g' {
                        &mut self.global
                    } else {
                        &mut self.pending
                    };
                    parse_pax(records, target)?;
                    self.pos = next_pos;
                },
                // GNU longname / longlink: the whole data is the next entry's name / link name.
                b'L' => {
                    let raw = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    self.pending.path = Some(Cow::Borrowed(cstr(raw)));
                    self.pos = next_pos;
                },
                b'K' => {
                    let raw = Self::slice(data, data_start, usize_of(raw_size)?)?;
                    self.pending.linkpath = Some(Cow::Borrowed(cstr(raw)));
                    self.pos = next_pos;
                },
                // Real entry.
                _ => {
                    let meta = self.build_meta(hdr, typeflag)?;
                    let len = usize_of(meta.size)?;
                    // Guarantee that the payload is within bounds.
                    let _ = Self::slice(data, data_start, len)?;
                    self.payload = SliceData::new(data, data_start, len);
                    self.pos = data_start
                        .checked_add(round_up(meta.size)?)
                        .ok_or(Error::Malformed("size overflow"))?;
                    self.pending = Overrides::default();
                    return Ok(Some(Entry::new(meta, &mut self.payload)));
                },
            }
        }
    }
}

// ── Incremental sans-IO source (Phase 4) ────────────────────────────────────────────────────────

/// Which kind of extended / long header the [`TarSource`] is currently accumulating.
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

/// The [`TarSource`] driver state. `Copy` so `pull` can read it out of `self`, mutate the other
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
    /// The archive has ended.
    Done,
}

/// The outcome of driving one state, before the (possibly buffer-borrowing) event is materialized.
/// `Entry` and `Data` carry no data here — their borrowed payload is built in [`TarSource::pull`]
/// from staged fields, keeping each state method free of a self-borrow it would have to return.
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

/// Incremental, sans-IO tar reader — the [`EntrySource`] reference implementation.
///
/// It reuses **every** field / record parser the slice [`TarReader`] uses (`field`, `cstr`,
/// `parse_numeric`, `verify_checksum`, `kind_from_typeflag`, `join_prefix_name`, `round_up`,
/// `parse_pax`, `apply_pax`, `parse_pax_time`); only the driver — a state machine over a growing
/// `Vec<u8>` with a read cursor — is new. Bytes arrive via [`feed`](EntrySource::feed) in any
/// chunking (down to a single byte); [`pull`](EntrySource::pull) emits events borrowing the internal
/// buffer, which is compacted (`drain(..cursor)`) at the top of every [`pull`](EntrySource::pull) —
/// reclaiming the bytes the previous event consumed, including each payload window mid-entry — so the
/// resident size stays bounded (about one in-flight window plus not-yet-consumed fed bytes),
/// independent of total entry size.
///
/// A future `enum AnySource { Tar, Cpio, Ar }` (the shape of [`AnyReader`](crate::format::AnyReader))
/// could wrap this and forward the three methods by exhaustive `match`, with no type erasure — this
/// type is deliberately a plain concrete implementor to make that wrapping trivial.
#[derive(Debug)]
pub struct TarSource {
    /// Growing accumulation buffer of fed archive bytes.
    buf: Vec<u8>,
    /// Read position within `buf`; bytes before it are consumed and reclaimed on compaction.
    cursor: usize,
    /// Driver state.
    state: State,
    /// Whether `finish_input` has been called (no more bytes will arrive).
    finished: bool,
    /// Overrides captured for the *next* real entry (PAX `x`, GNU `L`/`K`).
    pending: OwnedOverrides,
    /// Global overrides (PAX `g`) applying to all subsequent entries.
    global: OwnedOverrides,
    /// Accumulator for the current extended / long header record (may span feeds).
    record: Vec<u8>,
    /// Overrides taken for the entry whose header was just parsed, staged for [`Poll::Entry`].
    stage_pending: OwnedOverrides,
    /// Payload size of the entry staged for [`Poll::Entry`].
    stage_size: u64,
    /// Length of the payload window staged for [`Poll::Data`] (it ends at `cursor`).
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
    pub fn new() -> Self {
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
            stage_len: 0,
        }
    }

    /// Bytes available past the cursor.
    fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Bytes currently held in the internal accumulation buffer (consumed-but-not-yet-reclaimed plus
    /// unconsumed). Compaction at the top of each [`pull`](EntrySource::pull) keeps this bounded to
    /// roughly one in-flight window plus not-yet-consumed fed bytes, independent of entry size — a
    /// hook for callers that want to apply their own feed backpressure, and for asserting the bound.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Drop consumed bytes and reset the cursor. Sound only when no event borrow is outstanding,
    /// which holds at the top of every [`pull`](EntrySource::pull) — the sole call site — because
    /// the previous event's borrow has ended by then.
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
                self.cursor = hdr_start + BLOCK;
                self.state = State::Payload {
                    remaining: size,
                    pad,
                };
                self.stage_pending = pending;
                self.stage_size = size;
                Ok(Poll::Entry)
            },
        }
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
            let want = usize_of(remaining)?.min(avail);
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
}

impl EntrySource for TarSource {
    fn feed(&mut self, input: &[u8]) -> Result<usize> {
        // We accept the whole slice: the buffer is compacted between entries, so it never holds more
        // than the in-flight entry window plus the current header/record — no backpressure needed.
        self.buf.extend_from_slice(input);
        Ok(input.len())
    }

    fn finish_input(&mut self) {
        self.finished = true;
    }

    fn pull(&mut self) -> Result<SourceEvent<'_>> {
        // Reclaim every byte consumed by the previous event before producing the next one. The
        // event returned by the prior `pull` borrowed `buf`; that borrow has ended (this method
        // takes `&mut self`), so draining `..cursor` here is sound and keeps residency bounded to
        // one in-flight window plus not-yet-consumed fed bytes, no matter how large the entry is.
        self.compact();
        loop {
            // Drive the current state. `Continue` loops; the terminal outcomes return an event.
            // `Entry`/`Data` events borrow the buffer, so they are materialized here from the
            // fields the state method staged, once all mutation is done.
            let poll = match self.state {
                State::Done => return Ok(SourceEvent::Done),
                State::Header => self.poll_header()?,
                State::Meta { kind, data, pad } => self.poll_meta(kind, data, pad)?,
                State::Payload { remaining, pad } => self.poll_payload(remaining, pad)?,
            };
            match poll {
                Poll::Continue => {},
                Poll::NeedInput => return Ok(SourceEvent::NeedInput),
                Poll::Done => return Ok(SourceEvent::Done),
                Poll::EndEntry => return Ok(SourceEvent::EndEntry),
                Poll::Entry => {
                    // `poll_header` advanced the cursor to just past this header block.
                    let start = self.cursor - BLOCK;
                    let hdr = &self.buf[start..start + BLOCK];
                    let meta =
                        build_source_meta(hdr, &self.stage_pending, &self.global, self.stage_size)?;
                    return Ok(SourceEvent::Entry(meta));
                },
                Poll::Data => {
                    // `poll_payload` advanced the cursor to the window's end.
                    let from = self.cursor - self.stage_len;
                    return Ok(SourceEvent::Data(&self.buf[from..self.cursor]));
                },
            }
        }
    }
}

/// Builds an [`EntryMeta`] for a real entry from its header block (`hdr`, borrowed from the source's
/// buffer) and the owned overrides. Non-overridden path / link fields borrow `hdr` (zero-copy);
/// overridden ones are cloned to owned, so the result borrows only `hdr`, never the overrides (which
/// are locals or fields the caller keeps mutating). Mirrors [`TarReader::build_meta`] field-for-field.
fn build_source_meta<'s>(
    hdr: &'s [u8],
    pending: &OwnedOverrides,
    global: &OwnedOverrides,
    size: u64,
) -> Result<EntryMeta<'s>> {
    let kind = kind_from_typeflag(hdr[O_TYPEFLAG])?;

    let name = cstr(field(hdr, F_NAME));
    let prefix = cstr(field(hdr, F_PREFIX));
    let is_ustar = field(hdr, F_MAGIC).starts_with(b"ustar");

    let path = match pending.path.as_ref().or(global.path.as_ref()) {
        Some(p) => Cow::Owned(p.clone().into_owned()),
        None => {
            if is_ustar && !prefix.is_empty() {
                join_prefix_name(prefix, name)
            } else {
                Cow::Borrowed(name)
            }
        },
    };

    let link_target = match kind {
        EntryKind::Symlink | EntryKind::Hardlink => Some(
            match pending.linkpath.as_ref().or(global.linkpath.as_ref()) {
                Some(l) => Cow::Owned(l.clone().into_owned()),
                None => Cow::Borrowed(cstr(field(hdr, F_LINKNAME))),
            },
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

    Ok(EntryMeta {
        kind,
        path,
        mode,
        uid,
        gid,
        mtime,
        size,
        link_target,
        pax: crate::meta::PaxMap::new(),
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
    if let Some(v) = src.uid {
        dst.uid = Some(v);
    }
    if let Some(v) = src.gid {
        dst.gid = Some(v);
    }
}

/// tar streaming writer — the dual of [`TarReader`]. Emits ustar headers (with GNU longname/
/// longlink for names over 100 bytes) into a [`Sink`], padding each entry and the trailer.
///
/// The declared `size` comes from `EntryMeta`, so the header is written up front at `start_entry`;
/// the payload is then streamed via the lent [`EntrySink`], and `close` pads to the block boundary.
#[derive(Debug)]
pub struct TarWriter<W: Sink> {
    sink: W,
    /// Bytes still expected for the currently open entry.
    remaining: u64,
    /// Zero padding owed after the current entry's payload.
    pad: usize,
    /// Whether an entry is open (its `EntrySink` not yet closed).
    open: bool,
}

impl<W: Sink> TarWriter<W> {
    /// Builds a writer over a byte sink.
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            remaining: 0,
            pad: 0,
            open: false,
        }
    }

    /// Consumes the writer and returns the underlying sink.
    pub fn into_inner(self) -> W {
        self.sink
    }
}

impl<W: Sink> EntryWriter for TarWriter<W> {
    type Sink = Self;

    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self>> {
        if self.open {
            return Err(Error::InvalidState("tar: previous entry not closed"));
        }
        write_header(&mut self.sink, meta)?;
        self.remaining = meta.size;
        self.pad = round_up(meta.size)? - usize_of(meta.size)?;
        self.open = true;
        Ok(EntrySink::new(self))
    }

    fn finish(&mut self) -> Result<()> {
        if self.open {
            return Err(Error::InvalidState("tar: entry open at finish"));
        }
        write_zeros(&mut self.sink, 2 * BLOCK)
    }
}

impl<W: Sink> EntryDataSink for TarWriter<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.remaining {
            return Err(Error::InvalidState("tar: payload exceeds declared size"));
        }
        self.sink.write_all(data)?;
        self.remaining -= data.len() as u64;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::InvalidState(
                "tar: payload shorter than declared size",
            ));
        }
        write_zeros(&mut self.sink, self.pad)?;
        self.pad = 0;
        self.open = false;
        Ok(())
    }
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

/// Prefers `pending` (take); if absent, returns `global` (clone).
fn take_first<'a>(
    pending: &mut Option<Cow<'a, [u8]>>,
    global: Option<&Cow<'a, [u8]>>,
) -> Option<Cow<'a, [u8]>> {
    pending.take().or_else(|| global.cloned())
}

/// Maps a typeflag to a typed kind. `'0'`/`'\0'`/`'7'` and unknown values are treated as regular files (tar convention).
fn kind_from_typeflag(tf: u8) -> Result<EntryKind> {
    Ok(match tf {
        b'5' => EntryKind::Dir,
        b'1' => EntryKind::Hardlink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::Char,
        b'4' => EntryKind::Block,
        b'6' => EntryKind::Fifo,
        b'S' => return Err(Error::Unsupported("GNU sparse tar entry")),
        _ => EntryKind::File,
    })
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
    match key {
        b"path" => into.path = Some(Cow::Borrowed(value)),
        b"linkpath" => into.linkpath = Some(Cow::Borrowed(value)),
        b"size" => into.size = Some(ascii_decimal(value)? as u64),
        b"uid" => into.uid = Some(ascii_decimal(value)? as u64),
        b"gid" => into.gid = Some(ascii_decimal(value)? as u64),
        b"mtime" => into.mtime = Some(parse_pax_time(value)?),
        _ => {}, // atime/ctime/uname/gname etc. are ignored in P1.
    }
    Ok(())
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

/// Parses a PAX mtime (`"secs"` or `"secs.nanos"`).
fn parse_pax_time(value: &[u8]) -> Result<Timestamp> {
    let (secs_part, frac_part) = match value.iter().position(|&b| b == b'.') {
        Some(dot) => (&value[..dot], &value[dot + 1..]),
        None => (value, &b""[..]),
    };
    let secs = i64::try_from(ascii_decimal(secs_part)?).unwrap_or(i64::MAX);
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
    Ok(Timestamp { secs, nanos })
}

// ── Writer helpers (dual of the reader's field parsing) ────────────────────────────────────────

/// Writes a full ustar header for `meta`, emitting GNU longname/longlink extension entries first
/// when the path or link target exceeds the 100-byte fields.
fn write_header<W: Sink>(sink: &mut W, meta: &EntryMeta<'_>) -> Result<()> {
    let typeflag = typeflag_for(meta.kind)?;

    if meta.path.len() > 100 {
        write_gnu_ext(sink, b'L', &meta.path)?;
    }
    if let Some(link) = &meta.link_target {
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
        .mtime
        .map_or(0, |t| u64::try_from(t.secs.max(0)).unwrap_or(0));
    put_octal(&mut h[F_MTIME.0..F_MTIME.1], mtime)?;
    h[O_TYPEFLAG] = typeflag;
    if let Some(link) = &meta.link_target {
        let l = &link[..link.len().min(100)];
        h[F_LINKNAME.0..F_LINKNAME.0 + l.len()].copy_from_slice(l);
    }
    h[F_MAGIC.0..F_MAGIC.0 + 5].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    write_checksum(&mut h)?;
    sink.write_all(&h)
}

/// Writes a GNU extension entry (`'L'` longname / `'K'` longlink) carrying `data` as its payload.
fn write_gnu_ext<W: Sink>(sink: &mut W, flag: u8, data: &[u8]) -> Result<()> {
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
    sink.write_all(&h)?;

    sink.write_all(data)?;
    sink.write_all(&[0u8])?; // NUL terminator
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

/// Writes `count` zero bytes to the sink, a block at a time.
fn write_zeros<W: Sink>(sink: &mut W, count: usize) -> Result<()> {
    const ZEROS: [u8; BLOCK] = [0; BLOCK];
    let mut left = count;
    while left > 0 {
        let n = left.min(BLOCK);
        sink.write_all(&ZEROS[..n])?;
        left -= n;
    }
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
