// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Format axis: filtered byte stream ⇄ structured entries.
//!
//! The format layer is **orthogonal** to the filter layer and knows nothing about
//! compression. Read/write polymorphism is expressed via the
//! [`EntryReader`]/[`EntryWriter`] traits, which form a category-theoretic dual.
//!
//! There is **zero type erasure** here: [`EntryReader::Data`] and [`EntryWriter::Sink`]
//! are associated types, and [`Entry`]/[`EntrySink`] are generic over the concrete payload
//! cursor/sink. Runtime format choice is expressed by the sealed [`AnyReader`] enum
//! (fully monomorphized, exhaustiveness compiler-checked) rather than a trait object.
//!
//! # Borrow-checked no-seek model
//!
//! [`EntryReader::next_entry`] returns an [`Entry`] that borrows `&mut self`. Therefore
//! **you cannot advance to the next entry until you have read the entry's data to completion and dropped the `Entry`**,
//! which is guaranteed at compile time. A type-level win over C's `void*` + procedural convention. No seek required.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::format::ar::ArReader;
use crate::format::cpio::CpioReader;
use crate::format::iso9660::IsoReader;
use crate::format::tar::TarReader;
use crate::meta::EntryMeta;
use crate::Result;
use core::fmt;

pub mod ar;
pub mod cpio;
pub mod iso9660;
pub mod tar;

/// Result of archive-format detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// We are confident this is the format.
    Match,
    /// This is not the format.
    NoMatch,
    /// More prefix bytes are needed to decide.
    NeedMore,
}

/// Detection anchor for an archive format (the entry point for the registry / auto-detection).
///
/// The concrete reading and writing is handled by types that implement [`EntryReader`]/[`EntryWriter`]. Thanks to this separation,
/// adding a new format is just "add a type that implements the same traits", leaving the existing traits unchanged.
pub trait ArchiveFormat {
    /// Human-readable format name (for diagnostics).
    const NAME: &'static str;

    /// Determine from the head of the byte stream whether this is the format.
    fn sniff(prefix: &[u8]) -> Detection;
}

/// sans-IO reading of an entry's body (payload).
///
/// Because it is `no_std`, it uses chunk pull rather than `std::io::Read`. On the std side we bridge it to `Read`.
pub trait EntryData {
    /// Pull decoded entry bytes into `out`. The return value is the amount produced. 0 means end of entry.
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize>;
}

/// A payload cursor over a byte slice, shared by the slice-based format readers
/// (`tar`, `cpio`, `ar`). `&'a [u8]` is `Copy`, so the whole cursor is `Copy`; a reader can
/// hold its own copy of the backing slice here without conflicting with borrows of the header
/// bytes, and [`AnyReader`] can lift it out of an inner entry by value when re-homing.
#[derive(Debug, Default, Clone, Copy)]
pub struct SliceData<'a> {
    bytes: &'a [u8],
    start: usize,
    len: usize,
    read: usize,
}

impl<'a> SliceData<'a> {
    /// A cursor over `bytes[start..start + len]`.
    #[must_use]
    pub fn new(bytes: &'a [u8], start: usize, len: usize) -> Self {
        Self {
            bytes,
            start,
            len,
            read: 0,
        }
    }
}

impl EntryData for SliceData<'_> {
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        let remaining = self.len - self.read;
        if remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let n = remaining.min(out.len());
        let from = self.start + self.read;
        out[..n].copy_from_slice(&self.bytes[from..from + n]);
        self.read += n;
        Ok(n)
    }
}

/// A payload cursor over an owned, already-decompressed buffer. Container formats whose entries
/// are individually decoded into memory (zip, 7z) materialize each entry here. It is `Default`
/// (empty), so [`AnyReader`] can `mem::take` it out of an inner entry when re-homing.
#[derive(Debug, Default)]
pub struct OwnedData {
    buf: Vec<u8>,
    pos: usize,
}

impl OwnedData {
    /// A cursor over an owned buffer, positioned at the start.
    #[must_use]
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf, pos: 0 }
    }

    /// The full backing buffer (regardless of read position).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
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

/// A streaming reader that pulls one entry at a time from an archive.
///
/// The payload cursor type is the associated [`EntryReader::Data`] — a concrete, statically known
/// [`EntryData`] (e.g. [`SliceData`] for the slice readers), never a trait object.
pub trait EntryReader {
    /// The concrete payload cursor this reader lends out.
    type Data: EntryData;

    /// Return the next entry, or `None` when the end has been reached.
    ///
    /// The returned [`Entry`] mutably borrows `self`, so you cannot advance until you have read its data to completion.
    fn next_entry(&mut self) -> Result<Option<Entry<'_, Self::Data>>>;
}

/// A single entry lent out by the reader. Holds the metadata and the payload stream.
///
/// The lifetime `'r` mutably borrows the parent reader, upholding the no-seek invariant at the
/// type level. `D` is the concrete payload cursor ([`EntryReader::Data`]).
pub struct Entry<'r, D: EntryData> {
    meta: EntryMeta<'r>,
    data: &'r mut D,
}

impl<D: EntryData> fmt::Debug for Entry<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The payload stream is opaque, so we show only the meta (no `D: Debug` bound required).
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl<'r, D: EntryData> Entry<'r, D> {
    /// Assemble an entry from metadata and a payload stream (used by format implementations).
    pub fn new(meta: EntryMeta<'r>, data: &'r mut D) -> Self {
        Self { meta, data }
    }

    /// The entry's metadata.
    #[must_use]
    pub fn meta(&self) -> &EntryMeta<'r> {
        &self.meta
    }

    /// The sans-IO stream of the entry's body.
    pub fn data(&mut self) -> &mut D {
        self.data
    }
}

/// A structural event yielded by an [`EntrySource`], borrowing the source's internal accumulation
/// buffer for `'s`.
///
/// # Lifetime
///
/// `SourceEvent<'s>` borrows **`&'s self`** — the source's growing internal buffer — not the slice
/// last handed to [`EntrySource::feed`] (that slice is copied into the buffer and need not outlive
/// the call). The borrow is stable only until the next `feed`/`pull`, exactly like the output slice
/// of a [`Transform`](crate::transform::Transform): consume the event before driving the source again.
///
/// [`SourceEvent::Entry`] paths that sit contiguously in the buffer are `Cow::Borrowed(&'s buf)`
/// (zero-copy); a path reassembled from a PAX record or a GNU long-name header is `Cow::Owned`
/// (the slice reader allocates at the very same points).
#[derive(Debug)]
pub enum SourceEvent<'s> {
    /// The source needs more bytes before it can produce the next event; call [`EntrySource::feed`].
    NeedInput,
    /// A new entry has begun. Its payload follows as zero or more [`SourceEvent::Data`] windows,
    /// terminated by [`SourceEvent::EndEntry`].
    Entry(EntryMeta<'s>),
    /// A window of the current entry's payload, borrowing the internal buffer.
    Data(&'s [u8]),
    /// The current entry's payload is complete.
    EndEntry,
    /// The archive has ended; further `pull` calls keep returning `Done`.
    Done,
}

/// Incremental, sans-IO reading of an archive from a caller-fed byte stream — the **format-axis dual
/// of [`Transform`](crate::transform::Transform)** (byte axis). Where a `Transform` maps
/// `Status{NeedInput, MoreOutput, Done}`,
/// a source enriches that with the structure a container format adds: [`SourceEvent::Entry`] /
/// [`SourceEvent::Data`] / [`SourceEvent::EndEntry`].
///
/// Unlike [`EntryReader`] (which needs the whole archive as one `&[u8]`), an `EntrySource` accepts
/// the archive in arbitrarily small pushes via [`feed`](EntrySource::feed) and yields events through
/// [`pull`](EntrySource::pull), holding only a bounded internal buffer (about one header block plus
/// the current extended-header record). It composes with the filter axis by feeding it the output of
/// an [`AnyDecoder`](crate::filter) — a fully monomorphized incremental pipeline with no trait objects.
///
/// This is additive: it does not touch the frozen [`EntryReader`]/[`EntryWriter`] algebra. Runtime
/// format choice would be expressed by a sealed `enum AnySource { Tar, Cpio, Ar }` (the shape of
/// [`AnyReader`]), never a trait object.
pub trait EntrySource {
    /// Append archive bytes to the internal buffer, returning how many were accepted (all of them).
    fn feed(&mut self, input: &[u8]) -> Result<usize>;

    /// Declare that no more bytes will be fed (end of the compressed/plain stream).
    fn finish_input(&mut self);

    /// Produce the next structural event, borrowing the internal buffer until the next
    /// `feed`/`pull`. Returns [`SourceEvent::NeedInput`] when starved (and input is not finished).
    fn pull(&mut self) -> Result<SourceEvent<'_>>;
}

/// sans-IO writing of an entry's body (payload). The dual of [`EntryData`].
pub trait EntryDataSink {
    /// Write entry bytes.
    fn write_chunk(&mut self, data: &[u8]) -> Result<()>;

    /// Finalize the writing of this entry.
    fn close(&mut self) -> Result<()>;
}

/// A streaming writer that writes one entry at a time into an archive. The dual of [`EntryReader`].
///
/// The body sink type is the associated [`EntryWriter::Sink`] — the dual of [`EntryReader::Data`].
/// A format writer is typically its own sink (`type Sink = Self`), so it is `?Sized`-tolerant for
/// symmetry with the reader side, but is always a concrete type, never a trait object.
pub trait EntryWriter {
    /// The concrete body sink this writer lends out (its dual is [`EntryReader::Data`]).
    type Sink: EntryDataSink + ?Sized;

    /// Begin writing an entry given its metadata, and lend out the body sink.
    ///
    /// The returned [`EntrySink`] mutably borrows `self`, so you cannot begin the next entry until it is finalized.
    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_, Self::Sink>>;

    /// Finalize the whole archive (write the trailing blocks, etc.).
    fn finish(&mut self) -> Result<()>;
}

/// The body sink of a single entry lent out by the writer. The dual of [`Entry`].
pub struct EntrySink<'w, S: EntryDataSink + ?Sized> {
    inner: &'w mut S,
}

impl<S: EntryDataSink + ?Sized> fmt::Debug for EntrySink<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySink").finish_non_exhaustive()
    }
}

impl<'w, S: EntryDataSink + ?Sized> EntrySink<'w, S> {
    /// Assemble an entry sink from a body sink (used by format implementations).
    pub fn new(inner: &'w mut S) -> Self {
        Self { inner }
    }

    /// Write body bytes.
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_chunk(data)
    }

    /// Finalize this entry.
    pub fn close(&mut self) -> Result<()> {
        self.inner.close()
    }
}

/// The payload cursor of whichever core (`no_std`) format is being read. The `EntryData` dual of
/// [`AnyReader`]: a sealed enum with one variant per cursor kind, so dispatch is fully
/// monomorphized (no type erasure) and adding a variant is a compiler-checked exhaustiveness obligation.
#[derive(Debug)]
pub enum AnyEntryData<'a> {
    /// A slice cursor (tar/cpio/ar).
    Slice(SliceData<'a>),
    /// An owned-buffer cursor (reserved for core container formats such as iso).
    Owned(OwnedData),
}

impl Default for AnyEntryData<'_> {
    fn default() -> Self {
        Self::Owned(OwnedData::default())
    }
}

impl EntryData for AnyEntryData<'_> {
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::Slice(d) => d.read_chunk(out),
            Self::Owned(d) => d.read_chunk(out),
        }
    }
}

/// The concrete kind of core archive reader, selected at runtime. Sealed: only the crate's own
/// formats appear, and the exhaustive `match` in [`AnyReader::next_entry`] fails to compile the
/// moment a variant is added without being handled.
///
/// Each inner reader is boxed (a `Box<Reader>`, an owning pointer — **not** a trait object): the
/// readers differ widely in size, so boxing keeps every variant one word wide and symmetric. The
/// single allocation happens once when the archive reader is constructed.
#[derive(Debug)]
enum AnyReaderKind<'a> {
    Tar(Box<TarReader<'a>>),
    Cpio(Box<CpioReader<'a>>),
    Ar(Box<ArReader<'a>>),
    Iso(Box<IsoReader<'a>>),
}

/// Runtime-selected core (`no_std`) archive reader, dispatched over a sealed enum with **zero type
/// erasure**. It is itself an [`EntryReader`] (`Data = AnyEntryData`), so it composes uniformly.
///
/// `next_entry` drives the chosen inner reader, then **re-homes** the entry into `self.slot`: the
/// metadata is deep-cloned into an owned, lifetime-independent [`EntryMeta`] and the payload cursor
/// is lifted out by value (`SliceData: Copy`, `OwnedData: Default` via `mem::take`). This one clone
/// per entry is the necessary cost of enum dispatch, not a shortcut.
#[derive(Debug)]
pub struct AnyReader<'a> {
    kind: AnyReaderKind<'a>,
    slot: AnyEntryData<'a>,
}

impl<'a> AnyReader<'a> {
    /// Wraps a tar reader.
    #[must_use]
    pub fn tar(reader: TarReader<'a>) -> Self {
        Self {
            kind: AnyReaderKind::Tar(Box::new(reader)),
            slot: AnyEntryData::default(),
        }
    }

    /// Wraps a cpio reader.
    #[must_use]
    pub fn cpio(reader: CpioReader<'a>) -> Self {
        Self {
            kind: AnyReaderKind::Cpio(Box::new(reader)),
            slot: AnyEntryData::default(),
        }
    }

    /// Wraps an ar reader.
    #[must_use]
    pub fn ar(reader: ArReader<'a>) -> Self {
        Self {
            kind: AnyReaderKind::Ar(Box::new(reader)),
            slot: AnyEntryData::default(),
        }
    }

    /// Wraps an iso9660 reader.
    #[must_use]
    pub fn iso(reader: IsoReader<'a>) -> Self {
        Self {
            kind: AnyReaderKind::Iso(Box::new(reader)),
            slot: AnyEntryData::default(),
        }
    }
}

impl<'a> EntryReader for AnyReader<'a> {
    type Data = AnyEntryData<'a>;

    fn next_entry(&mut self) -> Result<Option<Entry<'_, AnyEntryData<'a>>>> {
        // Re-home the inner entry into `self.slot`. Each inner reader lends a slice cursor, which is
        // `Copy`, so it is lifted out by value; the metadata is deep-cloned to an owned form that no
        // longer borrows the (now-released) inner reader borrow.
        let meta = match &mut self.kind {
            AnyReaderKind::Tar(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Slice(*e.data());
                    meta
                },
                None => return Ok(None),
            },
            AnyReaderKind::Cpio(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Slice(*e.data());
                    meta
                },
                None => return Ok(None),
            },
            AnyReaderKind::Ar(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Slice(*e.data());
                    meta
                },
                None => return Ok(None),
            },
            AnyReaderKind::Iso(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Slice(*e.data());
                    meta
                },
                None => return Ok(None),
            },
        };
        Ok(Some(Entry::new(meta, &mut self.slot)))
    }
}
