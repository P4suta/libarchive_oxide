// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive format traits and implementations.
//!
//! Formats consume uncompressed bytes. [`EntryReader::Data`] and
//! [`EntryWriter::Sink`] are associated types. Runtime selection uses
//! [`AnyReader`]. An [`Entry`] borrows its reader, so the reader cannot advance
//! while the entry is live.

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

/// Archive-format detection interface.
pub trait ArchiveFormat {
    /// Human-readable format name (for diagnostics).
    const NAME: &'static str;

    /// Determine from the head of the byte stream whether this is the format.
    fn sniff(prefix: &[u8]) -> Detection;
}

/// Sans-IO entry data reader.
pub trait EntryData {
    /// Pull decoded entry bytes into `out`. The return value is the amount produced. 0 means end of entry.
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize>;
}

/// Payload cursor used by slice-based readers.
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

/// Streaming archive reader.
pub trait EntryReader {
    /// Entry data type.
    type Data: EntryData;

    /// Returns the next entry.
    ///
    /// Returns `None` at end of archive. The returned [`Entry`] mutably borrows
    /// the reader.
    fn next_entry(&mut self) -> Result<Option<Entry<'_, Self::Data>>>;
}

/// Archive entry metadata and data.
pub struct Entry<'r, D: EntryData> {
    meta: EntryMeta<'r>,
    data: &'r mut D,
}

impl<D: EntryData> fmt::Debug for Entry<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid a `D: Debug` bound.
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl<'r, D: EntryData> Entry<'r, D> {
    /// Creates an entry.
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

/// Event returned by [`EntrySource`].
///
/// Events borrow the source until the next `feed` or `pull`. Reconstructed
/// metadata may be owned.
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

/// Incremental sans-IO archive reader.
///
/// [`feed`](EntrySource::feed) accepts bytes. [`pull`](EntrySource::pull)
/// returns structural events.
pub trait EntrySource {
    /// Appends input and returns the accepted byte count.
    fn feed(&mut self, input: &[u8]) -> Result<usize>;

    /// Marks end of input.
    fn finish_input(&mut self);

    /// Returns the next event.
    ///
    /// Returns [`SourceEvent::NeedInput`] when more input is required.
    fn pull(&mut self) -> Result<SourceEvent<'_>>;
}

/// sans-IO writing of an entry's body (payload). The dual of [`EntryData`].
pub trait EntryDataSink {
    /// Write entry bytes.
    fn write_chunk(&mut self, data: &[u8]) -> Result<()>;

    /// Finalize the writing of this entry.
    fn close(&mut self) -> Result<()>;
}

/// Streaming archive writer.
///
/// [`EntryWriter::Sink`] receives entry data. Writers are typically their own
/// sink.
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

/// Runtime-selected core reader implementation.
///
/// Readers are boxed to bound the enum size.
#[derive(Debug)]
enum AnyReaderKind<'a> {
    Tar(Box<TarReader<'a>>),
    Cpio(Box<CpioReader<'a>>),
    Ar(Box<ArReader<'a>>),
    Iso(Box<IsoReader<'a>>),
}

/// Runtime-selected core archive reader.
///
/// Implements [`EntryReader`] with [`AnyEntryData`].
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
