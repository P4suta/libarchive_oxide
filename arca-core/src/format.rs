//! Format axis: filtered byte stream ⇄ structured entries.
//!
//! The format layer is **orthogonal** to the filter layer and knows nothing about
//! compression. Read/write polymorphism is expressed via the
//! [`EntryReader`]/[`EntryWriter`] trait objects, which form a
//! category-theoretic dual.
//!
//! # Borrow-checked no-seek model
//!
//! [`EntryReader::next_entry`] returns an [`Entry`] that borrows `&mut self`. Therefore
//! **you cannot advance to the next entry until you have read the entry's data to completion and dropped the `Entry`**,
//! which is guaranteed at compile time. A type-level win over C's `void*` + procedural convention. No seek required.

use crate::meta::EntryMeta;
use crate::Result;
use core::fmt;

pub mod cpio;
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

/// A streaming reader that pulls one entry at a time from an archive.
pub trait EntryReader {
    /// Return the next entry, or `None` when the end has been reached.
    ///
    /// The returned [`Entry`] mutably borrows `self`, so you cannot advance until you have read its data to completion.
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>>;
}

/// A single entry lent out by the reader. Holds the metadata and the payload stream.
///
/// The lifetime `'r` mutably borrows the parent reader, upholding the no-seek invariant at the type level.
pub struct Entry<'r> {
    meta: EntryMeta<'r>,
    data: &'r mut dyn EntryData,
}

impl fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The payload stream is opaque, so we show only the meta.
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl<'r> Entry<'r> {
    /// Assemble an entry from metadata and a payload stream (used by format implementations).
    pub fn new(meta: EntryMeta<'r>, data: &'r mut dyn EntryData) -> Self {
        Self { meta, data }
    }

    /// The entry's metadata.
    #[must_use]
    pub fn meta(&self) -> &EntryMeta<'r> {
        &self.meta
    }

    /// The sans-IO stream of the entry's body.
    pub fn data(&mut self) -> &mut dyn EntryData {
        self.data
    }
}

/// sans-IO writing of an entry's body (payload). The dual of [`EntryData`].
pub trait EntryDataSink {
    /// Write entry bytes.
    fn write_chunk(&mut self, data: &[u8]) -> Result<()>;

    /// Finalize the writing of this entry.
    fn close(&mut self) -> Result<()>;
}

/// A streaming writer that writes one entry at a time into an archive. The dual of [`EntryReader`].
pub trait EntryWriter {
    /// Begin writing an entry given its metadata, and lend out the body sink.
    ///
    /// The returned [`EntrySink`] mutably borrows `self`, so you cannot begin the next entry until it is finalized.
    fn start_entry(&mut self, meta: &EntryMeta<'_>) -> Result<EntrySink<'_>>;

    /// Finalize the whole archive (write the trailing blocks, etc.).
    fn finish(&mut self) -> Result<()>;
}

/// The body sink of a single entry lent out by the writer. The dual of [`Entry`].
pub struct EntrySink<'w> {
    inner: &'w mut dyn EntryDataSink,
}

impl fmt::Debug for EntrySink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySink").finish_non_exhaustive()
    }
}

impl<'w> EntrySink<'w> {
    /// Assemble an entry sink from a body sink (used by format implementations).
    pub fn new(inner: &'w mut dyn EntryDataSink) -> Self {
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
