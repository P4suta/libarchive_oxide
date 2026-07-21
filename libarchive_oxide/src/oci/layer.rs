// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded reader for OCI image layers.
//!
//! [`OciLayerEngine`] opens a layer blob and returns an [`OciLayerSession`] that
//! streams entry descriptors one at a time while computing the compressed digest
//! and diffID in a single pass. No entry body and no compressed frame is
//! retained: hashing happens as bytes flow through nested [`HashingReader`]s
//! wrapped around the outer filter and the decoded tar stream.
//!
//! After the entries are consumed, [`OciLayerSession::digests`] returns the
//! finalized [`LayerDigests`] and [`OciLayerSession::verify`] compares them
//! against an expected pair.

use std::fmt;
use std::io::{self, Read};

use libarchive_oxide_core::{EntryKind, EntryMetadata, Limits};

use super::digest::{HashingReader, LayerDigests, SharedHasher, encode_hex};
use crate::filtered_io::FilterReader;
use crate::stream::{ArchiveReader, ReaderEvent, StreamError};

/// Scratch buffer size used to drain the compressed source to end-of-stream.
const DRAIN_BUFFER: usize = 64 * 1024;

/// The nested reader stack used by an [`OciLayerSession`].
///
/// From the inside out: the raw compressed input is wrapped by a hashing reader
/// (compressed digest), then the outer filter decompresses it, then a second
/// hashing reader (diffID) feeds the bounded tar reader.
type LayerReader<R> = ArchiveReader<HashingReader<FilterReader<HashingReader<R>>>>;

/// Configuration for reading OCI image layers.
#[derive(Debug, Clone, Copy)]
pub struct OciLayerEngine {
    limits: Limits,
}

impl OciLayerEngine {
    /// Creates an engine with safe finite resource limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
        }
    }

    /// Creates an engine with explicit resource limits.
    ///
    /// The limits bound the decoded (uncompressed) output of the outer filter,
    /// so a hostile layer cannot expand without limit while its diffID is
    /// computed.
    #[must_use]
    pub const fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }

    /// Resource limits used by this engine.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Opens a layer blob for bounded inspection and digest computation.
    ///
    /// The outer filter (none, gzip, or zstd) is auto-detected. The returned
    /// session streams entry descriptors and, once drained, yields the
    /// compressed digest and diffID.
    ///
    /// # Errors
    ///
    /// Returns an error if the outer filter prelude cannot be read or the
    /// detected filter is not enabled in the active codec profile.
    pub fn open<R: Read>(&self, reader: R) -> Result<OciLayerSession<R>, OciLayerError> {
        let compressed = SharedHasher::new();
        let diff_id = SharedHasher::new();
        let outer = HashingReader::new(reader, compressed.clone());
        let decompressed =
            FilterReader::with_limits(outer, self.limits).map_err(OciLayerError::Io)?;
        let inner = HashingReader::new(decompressed, diff_id.clone());
        // The decoded bytes are already plain tar; disabling filter detection on
        // the tar reader keeps this a single decompression pass.
        let tar_limits = self.limits.with_filter_depth(Some(0));
        let reader = ArchiveReader::with_limits(inner, tar_limits);
        Ok(OciLayerSession {
            reader: Some(reader),
            compressed,
            diff_id,
        })
    }
}

impl Default for OciLayerEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded, single-pass reader over one OCI image layer.
///
/// Entry descriptors are produced by [`next_entry`](Self::next_entry). Once the
/// layer is fully consumed, [`digests`](Self::digests) returns the finalized
/// digest pair. Both methods drive the same underlying stream, so the digests
/// always cover the entire compressed blob and its decoded tar bytes.
pub struct OciLayerSession<R: Read> {
    reader: Option<LayerReader<R>>,
    compressed: SharedHasher,
    diff_id: SharedHasher,
}

impl<R: Read> OciLayerSession<R> {
    /// Returns the next entry descriptor, or `None` once the layer ends.
    ///
    /// The entry body flows through the digest accumulators but is never
    /// buffered.
    ///
    /// # Errors
    ///
    /// Returns an error if the tar stream is malformed or the outer filter
    /// fails to decode.
    pub fn next_entry(&mut self) -> Result<Option<OciLayerEntry>, OciLayerError> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(None);
        };
        loop {
            match reader.next_event()? {
                ReaderEvent::Entry(metadata) => {
                    return Ok(Some(OciLayerEntry::from_metadata(&metadata)));
                },
                ReaderEvent::Done => return Ok(None),
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {
                },
            }
        }
    }

    /// Drains any remaining tar bytes and then the trailing compressed bytes so
    /// both digests cover the complete streams.
    fn finish(&mut self) -> Result<(), OciLayerError> {
        let Some(mut reader) = self.reader.take() else {
            return Ok(());
        };
        loop {
            match reader.next_event()? {
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_)
                | ReaderEvent::Entry(_)
                | ReaderEvent::Data(_)
                | ReaderEvent::EndEntry => {},
            }
        }
        // The tar decoder stops at the archive trailer, which may leave a few
        // trailing compressed bytes unread. Drain the raw source so the
        // compressed digest covers the entire blob.
        let mut source = reader.into_inner().into_inner().into_inner();
        let mut scratch = vec![0u8; DRAIN_BUFFER];
        loop {
            let read = source.read(&mut scratch).map_err(OciLayerError::Io)?;
            if read == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Finalizes and returns the compressed digest and diffID.
    ///
    /// Any entries not yet consumed are drained first, so this always reflects
    /// the whole layer.
    ///
    /// # Errors
    ///
    /// Returns an error if draining the remaining stream fails.
    pub fn digests(&mut self) -> Result<LayerDigests, OciLayerError> {
        self.finish()?;
        Ok(LayerDigests::from_bytes(
            self.compressed.finalize(),
            self.diff_id.finalize(),
        ))
    }

    /// Verifies the layer against an expected compressed digest and diffID.
    ///
    /// The compressed digest is checked first, then the diffID.
    ///
    /// # Errors
    ///
    /// Returns [`OciLayerError::DigestMismatch`] if either digest differs, or a
    /// stream error if draining fails.
    pub fn verify(&mut self, expected: LayerDigests) -> Result<(), OciLayerError> {
        let actual = self.digests()?;
        if actual.compressed() != expected.compressed() {
            return Err(OciLayerError::DigestMismatch(DigestMismatch {
                kind: DigestKind::Compressed,
                expected: *expected.compressed(),
                actual: *actual.compressed(),
            }));
        }
        if actual.diff_id() != expected.diff_id() {
            return Err(OciLayerError::DigestMismatch(DigestMismatch {
                kind: DigestKind::DiffId,
                expected: *expected.diff_id(),
                actual: *actual.diff_id(),
            }));
        }
        Ok(())
    }
}

impl<R: Read> fmt::Debug for OciLayerSession<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciLayerSession")
            .field("finished", &self.reader.is_none())
            .finish_non_exhaustive()
    }
}

/// A bounded descriptor for one entry in an OCI layer's tar stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayerEntry {
    path: Vec<u8>,
    kind: EntryKind,
    size: Option<u64>,
    link_target: Option<Vec<u8>>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
}

impl OciLayerEntry {
    /// Projects the streamed tar metadata into a bounded descriptor.
    fn from_metadata(metadata: &EntryMetadata) -> Self {
        Self {
            path: metadata.path().as_bytes().to_vec(),
            kind: metadata.kind(),
            size: metadata.size(),
            link_target: metadata
                .link_target()
                .map(|target| target.as_bytes().to_vec()),
            mode: metadata.mode(),
            uid: metadata.owner().uid,
            gid: metadata.owner().gid,
        }
    }

    /// Archive-native path bytes.
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Entry kind.
    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Declared body size, when known before streaming.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// Link target bytes for symbolic and hard links.
    #[must_use]
    pub fn link_target(&self) -> Option<&[u8]> {
        self.link_target.as_deref()
    }

    /// Unix permission bits, when present.
    #[must_use]
    pub const fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Numeric owner user id, when present.
    #[must_use]
    pub const fn uid(&self) -> Option<u64> {
        self.uid
    }

    /// Numeric owner group id, when present.
    #[must_use]
    pub const fn gid(&self) -> Option<u64> {
        self.gid
    }
}

/// Which digest failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestKind {
    /// The compressed-blob digest (OCI descriptor `digest`).
    Compressed,
    /// The uncompressed-stream digest (OCI `diffID`).
    DiffId,
}

impl DigestKind {
    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Compressed => "compressed digest",
            Self::DiffId => "diffID",
        }
    }
}

/// Details of a digest verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestMismatch {
    kind: DigestKind,
    expected: [u8; 32],
    actual: [u8; 32],
}

impl DigestMismatch {
    /// Which digest failed.
    #[must_use]
    pub const fn kind(self) -> DigestKind {
        self.kind
    }

    /// The expected digest bytes.
    #[must_use]
    pub const fn expected(&self) -> &[u8; 32] {
        &self.expected
    }

    /// The computed digest bytes.
    #[must_use]
    pub const fn actual(&self) -> &[u8; 32] {
        &self.actual
    }
}

impl fmt::Display for DigestMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} mismatch: expected sha256:{}, computed sha256:{}",
            self.kind.label(),
            encode_hex(self.expected),
            encode_hex(self.actual),
        )
    }
}

/// An error from reading, verifying, or applying an OCI layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum OciLayerError {
    /// The underlying archive stream failed to parse or decode.
    Stream(StreamError),
    /// An adapter I/O error occurred while reading the compressed source.
    Io(io::Error),
    /// A digest did not match the expected value during verification.
    DigestMismatch(DigestMismatch),
    /// A filesystem adapter reported a fatal infrastructure failure.
    Adapter(crate::filesystem::FilesystemAdapterError),
    /// A plan was applied to the wrong session or applied more than once.
    Session(&'static str),
}

impl fmt::Display for OciLayerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => write!(formatter, "OCI layer stream error: {error}"),
            Self::Io(error) => write!(formatter, "OCI layer I/O error: {error}"),
            Self::DigestMismatch(mismatch) => write!(formatter, "OCI layer {mismatch}"),
            Self::Adapter(error) => write!(formatter, "OCI layer adapter error: {error}"),
            Self::Session(context) => write!(formatter, "OCI layer session error: {context}"),
        }
    }
}

impl std::error::Error for OciLayerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Adapter(error) => Some(error),
            Self::DigestMismatch(_) | Self::Session(_) => None,
        }
    }
}

impl From<crate::filesystem::FilesystemAdapterError> for OciLayerError {
    fn from(error: crate::filesystem::FilesystemAdapterError) -> Self {
        Self::Adapter(error)
    }
}

impl From<StreamError> for OciLayerError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}
