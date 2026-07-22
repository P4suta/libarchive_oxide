// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic OCI image layer creation.
//!
//! [`OciLayerBuilder`] turns an ordered list of explicit entry descriptions
//! into a single tar layer blob, optionally wrapped in the gzip or zstd outer
//! filter, and returns the pair of SHA-256 digests ([`LayerDigests`]) that
//! identify the layer: the compressed digest over the stored blob and the
//! diffID over the decoded tar stream.
//!
//! Reproducibility is the contract. Given the same ordered entries and the same
//! outer filter, [`OciLayerBuilder::build`] always writes **byte-identical**
//! output and returns identical digests. This holds because:
//!
//! * entry order is exactly the order the caller supplied;
//! * every timestamp, mode, and owner id is taken from the caller's metadata,
//!   never from the wall clock (an unset modification time serializes as `0`);
//! * PAX records (timestamps, ownership names, `SCHILY.xattr.*`) are emitted
//!   solely from the supplied metadata; and
//! * the gzip encoder writes a fixed header (`mtime = 0`, unknown OS) and the
//!   zstd encoder is deterministic, so no environmental state leaks into the
//!   stored bytes.
//!
//! The builder reuses the sequential tar encoder and the outer filter writer,
//! so a layer it produces reads back through an
//! [`OciLayerSession`](super::layer::OciLayerSession) with matching digests.

use std::io::{Cursor, Read};

use libarchive_oxide_core::{EntryMetadata, FilterId, FormatId, Limits};
use sha2::{Digest, Sha256};

use super::digest::LayerDigests;
use super::layer::OciLayerError;
use crate::engine::{ArchiveEngine, CreateOptions};
use crate::filtered_io::FilterReader;

/// Computes a SHA-256 digest over a byte slice.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&output);
    digest
}

/// The outer filter applied to a built OCI layer blob.
///
/// Every variant is deterministic: the same tar stream always produces the same
/// stored bytes, so a layer's compressed digest is stable across builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OciLayerFilter {
    /// Store the tar stream uncompressed. The compressed digest and diffID are
    /// then identical.
    Uncompressed,
    /// Compress with the deterministic gzip encoder (fixed header, `mtime = 0`).
    Gzip,
    /// Compress with the deterministic zstd encoder.
    Zstd,
}

impl OciLayerFilter {
    /// The underlying [`FilterId`], or `None` for an uncompressed layer.
    #[must_use]
    pub const fn filter_id(self) -> Option<FilterId> {
        match self {
            Self::Uncompressed => None,
            Self::Gzip => Some(FilterId::Gzip),
            Self::Zstd => Some(FilterId::Zstd),
        }
    }
}

/// A single ordered entry queued for a layer: its metadata and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerEntry {
    metadata: EntryMetadata,
    body: Vec<u8>,
}

/// A builder for deterministic OCI image layers.
///
/// Entries are appended in order with [`push_entry`](Self::push_entry) and the
/// layer is materialized with [`build`](Self::build). Because `build` borrows
/// the builder, the same builder can be built repeatedly to obtain
/// byte-identical output, which is the basis of the reproducibility guarantee.
///
/// # Examples
///
/// ```
/// use libarchive_oxide::{OciLayerBuilder, OciLayerFilter};
/// use libarchive_oxide::libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata};
///
/// let mut builder = OciLayerBuilder::new(OciLayerFilter::Gzip);
/// let metadata = EntryMetadata::builder(
///     EntryKind::File,
///     ArchivePath::from_bytes(b"etc/hostname".to_vec()),
/// )
/// .size(Some(6))
/// .build();
/// builder.push_entry(metadata, b"oxide\n".to_vec());
///
/// let first = builder.build().expect("build layer");
/// let second = builder.build().expect("rebuild layer");
/// // Same input, same bytes, same digests.
/// assert_eq!(first.blob(), second.blob());
/// assert_eq!(first.digests(), second.digests());
/// ```
#[derive(Debug, Clone)]
pub struct OciLayerBuilder {
    filter: OciLayerFilter,
    limits: Limits,
    entries: Vec<LayerEntry>,
}

impl OciLayerBuilder {
    /// Creates a builder that writes layers with the given outer filter and safe
    /// resource limits.
    #[must_use]
    pub fn new(filter: OciLayerFilter) -> Self {
        Self::with_limits(filter, Limits::safe())
    }

    /// Creates a builder with an explicit outer filter and resource limits.
    ///
    /// The limits bound the decoded tar stream while the diffID is computed, so
    /// a caller can cap the memory used to re-read a compressed layer.
    #[must_use]
    pub fn with_limits(filter: OciLayerFilter, limits: Limits) -> Self {
        Self {
            filter,
            limits,
            entries: Vec::new(),
        }
    }

    /// The outer filter this builder applies.
    #[must_use]
    pub const fn filter(&self) -> OciLayerFilter {
        self.filter
    }

    /// The number of entries queued so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries are queued yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends one entry, preserving insertion order.
    ///
    /// The metadata carries every reproducible field: path, kind, mode, owner
    /// ids and names, timestamps, and extended attributes. The body bytes are
    /// the entry payload; pass an empty slice for directories, links, and
    /// zero-length files.
    pub fn push_entry(&mut self, metadata: EntryMetadata, body: impl Into<Vec<u8>>) -> &mut Self {
        self.entries.push(LayerEntry {
            metadata,
            body: body.into(),
        });
        self
    }

    /// Writes the queued entries into a single deterministic layer blob.
    ///
    /// Returns the stored bytes together with the compressed digest and diffID.
    /// Building the same builder twice yields byte-identical blobs and equal
    /// digests.
    ///
    /// # Errors
    ///
    /// Returns [`OciLayerError::Stream`] if the tar encoder or outer filter
    /// rejects an entry (for example a tar entry without a declared size), or
    /// [`OciLayerError::Io`] if re-decoding the compressed blob to compute the
    /// diffID fails or exceeds the configured limits.
    pub fn build(&self) -> Result<OciLayerBlob, OciLayerError> {
        let filter = self.filter.filter_id();
        let mut writer = ArchiveEngine::new().create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )?;
        for entry in &self.entries {
            writer.start_entry(&entry.metadata)?;
            if !entry.body.is_empty() {
                writer.write_data(&entry.body)?;
            }
            writer.end_entry()?;
        }
        let blob = writer.finish()?;

        let compressed = sha256(&blob);
        let diff_id = if filter.is_none() {
            // An uncompressed layer stores the tar stream verbatim, so the two
            // digests coincide.
            compressed
        } else {
            let mut reader = FilterReader::with_limits(Cursor::new(blob.as_slice()), self.limits)
                .map_err(OciLayerError::Io)?;
            let mut plain = Vec::new();
            reader.read_to_end(&mut plain).map_err(OciLayerError::Io)?;
            sha256(&plain)
        };

        Ok(OciLayerBlob {
            blob,
            digests: LayerDigests::from_bytes(compressed, diff_id),
        })
    }
}

/// A built OCI layer: its stored blob and identifying digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayerBlob {
    blob: Vec<u8>,
    digests: LayerDigests,
}

impl OciLayerBlob {
    /// The stored layer bytes, ready to write as an OCI blob.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The compressed digest and diffID identifying this layer.
    #[must_use]
    pub const fn digests(&self) -> LayerDigests {
        self.digests
    }

    /// Consumes the layer, returning ownership of the stored bytes.
    #[must_use]
    pub fn into_blob(self) -> Vec<u8> {
        self.blob
    }
}
