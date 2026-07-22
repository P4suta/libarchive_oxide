// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One-pass SHA-256 hashing for OCI layer compressed digests and diffIDs.
//!
//! An OCI image layer is identified by two SHA-256 values:
//!
//! * the **compressed digest** (the descriptor `digest` field) over the layer
//!   blob exactly as stored, and
//! * the **diffID** over the uncompressed tar stream.
//!
//! [`HashingReader`] wraps a byte source and feeds every yielded byte into a
//! shared accumulator without retaining the stream. Nesting one accumulator
//! under the outer filter and one over the decoded tar bytes lets a single read
//! pass compute both digests at once. For an uncompressed tar layer the two
//! digests are identical.

use std::cell::RefCell;
use std::fmt;
use std::io::{self, Read};
use std::rc::Rc;

use sha2::{Digest, Sha256};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encodes 32 SHA-256 bytes as a lowercase hexadecimal string.
#[must_use]
pub fn encode_hex(bytes: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// The pair of SHA-256 digests that identify an OCI image layer.
///
/// * [`compressed`](Self::compressed) is the digest of the layer blob exactly
///   as stored (the OCI descriptor `digest`).
/// * [`diff_id`](Self::diff_id) is the digest of the uncompressed tar stream
///   (the OCI `diffID`).
///
/// For an uncompressed tar layer the two values are equal.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LayerDigests {
    compressed: [u8; 32],
    diff_id: [u8; 32],
}

impl LayerDigests {
    /// Builds a digest pair from raw 32-byte SHA-256 values.
    #[must_use]
    pub const fn from_bytes(compressed: [u8; 32], diff_id: [u8; 32]) -> Self {
        Self {
            compressed,
            diff_id,
        }
    }

    /// The compressed-blob digest bytes (OCI descriptor `digest`).
    #[must_use]
    pub const fn compressed(&self) -> &[u8; 32] {
        &self.compressed
    }

    /// The uncompressed-stream digest bytes (OCI `diffID`).
    #[must_use]
    pub const fn diff_id(&self) -> &[u8; 32] {
        &self.diff_id
    }

    /// The compressed digest as a lowercase hexadecimal string.
    #[must_use]
    pub fn compressed_hex(self) -> String {
        encode_hex(self.compressed)
    }

    /// The diffID as a lowercase hexadecimal string.
    #[must_use]
    pub fn diff_id_hex(self) -> String {
        encode_hex(self.diff_id)
    }

    /// The compressed digest as an OCI descriptor string `sha256:<hex>`.
    #[must_use]
    pub fn compressed_descriptor(self) -> String {
        format!("sha256:{}", self.compressed_hex())
    }

    /// The diffID as an OCI descriptor string `sha256:<hex>`.
    #[must_use]
    pub fn diff_id_descriptor(self) -> String {
        format!("sha256:{}", self.diff_id_hex())
    }
}

impl fmt::Debug for LayerDigests {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LayerDigests")
            .field("compressed", &self.compressed_descriptor())
            .field("diff_id", &self.diff_id_descriptor())
            .finish()
    }
}

/// A SHA-256 accumulator shared between a [`HashingReader`] and its owner.
///
/// The reader updates the accumulator as bytes flow through it; the owner can
/// finalize a clone of the running state once the stream is fully consumed.
#[derive(Clone)]
pub(crate) struct SharedHasher(Rc<RefCell<Sha256>>);

impl SharedHasher {
    /// Creates an empty shared accumulator.
    pub(crate) fn new() -> Self {
        Self(Rc::new(RefCell::new(Sha256::new())))
    }

    /// Absorbs bytes into the running digest.
    fn update(&self, bytes: &[u8]) {
        self.0.borrow_mut().update(bytes);
    }

    /// Finalizes a snapshot of the running digest without disturbing it.
    pub(crate) fn finalize(&self) -> [u8; 32] {
        let output = self.0.borrow().clone().finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&output);
        bytes
    }
}

impl fmt::Debug for SharedHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedHasher")
            .finish_non_exhaustive()
    }
}

/// A `Read` adapter that feeds every byte it yields into a [`SharedHasher`]
/// without buffering the stream.
pub(crate) struct HashingReader<R: Read> {
    inner: R,
    hasher: SharedHasher,
}

impl<R: Read> HashingReader<R> {
    /// Wraps a reader so its bytes update `hasher` as they are read.
    pub(crate) fn new(inner: R, hasher: SharedHasher) -> Self {
        Self { inner, hasher }
    }

    /// Recovers the wrapped reader.
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read != 0 {
            self.hasher.update(&buf[..read]);
        }
        Ok(read)
    }
}

impl<R: Read> fmt::Debug for HashingReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HashingReader")
            .finish_non_exhaustive()
    }
}
