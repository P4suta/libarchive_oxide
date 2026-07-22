// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reusable interoperability-evidence harness (RM-301).
//!
//! This module is the single foundation that later format slices (ZIP/7z/tar/cpio/ar/ISO/CAB/XAR)
//! sit on to produce two kinds of evidence:
//!
//! * *"≥3 producers can be read"* — [`assert_producers_agree`] feeds the SAME logical entry set to
//!   N independent encoders and asserts arca reads every encoding back to identical shapes+content.
//! * *"≥2 consumers accept"* — [`assert_consumers_accept`] hands arca's writer output to M
//!   independent decoders and asserts every one reconstructs identical shapes+content.
//!
//! Heterogeneous producers/consumers are carried as bare `fn` pointers inside concrete
//! non-generic case structs. A `fn` pointer is a `Copy` scalar — not a trait object, not a
//! closure, not a generic param — so the harness satisfies the crate's no-dyn gate while letting
//! RM-302/303/304 add cases by writing a free fn and a `&[]` array, never editing this file.
//!
//! Files under `tests/common/` are NOT compiled as their own test binary; a test binary pulls this
//! in with `mod common;`. `dead_code` is allowed because not every including binary uses every
//! helper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::io::Cursor;

use libarchive_oxide::{ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::EntryKind;

/// Compression method WHERE OBSERVABLE. arca's reader decodes transparently and exposes no
/// per-entry codec, so [`read_with_arca`] always yields `None`. `Some(..)` is set only by
/// consumers/producers that expose their own codec view. Kept OUTSIDE content-equality so a Store
/// producer and a Deflate producer of the same logical set still compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionMethod {
    Store,
    Deflate,
    Lzma,
    Lzma2,
    Bzip2,
    Zstd,
    Other(u16),
}

/// The SAME logical entry every producer must encode. RAW path bytes only; content is the full
/// uncompressed payload (empty for `Dir`). This is the harness's single source of truth:
/// [`assert_producers_agree`] feeds the identical slice to every producer.
#[derive(Clone, Debug)]
pub struct LogicalEntry {
    pub path: Vec<u8>,
    pub kind: EntryKind,
    pub content: Vec<u8>,
}

impl LogicalEntry {
    /// A regular file with the given raw path bytes and full payload.
    pub fn file(path: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::File,
            content: content.into(),
        }
    }

    /// A directory with the given raw path bytes; content is always empty.
    pub fn dir(path: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::Dir,
            content: Vec::new(),
        }
    }
}

/// Normalized, content-comparable entry read back out of an archive.
#[derive(Clone, Debug)]
pub struct EntryShape {
    path: Vec<u8>,
    kind: EntryKind,
    content: Vec<u8>,
    method: Option<CompressionMethod>,
}

impl EntryShape {
    /// The ONLY constructor. Centralizes dir-slash normalization so every shape (arca-read and
    /// consumer-decoded) is canonical and comparisons are honest: when `kind == Dir` exactly ONE
    /// trailing `b'/'` is stripped, matching real producer behavior (arca writes `b"sub"`, the
    /// `zip` crate and any spec-conformant raw ZIP store `b"sub/"`).
    pub fn new(path: impl Into<Vec<u8>>, kind: EntryKind, content: impl Into<Vec<u8>>) -> Self {
        let kind = shape_kind(kind);
        let mut p = path.into();
        if kind == EntryKind::Dir && p.last() == Some(&b'/') {
            p.pop();
        }
        Self {
            path: p,
            kind,
            content: content.into(),
            method: None,
        }
    }

    /// Attach an observed compression method (excluded from equality).
    #[must_use]
    pub fn with_method(mut self, m: CompressionMethod) -> Self {
        self.method = Some(m);
        self
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }

    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// DERIVED from content, never stored — so a `size = None` vs `Some` mismatch can't diverge.
    pub fn size(&self) -> u64 {
        self.content.len() as u64
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn method(&self) -> Option<CompressionMethod> {
        self.method
    }

    /// Panics if this shape carries a method that disagrees with `expected`; a no-op when the
    /// method is `None` (arca-read shapes expose no codec).
    #[track_caller]
    pub fn assert_method(&self, expected: CompressionMethod) {
        if let Some(actual) = self.method {
            assert_eq!(
                actual, expected,
                "compression method mismatch for {:?}",
                self.path
            );
        }
    }

    /// Module-private: append a streamed `Data` chunk to the current entry's content.
    pub(crate) fn push_data(&mut self, bytes: &[u8]) {
        self.content.extend_from_slice(bytes);
    }
}

// EQUALITY = CONTENT equality over (path, kind, content) ONLY. `method` and the derived `size` are
// excluded. A field-subset projection is a valid equivalence relation, so the Eq contract holds; no
// Hash is derived or needed.
impl PartialEq for EntryShape {
    fn eq(&self, o: &Self) -> bool {
        self.path == o.path && self.kind == o.kind && self.content == o.content
    }
}
impl Eq for EntryShape {}

/// `EntryKind` is `#[non_exhaustive]` → the mapping MUST have a wildcard arm. Symlink/device kinds
/// (out of scope this slice) fold to `File` deterministically.
fn shape_kind(k: EntryKind) -> EntryKind {
    match k {
        EntryKind::Dir => EntryKind::Dir,
        _ => EntryKind::File,
    }
}

/// Canonical order: paths are unique within one archive, so sorting by path makes
/// central-directory order vs stream order compare equal (robust + documented).
fn sorted_by_path(mut v: Vec<EntryShape>) -> Vec<EntryShape> {
    v.sort_by(|a, b| a.path().cmp(b.path()));
    v
}

/// Independent encoder: turns the shared logical set into archive bytes. `name` = `"crate@version"`
/// provenance (e.g. `"zip@8.6.0"`); flows into panic messages.
pub struct ProducerCase {
    pub name: &'static str,
    pub encode: fn(&[LogicalEntry]) -> Vec<u8>,
}

/// Independent decoder: reconstructs shapes (WITH content) from archive bytes.
pub struct ConsumerCase {
    pub name: &'static str,
    pub decode: fn(&[u8]) -> Vec<EntryShape>,
}

/// (2) Read ANY arca-readable bytes through the seek reader into shapes with real content. `method`
/// left `None` (arca abstracts compression). Panics on arca error (test-only).
///
/// `ReaderEvent` is `#[non_exhaustive]` in the arca crate, so from this external test binary the
/// match needs a wildcard arm (mirrors `sevenz_differential.rs`).
#[track_caller]
pub fn read_with_arca(bytes: &[u8]) -> Vec<EntryShape> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut out: Vec<EntryShape> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => out.push(EntryShape::new(
                meta.path().as_bytes().to_vec(),
                meta.kind(),
                Vec::new(),
            )),
            ReaderEvent::Data(d) => out.last_mut().unwrap().push_data(d),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return out,
            _ => panic!("unexpected future reader event"),
        }
    }
}

/// (3) N-producer evidence (*"≥3 producers can be read"*, applied repeatedly). Every producer
/// encodes the SAME `entries`; arca reads each output back and each read-back must equal the
/// canonical shapes DERIVED from `entries` (source of truth → a shared bug in all producers cannot
/// pass). Returns the agreed, path-sorted shapes for downstream [`assert_consumers_accept`].
#[track_caller]
pub fn assert_producers_agree(
    entries: &[LogicalEntry],
    producers: &[ProducerCase],
) -> Vec<EntryShape> {
    let expected = sorted_by_path(
        entries
            .iter()
            .map(|e| EntryShape::new(e.path.clone(), e.kind, e.content.clone()))
            .collect(),
    );
    for p in producers {
        let got = sorted_by_path(read_with_arca(&(p.encode)(entries)));
        assert_eq!(got, expected, "producer {} disagreed", p.name);
    }
    expected
}

/// (4) M-consumer evidence (*"≥2 consumers accept"*). arca's writer output `archive` is handed to
/// each independent consumer; each must reconstruct `expected` exactly (method excluded from Eq, so
/// a Deflate-reporting consumer still matches).
#[track_caller]
pub fn assert_consumers_accept(
    archive: &[u8],
    expected: &[EntryShape],
    consumers: &[ConsumerCase],
) {
    let expected = sorted_by_path(expected.to_vec());
    for c in consumers {
        let got = sorted_by_path((c.decode)(archive));
        assert_eq!(
            got, expected,
            "consumer {} rejected/misread arca output",
            c.name
        );
    }
}

/// Independent ZIP decoder built on the `zip` crate: `by_index` over every member, raw name bytes,
/// `.is_dir()` → `Dir`, `.compression()` → `.with_method(..)`, `read_to_end` into content. Usable
/// directly as a [`ConsumerCase::decode`] field.
pub fn zip_crate_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use std::io::Read;

    let mut archive = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let raw = f.name_raw().to_vec();
        let kind = if f.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let method = match f.compression() {
            zip::CompressionMethod::Stored => CompressionMethod::Store,
            zip::CompressionMethod::Deflated => CompressionMethod::Deflate,
            zip::CompressionMethod::Bzip2 => CompressionMethod::Bzip2,
            zip::CompressionMethod::Zstd => CompressionMethod::Zstd,
            zip::CompressionMethod::Lzma => CompressionMethod::Lzma,
            _ => CompressionMethod::Other(0),
        };
        let mut content = Vec::new();
        if !f.is_dir() {
            f.read_to_end(&mut content).unwrap();
        }
        out.push(EntryShape::new(raw, kind, content).with_method(method));
    }
    out
}

/// Independent 7z decoder built on `sevenz-rust2`: `SevenReader::new` + `Password::empty()`,
/// `archive().files` for name/`is_directory`, `read_file(name)` for content, `.with_method(Lzma2)`.
/// Usable directly as a [`ConsumerCase::decode`] field.
#[cfg(feature = "sevenz")]
pub fn sevenz_rust2_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use sevenz_rust2::{ArchiveReader as SevenReader, Password};

    let mut reader = SevenReader::new(Cursor::new(bytes.to_vec()), Password::empty()).unwrap();
    // Snapshot names/kinds under the immutable borrow first, then read contents.
    let meta: Vec<(String, bool)> = reader
        .archive()
        .files
        .iter()
        .map(|e| (e.name().to_string(), e.is_directory()))
        .collect();

    let mut out = Vec::with_capacity(meta.len());
    for (name, is_dir) in meta {
        let (kind, content) = if is_dir {
            (EntryKind::Dir, Vec::new())
        } else {
            (EntryKind::File, reader.read_file(&name).unwrap())
        };
        out.push(
            EntryShape::new(name.into_bytes(), kind, content).with_method(CompressionMethod::Lzma2),
        );
    }
    out
}
