// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! XAR (`.xar`) read-only metadata + payload interoperability evidence (RM-305).
//!
//! XAR is a read-only, seek-native format in arca (no writer), so the interop
//! evidence is producer-driven: a first-party, deterministic RAW XAR byte builder
//! (`raw_xar`) emits a valid archive with a big-endian header, a zlib-compressed
//! TOC, and a heap carrying both STORED (`application/octet-stream`) and zlib
//! (`application/x-gzip`) blobs. arca reads it back through the RM-301 harness
//! (`read_with_arca`) and every (path, kind, content) must equal the canonical
//! shapes DERIVED from the shared logical corpus.
//!
//! Negative coverage (direct `SeekArchiveReader`): an unknown data-encoding style
//! yields a structured `Unsupported`, and a truncated header yields a structured
//! `Malformed`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::io::{Cursor, Write};

use libarchive_oxide::SeekArchiveReader;
use libarchive_oxide_core::{EntryKind, ErrorKind};

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Shared logical corpus: a small file, a compressible file, an empty file, and
// a nested-directory path (dir + file-in-subdir).
// ---------------------------------------------------------------------------

fn xar_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello xar world\n".to_vec()),
        LogicalEntry::file(b"notes.txt".to_vec(), big),
        LogicalEntry::file(b"empty.txt".to_vec(), Vec::new()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/nested.txt".to_vec(), b"nested payload\n".to_vec()),
    ]
}

// ---------------------------------------------------------------------------
// First-party RAW XAR builder (independent, deterministic, no external tool).
// Header integers are BIG-endian. The TOC is a hand-written XML document,
// zlib-compressed with flate2 (RFC-1950). Heap blobs are STORED or zlib
// (x-gzip) at the offsets the XML declares.
// ---------------------------------------------------------------------------

/// How the raw builder should store a given logical file on the heap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    Stored,
    Gzip,
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

struct XmlBuilder {
    xml: Vec<u8>,
    heap: Vec<u8>,
    id: u64,
}

impl XmlBuilder {
    fn new() -> Self {
        Self {
            xml: Vec::new(),
            heap: Vec::new(),
            id: 1,
        }
    }

    fn push(&mut self, s: &str) {
        self.xml.extend_from_slice(s.as_bytes());
    }

    fn next_id(&mut self) -> u64 {
        let v = self.id;
        self.id += 1;
        v
    }

    /// Opens a `<file>` element with name + type; caller closes with `close_file`.
    fn open_file(&mut self, name: &str, kind: &str) {
        let id = self.next_id();
        self.push(&format!(
            "<file id=\"{id}\"><name>{name}</name><type>{kind}</type>"
        ));
        self.push("<mode>0644</mode><uid>0</uid><gid>0</gid>");
    }

    fn close_file(&mut self) {
        self.push("</file>");
    }

    /// Appends a regular-file `<data>` blob (with the given encoding) to the heap
    /// and writes the matching `<data>` element referencing its offset.
    fn add_regular(&mut self, name: &str, content: &[u8], enc: Enc) {
        self.open_file(name, "file");
        let (style, blob) = match enc {
            Enc::Stored => ("application/octet-stream", content.to_vec()),
            Enc::Gzip => ("application/x-gzip", zlib_compress(content)),
        };
        let offset = self.heap.len() as u64;
        let stored_size = blob.len() as u64;
        let length = content.len() as u64;
        self.heap.extend_from_slice(&blob);
        self.push(&format!(
            "<data><length>{length}</length><offset>{offset}</offset><size>{stored_size}</size>\
             <encoding style=\"{style}\"/></data>"
        ));
        self.close_file();
    }
}

/// Assembles the 28-byte BE header + zlib TOC + heap into a valid `.xar`.
fn assemble(toc_xml: &[u8], heap: &[u8]) -> Vec<u8> {
    let toc_comp = zlib_compress(toc_xml);
    let mut out = Vec::new();
    out.extend_from_slice(&0x7861_7221_u32.to_be_bytes()); // magic 'xar!'
    out.extend_from_slice(&28_u16.to_be_bytes()); // size (header length)
    out.extend_from_slice(&1_u16.to_be_bytes()); // version
    out.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes()); // toc_length_compressed
    out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes()); // toc_length_uncompressed
    out.extend_from_slice(&0_u32.to_be_bytes()); // cksum_alg = none
    debug_assert_eq!(out.len(), 28);
    out.extend_from_slice(&toc_comp);
    out.extend_from_slice(heap);
    out
}

/// `ProducerCase`-compatible builder: mirrors `xar_entries` layout, choosing
/// STORED for the small file and zlib (x-gzip) for the larger/nested payloads.
fn raw_xar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut b = XmlBuilder::new();
    b.push("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    b.push("<xar><toc>");
    b.push("<creation-time>2026-07-23T00:00:00Z</creation-time>");
    for e in entries {
        let name = std::str::from_utf8(&e.path).unwrap();
        match e.kind {
            EntryKind::Dir => {
                // Top-level directory carrying its nested children.
                b.open_file(name, "directory");
                for child in entries {
                    if let Some(base) = child_of(&child.path, &e.path) {
                        if child.kind == EntryKind::File {
                            let enc = if child.content.len() > 32 {
                                Enc::Gzip
                            } else {
                                Enc::Stored
                            };
                            b.add_regular(base, &child.content, enc);
                        }
                    }
                }
                b.close_file();
            },
            EntryKind::File => {
                if e.path.contains(&b'/') {
                    // Emitted as a nested child by its parent directory above.
                    continue;
                }
                if e.content.is_empty() {
                    // Empty file: no <data> element at all.
                    b.open_file(name, "file");
                    b.close_file();
                } else {
                    let enc = if e.content.len() > 32 {
                        Enc::Gzip
                    } else {
                        Enc::Stored
                    };
                    b.add_regular(name, &e.content, enc);
                }
            },
            _ => {},
        }
    }
    b.push("</toc></xar>");
    assemble(&b.xml, &b.heap)
}

/// If `path` is a direct child of `dir` (one component deeper), returns its
/// basename component.
fn child_of<'a>(path: &'a [u8], dir: &[u8]) -> Option<&'a str> {
    let rest = path.strip_prefix(dir)?;
    let rest = rest.strip_prefix(b"/")?;
    if rest.is_empty() || rest.contains(&b'/') {
        return None;
    }
    std::str::from_utf8(rest).ok()
}

// ---------------------------------------------------------------------------
// Positive: raw XAR builder -> arca reads back identical shapes + content.
// ---------------------------------------------------------------------------

#[test]
fn xar_meta_roundtrip() {
    let entries = xar_entries();
    assert_producers_agree(
        &entries,
        &[ProducerCase {
            name: "raw-xar-builder",
            encode: raw_xar,
        }],
    );
}

/// A byte-level spot check independent of the harness projection: confirms both
/// STORED and zlib payloads decode to their exact original bytes.
#[test]
fn xar_payload_bytes_exact() {
    let entries = xar_entries();
    let shapes = read_with_arca(&raw_xar(&entries));
    let find = |p: &[u8]| {
        shapes
            .iter()
            .find(|s| s.path() == p)
            .unwrap_or_else(|| panic!("missing {p:?}"))
    };
    assert_eq!(find(b"readme.txt").content(), b"hello xar world\n");
    assert_eq!(
        find(b"notes.txt").content(),
        &b"the quick brown fox jumps over the lazy dog\n".repeat(64)[..]
    );
    assert_eq!(find(b"empty.txt").content(), b"");
    assert_eq!(find(b"empty.txt").kind(), EntryKind::File);
    assert_eq!(find(b"sub").kind(), EntryKind::Dir);
    assert_eq!(find(b"sub/nested.txt").content(), b"nested payload\n");
}

// ---------------------------------------------------------------------------
// Negative: unsupported encoding -> structured Unsupported (direct reader).
// ---------------------------------------------------------------------------

/// Drives `SeekArchiveReader` to completion, returning the first error (if any).
fn read_all(bytes: &[u8]) -> Result<usize, libarchive_oxide::StreamError> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes.to_vec()))?;
    let mut entries = 0usize;
    loop {
        match reader.next_event()? {
            libarchive_oxide::ReaderEvent::Entry(_) => entries += 1,
            libarchive_oxide::ReaderEvent::Done => return Ok(entries),
            _ => {},
        }
    }
}

#[test]
fn xar_unsupported_encoding_errors() {
    // A single file whose <data> encoding is an out-of-scope style.
    let content = b"payload bytes that will never decode";
    let mut heap = Vec::new();
    heap.extend_from_slice(content);
    let offset = 0u64;
    let size = content.len();
    let xml = format!(
        "<?xml version=\"1.0\"?><xar><toc>\
         <file id=\"1\"><name>weird.bin</name><type>file</type>\
         <data><length>{size}</length><offset>{offset}</offset><size>{size}</size>\
         <encoding style=\"application/x-lzma\"/></data></file>\
         </toc></xar>"
    );
    let bytes = assemble(xml.as_bytes(), &heap);

    let err = read_all(&bytes).expect_err("unsupported encoding must error");
    let archive = err
        .archive_error()
        .expect("expected a structured archive error");
    assert_eq!(archive.kind(), ErrorKind::Unsupported);
    assert_eq!(archive.format(), Some("xar"));
}

// ---------------------------------------------------------------------------
// Negative: truncated header -> structured Malformed (at open time).
// ---------------------------------------------------------------------------

#[test]
fn xar_truncated_header_errors() {
    // Only the 4-byte magic is present; the seek dispatch routes it to the XAR
    // reader on the magic, then the header read fails.
    let bytes = b"xar!".to_vec();
    let err = SeekArchiveReader::new(Cursor::new(bytes)).err();
    // Either the open errors (header read/parse) — assert it is structured when so.
    let err = err.expect("truncated header must fail to open");
    // A short read surfaces as I/O; a bad/short header surfaces as Malformed xar.
    if let Some(archive) = err.archive_error() {
        assert_eq!(archive.format(), Some("xar"));
        assert_eq!(archive.kind(), ErrorKind::Malformed);
    } else {
        assert!(err.io_error().is_some(), "expected io or archive error");
    }
}

/// Regression (RM-305 adversarial review): a file carrying an `<ea>`
/// extended-attribute block — whose children mirror `<data>` (name / offset /
/// size / length / encoding) — must NOT have that block overwrite the file's own
/// name or data plan. The reader must surface the real filename and the real
/// `<data>` body, never the xattr name or the xattr heap window.
#[test]
fn xar_extended_attribute_does_not_clobber_data() {
    let body = b"the real file body bytes";
    let xattr = b"com.apple.quarantine xattr blob payload";
    let mut heap = Vec::new();
    heap.extend_from_slice(body); // offset 0
    heap.extend_from_slice(xattr); // offset body.len()
    let xml = format!(
        "<?xml version=\"1.0\"?><xar><toc>\
         <file id=\"1\"><name>readme.txt</name><type>file</type>\
         <data><length>{bl}</length><offset>0</offset><size>{bl}</size>\
         <encoding style=\"application/octet-stream\"/></data>\
         <ea id=\"2\"><name>com.apple.quarantine</name><length>{xl}</length>\
         <offset>{bl}</offset><size>{xl}</size>\
         <encoding style=\"application/octet-stream\"/></ea>\
         </file></toc></xar>",
        bl = body.len(),
        xl = xattr.len(),
    );
    let bytes = assemble(xml.as_bytes(), &heap);
    let shapes = read_with_arca(&bytes);
    assert_eq!(shapes.len(), 1, "exactly one file entry");
    assert_eq!(
        shapes[0].path(),
        b"readme.txt",
        "the <ea> name must not overwrite the file name"
    );
    assert_eq!(
        shapes[0].content(),
        body,
        "the <ea> heap window must not overwrite the file body"
    );
}

/// A header that is well-formed up front but declares a TOC region past EOF must
/// be a structured `Malformed` (not a panic).
#[test]
fn xar_toc_region_past_eof_errors() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x7861_7221_u32.to_be_bytes());
    bytes.extend_from_slice(&28_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&9999_u64.to_be_bytes()); // toc_length_compressed >> file
    bytes.extend_from_slice(&100_u64.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    // No TOC/heap bytes follow.
    let err = SeekArchiveReader::new(Cursor::new(bytes)).expect_err("region past EOF must fail");
    let archive = err.archive_error().expect("structured error expected");
    assert_eq!(archive.format(), Some("xar"));
    assert_eq!(archive.kind(), ErrorKind::Malformed);
}
