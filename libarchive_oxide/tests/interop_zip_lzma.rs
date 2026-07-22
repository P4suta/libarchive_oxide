// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP LZMA (method 14) interoperability evidence (RM-302).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) to prove method 14. The whole file is gated
//! on the `xz` feature (enabled on BOTH codec profiles: LZMA read AND write use `lzma-rust2`).
//!
//! ## Two-independent-codecs honesty note
//!
//! Unlike Store/Deflate/BZip2, only TWO independent LZMA codecs exist in this ecosystem:
//! `lzma-rust2` (the pure-Rust codec arca and the `zip` crate both use) and `liblzma` (the C
//! library CPython's `zipfile` wraps). Therefore:
//!
//! * Producer 1 `arca` and producer 2 `raw-zip-lzma-builder` BOTH drive `lzma-rust2` — they are
//!   independent ZIP *container* builders but share the LZMA *codec*.
//! * Producer 3 is the committed CPython/liblzma fixture
//!   (`tests/fixtures/zip/python-lzma/lzma-basic.zip`) — the only INDEPENDENT-codec reference,
//!   generated fully outside arca and `lzma-rust2` (see `PROVENANCE.md`, ADR-0011 escape hatch).
//! * Consumers are `arca` and the `zip` crate (`zip@8.6.0` with its `lzma` feature). The `zip`
//!   crate cannot WRITE LZMA (consumer-only for method 14), so WRITE evidence is: the `zip` crate
//!   decodes arca's method-14 output to byte-identical content — the strong header/stream-validity
//!   check that arca's 9-byte ZIP-LZMA header + raw LZMA1 stream are spec-valid.
#![cfg(feature = "xz")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use libarchive_oxide::{ArchiveWriter, ZipMethod};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Shared logical corpus (file, dir, file-in-subdir, empty file).
// ---------------------------------------------------------------------------

fn zip_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello lzma world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer 1: arca's own streaming ZIP writer (system under test).
// ---------------------------------------------------------------------------

fn arca_zip(entries: &[LogicalEntry], method: ZipMethod) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), method, Limits::default());
    for e in entries {
        let mode = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        let metadata = EntryMetadata::builder(e.kind, ArchivePath::from_bytes(e.path.clone()))
            .size(None)
            .mode(Some(mode))
            .build();
        writer.start_entry(&metadata).unwrap();
        if !e.content.is_empty() {
            for chunk in e.content.chunks(97) {
                writer.write_data(chunk).unwrap();
            }
        }
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

fn arca_zip_lzma(entries: &[LogicalEntry]) -> Vec<u8> {
    arca_zip(entries, ZipMethod::Lzma)
}

// ---------------------------------------------------------------------------
// Producer 2: a first-party raw ZIP builder, independent of BOTH arca and the
// `zip` crate at the CONTAINER level. Bodies are raw LZMA1 streams built with
// `lzma-rust2`'s LzmaWriter directly, prefixed with the 9-byte ZIP-LZMA header
// (shares the LZMA codec with arca; see honesty note). CRC-32 is flate2's Crc
// of the RAW content. "version needed to extract" = 63 for method-14 members.
// ---------------------------------------------------------------------------

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// Builds a ZIP-LZMA member payload: the 9-byte header + raw LZMA1 stream with
/// an end-of-stream marker, matching arca's wire format.
fn raw_lzma(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let options = lzma_rust2::LzmaOptions::with_preset(6);
    let mut sink = Vec::new();
    sink.extend_from_slice(&[9, 20]);
    sink.extend_from_slice(&5_u16.to_le_bytes());
    sink.push(options.get_props());
    sink.extend_from_slice(&options.dict_size.to_le_bytes());
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(sink, &options, true).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap()
}

struct RawMember {
    name: Vec<u8>,
    version: u16,
    method: u16,
    flags: u16,
    crc: u32,
    comp: u32,
    uncomp: u32,
    body: Vec<u8>,
}

fn resolve_raw(entries: &[LogicalEntry]) -> Vec<RawMember> {
    entries
        .iter()
        .map(|e| {
            if e.kind == EntryKind::Dir {
                let mut name = e.path.clone();
                name.push(b'/');
                RawMember {
                    name,
                    version: 20,
                    method: 0,
                    flags: 0,
                    crc: 0,
                    comp: 0,
                    uncomp: 0,
                    body: Vec::new(),
                }
            } else {
                let body = raw_lzma(&e.content);
                RawMember {
                    name: e.path.clone(),
                    version: 63,
                    method: 14,
                    // General-purpose bit 1: end-of-stream-marker convention.
                    flags: 0x0002,
                    crc: crc32(&e.content),
                    comp: body.len() as u32,
                    uncomp: e.content.len() as u32,
                    body,
                }
            }
        })
        .collect()
}

fn raw_zip_lzma(entries: &[LogicalEntry]) -> Vec<u8> {
    let members = resolve_raw(entries);
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for m in &members {
        offsets.push(out.len() as u32);
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, m.version);
        push_u16(&mut out, m.flags);
        push_u16(&mut out, m.method);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0x21);
        push_u32(&mut out, m.crc);
        push_u32(&mut out, m.comp);
        push_u32(&mut out, m.uncomp);
        push_u16(&mut out, m.name.len() as u16);
        push_u16(&mut out, 0);
        out.extend_from_slice(&m.name);
        out.extend_from_slice(&m.body);
    }
    let central_offset = out.len() as u32;
    let mut central = Vec::new();
    for (m, offset) in members.iter().zip(offsets.iter()) {
        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 0x031e);
        push_u16(&mut central, m.version);
        push_u16(&mut central, m.flags);
        push_u16(&mut central, m.method);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0x21);
        push_u32(&mut central, m.crc);
        push_u32(&mut central, m.comp);
        push_u32(&mut central, m.uncomp);
        push_u16(&mut central, m.name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, *offset);
        central.extend_from_slice(&m.name);
    }
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, members.len() as u16);
    push_u16(&mut out, members.len() as u16);
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0);
    out
}

// ---------------------------------------------------------------------------
// 3-producer / 2-consumer interop matrix (arca + raw-builder share lzma-rust2).
// ---------------------------------------------------------------------------

#[test]
fn zip_lzma_interop() {
    let entries = zip_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_zip_lzma,
            },
            ProducerCase {
                name: "raw-zip-lzma-builder",
                encode: raw_zip_lzma,
            },
        ],
    );

    let arca_bytes = arca_zip_lzma(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[
            ConsumerCase {
                name: "arca",
                decode: read_with_arca,
            },
            ConsumerCase {
                name: "zip@8.6.0",
                decode: zip_crate_decode,
            },
        ],
    );

    // WRITE-side codec-method evidence: non-empty file members are LZMA through
    // the `zip` consumer (the strong header/stream-validity check on arca output).
    for shape in zip_crate_decode(&arca_bytes) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Lzma);
        }
    }
}

// ---------------------------------------------------------------------------
// Producer 3: the committed CPython/liblzma fixture (the INDEPENDENT-codec
// reference). arca reads it back to the KNOWN fixed content the generator used.
// ---------------------------------------------------------------------------

/// The exact bytes CPython 3.14 `zipfile`/`liblzma` produced; regenerated by
/// `tests/fixtures/zip/python-lzma/generate.py` (see `PROVENANCE.md`).
const PYTHON_LZMA_FIXTURE: &[u8] = include_bytes!("fixtures/zip/python-lzma/lzma-basic.zip");

#[test]
fn zip_lzma_reads_committed_python_liblzma_fixture() {
    // The generator's fixed member set (order preserved; no explicit `sub/` dir).
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    let expected: Vec<(&[u8], Vec<u8>)> = vec![
        (b"readme.txt", b"hello lzma world\n".to_vec()),
        (b"sub/big.txt", big),
        (b"sub/empty.txt", Vec::new()),
    ];

    let shapes = read_with_arca(PYTHON_LZMA_FIXTURE);
    let files: Vec<_> = shapes
        .iter()
        .filter(|s| s.kind() == EntryKind::File)
        .collect();
    assert_eq!(files.len(), expected.len(), "member count");
    for (shape, (name, content)) in files.iter().zip(expected.iter()) {
        assert_eq!(shape.path(), *name, "member name");
        assert_eq!(shape.content(), content.as_slice(), "member content");
    }

    // The `zip` crate (also lzma-rust2-backed) agrees, and reports method 14 on
    // the non-empty members — a second independent ZIP-container parse.
    for shape in zip_crate_decode(PYTHON_LZMA_FIXTURE) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Lzma);
        }
    }
}

// ---------------------------------------------------------------------------
// WRITE evidence: arca's method-14 output is decoded by the `zip` crate to
// byte-identical content, with method 14 confirmed.
// ---------------------------------------------------------------------------

#[test]
fn zip_lzma_write_is_decoded_by_zip_crate() {
    let content = b"arca-produced LZMA member for independent container decode\n".repeat(64);
    let entries = vec![LogicalEntry::file(b"payload.bin".to_vec(), content.clone())];
    let arca_bytes = arca_zip_lzma(&entries);

    let decoded = zip_crate_decode(&arca_bytes);
    let file = decoded
        .iter()
        .find(|s| s.kind() == EntryKind::File)
        .expect("file member");
    assert_eq!(file.content(), content.as_slice());
    file.assert_method(CompressionMethod::Lzma);
}
