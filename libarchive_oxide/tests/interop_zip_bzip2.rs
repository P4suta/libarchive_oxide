// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP BZip2 (method 12) interoperability evidence (RM-302).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) to prove method 12 with THREE independent
//! producers (arca's ZIP writer, the `zip` crate, and a first-party raw-ZIP builder that stores a
//! raw `.bz2` stream produced by the `bzip2` crate directly) and TWO consumers (arca's seek reader
//! and the `zip` crate). Content equality is byte-level; the `zip` consumer additionally exposes
//! the BZip2 codec for method evidence.
//!
//! Whole file is gated on the `bzip2` feature.
#![cfg(feature = "bzip2")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::io::Cursor;

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
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello bzip2 world\n".to_vec()),
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

fn arca_zip_bzip2(entries: &[LogicalEntry]) -> Vec<u8> {
    arca_zip(entries, ZipMethod::Bzip2)
}

// ---------------------------------------------------------------------------
// Producer 2: the independent `zip` crate (zip@8.6.0) with method BZip2.
// ---------------------------------------------------------------------------

fn zipcrate_zip_bzip2(entries: &[LogicalEntry]) -> Vec<u8> {
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
    for e in entries {
        let name = std::str::from_utf8(&e.path).unwrap();
        if e.kind == EntryKind::Dir {
            let opts = SimpleFileOptions::default().unix_permissions(0o755);
            zw.add_directory(name, opts).unwrap();
        } else {
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Bzip2)
                .unix_permissions(0o644);
            zw.start_file(name, opts).unwrap();
            zw.write_all(&e.content).unwrap();
        }
    }
    zw.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw ZIP builder, independent of BOTH arca and the
// `zip` crate. Bodies are raw `.bz2` streams built with the `bzip2` crate
// directly; CRC-32 is flate2's Crc of the RAW content so arca's reader accepts
// the bytes. "version needed to extract" = 46 for method-12 members.
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

fn raw_bzip2(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

struct RawMember {
    name: Vec<u8>,
    version: u16,
    method: u16,
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
                    crc: 0,
                    comp: 0,
                    uncomp: 0,
                    body: Vec::new(),
                }
            } else {
                let body = raw_bzip2(&e.content);
                RawMember {
                    name: e.path.clone(),
                    version: 46,
                    method: 12,
                    crc: crc32(&e.content),
                    comp: body.len() as u32,
                    uncomp: e.content.len() as u32,
                    body,
                }
            }
        })
        .collect()
}

fn raw_zip_bzip2(entries: &[LogicalEntry]) -> Vec<u8> {
    let members = resolve_raw(entries);
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for m in &members {
        offsets.push(out.len() as u32);
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, m.version);
        push_u16(&mut out, 0);
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
        push_u16(&mut central, 0);
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
// 3x2 interop test.
// ---------------------------------------------------------------------------

#[test]
fn zip_bzip2_interop() {
    let entries = zip_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_zip_bzip2,
            },
            ProducerCase {
                name: "zip@8.6.0",
                encode: zipcrate_zip_bzip2,
            },
            ProducerCase {
                name: "raw-zip-bzip2-builder",
                encode: raw_zip_bzip2,
            },
        ],
    );

    let arca_bytes = arca_zip_bzip2(&entries);
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

    // Codec-method evidence: non-empty file members are BZip2 through the `zip` consumer.
    for shape in zip_crate_decode(&arca_bytes) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Bzip2);
        }
    }
}
