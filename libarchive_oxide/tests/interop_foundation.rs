// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Demo / self-test proving the reusable interop-evidence harness (`tests/common/mod.rs`) on
//! ALREADY-SUPPORTED formats. It adds no new archive method — it exercises the machinery the way
//! RM-302/303/304 will:
//!
//! * ZIP Store and ZIP Deflate — each proven with three independent producers (arca, the `zip`
//!   crate, and a first-party raw builder) and two consumers (arca and the `zip` crate), with real
//!   byte-level content equality plus a codec-method assertion where the `zip` consumer exposes it.
//! * 7z LZMA2 (feature `sevenz`) — two producers (arca and `sevenz-rust2`) and two consumers
//!   (arca and `sevenz-rust2`).
//!
//! Producers/consumers are bare `fn` pointers assembled into `&[]` arrays at the call site — the
//! no-harness-edit extension pattern.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::Cursor;

use libarchive_oxide::{ArchiveWriter, ZipMethod};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Shared logical corpus. Exercises file, dir, and file-in-subdir so the
// dir-slash normalization path in EntryShape::new is actually hit.
// ---------------------------------------------------------------------------

fn zip_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer: arca's own streaming ZIP writer (system under test).
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
            writer.write_data(&e.content).unwrap();
        }
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

fn arca_zip_store(entries: &[LogicalEntry]) -> Vec<u8> {
    arca_zip(entries, ZipMethod::Store)
}

fn arca_zip_deflate(entries: &[LogicalEntry]) -> Vec<u8> {
    arca_zip(entries, ZipMethod::Deflate)
}

// ---------------------------------------------------------------------------
// Producer: the independent `zip` crate (zip@8.6.0).
// ---------------------------------------------------------------------------

fn zipcrate_zip(entries: &[LogicalEntry], method: zip::CompressionMethod) -> Vec<u8> {
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
                .compression_method(method)
                .unix_permissions(0o644);
            zw.start_file(name, opts).unwrap();
            zw.write_all(&e.content).unwrap();
        }
    }
    zw.finish().unwrap().into_inner()
}

fn zipcrate_zip_store(entries: &[LogicalEntry]) -> Vec<u8> {
    zipcrate_zip(entries, zip::CompressionMethod::Stored)
}

fn zipcrate_zip_deflate(entries: &[LogicalEntry]) -> Vec<u8> {
    zipcrate_zip(entries, zip::CompressionMethod::Deflated)
}

// ---------------------------------------------------------------------------
// Producer: a first-party raw ZIP builder, independent of BOTH arca and the
// `zip` crate. Hand-written local-header + central-directory layout; template
// is the `build_zip` helper in package_zip.rs. CRC-32 is computed with flate2's
// Crc so arca's reader (which verifies CRC-32) accepts the bytes.
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

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// One resolved raw member: spec-conformant name (dirs gain a trailing `/`), method, CRC, sizes,
/// and the on-disk body.
struct RawMember {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    comp: u32,
    uncomp: u32,
    body: Vec<u8>,
}

fn resolve_raw(entries: &[LogicalEntry], deflate: bool) -> Vec<RawMember> {
    entries
        .iter()
        .map(|e| {
            if e.kind == EntryKind::Dir {
                let mut name = e.path.clone();
                name.push(b'/');
                RawMember {
                    name,
                    method: 0,
                    crc: 0,
                    comp: 0,
                    uncomp: 0,
                    body: Vec::new(),
                }
            } else if deflate {
                let body = raw_deflate(&e.content);
                RawMember {
                    name: e.path.clone(),
                    method: 8,
                    crc: crc32(&e.content),
                    comp: body.len() as u32,
                    uncomp: e.content.len() as u32,
                    body,
                }
            } else {
                RawMember {
                    name: e.path.clone(),
                    method: 0,
                    crc: crc32(&e.content),
                    comp: e.content.len() as u32,
                    uncomp: e.content.len() as u32,
                    body: e.content.clone(),
                }
            }
        })
        .collect()
}

fn raw_zip(entries: &[LogicalEntry], deflate: bool) -> Vec<u8> {
    let members = resolve_raw(entries, deflate);
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for m in &members {
        offsets.push(out.len() as u32);
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, 20);
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
        push_u16(&mut central, 20);
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

fn raw_zip_store(entries: &[LogicalEntry]) -> Vec<u8> {
    raw_zip(entries, false)
}

fn raw_zip_deflate(entries: &[LogicalEntry]) -> Vec<u8> {
    raw_zip(entries, true)
}

// ---------------------------------------------------------------------------
// ZIP tests.
// ---------------------------------------------------------------------------

#[test]
fn zip_store_interop() {
    let entries = zip_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_zip_store,
            },
            ProducerCase {
                name: "zip@8.6.0",
                encode: zipcrate_zip_store,
            },
            ProducerCase {
                name: "raw-zip-builder",
                encode: raw_zip_store,
            },
        ],
    );

    let arca_bytes = arca_zip_store(&entries);
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

    // Codec-method evidence: the `zip` consumer exposes the stored method for file members.
    for shape in zip_crate_decode(&arca_bytes) {
        if shape.kind() == EntryKind::File {
            shape.assert_method(CompressionMethod::Store);
        }
    }
}

#[test]
fn zip_deflate_interop() {
    let entries = zip_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_zip_deflate,
            },
            ProducerCase {
                name: "zip@8.6.0",
                encode: zipcrate_zip_deflate,
            },
            ProducerCase {
                name: "raw-zip-builder",
                encode: raw_zip_deflate,
            },
        ],
    );

    let arca_bytes = arca_zip_deflate(&entries);
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

    // Codec-method evidence: non-empty file members are Deflate through the `zip` consumer.
    for shape in zip_crate_decode(&arca_bytes) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Deflate);
        }
    }
}

// ---------------------------------------------------------------------------
// 7z LZMA2 (feature `sevenz`).
// ---------------------------------------------------------------------------

#[cfg(feature = "sevenz")]
fn sevenz_entries() -> Vec<LogicalEntry> {
    vec![
        LogicalEntry::file(b"pkg/a.txt".to_vec(), b"first independent file\n".to_vec()),
        LogicalEntry::file(
            b"pkg/b.txt".to_vec(),
            b"second independent file, a bit longer\n".repeat(20),
        ),
    ]
}

#[cfg(feature = "sevenz")]
fn arca_7z(entries: &[LogicalEntry]) -> Vec<u8> {
    use libarchive_oxide::SeekArchiveWriter;
    use libarchive_oxide_core::FormatId;

    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    for e in entries {
        let metadata = EntryMetadata::builder(e.kind, ArchivePath::from_bytes(e.path.clone()))
            .size(None)
            .mode(Some(0o644))
            .build();
        writer.start_entry(&metadata).unwrap();
        if !e.content.is_empty() {
            for chunk in e.content.chunks(13) {
                writer.write_data(chunk).unwrap();
            }
        }
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[cfg(feature = "sevenz")]
fn sevenz_rust2_7z(entries: &[LogicalEntry]) -> Vec<u8> {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter as SevenWriter, SourceReader};

    let contents: Vec<Vec<u8>> = entries.iter().map(|e| e.content.clone()).collect();
    let archive_entries: Vec<ArchiveEntry> = entries
        .iter()
        .map(|e| ArchiveEntry::new_file(std::str::from_utf8(&e.path).unwrap()))
        .collect();
    let sources: Vec<SourceReader<&[u8]>> = contents
        .iter()
        .map(|c| SourceReader::from(c.as_slice()))
        .collect();

    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    w.push_archive_entries(archive_entries, sources).unwrap();
    w.finish().unwrap().into_inner()
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_lzma2_interop() {
    let entries = sevenz_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_7z,
            },
            ProducerCase {
                name: "sevenz-rust2@0.21.3",
                encode: sevenz_rust2_7z,
            },
        ],
    );

    let arca_bytes = arca_7z(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[
            ConsumerCase {
                name: "arca",
                decode: read_with_arca,
            },
            ConsumerCase {
                name: "sevenz-rust2@0.21.3",
                decode: sevenz_rust2_decode,
            },
        ],
    );

    // Codec-method evidence: the sevenz-rust2 consumer reports the LZMA2 folder codec.
    for shape in sevenz_rust2_decode(&arca_bytes) {
        shape.assert_method(CompressionMethod::Lzma2);
    }
}
