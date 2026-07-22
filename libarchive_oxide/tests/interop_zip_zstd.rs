// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP Zstandard (method 93) interoperability evidence (RM-302).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`). The whole file is gated on the `zstd`
//! feature, which is enabled on BOTH codec profiles (portable-codecs and native-codecs).
//!
//! Profile asymmetry (stated honestly, mirrored in campaign-3-evidence.md):
//!
//! * READ is proven on BOTH profiles by TWO independent external producers — the `zip` crate with
//!   `CompressionMethod::Zstd`, and a first-party raw-ZIP builder embedding a raw zstd frame from
//!   the independent-C `zstd` crate (dev-dep `zstd-codec`). arca reads each back byte-identical.
//! * WRITE + a THIRD producer (arca itself emitting method-93 members) are proven ONLY on
//!   native-codecs (`#[cfg(feature = "native-codecs")]`), because the portable `ruzstd` path is
//!   deliberately decode-only for ZIP production. Both the `zip` crate and the independent-C `zstd`
//!   crate decode arca's members back to identical content.
#![cfg(feature = "zstd")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::io::Cursor;

#[cfg(feature = "native-codecs")]
use libarchive_oxide::{ArchiveWriter, ZipMethod};
use libarchive_oxide_core::EntryKind;
#[cfg(feature = "native-codecs")]
use libarchive_oxide_core::{ArchivePath, EntryMetadata, Limits};

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Shared logical corpus (file, dir, file-in-subdir, empty file).
// ---------------------------------------------------------------------------

fn zip_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello zstd world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer 1 (native only): arca's own streaming ZIP writer (system under test).
// ---------------------------------------------------------------------------

#[cfg(feature = "native-codecs")]
fn arca_zip_zstd(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Zstd, Limits::default());
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

// ---------------------------------------------------------------------------
// Producer 2: the independent `zip` crate (zip@8.6.0) with method Zstd.
// ---------------------------------------------------------------------------

fn zipcrate_zip_zstd(entries: &[LogicalEntry]) -> Vec<u8> {
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
                .compression_method(zip::CompressionMethod::Zstd)
                .unix_permissions(0o644);
            zw.start_file(name, opts).unwrap();
            zw.write_all(&e.content).unwrap();
        }
    }
    zw.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw ZIP builder, independent of BOTH arca and the
// `zip` crate. Bodies are raw zstd frames produced by the independent-C `zstd`
// crate (dev-dep `zstd-codec`, package `zstd` 0.13.3). CRC-32 is flate2's Crc of
// the RAW content. "version needed to extract" = 63 for method-93 members.
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

fn raw_zstd(data: &[u8]) -> Vec<u8> {
    zstd_codec::stream::encode_all(Cursor::new(data), 3).unwrap()
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
                let body = raw_zstd(&e.content);
                RawMember {
                    name: e.path.clone(),
                    version: 63,
                    method: 93,
                    crc: crc32(&e.content),
                    comp: body.len() as u32,
                    uncomp: e.content.len() as u32,
                    body,
                }
            }
        })
        .collect()
}

fn raw_zip_zstd(entries: &[LogicalEntry]) -> Vec<u8> {
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
// READ evidence: >=2 external producers, arca (+ arca on native) read back
// byte-identical; both arca and the `zip` crate consume, with a method==93
// assertion through the `zip` consumer.
// ---------------------------------------------------------------------------

#[test]
fn zip_zstd_interop() {
    let entries = zip_entries();
    #[allow(unused_mut)]
    let mut producers = vec![
        ProducerCase {
            name: "zip@8.6.0",
            encode: zipcrate_zip_zstd,
        },
        ProducerCase {
            name: "raw-zip-zstd-builder",
            encode: raw_zip_zstd,
        },
    ];
    // WRITE evidence + third producer: arca as a producer, native-codecs only.
    #[cfg(feature = "native-codecs")]
    producers.push(ProducerCase {
        name: "arca",
        encode: arca_zip_zstd,
    });
    let shapes = assert_producers_agree(&entries, &producers);

    // Codec-method evidence: the raw builder's file members are method 93, and the `zip`
    // consumer reads them back as Zstd (the raw builder pins method 93 unconditionally, so
    // this is not subject to any writer's small-file store heuristic).
    let external = raw_zip_zstd(&entries);
    for shape in zip_crate_decode(&external) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Zstd);
        }
    }

    // Consumers accept the raw-builder archive on both profiles (arca + the `zip` crate).
    assert_consumers_accept(
        &external,
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

    // On native-codecs, arca's own method-93 output is also read back as Zstd by the `zip`
    // consumer (WRITE-side codec-method evidence).
    #[cfg(feature = "native-codecs")]
    for shape in zip_crate_decode(&arca_zip_zstd(&entries)) {
        if shape.kind() == EntryKind::File && !shape.content().is_empty() {
            shape.assert_method(CompressionMethod::Zstd);
        }
    }
}

// ---------------------------------------------------------------------------
// WRITE evidence (native-codecs only): arca produces method-93 members that the
// `zip` crate AND the independent-C `zstd` crate decode to identical content.
// ---------------------------------------------------------------------------

/// Extracts the single file member's raw compressed frame, method code, and
/// declared content from an arca-produced ZIP by parsing the central directory
/// (arca writes data descriptors, so authoritative sizes live there).
#[cfg(feature = "native-codecs")]
fn extract_single_member(zip: &[u8]) -> (u16, Vec<u8>, u32) {
    let read_u16 = |o: usize| u16::from_le_bytes([zip[o], zip[o + 1]]);
    let read_u32 = |o: usize| u32::from_le_bytes([zip[o], zip[o + 1], zip[o + 2], zip[o + 3]]);

    // Locate the End of Central Directory (no archive comment -> last 22 bytes).
    let eocd = zip.len() - 22;
    assert_eq!(&zip[eocd..eocd + 4], b"PK\x05\x06", "missing EOCD");
    let central_offset = read_u32(eocd + 16) as usize;

    // Walk the central directory to the first file record (method != 0).
    let mut cursor = central_offset;
    loop {
        assert_eq!(
            &zip[cursor..cursor + 4],
            b"PK\x01\x02",
            "missing central record"
        );
        let method = read_u16(cursor + 10);
        let comp_size = read_u32(cursor + 20) as usize;
        let uncomp_size = read_u32(cursor + 24);
        let name_len = read_u16(cursor + 28) as usize;
        let extra_len = read_u16(cursor + 30) as usize;
        let comment_len = read_u16(cursor + 32) as usize;
        let local_offset = read_u32(cursor + 42) as usize;
        if method != 0 {
            // Compute the local body start: 30-byte fixed header + name + extra.
            assert_eq!(&zip[local_offset..local_offset + 4], b"PK\x03\x04");
            let l_name = read_u16(local_offset + 26) as usize;
            let l_extra = read_u16(local_offset + 28) as usize;
            let body_start = local_offset + 30 + l_name + l_extra;
            let body = zip[body_start..body_start + comp_size].to_vec();
            return (method, body, uncomp_size);
        }
        cursor += 46 + name_len + extra_len + comment_len;
    }
}

/// Produces a single-file arca ZIP with a KNOWN entry size so the central
/// directory stores plain (non-zip64) 32-bit sizes, keeping [`extract_single_member`]
/// simple. WRITE bytes are still genuine arca method-93 output.
#[cfg(feature = "native-codecs")]
fn arca_single_file_known_size(name: &[u8], content: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Zstd, Limits::default());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
        .size(Some(content.len() as u64))
        .mode(Some(0o644))
        .build();
    writer.start_entry(&metadata).unwrap();
    for chunk in content.chunks(97) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

#[cfg(feature = "native-codecs")]
#[test]
fn zip_zstd_write_is_decoded_by_independent_libzstd_and_zip_crate() {
    let content = b"arca-produced zstd member for independent decode\n".repeat(64);
    let arca_bytes = arca_single_file_known_size(b"payload.bin", &content);

    // Consumer A: the `zip` crate reconstructs identical content and reports method 93.
    let decoded = zip_crate_decode(&arca_bytes);
    let file = decoded
        .iter()
        .find(|s| s.kind() == EntryKind::File)
        .expect("file member");
    assert_eq!(file.content(), content.as_slice());
    file.assert_method(CompressionMethod::Zstd);

    // Consumer B: extract arca's raw frame and decode with the independent-C `zstd` crate.
    let (method, frame, uncomp) = extract_single_member(&arca_bytes);
    assert_eq!(method, 93, "arca must emit ZIP method 93 for Zstandard");
    assert_eq!(uncomp as usize, content.len());
    let plain = zstd_codec::stream::decode_all(Cursor::new(frame)).unwrap();
    assert_eq!(plain, content, "independent libzstd decode of arca member");
}
