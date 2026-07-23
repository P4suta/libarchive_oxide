// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! cpio producer-specific corpora and metadata round trips (RM-304).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) for content interop across
//! THREE independent producers — arca's sequential cpio writer (`newc`), a
//! first-party raw `newc` (070701) builder, and a first-party raw `odc` (070707)
//! builder (a genuinely different on-disk encoding: octal fields, no header/data
//! padding) — and TWO consumers (arca's sequential `ArchiveReader` and a
//! first-party raw `newc` parser independent of arca's decoder). Beyond content
//! it asserts metadata FIDELITY through arca's `MetaShape`: mode, uid/gid, mtime,
//! and hardlink targets written by arca survive a round trip unchanged.
//!
//! No mature pure-Rust cpio *producer* crate exists, so the third independent
//! producer is a second first-party raw builder in a different dialect rather
//! than a third-party crate; see `tests/fixtures/cpio/PROVENANCE.md` for the
//! honesty note. cpio carries mode/uid/gid/mtime/nlink/inode/device but NO
//! xattr/acl, so metadata fidelity is asserted over that subset only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use libarchive_oxide::{ArchiveWriter, CpioDialect};
use libarchive_oxide_core::{
    ArchivePath, Device, EntryKind, EntryMetadata, EntryTimes, Limits, Owner, Timestamp,
};

mod common;
use common::*;

fn cpio_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello cpio world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// File-type bits (`S_IFMT`) for the raw builders.
const S_IFMT: u64 = 0o170_000;
const S_IFREG: u64 = 0o100_000;
const S_IFDIR: u64 = 0o040_000;

fn ifmt_bits(kind: EntryKind) -> u64 {
    match kind {
        EntryKind::Dir => S_IFDIR,
        _ => S_IFREG,
    }
}

// ---------------------------------------------------------------------------
// Producer 1: arca's sequential cpio writer (system under test), `newc` dialect.
// ---------------------------------------------------------------------------

fn arca_cpio(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_cpio_dialect(Vec::new(), CpioDialect::Newc, Limits::default());
    for e in entries {
        let mode = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        let metadata = EntryMetadata::builder(e.kind, ArchivePath::from_bytes(e.path.clone()))
            .size(Some(e.content.len() as u64))
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
// Producer 2: a first-party raw SVR4 "newc" (070701) builder, independent of
// arca. 110-byte fixed header of 13 eight-hex-digit fields; header+name and data
// each padded to a 4-byte boundary; "TRAILER!!!" terminates the stream.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn newc_header(
    name: &[u8],
    kind: EntryKind,
    size: u64,
    perm: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    ino: u64,
    nlink: u64,
) -> Vec<u8> {
    let mode = ifmt_bits(kind) | u64::from(perm & 0o7777);
    let namesize = name.len() as u64 + 1;
    // Field order: ino, mode, uid, gid, nlink, mtime, filesize,
    // devmajor, devminor, rdevmajor, rdevminor, namesize, check.
    let fields = [
        ino, mode, uid, gid, nlink, mtime, size, 0, 0, 0, 0, namesize, 0,
    ];
    let mut out = Vec::new();
    out.extend_from_slice(b"070701");
    for f in fields {
        out.extend_from_slice(format!("{:08X}", f as u32).as_bytes());
    }
    out.extend_from_slice(name);
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn raw_newc(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let perm = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        out.extend_from_slice(&newc_header(
            &e.path,
            e.kind,
            e.content.len() as u64,
            perm,
            0,
            0,
            0,
            i as u64 + 1,
            1,
        ));
        out.extend_from_slice(&e.content);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out.extend_from_slice(&newc_header(
        b"TRAILER!!!",
        EntryKind::File,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ));
    out
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw POSIX "odc" (070707) builder, independent of
// both arca and the newc builder. A genuinely different on-disk encoding — octal
// ASCII fields at fixed offsets, 76-byte header, and NO header or data padding —
// so it is independent evidence, not a re-encoding of the same layout.
// ---------------------------------------------------------------------------

fn push_octal(out: &mut Vec<u8>, width: usize, value: u64) {
    out.extend_from_slice(format!("{value:0width$o}").as_bytes());
}

#[allow(clippy::too_many_arguments)]
fn odc_header(
    name: &[u8],
    kind: EntryKind,
    size: u64,
    perm: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    ino: u64,
    nlink: u64,
) -> Vec<u8> {
    let mode = ifmt_bits(kind) | u64::from(perm & 0o7777);
    let namesize = name.len() as u64 + 1;
    let mut out = Vec::new();
    out.extend_from_slice(b"070707");
    push_octal(&mut out, 6, 0); // dev
    push_octal(&mut out, 6, ino);
    push_octal(&mut out, 6, mode);
    push_octal(&mut out, 6, uid);
    push_octal(&mut out, 6, gid);
    push_octal(&mut out, 6, nlink);
    push_octal(&mut out, 6, 0); // rdev
    push_octal(&mut out, 11, mtime);
    push_octal(&mut out, 6, namesize);
    push_octal(&mut out, 11, size);
    out.extend_from_slice(name);
    out.push(0);
    // odc has 1-byte alignment: no header or data padding.
    out
}

fn raw_odc(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let perm = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        out.extend_from_slice(&odc_header(
            &e.path,
            e.kind,
            e.content.len() as u64,
            perm,
            0,
            0,
            0,
            i as u64 + 1,
            1,
        ));
        out.extend_from_slice(&e.content);
    }
    out.extend_from_slice(&odc_header(
        b"TRAILER!!!",
        EntryKind::File,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ));
    out
}

// ---------------------------------------------------------------------------
// Consumer 2: a first-party raw "newc" parser, independent of arca's decoder.
// arca writes `newc`, so this decodes arca's own output a second, disjoint way.
// ---------------------------------------------------------------------------

fn parse_hex(field: &[u8]) -> u64 {
    let text = std::str::from_utf8(field).unwrap();
    u64::from_str_radix(text.trim(), 16).unwrap()
}

fn raw_newc_decode(bytes: &[u8]) -> Vec<EntryShape> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let header = &bytes[pos..pos + 110];
        assert_eq!(&header[..6], b"070701", "raw-newc-parser: bad magic");
        let field = |i: usize| parse_hex(&header[6 + i * 8..6 + i * 8 + 8]);
        let mode = field(1);
        let size = field(6) as usize;
        let namesize = field(11) as usize;
        let name = &bytes[pos + 110..pos + 110 + namesize - 1]; // strip trailing NUL
        let header_len = 110 + namesize;
        let header_padded = (header_len + 3) & !3;
        pos += header_padded;
        if name == b"TRAILER!!!" {
            break;
        }
        let content = bytes[pos..pos + size].to_vec();
        pos += (size + 3) & !3;
        let kind = if mode & S_IFMT == S_IFDIR {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        out.push(EntryShape::new(name.to_vec(), kind, content));
    }
    out
}

// ---------------------------------------------------------------------------
// 3x2 content interop.
// ---------------------------------------------------------------------------

#[test]
fn cpio_content_interop() {
    let entries = cpio_entries();
    let shapes = assert_producers_agree_seq(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_cpio,
            },
            ProducerCase {
                name: "raw-newc-builder",
                encode: raw_newc,
            },
            ProducerCase {
                name: "raw-odc-builder",
                encode: raw_odc,
            },
        ],
    );

    let arca_bytes = arca_cpio(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[
            ConsumerCase {
                name: "arca",
                decode: read_seq_with_arca,
            },
            ConsumerCase {
                name: "raw-newc-parser",
                decode: raw_newc_decode,
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// Metadata fidelity: mode / uid / gid / mtime for a plain file, and a
// hardlink pair (File payload record + Hardlink alias) round trip through arca.
// ---------------------------------------------------------------------------

const UID: u64 = 1000;
const GID: u64 = 1001;
const MTIME: i64 = 1_700_200_000;

fn arca_cpio_meta() -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_cpio_dialect(Vec::new(), CpioDialect::Newc, Limits::default());

    // Plain file: exercises mode / uid / gid / mtime fidelity.
    let file = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"file.txt".to_vec()),
    )
    .size(Some(5))
    .mode(Some(0o640))
    .owner(Owner {
        uid: Some(UID),
        gid: Some(GID),
        ..Owner::default()
    })
    .times(EntryTimes {
        modified: Some(Timestamp {
            secs: MTIME,
            nanos: 0,
        }),
        ..EntryTimes::default()
    })
    .build();
    writer.start_entry(&file).unwrap();
    writer.write_data(b"hello").unwrap();
    writer.end_entry().unwrap();

    // Hardlink group: the payload-bearing target (nlink 2) precedes its alias.
    let device = Device { major: 8, minor: 1 };
    let target =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(b"target".to_vec()))
            .size(Some(4))
            .mode(Some(0o644))
            .inode_and_links(Some(42), Some(2))
            .devices(Some(device), None)
            .build();
    writer.start_entry(&target).unwrap();
    writer.write_data(b"body").unwrap();
    writer.end_entry().unwrap();

    let alias = EntryMetadata::builder(
        EntryKind::Hardlink,
        ArchivePath::from_bytes(b"alias".to_vec()),
    )
    .size(Some(0))
    .link_target(Some(ArchivePath::from_bytes(b"target".to_vec())))
    .build();
    writer.start_entry(&alias).unwrap();
    writer.end_entry().unwrap();

    writer.finish().unwrap()
}

#[test]
fn cpio_metadata_round_trip() {
    let bytes = arca_cpio_meta();
    let shapes = read_meta_seq_with_arca(&bytes);

    let file = shapes
        .iter()
        .find(|shape| shape.path == b"file.txt")
        .expect("file.txt missing");
    assert_eq!(file.kind, EntryKind::File, "file kind");
    assert_eq!(file.mode, Some(0o640), "file mode");
    assert_eq!(file.owner(), (Some(UID), Some(GID)), "file owner");
    assert_eq!(file.mtime, Some(MTIME), "file mtime");

    // The payload-bearing member surfaces as a plain File...
    let target = shapes
        .iter()
        .find(|shape| shape.path == b"target")
        .expect("target missing");
    assert_eq!(target.kind, EntryKind::File, "target kind");
    assert_eq!(target.mode, Some(0o644), "target mode");

    // ...and its alias surfaces as a typed Hardlink pointing back at it.
    let alias = shapes
        .iter()
        .find(|shape| shape.path == b"alias")
        .expect("alias missing");
    assert_eq!(alias.kind, EntryKind::Hardlink, "alias kind");
    assert_eq!(
        alias.link_target.as_deref(),
        Some(&b"target"[..]),
        "alias hardlink target"
    );
}

// Dialect coverage note: arca's cpio encoder supports Newc, Crc, Odc, and legacy
// binary little-/big-endian (`CpioDialect`). This interop slice drives the `Newc`
// dialect for deterministic, checksum-free bytes; `Crc` (which requires a per-entry
// four-byte big-endian payload byte-sum) and every other dialect are exercised by
// `libarchive_oxide-core/tests/protocol_v2.rs::cpio_encoder_roundtrips_every_supported_dialect`.
