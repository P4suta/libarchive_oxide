// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ar (Unix archiver) producer-specific corpora and metadata round trips (RM-304).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) for content interop across
//! THREE independent producers — arca's sequential ar writer, the `ar` crate, and
//! a first-party raw ar builder (`!<arch>\n` magic + 60-byte member headers) — and
//! TWO consumers (arca's sequential `ArchiveReader` and the `ar` crate). Beyond
//! content it asserts metadata FIDELITY through arca's `MetaShape`: the mode,
//! uid/gid, and mtime a producer writes are surfaced unchanged.
//!
//! `ar` carries no directory or symlink concept — every member is a FLAT regular
//! file — so the corpus is regular files only, and there is no link-target
//! fidelity to check (unlike the tar slice). Member names are kept < 16 bytes so
//! every producer stays on the short-name path: arca writes BSD long names
//! (`#1/LEN`) at len > 15 while the `ar` crate's `Builder` switches to BSD only at
//! len > 16 or on an embedded space, so short names keep all three producers on the
//! byte-compatible common/SysV `name/` layout that arca reads identically.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use libarchive_oxide::ArchiveWriter;
use libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, FormatId, Limits, Owner, Timestamp,
};

mod common;
use common::*;

fn ar_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello ar world\n".to_vec()),
        LogicalEntry::file(b"data.bin".to_vec(), (0_u8..=255).collect::<Vec<u8>>()),
        LogicalEntry::file(b"big.txt".to_vec(), big),
        LogicalEntry::file(b"empty".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer 1: arca's sequential ar writer (system under test).
// ---------------------------------------------------------------------------

fn arca_ar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Ar, Limits::default()).unwrap();
    for e in entries {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(e.path.clone()))
                .size(Some(e.content.len() as u64))
                .mode(Some(0o644))
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
// Producer 2: the independent `ar` crate (ar@0.9). Short, space-free names keep
// its `Builder` on the common variant (name space-padded to 16), which arca reads
// back as a plain SysV member.
// ---------------------------------------------------------------------------

fn arcrate_ar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut builder = ar::Builder::new(Vec::new());
    for e in entries {
        let mut header = ar::Header::new(e.path.clone(), e.content.len() as u64);
        header.set_mode(0o100_644);
        builder.append(&header, e.content.as_slice()).unwrap();
    }
    builder.into_inner().unwrap()
}

fn arcrate_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use std::io::Read;

    let mut archive = ar::Archive::new(bytes);
    let mut out = Vec::new();
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry.unwrap();
        let name = entry.header().identifier().to_vec();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        out.push(EntryShape::new(name, EntryKind::File, content));
    }
    out
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw ar builder, independent of both arca and the `ar`
// crate. `!<arch>\n` global magic + 60-byte ASCII member headers, SysV `name/`
// terminator, decimal mtime/uid/gid, octal mode, decimal size, `` `\n `` header
// terminator, one `\n` pad byte after odd-sized members.
// ---------------------------------------------------------------------------

fn put_field(header: &mut [u8], (start, end): (usize, usize), value: &[u8]) {
    // ar header fields are left-justified and space padded (the field is already
    // filled with spaces by the caller).
    let field = &mut header[start..end];
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
}

fn raw_member_header(name: &[u8], size: u64) -> [u8; 60] {
    let mut header = [b' '; 60];
    let mut name_field = name.to_vec();
    name_field.push(b'/'); // SysV terminator; keeps the field unambiguous.
    put_field(&mut header, (0, 16), &name_field);
    put_field(&mut header, (16, 28), b"0"); // mtime
    put_field(&mut header, (28, 34), b"0"); // uid
    put_field(&mut header, (34, 40), b"0"); // gid
    put_field(&mut header, (40, 48), b"100644"); // mode (S_IFREG | 0644), octal
    put_field(&mut header, (48, 58), format!("{size}").as_bytes());
    header[58] = b'`';
    header[59] = b'\n';
    header
}

fn raw_ar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"!<arch>\n");
    for e in entries {
        out.extend_from_slice(&raw_member_header(&e.path, e.content.len() as u64));
        out.extend_from_slice(&e.content);
        if e.content.len() % 2 != 0 {
            out.push(b'\n'); // members are 2-byte aligned.
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 3x2 content interop.
// ---------------------------------------------------------------------------

#[test]
fn ar_content_interop() {
    let entries = ar_entries();
    let shapes = assert_producers_agree_seq(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_ar,
            },
            ProducerCase {
                name: "ar@0.9",
                encode: arcrate_ar,
            },
            ProducerCase {
                name: "raw-ar-builder",
                encode: raw_ar,
            },
        ],
    );

    let arca_bytes = arca_ar(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[
            ConsumerCase {
                name: "arca",
                decode: read_seq_with_arca,
            },
            ConsumerCase {
                name: "ar@0.9",
                decode: arcrate_decode,
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// Metadata fidelity: mode / uid / gid / mtime round trip. ar carries no symlink
// or directory metadata, so those are out of scope for this format.
// ---------------------------------------------------------------------------

const UID: u64 = 1000;
const GID: u64 = 1001;
const MTIME: i64 = 1_700_200_000;

fn arca_ar_meta() -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Ar, Limits::default()).unwrap();
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
    writer.finish().unwrap()
}

fn arcrate_ar_meta() -> Vec<u8> {
    let mut builder = ar::Builder::new(Vec::new());
    let mut header = ar::Header::new(b"file.txt".to_vec(), 5);
    header.set_mode(0o100_640); // S_IFREG | 0640, as a real ar tool records it.
    header.set_uid(UID as u32);
    header.set_gid(GID as u32);
    header.set_mtime(MTIME as u64);
    builder.append(&header, &b"hello"[..]).unwrap();
    builder.into_inner().unwrap()
}

fn assert_meta_fidelity(bytes: &[u8], producer: &str) {
    let shapes = read_meta_seq_with_arca(bytes);
    let file = shapes
        .iter()
        .find(|shape| shape.path == b"file.txt")
        .unwrap_or_else(|| panic!("{producer}: file.txt missing"));
    assert_eq!(file.kind, EntryKind::File, "{producer}: file kind");
    // ar masks the mode to the low 12 permission bits (the S_IFREG type bits are
    // dropped on read), so 0o640 must survive exactly.
    assert_eq!(file.mode, Some(0o640), "{producer}: file mode");
    assert_eq!(
        file.owner(),
        (Some(UID), Some(GID)),
        "{producer}: file owner"
    );
    assert_eq!(file.mtime, Some(MTIME), "{producer}: file mtime");
}

#[test]
fn ar_metadata_round_trip() {
    // arca's own writer round-trips its typed metadata...
    assert_meta_fidelity(&arca_ar_meta(), "arca");
    // ...and arca reads the independent `ar` crate's metadata identically.
    assert_meta_fidelity(&arcrate_ar_meta(), "ar@0.9");
}
