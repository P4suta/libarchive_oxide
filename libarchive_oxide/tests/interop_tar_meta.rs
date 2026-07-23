// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! tar producer-specific corpora and metadata round trips (RM-304).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) for content interop across
//! THREE independent producers — arca's sequential tar writer, the `tar` crate,
//! and a first-party raw ustar builder — and TWO consumers (arca's sequential
//! `ArchiveReader` and the `tar` crate). Beyond content it asserts metadata
//! FIDELITY through arca's `MetaShape`: mode, uid/gid, mtime, and symlink targets
//! written by a producer are surfaced unchanged.
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

fn tar_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello tar world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer 1: arca's sequential tar writer (system under test).
// ---------------------------------------------------------------------------

fn arca_tar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Tar, Limits::default())
            .unwrap();
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
// Producer 2: the independent `tar` crate (tar@0.4).
// ---------------------------------------------------------------------------

fn tarcrate_tar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for e in entries {
        let name = std::str::from_utf8(&e.path).unwrap();
        let mut header = tar::Header::new_ustar();
        if e.kind == EntryKind::Dir {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
            let mut dir = name.to_string();
            dir.push('/');
            header.set_path(&dir).unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(e.content.len() as u64);
            header.set_path(name).unwrap();
            header.set_cksum();
            builder.append(&header, e.content.as_slice()).unwrap();
        }
    }
    builder.into_inner().unwrap()
}

fn tarcrate_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use std::io::Read;

    let mut archive = tar::Archive::new(bytes);
    let mut out = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let raw = entry.path_bytes().to_vec();
        let kind = if entry.header().entry_type().is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let mut content = Vec::new();
        if !entry.header().entry_type().is_dir() {
            entry.read_to_end(&mut content).unwrap();
        }
        out.push(EntryShape::new(raw, kind, content));
    }
    out
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw ustar builder, independent of both arca and the
// `tar` crate. 512-byte header blocks, POSIX ustar magic, computed checksum.
// ---------------------------------------------------------------------------

fn put_octal(block: &mut [u8], offset: usize, width: usize, value: u64) {
    let digits = format!("{value:0>width$o}", width = width - 1);
    block[offset..offset + width - 1].copy_from_slice(digits.as_bytes());
    // trailing NUL already zero
}

fn ustar_header(name: &[u8], kind: EntryKind, size: u64, mode: u32) -> [u8; 512] {
    let mut block = [0_u8; 512];
    let (name_bytes, typeflag): (Vec<u8>, u8) = if kind == EntryKind::Dir {
        let mut n = name.to_vec();
        n.push(b'/');
        (n, b'5')
    } else {
        (name.to_vec(), b'0')
    };
    block[..name_bytes.len()].copy_from_slice(&name_bytes);
    put_octal(&mut block, 100, 8, u64::from(mode & 0o7777));
    put_octal(&mut block, 108, 8, 0); // uid
    put_octal(&mut block, 116, 8, 0); // gid
    put_octal(&mut block, 124, 12, size);
    put_octal(&mut block, 136, 12, 0); // mtime
    block[156] = typeflag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    // Checksum: sum of all bytes with the 8-byte chksum field treated as spaces.
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    let checksum = format!("{sum:0>6o}");
    block[148..154].copy_from_slice(checksum.as_bytes());
    block[154] = 0;
    block[155] = b' ';
    block
}

fn raw_tar(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let mode = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        out.extend_from_slice(&ustar_header(&e.path, e.kind, e.content.len() as u64, mode));
        if !e.content.is_empty() {
            out.extend_from_slice(&e.content);
            let padding = (512 - e.content.len() % 512) % 512;
            out.extend(std::iter::repeat_n(0_u8, padding));
        }
    }
    out.extend_from_slice(&[0_u8; 1024]); // two zero blocks terminate the archive
    out
}

// ---------------------------------------------------------------------------
// 3x2 content interop.
// ---------------------------------------------------------------------------

#[test]
fn tar_content_interop() {
    let entries = tar_entries();
    let shapes = assert_producers_agree_seq(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_tar,
            },
            ProducerCase {
                name: "tar@0.4",
                encode: tarcrate_tar,
            },
            ProducerCase {
                name: "raw-ustar-builder",
                encode: raw_tar,
            },
        ],
    );

    let arca_bytes = arca_tar(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[
            ConsumerCase {
                name: "arca",
                decode: read_seq_with_arca,
            },
            ConsumerCase {
                name: "tar@0.4",
                decode: tarcrate_decode,
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// Metadata fidelity: mode / uid / gid / mtime / symlink round trip.
// ---------------------------------------------------------------------------

const UID: u64 = 1000;
const GID: u64 = 1001;
const MTIME: i64 = 1_700_200_000;

fn arca_tar_meta() -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Tar, Limits::default())
            .unwrap();
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

    let link = EntryMetadata::builder(
        EntryKind::Symlink,
        ArchivePath::from_bytes(b"link".to_vec()),
    )
    .size(Some(0))
    .mode(Some(0o777))
    .link_target(Some(ArchivePath::from_bytes(b"file.txt".to_vec())))
    .build();
    writer.start_entry(&link).unwrap();
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn tarcrate_tar_meta() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o640);
    header.set_uid(UID);
    header.set_gid(GID);
    header.set_mtime(MTIME as u64);
    header.set_size(5);
    header.set_path("file.txt").unwrap();
    header.set_cksum();
    builder.append(&header, &b"hello"[..]).unwrap();

    let mut link = tar::Header::new_ustar();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_mode(0o777);
    link.set_size(0);
    link.set_path("link").unwrap();
    link.set_link_name("file.txt").unwrap();
    link.set_cksum();
    builder.append(&link, std::io::empty()).unwrap();

    builder.into_inner().unwrap()
}

fn assert_meta_fidelity(bytes: &[u8], producer: &str) {
    let shapes = read_meta_seq_with_arca(bytes);
    let file = shapes
        .iter()
        .find(|shape| shape.path == b"file.txt")
        .unwrap_or_else(|| panic!("{producer}: file.txt missing"));
    assert_eq!(file.kind, EntryKind::File, "{producer}: file kind");
    assert_eq!(file.mode, Some(0o640), "{producer}: file mode");
    assert_eq!(
        file.owner(),
        (Some(UID), Some(GID)),
        "{producer}: file owner"
    );
    assert_eq!(file.mtime, Some(MTIME), "{producer}: file mtime");

    let link = shapes
        .iter()
        .find(|shape| shape.path == b"link")
        .unwrap_or_else(|| panic!("{producer}: link missing"));
    assert_eq!(link.kind, EntryKind::Symlink, "{producer}: link kind");
    assert_eq!(
        link.link_target.as_deref(),
        Some(&b"file.txt"[..]),
        "{producer}: link target"
    );
}

#[test]
fn tar_metadata_round_trip() {
    // arca's own writer round-trips its typed metadata...
    assert_meta_fidelity(&arca_tar_meta(), "arca");
    // ...and arca reads the independent `tar` crate's metadata identically.
    assert_meta_fidelity(&tarcrate_tar_meta(), "tar@0.4");
}
