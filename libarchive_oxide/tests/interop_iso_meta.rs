// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO 9660 producer corpus and metadata round trips (RM-304).
//!
//! ISO is a SEEK format, so this slice reuses the RM-301 harness
//! (`tests/common/mod.rs`) through the SEEK entry points: content interop via
//! `read_with_arca` / `assert_producers_agree` / `assert_consumers_accept`, and
//! metadata FIDELITY via `read_meta_seek_with_arca` + `MetaShape`.
//!
//! Producer independence is fundamentally narrower than for tar/ZIP: there is NO
//! usable pure-Rust independent ISO reader on every target this suite runs on (the
//! `iso9660` crate is a libcdio C binding; `cdfs` pulls in FUSE, which does not
//! build on Windows). So content interop is:
//!
//! * `arca` write -> `arca` read (self round trip through the ISO writer + reader), and
//! * an external ISO mastering tool (`xorriso`/`genisoimage`/`mkisofs`) as an
//!   INDEPENDENT producer that arca reads back, with a graceful skip when none is
//!   installed — mirroring `iso_differential.rs::arca_reads_system_mastered_image`.
//!
//! Metadata fidelity exercises arca's Rock Ridge emission (PX mode/uid/gid, TF
//! times, SL symlink), which the writer emits by DEFAULT and the reader
//! auto-detects and prefers over the Joliet tree.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::io::Cursor;
use std::process::Command;

use libarchive_oxide::SeekArchiveWriter;
use libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, FormatId, Limits, Owner, Timestamp,
};

mod common;
use common::*;

fn iso_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello iso world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer: arca's ISO 9660 seek writer (system under test).
// ---------------------------------------------------------------------------

fn arca_iso(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
    .unwrap();
    for e in entries {
        let mode = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        // ISO directory records carry a trailing slash; arca's tree builder wants it.
        let mut path = e.path.clone();
        if e.kind == EntryKind::Dir && path.last() != Some(&b'/') {
            path.push(b'/');
        }
        let metadata = EntryMetadata::builder(e.kind, ArchivePath::from_bytes(path))
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
    writer.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------------------
// Content interop: arca writes -> arca reads back to the canonical shapes.
// Only arca can read ISO in-code (no independent pure-Rust reader on all
// targets), so this is a single-producer / single-consumer self round trip. The
// INDEPENDENT-producer evidence lives in `arca_reads_system_mastered_image`.
// ---------------------------------------------------------------------------

#[test]
fn iso_content_interop() {
    let entries = iso_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[ProducerCase {
            name: "arca",
            encode: arca_iso,
        }],
    );

    let arca_bytes = arca_iso(&entries);
    assert_consumers_accept(
        &arca_bytes,
        &shapes,
        &[ConsumerCase {
            name: "arca",
            decode: read_with_arca,
        }],
    );
}

// ---------------------------------------------------------------------------
// Independent producer (graceful skip): a system ISO mastering tool writes an
// image; arca reads it back and must reconstruct the exact file content. Mirrors
// `iso_differential.rs::arca_reads_system_mastered_image`.
// ---------------------------------------------------------------------------

/// Locates an installed ISO-mastering tool, returning its name if any.
fn iso_tool() -> Option<&'static str> {
    for tool in ["xorriso", "genisoimage", "mkisofs"] {
        let ok = Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty());
        if ok {
            return Some(tool);
        }
    }
    None
}

#[test]
fn arca_reads_system_mastered_image() {
    let Some(tool) = iso_tool() else {
        eprintln!("skipping: no xorriso/genisoimage/mkisofs installed");
        return;
    };

    let hello = b"independent-producer payload read back by arca\n";
    let data = vec![0x5Au8; 4096];

    let dir = std::env::temp_dir().join(format!("arca_iso_meta_{}", std::process::id()));
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join("readme.txt"), hello).unwrap();
    std::fs::write(sub.join("big.bin"), &data).unwrap();

    let out = dir.join("out.iso");
    // xorriso understands the mkisofs CLI via `-as mkisofs`; `-R` requests Rock Ridge.
    let status = if tool == "xorriso" {
        Command::new(tool)
            .args(["-as", "mkisofs", "-R", "-J", "-o"])
            .arg(&out)
            .arg(&dir)
            .status()
    } else {
        Command::new(tool)
            .args(["-R", "-J", "-o"])
            .arg(&out)
            .arg(&dir)
            .status()
    };

    let made = status.is_ok_and(|s| s.success());
    if !made {
        eprintln!("skipping: {tool} failed to master an image");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let bytes = std::fs::read(&out).unwrap();
    let shapes = read_with_arca(&bytes);
    let readme = shapes
        .iter()
        .find(|s| s.path().ends_with(b"readme.txt"))
        .unwrap_or_else(|| panic!("{tool}: readme.txt missing from arca read-back"));
    assert_eq!(readme.content(), hello, "{tool}: readme.txt content");
    let big = shapes
        .iter()
        .find(|s| s.path().ends_with(b"big.bin"))
        .unwrap_or_else(|| panic!("{tool}: big.bin missing from arca read-back"));
    assert_eq!(big.content(), data.as_slice(), "{tool}: big.bin content");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Metadata fidelity: mode / uid / gid / mtime / symlink round trip through
// arca's Rock Ridge (PX / TF / SL), read back with the SEEK reader.
// ---------------------------------------------------------------------------

const UID: u64 = 1000;
const GID: u64 = 1001;
const MTIME: i64 = 1_700_200_000;

fn arca_iso_meta() -> Vec<u8> {
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
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

    writer.finish().unwrap().into_inner()
}

#[test]
fn iso_metadata_round_trip() {
    let bytes = arca_iso_meta();
    let shapes = read_meta_seek_with_arca(&bytes);

    let file = shapes
        .iter()
        .find(|shape| shape.path == b"file.txt")
        .unwrap_or_else(|| panic!("file.txt missing"));
    assert_eq!(file.kind, EntryKind::File, "file kind");
    assert_eq!(file.mode, Some(0o640), "file mode survives Rock Ridge PX");
    assert_eq!(
        file.owner(),
        (Some(UID), Some(GID)),
        "file owner survives Rock Ridge PX"
    );
    assert_eq!(file.mtime, Some(MTIME), "file mtime survives Rock Ridge TF");

    let link = shapes
        .iter()
        .find(|shape| shape.path == b"link")
        .unwrap_or_else(|| panic!("link missing"));
    assert_eq!(
        link.kind,
        EntryKind::Symlink,
        "link kind survives Rock Ridge"
    );
    assert_eq!(
        link.link_target.as_deref(),
        Some(&b"file.txt"[..]),
        "symlink target survives Rock Ridge SL"
    );
    assert_eq!(
        link.mode,
        Some(0o777),
        "symlink mode survives Rock Ridge PX"
    );
}
