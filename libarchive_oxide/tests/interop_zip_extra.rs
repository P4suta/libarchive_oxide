// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP extra-field structured-interpretation interoperability evidence (RM-308).
//!
//! Reuses the RM-301 harness (`tests/common/mod.rs`) to prove that structured
//! interpretation of ZIP extra fields (Info-ZIP New Unix uid/gid 0x7855 and the
//! Extended Timestamp 0x5455) never disturbs content interoperability, across
//! THREE independent producers — arca's ZIP writer driven from typed owner/time
//! metadata (so it synthesizes the extras), the `zip` crate (which emits its own
//! extended-timestamp extra), and a first-party raw-ZIP builder that embeds the
//! Info-ZIP Unix and Extended Timestamp fields verbatim — and TWO consumers
//! (arca's seek reader and the `zip` crate).
//!
//! Beyond content equality, it asserts metadata FIDELITY at the interop level:
//! reading the raw producer's output back through arca surfaces the exact uid,
//! gid, and modification time the producer wrote, and arca's own owner/time
//! output round-trips the same way.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::io::Cursor;

use libarchive_oxide::{ArchiveWriter, ReaderEvent, SeekArchiveReader, ZipMethod};
use libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, Limits, Owner, Timestamp,
};

mod common;
use common::*;

// Fixed uid/gid/mtime the extra-bearing producers encode; the reader must
// surface exactly these.
const UID: u16 = 1234;
const GID: u16 = 5678;
const MTIME: i32 = 1_700_100_000;

fn zip_entries() -> Vec<LogicalEntry> {
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    vec![
        LogicalEntry::file(b"readme.txt".to_vec(), b"hello extra world\n".to_vec()),
        LogicalEntry::dir(b"sub".to_vec()),
        LogicalEntry::file(b"sub/big.txt".to_vec(), big),
        LogicalEntry::file(b"sub/empty.txt".to_vec(), Vec::new()),
    ]
}

// ---------------------------------------------------------------------------
// Producer 1: arca's ZIP writer, driven from typed owner + time metadata so it
// synthesizes the Extended Timestamp and Info-ZIP New Unix extras itself.
// ---------------------------------------------------------------------------

fn arca_zip_extra(entries: &[LogicalEntry]) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    for e in entries {
        let mode = if e.kind == EntryKind::Dir {
            0o755
        } else {
            0o644
        };
        let metadata = EntryMetadata::builder(e.kind, ArchivePath::from_bytes(e.path.clone()))
            .size(None)
            .mode(Some(mode))
            .owner(Owner {
                uid: Some(u64::from(UID)),
                gid: Some(u64::from(GID)),
                ..Owner::default()
            })
            .times(EntryTimes {
                modified: Some(Timestamp {
                    secs: i64::from(MTIME),
                    nanos: 0,
                }),
                ..EntryTimes::default()
            })
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
// Producer 2: the independent `zip` crate (emits its own extended-timestamp).
// ---------------------------------------------------------------------------

fn zipcrate_zip(entries: &[LogicalEntry]) -> Vec<u8> {
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
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o644);
            zw.start_file(name, opts).unwrap();
            zw.write_all(&e.content).unwrap();
        }
    }
    zw.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------------------
// Producer 3: a first-party raw ZIP builder, independent of BOTH arca and the
// `zip` crate, that embeds the Info-ZIP New Unix (0x7855) and Extended Timestamp
// (0x5455) extras verbatim in every member's local AND central headers.
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

// Info-ZIP New Unix (uid/gid) + Extended Timestamp (mtime), identical in the
// local and central headers so a spec-conformant reader parses either.
fn infozip_extras() -> Vec<u8> {
    let mut extra = Vec::new();
    push_u16(&mut extra, 0x7855);
    push_u16(&mut extra, 4);
    push_u16(&mut extra, UID);
    push_u16(&mut extra, GID);
    push_u16(&mut extra, 0x5455);
    push_u16(&mut extra, 5);
    extra.push(0x01);
    push_u32(&mut extra, MTIME as u32);
    extra
}

struct RawMember {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    size: u32,
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
                    method: 0,
                    crc: 0,
                    size: 0,
                    body: Vec::new(),
                }
            } else {
                RawMember {
                    name: e.path.clone(),
                    method: 0,
                    crc: crc32(&e.content),
                    size: e.content.len() as u32,
                    body: e.content.clone(),
                }
            }
        })
        .collect()
}

fn raw_zip_extra(entries: &[LogicalEntry]) -> Vec<u8> {
    let members = resolve_raw(entries);
    let extra = infozip_extras();
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
        push_u32(&mut out, m.size);
        push_u32(&mut out, m.size);
        push_u16(&mut out, m.name.len() as u16);
        push_u16(&mut out, extra.len() as u16);
        out.extend_from_slice(&m.name);
        out.extend_from_slice(&extra);
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
        push_u32(&mut central, m.size);
        push_u32(&mut central, m.size);
        push_u16(&mut central, m.name.len() as u16);
        push_u16(&mut central, extra.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, *offset);
        central.extend_from_slice(&m.name);
        central.extend_from_slice(&extra);
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
// Metadata-fidelity helper: the uid/gid/mtime arca surfaces for the first file.
// ---------------------------------------------------------------------------

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn first_file_owner_and_mtime(archive: &[u8]) -> (Option<u64>, Option<u64>, Option<i64>) {
    let mut reader = SeekArchiveReader::new(Cursor::new(archive.to_vec())).unwrap();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => {
                if metadata.kind() == EntryKind::File {
                    return (
                        metadata.owner().uid,
                        metadata.owner().gid,
                        metadata.times().modified.map(|value| value.secs),
                    );
                }
            },
            ReaderEvent::Done => panic!("no file entry found"),
            _ => {},
        }
    }
}

// ---------------------------------------------------------------------------
// 3x2 content interop + metadata fidelity.
// ---------------------------------------------------------------------------

#[test]
fn zip_extra_interop() {
    let entries = zip_entries();
    let shapes = assert_producers_agree(
        &entries,
        &[
            ProducerCase {
                name: "arca",
                encode: arca_zip_extra,
            },
            ProducerCase {
                name: "zip@8.6.0",
                encode: zipcrate_zip,
            },
            ProducerCase {
                name: "raw-zip-extra-builder",
                encode: raw_zip_extra,
            },
        ],
    );

    let arca_bytes = arca_zip_extra(&entries);
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

    // Metadata fidelity: the raw producer's Info-ZIP extras are surfaced exactly.
    let (uid, gid, mtime) = first_file_owner_and_mtime(&raw_zip_extra(&entries));
    assert_eq!(uid, Some(u64::from(UID)));
    assert_eq!(gid, Some(u64::from(GID)));
    assert_eq!(mtime, Some(i64::from(MTIME)));

    // And arca's own owner/time output round-trips through arca identically.
    let (uid, gid, mtime) = first_file_owner_and_mtime(&arca_bytes);
    assert_eq!(uid, Some(u64::from(UID)));
    assert_eq!(gid, Some(u64::from(GID)));
    assert_eq!(mtime, Some(i64::from(MTIME)));

    // Independent of arca's own reader, scan the raw output bytes for the exact
    // synthesized extra-field TLVs so a shared writer/reader convention error
    // cannot pass undetected. Info-ZIP New Unix (0x7855): id, len=4, uid, gid.
    let mut new_unix_tlv = vec![0x55, 0x78, 0x04, 0x00];
    new_unix_tlv.extend_from_slice(&UID.to_le_bytes());
    new_unix_tlv.extend_from_slice(&GID.to_le_bytes());
    assert!(
        contains_subslice(&arca_bytes, &new_unix_tlv),
        "arca output is missing the synthesized 0x7855 uid/gid extra"
    );
    // Extended Timestamp (0x5455): id, len=5, flags=0x01 (mtime), mtime.
    let mut timestamp_tlv = vec![0x55, 0x54, 0x05, 0x00, 0x01];
    timestamp_tlv.extend_from_slice(&(MTIME as u32).to_le_bytes());
    assert!(
        contains_subslice(&arca_bytes, &timestamp_tlv),
        "arca output is missing the synthesized 0x5455 modification-time extra"
    );
}
