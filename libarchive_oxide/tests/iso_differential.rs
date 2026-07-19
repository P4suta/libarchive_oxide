// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential / independent-validation test for the ISO 9660 + Joliet writer.
//!
//! No usable independent *pure-Rust* ISO reader exists on every target this suite runs on: the
//! `iso9660` crate is a libcdio (C) binding, and `cdfs` pulls in `fuser` (FUSE), which does not
//! build on Windows. So this test validates arca's writer two ways that do not lean on arca's own
//! `IsoReader`:
//!
//! 1. **Structural byte assertions** (always run): the volume-descriptor set (PVD type 1, Joliet SVD
//!    type 2 with the `25 2F 45` escape, terminator type 255), the root directory record, the
//!    path-table locations, and a **manual directory-record walk** that locates a known file and
//!    checks its extent bytes equal the exact content — an independent decode of arca's layout.
//! 2. **System `xorriso`/`mkisofs`/`genisoimage` → arca** (graceful skip when none is installed): an
//!    image mastered by a mature external tool is read back with arca, cross-validating the reader.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::process::Command;

use libarchive_oxide::{ReaderEvent, SeekArchiveReader, SeekArchiveWriter};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

const SECTOR: usize = 2048;

fn write_entry(
    writer: &mut SeekArchiveWriter<Cursor<Vec<u8>>>,
    kind: EntryKind,
    path: &[u8],
    data: &[u8],
) {
    let metadata = EntryMetadata::builder(kind, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(data.len() as u64))
        .build();
    writer.start_entry(&metadata).unwrap();
    if !data.is_empty() {
        writer.write_data(data).unwrap();
    }
    writer.end_entry().unwrap();
}

fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The exact content used for the extent-byte check.
const HELLO_CONTENT: &[u8] = b"structural-check payload for the extent walk\n";

fn arca_image() -> Vec<u8> {
    let mut w = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
    .unwrap();
    // Uppercase ASCII names so the *primary* tree (which mangles to d-characters) keeps them intact,
    // letting the manual primary-tree walk locate the file by its mangled identifier.
    write_entry(&mut w, EntryKind::File, b"HELLO.TXT", HELLO_CONTENT);
    write_entry(&mut w, EntryKind::Dir, b"SUB/", b"");
    write_entry(
        &mut w,
        EntryKind::File,
        b"SUB/DATA.BIN",
        &vec![0xABu8; 3000],
    );
    w.finish().unwrap().into_inner()
}

#[test]
fn writer_output_is_structurally_valid() {
    let img = arca_image();

    // Standard identifier at 0x8001.
    assert_eq!(&img[0x8001..0x8006], b"CD001");

    // Sector 16: Primary Volume Descriptor.
    let pvd = &img[16 * SECTOR..17 * SECTOR];
    assert_eq!(pvd[0], 1, "PVD type");
    assert_eq!(&pvd[1..6], b"CD001");
    assert_eq!(pvd[6], 1, "VD version");
    assert_eq!(
        u16::from_le_bytes([pvd[128], pvd[129]]),
        u16::try_from(SECTOR).unwrap(),
        "logical block size"
    );

    // Sector 17: Joliet Supplementary Volume Descriptor with the UCS-2 level-3 escape.
    let svd = &img[17 * SECTOR..18 * SECTOR];
    assert_eq!(svd[0], 2, "SVD type");
    assert_eq!(&svd[1..6], b"CD001");
    assert_eq!(&svd[88..91], &[0x25, 0x2F, 0x45], "Joliet escape sequence");

    // Sector 18: volume-descriptor set terminator.
    let term = &img[18 * SECTOR..19 * SECTOR];
    assert_eq!(term[0], 255, "terminator type");
    assert_eq!(&term[1..6], b"CD001");

    // Root directory record embedded in the PVD (offset 156, 34 bytes).
    let root = &pvd[156..190];
    assert_eq!(root[0], 34, "root record length");
    assert_eq!(root[25] & 0x02, 0x02, "root record is a directory");
    assert_eq!(root[32], 1, "root identifier length");
    assert_eq!(root[33], 0x00, "root identifier is 0x00");

    // Path-table locations are present (non-zero).
    assert_ne!(read_u32_le(pvd, 140), 0, "type-L path table location");
    assert_ne!(
        u32::from_be_bytes([pvd[148], pvd[149], pvd[150], pvd[151]]),
        0,
        "type-M path table location"
    );

    // Independent decode: walk the primary root extent, find HELLO.TXT, check its extent bytes.
    let root_lba = read_u32_le(pvd, 156 + 2) as usize;
    let root_size = read_u32_le(pvd, 156 + 10) as usize;
    let (lba, size) = find_in_extent(&img, root_lba, root_size, b"HELLO.TXT;1")
        .expect("HELLO.TXT;1 present in primary root directory");
    let start = lba * SECTOR;
    assert_eq!(
        &img[start..start + size],
        HELLO_CONTENT,
        "file extent bytes match the exact content"
    );
}

/// Walks a directory extent's records, returning `(lba, size)` for the record whose identifier
/// matches `want` (a raw primary-tree identifier such as `HELLO.TXT;1`).
fn find_in_extent(img: &[u8], lba: usize, size: usize, want: &[u8]) -> Option<(usize, usize)> {
    let base = lba * SECTOR;
    let extent = img.get(base..base + size)?;
    let mut pos = 0usize;
    while pos < extent.len() {
        let rlen = extent[pos] as usize;
        if rlen == 0 {
            pos = (pos / SECTOR + 1) * SECTOR;
            continue;
        }
        if rlen < 34 || pos + rlen > extent.len() {
            break;
        }
        let rec = &extent[pos..pos + rlen];
        let ilen = rec[32] as usize;
        let ident = &rec[33..33 + ilen];
        if ident == want {
            let child_lba = read_u32_le(rec, 2) as usize;
            let child_size = read_u32_le(rec, 10) as usize;
            return Some((child_lba, child_size));
        }
        pos += rlen;
    }
    None
}

/// Locates an installed ISO-mastering tool, returning its name if any.
fn iso_tool() -> Option<&'static str> {
    for tool in ["xorriso", "genisoimage", "mkisofs"] {
        // `--version` returns 0 when the tool exists; probing avoids a hard dependency.
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

    let dir = std::env::temp_dir().join(format!("arca_iso_diff_{}", std::process::id()));
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join("hello.txt"), HELLO_CONTENT).unwrap();
    std::fs::write(sub.join("data.bin"), vec![0x5Au8; 4096]).unwrap();

    let out = dir.join("out.iso");
    // xorriso understands the mkisofs CLI via `-as mkisofs`; the others take these flags directly.
    let status = if tool == "xorriso" {
        Command::new(tool)
            .args(["-as", "mkisofs", "-J", "-o"])
            .arg(&out)
            .arg(&dir)
            .status()
    } else {
        Command::new(tool)
            .args(["-J", "-o"])
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
    let mut reader =
        SeekArchiveReader::new(Cursor::new(bytes)).expect("arca detects the system ISO");
    let mut found_hello = false;
    let mut found_data = false;
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current = Some((metadata.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(bytes) => current.as_mut().unwrap().1.extend_from_slice(bytes),
            ReaderEvent::EndEntry => {
                let (path, content) = current.take().unwrap();
                if path.ends_with(b"hello.txt") {
                    assert_eq!(content, HELLO_CONTENT, "system ISO hello.txt content");
                    found_hello = true;
                }
                if path.ends_with(b"data.bin") {
                    assert_eq!(content, vec![0x5Au8; 4096], "system ISO data.bin content");
                    found_data = true;
                }
            },
            ReaderEvent::Done => break,
            _ => panic!("unexpected future ISO event"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(found_hello, "arca read hello.txt from the {tool} image");
    assert!(found_data, "arca read data.bin from the {tool} image");
}
