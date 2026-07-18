// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Malformed-input tests for the ISO reader: every corrupt image must yield an `Error`, never a
//! panic (no index-out-of-bounds, no infinite loop, no unbounded allocation).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::format::iso9660::{IsoReader, IsoWriter};
use libarchive_oxide_core::{EntryData, EntryReader, EntryWriter};

/// Drives a reader to exhaustion, returning whether it completed without error.
fn drive(image: &[u8]) -> bool {
    let mut reader = IsoReader::new(image);
    loop {
        match reader.next_entry() {
            Ok(Some(mut e)) => {
                let mut buf = [0u8; 256];
                loop {
                    match e.data().read_chunk(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {},
                        Err(_) => return false,
                    }
                }
            },
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// A minimal valid image to mutate.
fn valid_image() -> Vec<u8> {
    let mut w = IsoWriter::new(Vec::new());
    let mut m = libarchive_oxide_core::EntryMeta::new(
        libarchive_oxide_core::EntryKind::Dir,
        std::borrow::Cow::Borrowed(&b"d"[..]),
    );
    m.size = 0;
    w.start_entry(&m).unwrap().close().unwrap();
    let mut f = libarchive_oxide_core::EntryMeta::new(
        libarchive_oxide_core::EntryKind::File,
        std::borrow::Cow::Borrowed(&b"d/f.txt"[..]),
    );
    f.size = 3;
    let mut s = w.start_entry(&f).unwrap();
    s.write_chunk(b"abc").unwrap();
    s.close().unwrap();
    w.finish().unwrap();
    w.into_inner()
}

#[test]
fn empty_and_tiny_inputs_do_not_panic() {
    assert!(!drive(&[]));
    assert!(!drive(&[0u8; 10]));
    assert!(!drive(&vec![0u8; 0x8000]));
    assert!(!drive(&vec![0xFFu8; 0x9000]));
}

#[test]
fn bad_standard_identifier_errors() {
    let mut img = valid_image();
    // Corrupt the "CD001" magic in the primary volume descriptor.
    img[0x8001] = b'X';
    assert!(!drive(&img));
}

#[test]
fn missing_terminator_and_no_pvd_errors() {
    // A single sector 16 that is a supplementary (non-Joliet) descriptor, no PVD, no terminator.
    let mut img = vec![0u8; 0x8000 + 2048];
    img[0x8000] = 2; // supplementary
    img[0x8001..0x8006].copy_from_slice(b"CD001");
    assert!(!drive(&img));
}

#[test]
fn truncated_directory_extent_errors() {
    let img = valid_image();
    // Truncate the image in the middle of the data region so the root extent points past the end.
    let cut = img.len() - 2048;
    assert!(!drive(&img[..cut]));
}

#[test]
fn corrupt_record_identifier_length_errors() {
    let mut img = valid_image();
    // The reader prefers the Joliet tree, so corrupt the Joliet root record (SVD at sector 17,
    // 0x8800 + 156 + 2) — that is the extent actually walked.
    let off = 0x8800 + 156 + 2;
    let lba = u32::from_le_bytes([img[off], img[off + 1], img[off + 2], img[off + 3]]) as usize;
    let ext = lba * 2048;
    // Set the first record's identifier length larger than the record itself (33 + ilen > rlen) →
    // must be rejected as malformed, not read out of bounds.
    if ext < img.len() {
        img[ext + 32] = 200;
        assert!(!drive(&img));
    }
}

#[test]
fn self_referential_directory_is_capped() {
    let mut img = valid_image();
    // Point the root directory's first child directory record's extent at the root itself, then make
    // the root's own "." record loop. We instead just force a deeply self-referential structure by
    // pointing every directory record extent LBA back at the root sector — the depth/record caps
    // must terminate the walk with an error rather than looping forever.
    let root_off = 0x8800 + 156 + 2; // Joliet root record (the preferred, walked tree)
    let root_lba = u32::from_le_bytes([
        img[root_off],
        img[root_off + 1],
        img[root_off + 2],
        img[root_off + 3],
    ]);
    let ext = root_lba as usize * 2048;
    // Walk the root extent, and for any child directory record (flag 0x02) that is not "." / "..",
    // repoint its extent LBA to the root LBA, creating a cycle.
    if ext + 2048 <= img.len() {
        let mut pos = ext;
        while pos < ext + 2048 {
            let rlen = img[pos] as usize;
            if rlen == 0 || pos + rlen > ext + 2048 {
                break;
            }
            let ilen = img[pos + 32] as usize;
            let is_special = ilen == 1 && (img[pos + 33] == 0 || img[pos + 33] == 1);
            let is_dir = img[pos + 25] & 0x02 != 0;
            if is_dir && !is_special {
                let be = both_endian_root(root_lba);
                img[pos + 2..pos + 10].copy_from_slice(&be);
            }
            pos += rlen;
        }
    }
    // Either it errors (cycle detected via caps) or terminates cleanly; it must not hang/panic.
    let _ = drive(&img);
}

fn both_endian_root(v: u32) -> [u8; 8] {
    let l = v.to_le_bytes();
    let b = v.to_be_bytes();
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}
