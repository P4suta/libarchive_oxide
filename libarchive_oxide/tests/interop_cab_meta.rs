// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Microsoft Cabinet (`.cab`) read-only interoperability evidence (RM-305).
//!
//! Every byte is produced by a first-party, deterministic, in-code raw CAB
//! builder (no external tool, no committed blob). The builder hand-assembles a
//! `CFHEADER` (no flags: no reserve area, no prev/next cabinet), the `CFFOLDER`
//! table, the `CFFILE` table at `coffFiles`, and the per-folder `CFDATA` blocks.
//! Stored folders carry the payload verbatim; MSZIP folders carry a `'CK'`
//! prefix plus a raw-DEFLATE stream produced by the independent `flate2` crate.
//!
//! The tests assert the `(path, kind, content)` round trip for a multi-file
//! solid folder (small file, empty file, nested-path file), a single-block and
//! a multi-block MSZIP folder, and that an unsupported compression method and a
//! truncated/inconsistent header each surface a structured error.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::{Cursor, Write};

use flate2::{Compression, write::DeflateEncoder};
use libarchive_oxide::{ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::EntryKind;

mod common;
use common::*;

// ---------------------------------------------------------------------------
// First-party raw CAB builder.
// ---------------------------------------------------------------------------

/// `typeCompress` method code for a stored folder.
const METHOD_NONE: u16 = 0;
/// `typeCompress` method code for an MSZIP folder.
const METHOD_MSZIP: u16 = 1;
/// `typeCompress` method code for a Quantum folder (out of scope -> Unsupported).
const METHOD_QUANTUM: u16 = 2;

struct FileSpec {
    name: Vec<u8>,
    content: Vec<u8>,
}

struct FolderSpec {
    method: u16,
    /// Maximum uncompressed bytes per `CFDATA` block (drives multi-block layout).
    block_size: usize,
    files: Vec<FileSpec>,
}

fn file(name: &[u8], content: &[u8]) -> FileSpec {
    FileSpec {
        name: name.to_vec(),
        content: content.to_vec(),
    }
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// The assembled `CFDATA` bytes for one folder plus their total length.
fn build_folder_data(folder: &FolderSpec) -> Vec<u8> {
    let stream: Vec<u8> = folder
        .files
        .iter()
        .flat_map(|f| f.content.iter().copied())
        .collect();
    let mut data = Vec::new();
    if stream.is_empty() {
        // A folder with only empty files still needs one CFDATA block so the
        // decoder has something to open; emit an empty stored block.
        push_u32(&mut data, 0); // csum (0 = none)
        push_u16(&mut data, 0); // cbData
        push_u16(&mut data, 0); // cbUncomp
        return data;
    }
    let block_size = folder.block_size.max(1);
    for chunk in stream.chunks(block_size) {
        let (payload, cb_uncomp) = match folder.method {
            METHOD_MSZIP => {
                let mut payload = b"CK".to_vec();
                payload.extend_from_slice(&raw_deflate(chunk));
                (payload, chunk.len())
            },
            // Store and any out-of-scope method carry the raw chunk; an
            // out-of-scope method's blocks are never actually decoded.
            _ => (chunk.to_vec(), chunk.len()),
        };
        push_u32(&mut data, 0); // csum
        push_u16(&mut data, payload.len() as u16); // cbData
        push_u16(&mut data, cb_uncomp as u16); // cbUncomp
        data.extend_from_slice(&payload);
    }
    data
}

/// Number of `CFDATA` blocks a folder produces.
fn folder_block_count(folder: &FolderSpec) -> u16 {
    let total: usize = folder.files.iter().map(|f| f.content.len()).sum();
    if total == 0 {
        1
    } else {
        total.div_ceil(folder.block_size.max(1)) as u16
    }
}

fn build_cab(folders: &[FolderSpec]) -> Vec<u8> {
    let total_files: usize = folders.iter().map(|f| f.files.len()).sum();

    let coff_files = 36 + folders.len() * 8;
    let file_table_size: usize = folders
        .iter()
        .flat_map(|f| f.files.iter())
        .map(|f| 16 + f.name.len() + 1)
        .sum();
    let data_start = coff_files + file_table_size;

    // Pre-render each folder's CFDATA and compute its absolute start offset.
    let mut folder_data = Vec::new();
    let mut folder_offsets = Vec::new();
    let mut cursor = data_start;
    for folder in folders {
        folder_offsets.push(cursor as u32);
        let data = build_folder_data(folder);
        cursor += data.len();
        folder_data.push(data);
    }

    let mut out = Vec::new();
    // CFHEADER.
    out.extend_from_slice(b"MSCF");
    push_u32(&mut out, 0); // reserved1
    push_u32(&mut out, cursor as u32); // cbCabinet (total size)
    push_u32(&mut out, 0); // reserved2
    push_u32(&mut out, coff_files as u32); // coffFiles
    push_u32(&mut out, 0); // reserved3
    out.push(3); // versionMinor
    out.push(1); // versionMajor
    push_u16(&mut out, folders.len() as u16); // cFolders
    push_u16(&mut out, total_files as u16); // cFiles
    push_u16(&mut out, 0); // flags
    push_u16(&mut out, 0); // setID
    push_u16(&mut out, 0); // iCabinet

    // CFFOLDER table.
    for (folder, offset) in folders.iter().zip(folder_offsets.iter()) {
        push_u32(&mut out, *offset); // coffCabStart
        push_u16(&mut out, folder_block_count(folder)); // cCFData
        push_u16(&mut out, folder.method); // typeCompress
    }

    // CFFILE table (files grouped by folder, with per-folder running offsets).
    for (index, folder) in folders.iter().enumerate() {
        let mut folder_offset = 0u32;
        for f in &folder.files {
            push_u32(&mut out, f.content.len() as u32); // cbFile
            push_u32(&mut out, folder_offset); // uoffFolderStart
            push_u16(&mut out, index as u16); // iFolder
            push_u16(&mut out, 0); // date
            push_u16(&mut out, 0); // time
            push_u16(&mut out, 0); // attribs
            out.extend_from_slice(&f.name);
            out.push(0);
            folder_offset += f.content.len() as u32;
        }
    }

    // CFDATA blocks.
    for data in &folder_data {
        out.extend_from_slice(data);
    }
    assert_eq!(
        out.len(),
        cursor,
        "computed layout must match emitted length"
    );
    out
}

/// Drives the reader to completion, returning the first error encountered (if any).
fn drive_to_error(bytes: &[u8]) -> Option<String> {
    let mut reader = match SeekArchiveReader::new(Cursor::new(bytes.to_vec())) {
        Ok(reader) => reader,
        Err(error) => return Some(format!("{error:?}")),
    };
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => return None,
            Ok(_) => {},
            Err(error) => return Some(format!("{error:?}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared corpus: small file, empty file, nested-path file, one solid folder.
// ---------------------------------------------------------------------------

fn corpus() -> Vec<FileSpec> {
    vec![
        file(b"readme.txt", b"hello cab\n"),
        file(b"empty.dat", b""),
        file(b"docs\\guide\\intro.txt", b"nested payload here\n"),
    ]
}

fn assert_corpus_round_trip(bytes: &[u8]) {
    let shapes = read_with_arca(bytes);
    assert_eq!(shapes.len(), 3, "expected three entries");

    // Backslashes are normalized to '/'; every entry is a File.
    let expect: [(&[u8], &[u8]); 3] = [
        (b"readme.txt", b"hello cab\n"),
        (b"empty.dat", b""),
        (b"docs/guide/intro.txt", b"nested payload here\n"),
    ];
    for (shape, (path, content)) in shapes.iter().zip(expect.iter()) {
        assert_eq!(shape.kind(), EntryKind::File, "kind for {path:?}");
        assert_eq!(shape.path(), *path, "path");
        assert_eq!(shape.content(), *content, "content for {path:?}");
    }
}

// ---------------------------------------------------------------------------
// Store: multi-file solid folder round trip.
// ---------------------------------------------------------------------------

#[test]
fn cab_store_multi_file_round_trip() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: corpus(),
    }]);
    assert_corpus_round_trip(&bytes);
}

// ---------------------------------------------------------------------------
// MSZIP: single-block folder round trip (raw DEFLATE via flate2).
// ---------------------------------------------------------------------------

#[test]
fn cab_mszip_single_block_round_trip() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 0x8000,
        files: corpus(),
    }]);
    assert_corpus_round_trip(&bytes);
}

// ---------------------------------------------------------------------------
// MSZIP: a file whose payload spans several CFDATA blocks (32-byte blocks),
// exercising the block-boundary staging and folder-stream concatenation.
// ---------------------------------------------------------------------------

#[test]
fn cab_mszip_multi_block_round_trip() {
    let payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 32,
        files: vec![
            file(b"a.bin", &payload),
            file(b"b.bin", b"tail file after a block boundary\n"),
        ],
    }]);

    let shapes = read_with_arca(&bytes);
    assert_eq!(shapes.len(), 2);
    assert_eq!(shapes[0].path(), b"a.bin");
    assert_eq!(shapes[0].content(), payload.as_slice());
    assert_eq!(shapes[1].path(), b"b.bin");
    assert_eq!(shapes[1].content(), b"tail file after a block boundary\n");
}

// ---------------------------------------------------------------------------
// MSZIP: highly repetitive content so real DEFLATE distance codes (LZ77
// back-references) are emitted and resolved against the sliding window.
// ---------------------------------------------------------------------------

#[test]
fn cab_mszip_backreferences_round_trip() {
    let repetitive = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
    assert!(repetitive.len() < 0x8000, "must fit one MSZIP block");
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 0x8000,
        files: vec![file(b"repeat.txt", &repetitive)],
    }]);
    let shapes = read_with_arca(&bytes);
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].content(), repetitive.as_slice());
}

// ---------------------------------------------------------------------------
// Unsupported compression method -> structured error while streaming.
// ---------------------------------------------------------------------------

#[test]
fn cab_unsupported_method_errors() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_QUANTUM,
        block_size: 0x8000,
        files: vec![file(b"data.bin", b"quantum payload not decodable")],
    }]);
    let error = drive_to_error(&bytes).expect("unsupported method must error");
    assert!(
        error.contains("Unsupported"),
        "expected an Unsupported error, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// Truncated / inconsistent header -> structured error at open.
// ---------------------------------------------------------------------------

#[test]
fn cab_truncated_header_errors() {
    // A cabinet whose coffFiles points past the end of the image.
    let mut bytes = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"readme.txt", b"hello")],
    }]);
    // Corrupt coffFiles (offset 16) to an absurd value beyond the image.
    bytes[16..20].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    assert!(
        drive_to_error(&bytes).is_some(),
        "an out-of-range CFFILE offset must error"
    );

    // A cabinet truncated below the fixed 36-byte CFHEADER.
    let stub = b"MSCF\0\0\0\0".to_vec();
    assert!(
        drive_to_error(&stub).is_some(),
        "a sub-header truncated cabinet must error"
    );
}
