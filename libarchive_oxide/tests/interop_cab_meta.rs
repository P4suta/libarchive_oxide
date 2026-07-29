// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Microsoft Cabinet (`.cab`) read-only interoperability evidence (RM-305).
//!
//! Store and MSZIP bytes use a first-party deterministic raw CAB builder. LZX
//! uses byte-exact ASCII-hex fixtures from Microsoft `makecab.exe` and the
//! libmspack corpus; full source, hashes, commands, licenses, and independent
//! consumer evidence live in `tests/fixtures/cab/PROVENANCE.md`.
//!
//! Tests cover exact content, multi-frame history/alignment, resource limits,
//! corruption/truncation, and structured feature-off/unknown-method failures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::{Cursor, Write};

use flate2::{Compression, write::DeflateEncoder};
use libarchive_oxide::{ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::{EntryKind, Limits};

mod common;
use common::*;

// ---------------------------------------------------------------------------
// First-party raw CAB builder.
// ---------------------------------------------------------------------------

/// `typeCompress` method code for a stored folder.
const METHOD_NONE: u16 = 0;
/// `typeCompress` method code for an MSZIP folder.
const METHOD_MSZIP: u16 = 1;
/// `typeCompress` method code for a Quantum folder.
#[cfg(feature = "cab-quantum")]
const METHOD_QUANTUM: u16 = 2;
/// An unassigned folder method used for the unknown-method failure boundary.
const METHOD_UNKNOWN: u16 = 4;
/// `typeCompress` method code for an LZX folder.
#[cfg(feature = "cab-lzx")]
const METHOD_LZX: u16 = 3;

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

/// Skips unrelated entries without opening their payload codec, then drives
/// one named entry until it ends or reports a structured error.
#[cfg(feature = "cab-quantum")]
fn drive_entry_to_error(bytes: &[u8], target: &[u8]) -> Option<String> {
    let mut reader = match SeekArchiveReader::new(Cursor::new(bytes.to_vec())) {
        Ok(reader) => reader,
        Err(error) => return Some(format!("{error:?}")),
    };
    let mut selected = false;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                selected = metadata.path().as_bytes() == target;
                if selected {
                    continue;
                }
                if let Err(error) = reader.skip_entry() {
                    return Some(format!("{error:?}"));
                }
            },
            Ok(ReaderEvent::EndEntry) if selected => return None,
            Ok(ReaderEvent::Done) => return None,
            Ok(_) => {},
            Err(error) => return Some(format!("{error:?}")),
        }
    }
}

fn drive_with_limits_to_error(bytes: &[u8], limits: Limits) -> Option<String> {
    let mut reader = match SeekArchiveReader::with_limits(Cursor::new(bytes.to_vec()), limits) {
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

/// Finds the exact metadata budget required to parse a small fixture.
fn minimum_open_metadata_budget(bytes: &[u8]) -> usize {
    let opens = |maximum| {
        SeekArchiveReader::with_limits(
            Cursor::new(bytes.to_vec()),
            Limits::safe().with_metadata_bytes(Some(maximum)),
        )
        .is_ok()
    };
    let mut low = 0_usize;
    let mut high = 4096_usize;
    assert!(opens(high), "test fixture must fit the search interval");
    while low < high {
        let middle = low + (high - low) / 2;
        if opens(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

fn decode_fixture_hex(encoded: &str) -> Vec<u8> {
    let compact: String = encoded
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "fixture hex must have byte pairs");
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[cfg(feature = "cab-lzx")]
fn makecab_lzx_fixture() -> Vec<u8> {
    decode_fixture_hex(include_str!("fixtures/cab/makecab/lzx-history.hex"))
}

fn libmspack_mixed_fixture() -> Vec<u8> {
    decode_fixture_hex(include_str!("fixtures/cab/libmspack/mszip_lzx_qtm.hex"))
}

#[cfg(feature = "cab-quantum")]
fn libmspack_quantum_history_fixture() -> Vec<u8> {
    decode_fixture_hex(include_str!(
        "fixtures/cab/libmspack/cve-2010-2801-qtm-flush.hex"
    ))
}

fn folder_data_offset(bytes: &[u8], folder_index: usize) -> usize {
    let start = 36 + folder_index * 8;
    u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize
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

#[test]
fn cab_cb_cabinet_bounds_all_reads_but_allows_a_transport_trailer() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"bounded.bin", b"cabinet payload")],
    }]);

    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"bytes outside the declared cabinet");
    let shapes = read_with_arca(&trailing);
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].content(), b"cabinet payload");

    let mut payload_outside_boundary = bytes.clone();
    let short = u32::try_from(payload_outside_boundary.len() - 1).unwrap();
    payload_outside_boundary[8..12].copy_from_slice(&short.to_le_bytes());
    let error = drive_to_error(&payload_outside_boundary)
        .expect("CFDATA outside cbCabinet must fail even when backing bytes exist");
    assert!(error.contains("Malformed"), "{error}");

    let mut short_header = bytes;
    short_header[8..12].copy_from_slice(&35_u32.to_le_bytes());
    let error = drive_to_error(&short_header).expect("cbCabinet below CFHEADER must fail");
    assert!(error.contains("Malformed"), "{error}");
}

#[test]
fn cab_rejects_reverse_and_alternating_cffile_folder_order() {
    let mut reversed = build_cab(&[
        FolderSpec {
            method: METHOD_NONE,
            block_size: 0x8000,
            files: vec![file(b"a.bin", b"a")],
        },
        FolderSpec {
            method: METHOD_NONE,
            block_size: 0x8000,
            files: vec![file(b"b.bin", b"b")],
        },
    ]);
    let files = 36 + 2 * 8;
    let record_size = 16 + b"a.bin".len() + 1;
    let first = reversed[files..files + record_size].to_vec();
    let second = reversed[files + record_size..files + 2 * record_size].to_vec();
    reversed[files..files + record_size].copy_from_slice(&second);
    reversed[files + record_size..files + 2 * record_size].copy_from_slice(&first);
    let error = drive_to_error(&reversed).expect("folder 1 before folder 0 must fail");
    assert!(error.contains("Malformed"), "{error}");

    let mut alternating = build_cab(&[
        FolderSpec {
            method: METHOD_NONE,
            block_size: 0x8000,
            files: vec![file(b"a.bin", b"a"), file(b"c.bin", b"c")],
        },
        FolderSpec {
            method: METHOD_NONE,
            block_size: 0x8000,
            files: vec![file(b"b.bin", b"b")],
        },
    ]);
    let files = 36 + 2 * 8;
    let second = alternating[files + record_size..files + 2 * record_size].to_vec();
    let third = alternating[files + 2 * record_size..files + 3 * record_size].to_vec();
    alternating[files + record_size..files + 2 * record_size].copy_from_slice(&third);
    alternating[files + 2 * record_size..files + 3 * record_size].copy_from_slice(&second);
    let error = drive_to_error(&alternating).expect("folder order 0,1,0 must fail");
    assert!(error.contains("Malformed"), "{error}");
}

#[test]
fn cab_store_caps_aggregate_scan_work_and_rejects_overlapping_folders() {
    let mut excessive_claim = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"claim.bin", b"x")],
    }]);
    excessive_claim[40..42].copy_from_slice(&u16::MAX.to_le_bytes());
    let error = drive_to_error(&excessive_claim)
        .expect("Store cCFData claim larger than the cabinet must fail");
    assert!(error.contains("Limit"), "{error}");

    let mut overlapping = build_cab(&[
        FolderSpec {
            method: METHOD_NONE,
            block_size: 0x8000,
            files: vec![file(b"a.bin", b"aaaa")],
        },
        FolderSpec {
            method: METHOD_MSZIP,
            block_size: 0x8000,
            files: vec![file(b"b.bin", b"bbbb")],
        },
    ]);
    let first_data = overlapping[36..40].to_vec();
    overlapping[44..48].copy_from_slice(&first_data);
    let error = drive_to_error(&overlapping).expect("overlapping CFDATA extents must fail");
    assert!(error.contains("Malformed"), "{error}");
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

#[test]
fn cab_store_and_mszip_enforce_zero_resource_budgets() {
    let stored = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"stored.bin", b"stored payload")],
    }]);
    let error = drive_with_limits_to_error(&stored, Limits::safe().with_in_flight_bytes(Some(0)))
        .expect("stored CFDATA staging must honor a zero-byte limit");
    assert!(error.contains("Limit"), "{error}");
    let error = drive_with_limits_to_error(&stored, Limits::safe().with_metadata_bytes(Some(0)))
        .expect("folder metadata must honor a zero-byte limit");
    assert!(error.contains("Limit"), "{error}");

    let mszip = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 0x8000,
        files: vec![file(b"compressed.bin", b"compressed payload")],
    }]);
    let error = drive_with_limits_to_error(
        &mszip,
        Limits::safe().with_codec_memory(Some((2 * 32_768) - 1)),
    )
    .expect("MSZIP history must be charged before allocation");
    assert!(error.contains("Limit"), "{error}");
    let error = drive_with_limits_to_error(&mszip, Limits::safe().with_in_flight_bytes(Some(0)))
        .expect("MSZIP CFDATA staging must honor a zero-byte limit");
    assert!(error.contains("Limit"), "{error}");
}

#[test]
fn cab_entry_prepare_failure_poisoning_prevents_retry_skip() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 0x8000,
        files: vec![file(b"allocation.bin", b"payload")],
    }]);
    let limits = Limits::safe().with_codec_memory(Some((2 * 32_768) - 1));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));

    let first = reader
        .next_event()
        .expect_err("entry preparation must reject the MSZIP workspace");
    assert!(format!("{first:?}").contains("Limit"));
    let retry = reader
        .next_event()
        .expect_err("a failed entry must not be skipped on retry");
    let retry = format!("{retry:?}");
    assert!(retry.contains("Limit"), "{retry}");
    assert!(retry.contains("poisoned"), "{retry}");
}

#[test]
fn cab_metadata_limit_is_aggregate_across_folder_and_file_tables() {
    let folder_only = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: Vec::new(),
    }]);
    let one_file = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"metadata-a.bin", b"x")],
    }]);
    let two_files = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"metadata-a.bin", b"x"), file(b"metadata-b.bin", b"x")],
    }]);

    let folder_budget = minimum_open_metadata_budget(&folder_only);
    let one_file_budget = minimum_open_metadata_budget(&one_file);
    let two_file_budget = minimum_open_metadata_budget(&two_files);
    assert_eq!(
        two_file_budget - folder_budget,
        2 * (one_file_budget - folder_budget),
        "folder and each equal-sized file record must share one aggregate budget"
    );
}

#[test]
fn cab_decoded_limit_rejects_the_next_frame_on_every_retry() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 3,
        files: vec![file(b"limited.bin", b"abcdef")],
    }]);
    let limits = Limits::safe().with_decoded_total(Some(4));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits).unwrap();

    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    match reader.next_event().unwrap() {
        ReaderEvent::Data(data) => assert_eq!(data, b"abc"),
        other => panic!("expected first bounded frame, got {other:?}"),
    }

    let first = reader.next_event().unwrap_err();
    assert!(format!("{first:?}").contains("Limit"));
    let retry = reader
        .next_event()
        .expect_err("retry must not expose the already rejected frame");
    let retry = format!("{retry:?}");
    assert!(retry.contains("Limit"), "{retry}");
    assert!(retry.contains("poisoned"), "{retry}");
}

#[test]
fn cab_cfdata_checksum_rejects_silent_store_corruption() {
    let mut bytes = build_cab(&[FolderSpec {
        method: METHOD_NONE,
        block_size: 0x8000,
        files: vec![file(b"checked.bin", b"abc")],
    }]);
    let data = folder_data_offset(&bytes, 0);
    // CSUMCompute("abc", 0) XOR LE32(cbData=3, cbUncomp=3).
    bytes[data..data + 4].copy_from_slice(&0x0062_6260_u32.to_le_bytes());
    assert!(
        drive_to_error(&bytes).is_none(),
        "the known Microsoft checksum vector must validate"
    );

    bytes[data + 8] ^= 1;
    let error = drive_to_error(&bytes).expect("checksummed payload corruption must fail");
    assert!(error.contains("Malformed"), "{error}");
}

#[test]
fn cab_mszip_rejects_a_match_before_any_history() {
    let mut bytes = build_cab(&[FolderSpec {
        method: METHOD_MSZIP,
        block_size: 0x8000,
        files: vec![file(b"invalid-history.bin", b"abc")],
    }]);
    let data = folder_data_offset(&bytes, 0);
    let cb_data = usize::from(u16::from_le_bytes(
        bytes[data + 4..data + 6].try_into().unwrap(),
    ));
    let payload = &mut bytes[data + 8..data + 8 + cb_data];
    assert!(payload.len() >= 5, "test payload must hold CK + DEFLATE");
    payload.fill(0);
    payload[..2].copy_from_slice(b"CK");
    // Final fixed-Huffman block: length=3, distance=1, end-of-block.
    // A wrapping zero-filled dictionary would silently emit three zeroes.
    payload[2..5].copy_from_slice(&[0x03, 0x02, 0x00]);

    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let error = reader
        .next_event()
        .expect_err("pre-history MSZIP match must fail");
    assert!(format!("{error:?}").contains("Malformed"));
    let retry = reader
        .next_event()
        .expect_err("malformed decoder state must be poisoned");
    let retry = format!("{retry:?}");
    assert!(retry.contains("Malformed"), "{retry}");
    assert!(retry.contains("poisoned"), "{retry}");
}

// ---------------------------------------------------------------------------
// LZX: independent producer fixtures, folder history, limits, and failures.
// ---------------------------------------------------------------------------

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_reads_microsoft_makecab_multi_block_history_fixture() {
    let bytes = makecab_lzx_fixture();
    let shapes = read_with_arca(&bytes);
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].path(), b"lzx-history.bin");
    let expected: Vec<u8> = (0_usize..96 * 1024)
        .map(|index| u8::try_from((index % 4096) % 251).expect("fixture byte is always below 251"))
        .collect();
    assert_eq!(shapes[0].content().len(), expected.len());
    let mismatch = shapes[0]
        .content()
        .iter()
        .zip(&expected)
        .position(|(actual, expected)| actual != expected);
    if let Some(index) = mismatch {
        panic!(
            "first payload mismatch at {index}: actual={:?}, expected={:?}",
            &shapes[0].content()[index..index + 16],
            &expected[index..index + 16]
        );
    }

    // The independent producer emitted three full-size CFDATA frames. A
    // per-block decoder reset cannot read the second/third continuation.
    let folder = 36;
    assert_eq!(
        u16::from_le_bytes(bytes[folder + 4..folder + 6].try_into().unwrap()),
        3
    );
    assert_eq!(
        u16::from_le_bytes(bytes[folder + 6..folder + 8].try_into().unwrap()) & 0x000F,
        METHOD_LZX
    );
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_reads_libmspack_corpus_fixture() {
    let bytes = libmspack_mixed_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Entry(metadata) => {
                let path = metadata.path().as_bytes().to_vec();
                if path == b"qtm.txt" {
                    reader.skip_entry().unwrap();
                } else {
                    entries.push((path, Vec::new()));
                }
            },
            ReaderEvent::Data(data) => entries.last_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => panic!("unexpected future reader event"),
        }
    }
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, b"mszip.txt");
    assert_eq!(entries[1].0, b"lzx.txt");
    assert_eq!(
        entries[1].1,
        b"-----------------------------------------------------------------\n\
If you can read this, the LZX decompressor is working!\n\
-----------------------------------------------------------------\n"
    );
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_truncation_and_declared_frame_corruption_error() {
    let mut truncated = makecab_lzx_fixture();
    truncated.truncate(truncated.len() - 10);
    assert!(
        drive_to_error(&truncated).is_some(),
        "truncated final CFDATA must fail"
    );

    let mut corrupt = libmspack_mixed_fixture();
    let lzx_data = folder_data_offset(&corrupt, 1);
    let declared = u16::from_le_bytes(corrupt[lzx_data + 6..lzx_data + 8].try_into().unwrap());
    corrupt[lzx_data + 6..lzx_data + 8].copy_from_slice(&(declared - 1).to_le_bytes());
    corrupt[lzx_data..lzx_data + 4].fill(0);
    let error = drive_to_error(&corrupt).expect("inconsistent LZX frame must fail");
    assert!(error.contains("Malformed"), "{error}");
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_rejects_corrupted_independent_producer_checksum() {
    let mut fixture = makecab_lzx_fixture();
    let data = folder_data_offset(&fixture, 0);
    let checksum = u32::from_le_bytes(fixture[data..data + 4].try_into().unwrap());
    assert_eq!(checksum, 0x11EA_ECA6, "known makecab.exe checksum");
    fixture[data] ^= 1;

    let error = drive_to_error(&fixture).expect("corrupted makecab checksum must fail");
    assert!(error.contains("Malformed"), "{error}");
    assert!(error.contains("checksum"), "{error}");
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_rejects_window_and_resource_claims_before_decode() {
    let fixture = makecab_lzx_fixture();

    let mut undersized_window = fixture.clone();
    undersized_window[42..44].copy_from_slice(&((14_u16 << 8) | METHOD_LZX).to_le_bytes());
    let error = drive_to_error(&undersized_window).expect("window 14 is outside CAB LZX");
    assert!(error.contains("Malformed"), "{error}");

    let mut oversized_window = fixture.clone();
    oversized_window[42..44].copy_from_slice(&((22_u16 << 8) | METHOD_LZX).to_le_bytes());
    let error = drive_to_error(&oversized_window).expect("window 22 is outside CAB LZX");
    assert!(error.contains("Malformed"), "{error}");

    let mut oversized_frame = fixture.clone();
    let data = folder_data_offset(&oversized_frame, 0);
    oversized_frame[data + 6..data + 8].copy_from_slice(&32_769_u16.to_le_bytes());
    let error = drive_to_error(&oversized_frame).expect("oversized frame must fail");
    assert!(error.contains("Malformed"), "{error}");

    let codec_limit = Limits::safe().with_codec_memory(Some((1 << 21) + 640 * 1024 - 1));
    let error = drive_with_limits_to_error(&fixture, codec_limit)
        .expect("window workspace must be charged before decoder allocation");
    assert!(error.contains("Limit"), "{error}");

    let in_flight_limit = Limits::safe().with_in_flight_bytes(Some((2 * 32_768) - 1));
    let error = drive_with_limits_to_error(&fixture, in_flight_limit)
        .expect("compressed/decoded staging must be charged before allocation");
    assert!(error.contains("Limit"), "{error}");

    let decoded_limit = Limits::safe().with_decoded_total(Some((96 * 1024) - 1));
    let error = drive_with_limits_to_error(&fixture, decoded_limit)
        .expect("folder output must be charged before decoder allocation");
    assert!(error.contains("Limit"), "{error}");
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_caps_aggregate_header_scan_work_before_scanning() {
    let mut fixture = makecab_lzx_fixture();
    fixture[40..42].copy_from_slice(&u16::MAX.to_le_bytes());

    let error = drive_to_error(&fixture).expect("impossible CFDATA scan claim must fail");
    assert!(error.contains("Limit"), "{error}");
    assert!(error.contains("aggregate CFDATA scan work"), "{error}");
}

#[cfg(feature = "cab-lzx")]
#[test]
fn cab_lzx_e8_ffffffff_is_bounded_and_reports_a_typed_error() {
    let mut fixture = makecab_lzx_fixture();
    let payload = folder_data_offset(&fixture, 0) + 8;
    // LZX wire bits are MSB-first inside little-endian u16 words. These
    // bytes encode flag=1 followed by filesize=0xFFFF_FFFF.
    fixture[payload..payload + 6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x80]);
    fixture[payload - 8..payload - 4].fill(0);
    let error = drive_to_error(&fixture)
        .expect("corrupted E8 frame must fail without looping or panicking");
    assert!(error.contains("Malformed"), "{error}");
}

#[cfg(not(feature = "cab-lzx"))]
#[test]
fn cab_lzx_feature_off_lists_metadata_then_reports_unsupported() {
    let bytes = libmspack_mixed_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"lzx.txt" => {
                let error = reader.next_event().unwrap_err();
                assert!(format!("{error:?}").contains("Unsupported"));
                break;
            },
            ReaderEvent::Entry(_) => reader.skip_entry().unwrap(),
            ReaderEvent::Done => panic!("LZX entry was not listed"),
            _ => {},
        }
    }
}

// ---------------------------------------------------------------------------
// Quantum: independent producer fixtures, folder history, and limits.
// ---------------------------------------------------------------------------

#[cfg(feature = "cab-quantum")]
#[test]
fn cab_quantum_reads_libmspack_mixed_method_fixture() {
    let bytes = libmspack_mixed_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut quantum = Vec::new();
    let mut reading_quantum = false;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Entry(metadata) => {
                reading_quantum = metadata.path().as_bytes() == b"qtm.txt";
                if !reading_quantum {
                    reader.skip_entry().unwrap();
                }
            },
            ReaderEvent::Data(data) if reading_quantum => quantum.extend_from_slice(data),
            ReaderEvent::Data(_) => panic!("data from a skipped non-Quantum entry"),
            ReaderEvent::Done => break,
            _ => panic!("unexpected future reader event"),
        }
    }
    assert_eq!(
        quantum,
        b"If you can read this, the Quantum decompressor is working!\n"
    );
}

#[cfg(feature = "cab-quantum")]
#[test]
fn cab_quantum_preserves_history_across_sixteen_cfdata_frames() {
    let bytes = libmspack_quantum_history_fixture();
    let folder = 36;
    assert_eq!(
        u16::from_le_bytes(bytes[folder + 4..folder + 6].try_into().unwrap()),
        16
    );
    assert_eq!(
        u16::from_le_bytes(bytes[folder + 6..folder + 8].try_into().unwrap()) & 0x000F,
        METHOD_QUANTUM
    );

    let shapes = read_with_arca(&bytes);
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].path(), b"zeroes");
    assert_eq!(shapes[0].content().len(), 524_159);
    assert!(shapes[0].content().iter().all(|byte| *byte == 0));
}

#[cfg(feature = "cab-quantum")]
#[test]
fn cab_quantum_rejects_truncation_corruption_and_invalid_settings() {
    let fixture = libmspack_mixed_fixture();
    let quantum_data = folder_data_offset(&fixture, 2);

    let mut truncated = fixture.clone();
    truncated[quantum_data..quantum_data + 4].fill(0);
    truncated[quantum_data + 4..quantum_data + 6].copy_from_slice(&8_u16.to_le_bytes());
    let error = drive_entry_to_error(&truncated, b"qtm.txt")
        .expect("truncated Quantum arithmetic stream must fail");
    assert!(error.contains("Malformed"), "{error}");

    let mut corrupt = fixture.clone();
    corrupt[quantum_data + 8] ^= 1;
    let error = drive_entry_to_error(&corrupt, b"qtm.txt")
        .expect("corrupted Quantum CFDATA checksum must fail");
    assert!(error.contains("Malformed"), "{error}");
    assert!(error.contains("checksum"), "{error}");

    let mut low_window = fixture.clone();
    low_window[58..60].copy_from_slice(&((9_u16 << 8) | (2 << 4) | METHOD_QUANTUM).to_le_bytes());
    let error = drive_to_error(&low_window).expect("Quantum window 9 is outside the CAB range");
    assert!(error.contains("Malformed"), "{error}");

    let mut high_window = fixture.clone();
    high_window[58..60].copy_from_slice(&((22_u16 << 8) | (2 << 4) | METHOD_QUANTUM).to_le_bytes());
    let error = drive_to_error(&high_window).expect("Quantum window 22 is outside the CAB range");
    assert!(error.contains("Malformed"), "{error}");

    let mut invalid_level = fixture.clone();
    invalid_level[58..60]
        .copy_from_slice(&((18_u16 << 8) | (8 << 4) | METHOD_QUANTUM).to_le_bytes());
    let error = drive_to_error(&invalid_level).expect("Quantum level 8 is outside the CAB range");
    assert!(error.contains("Malformed"), "{error}");

    let mut reserved = fixture;
    reserved[58..60]
        .copy_from_slice(&(0x8000 | (18_u16 << 8) | (2 << 4) | METHOD_QUANTUM).to_le_bytes());
    let error = drive_to_error(&reserved).expect("Quantum reserved bits must fail");
    assert!(error.contains("Malformed"), "{error}");
}

#[cfg(feature = "cab-quantum")]
#[test]
fn cab_quantum_enforces_codec_in_flight_decoded_and_scan_budgets() {
    let fixture = libmspack_mixed_fixture();

    let codec_limit = Limits::safe().with_codec_memory(Some((1 << 18) + (80 * 1024) - 1));
    let error = drive_with_limits_to_error(&fixture, codec_limit)
        .expect("Quantum dictionary and workspace must be charged before allocation");
    assert!(error.contains("Limit"), "{error}");

    // The 48-byte payload gains a synthetic trailer, is copied once into
    // compcol, and coexists with the 59-byte decoded frame: 49*2+59 = 157.
    let in_flight_limit = Limits::safe().with_in_flight_bytes(Some(156));
    let error = drive_with_limits_to_error(&fixture, in_flight_limit)
        .expect("Quantum adapter and codec staging must share the in-flight budget");
    assert!(error.contains("Limit"), "{error}");

    let decoded_limit = Limits::safe().with_decoded_total(Some(58));
    let error = drive_with_limits_to_error(&fixture, decoded_limit)
        .expect("Quantum declared output must be charged before decoder allocation");
    assert!(error.contains("Limit"), "{error}");

    let mut impossible_scan = libmspack_quantum_history_fixture();
    impossible_scan[40..42].copy_from_slice(&u16::MAX.to_le_bytes());
    let error = drive_to_error(&impossible_scan).expect("impossible Quantum scan must fail");
    assert!(error.contains("Limit"), "{error}");
    assert!(error.contains("aggregate CFDATA scan work"), "{error}");
}

#[cfg(feature = "cab-quantum")]
#[test]
fn cab_quantum_rejects_a_short_non_final_frame() {
    let mut fixture = libmspack_quantum_history_fixture();
    let first = folder_data_offset(&fixture, 0);
    fixture[first + 6..first + 8].copy_from_slice(&32_767_u16.to_le_bytes());
    let error = drive_to_error(&fixture).expect("short interior Quantum frame must fail");
    assert!(error.contains("Malformed"), "{error}");
    assert!(error.contains("non-final Quantum"), "{error}");
}

#[cfg(not(feature = "cab-quantum"))]
#[test]
fn cab_quantum_feature_off_lists_metadata_then_reports_unsupported() {
    let bytes = libmspack_mixed_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"qtm.txt" => {
                let error = reader.next_event().unwrap_err();
                assert!(format!("{error:?}").contains("Unsupported"));
                break;
            },
            ReaderEvent::Entry(_) => reader.skip_entry().unwrap(),
            ReaderEvent::Done => panic!("Quantum entry was not listed"),
            _ => {},
        }
    }
}

// ---------------------------------------------------------------------------
// Unknown compression method -> structured error while streaming.
// ---------------------------------------------------------------------------

#[test]
fn cab_unknown_method_errors() {
    let bytes = build_cab(&[FolderSpec {
        method: METHOD_UNKNOWN,
        block_size: 0x8000,
        files: vec![file(b"data.bin", b"unknown payload not decodable")],
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
