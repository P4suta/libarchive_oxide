// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential test against the independent pure-Rust `sevenz-rust2` crate, mirroring how the zip
//! tests lean on the `zip` crate. Two directions run:
//!
//! (a) `sevenz-rust2` reads a `.7z` produced by arca's seek writer — validating arca's folder /
//!     substream / FilesInfo byte layout against an independent decoder.
//! (b) arca's seek reader reads a `.7z` produced by `sevenz-rust2`'s `ArchiveWriter` (solid,
//!     single-folder LZMA2) — validating arca's parser against an independent encoder.
//!
//! The suite also exercises independent LZMA/PPMd/filter/general-codec producers and a BCJ2
//! four-stream splitter, including compressed headers, non-solid folders, resource bounds, and
//! malformed inputs.
#![cfg(feature = "sevenz")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation
)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use libarchive_oxide::{Error, ReaderEvent, SeekArchiveReader, SeekArchiveWriter};
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, ErrorKind, FormatId, Limits,
};

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader as SevenReader, ArchiveWriter as SevenWriter, EncoderConfiguration,
    EncoderMethod, Password, SourceReader,
    encoder_options::{DeltaOptions, EncoderOptions, PpmdOptions},
};

mod common;
use common::{EntryShape, read_with_arca};

/// Writes an arca 7z with a directory, two content files, and an empty file.
fn arca_archive() -> Vec<u8> {
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    let items: Vec<(EntryKind, &[u8], Vec<u8>)> = vec![
        (EntryKind::Dir, b"d", Vec::new()),
        (EntryKind::File, b"d/a.txt", b"alpha payload\n".to_vec()),
        (
            EntryKind::File,
            b"d/b.txt",
            b"the quick brown fox\n".repeat(50),
        ),
        (EntryKind::File, b"d/empty.txt", Vec::new()),
    ];
    for (kind, name, data) in items {
        let metadata = EntryMetadata::builder(kind, ArchivePath::from_bytes(name.to_vec()))
            .size(None)
            .mode(Some(if kind == EntryKind::Dir { 0o755 } else { 0o644 }))
            .build();
        writer.start_entry(&metadata).unwrap();
        if !data.is_empty() {
            for chunk in data.chunks(13) {
                writer.write_data(chunk).unwrap();
            }
        }
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn sevenz_rust2_reads_arca_output() {
    let bytes = arca_archive();
    let mut reader =
        SevenReader::new(Cursor::new(bytes), Password::empty()).expect("sevenz-rust2 opens arca");

    // Snapshot the entry shapes first (immutable borrow), then read file contents.
    let shapes: Vec<(String, bool, u64)> = reader
        .archive()
        .files
        .iter()
        .map(|e| (e.name().to_string(), e.is_directory(), e.size()))
        .collect();

    assert_eq!(shapes.len(), 4);
    assert_eq!(shapes[0], ("d".to_string(), true, 0));
    assert_eq!(shapes[1].0, "d/a.txt");
    assert!(!shapes[1].1);
    assert_eq!(shapes[2].0, "d/b.txt");
    assert_eq!(shapes[3], ("d/empty.txt".to_string(), false, 0));

    assert_eq!(reader.read_file("d/a.txt").unwrap(), b"alpha payload\n");
    assert_eq!(
        reader.read_file("d/b.txt").unwrap(),
        b"the quick brown fox\n".repeat(50)
    );
    assert!(reader.read_file("d/empty.txt").unwrap().is_empty());
}

#[test]
fn arca_reads_sevenz_rust2_output() {
    let a = b"first independent file\n".to_vec();
    let b = b"second independent file, a bit longer\n".repeat(20);

    let cursor = Cursor::new(Vec::new());
    let mut w = SevenWriter::new(cursor).unwrap();
    let entries = vec![
        ArchiveEntry::new_file("pkg/a.txt"),
        ArchiveEntry::new_file("pkg/b.txt"),
    ];
    let sources: Vec<SourceReader<&[u8]>> = vec![
        SourceReader::from(a.as_slice()),
        SourceReader::from(b.as_slice()),
    ];
    w.push_archive_entries(entries, sources).unwrap();
    let cursor = w.finish().unwrap();
    let bytes = cursor.into_inner();

    // Route the read/compare through the shared interop harness: byte-level content equality
    // against canonical shapes (path + kind + content), not a count-only check.
    let got = read_with_arca(&bytes);
    let expected = vec![
        EntryShape::new(b"pkg/a.txt".to_vec(), EntryKind::File, a.clone()),
        EntryShape::new(b"pkg/b.txt".to_vec(), EntryKind::File, b.clone()),
    ];
    assert_eq!(got, expected);
}

/// The plain-**LZMA** (method `03 01 01`) folder coder — what 7-Zip and `sevenz-rust2` use — must be
/// readable by arca, not just LZMA2. `sevenz-rust2` is told to compress content with `EncoderMethod::LZMA`.
#[test]
fn arca_reads_sevenz_rust2_lzma_folder() {
    let a = b"first lzma-coded file\n".to_vec();
    let b = b"second lzma-coded file, repeated a lot\n".repeat(40);

    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    w.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::LZMA)]);
    let entries = vec![
        ArchiveEntry::new_file("pkg/a.txt"),
        ArchiveEntry::new_file("pkg/b.txt"),
    ];
    let sources: Vec<SourceReader<&[u8]>> = vec![
        SourceReader::from(a.as_slice()),
        SourceReader::from(b.as_slice()),
    ];
    w.push_archive_entries(entries, sources).unwrap();
    let bytes = w.finish().unwrap().into_inner();

    let got = read_with_arca(&bytes);
    let expected = vec![
        EntryShape::new(b"pkg/a.txt".to_vec(), EntryKind::File, a.clone()),
        EntryShape::new(b"pkg/b.txt".to_vec(), EntryKind::File, b.clone()),
    ];
    assert_eq!(got, expected);
}

/// Non-solid archives put every file in its own folder (its own pack stream and coder). `sevenz-rust2`
/// produces exactly that when each entry is pushed with the singular `push_archive_entry`. arca must
/// walk the resulting `Vec<Folder>`, activating one decoder at a time, and reproduce every file's
/// bytes — the core of RM-303 step 1. Directory and empty-file entries (which carry no folder) are
/// interleaved to confirm the file->folder mapping skips them correctly.
#[test]
fn arca_reads_sevenz_rust2_multi_folder() {
    let a = b"alpha folder payload\n".to_vec();
    let b = b"beta folder payload, repeated for compressibility\n".repeat(30);
    let c = b"gamma folder payload with different bytes\n".repeat(12);

    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    // A directory and an empty file carry no content stream, so they never open a folder.
    w.push_archive_entry::<&[u8]>(ArchiveEntry::new_directory("pkg"), None)
        .unwrap();
    w.push_archive_entry(ArchiveEntry::new_file("pkg/a.txt"), Some(a.as_slice()))
        .unwrap();
    w.push_archive_entry(ArchiveEntry::new_file("pkg/b.txt"), Some(b.as_slice()))
        .unwrap();
    w.push_archive_entry::<&[u8]>(ArchiveEntry::new_file("pkg/empty.txt"), None)
        .unwrap();
    w.push_archive_entry(ArchiveEntry::new_file("pkg/c.txt"), Some(c.as_slice()))
        .unwrap();
    let bytes = w.finish().unwrap().into_inner();

    // Three distinct content files => three separate folders/blocks (non-solid).
    let reader = SevenReader::new(Cursor::new(bytes.clone()), Password::empty())
        .expect("sevenz-rust2 opens its own multi-folder archive");
    assert!(
        !reader.archive().is_solid,
        "push_archive_entry should produce a non-solid (multi-folder) archive"
    );
    assert!(
        reader.archive().blocks.len() >= 3,
        "expected one folder per content file, got {} folders",
        reader.archive().blocks.len()
    );

    let got = read_with_arca(&bytes);
    let expected = vec![
        EntryShape::new(b"pkg".to_vec(), EntryKind::Dir, Vec::new()),
        EntryShape::new(b"pkg/a.txt".to_vec(), EntryKind::File, a.clone()),
        EntryShape::new(b"pkg/b.txt".to_vec(), EntryKind::File, b.clone()),
        EntryShape::new(b"pkg/empty.txt".to_vec(), EntryKind::File, Vec::new()),
        EntryShape::new(b"pkg/c.txt".to_vec(), EntryKind::File, c.clone()),
    ];
    assert_eq!(got, expected);
}

/// The same non-solid multi-folder shape, but with the plain-LZMA coder: each file is its own
/// folder, so arca must tear down one `LzmaReader` and seek+build the next between entries.
#[test]
fn arca_reads_sevenz_rust2_multi_folder_lzma() {
    let a = b"first lzma folder\n".repeat(8);
    let b = b"second lzma folder, a good deal longer than the first\n".repeat(25);

    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    w.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::LZMA)]);
    w.push_archive_entry(ArchiveEntry::new_file("a.bin"), Some(a.as_slice()))
        .unwrap();
    w.push_archive_entry(ArchiveEntry::new_file("b.bin"), Some(b.as_slice()))
        .unwrap();
    let bytes = w.finish().unwrap().into_inner();

    let got = read_with_arca(&bytes);
    let expected = vec![
        EntryShape::new(b"a.bin".to_vec(), EntryKind::File, a.clone()),
        EntryShape::new(b"b.bin".to_vec(), EntryKind::File, b.clone()),
    ];
    assert_eq!(got, expected);
}

/// A compressed (`kEncodedHeader`) next header is what mainstream 7-Zip / `sevenz-rust2` emit once an
/// archive carries more than a trivial number of entries: `sevenz-rust2` LZMA-compresses the header
/// whenever that shrinks it. Enough long, repetitive names force that path, so this archive lands on
/// the `K_ENCODED_HEADER` branch with an LZMA-coded folder — proving that branch is live, not dead.
#[test]
fn arca_reads_sevenz_rust2_compressed_header() {
    // Many entries with long, highly compressible names make the raw header large and its LZMA
    // encoding small, so `sevenz-rust2` writes a kEncodedHeader (not a plain kHeader).
    let count = 300usize;
    let mut expected: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(count);
    let mut entries = Vec::with_capacity(count);
    let mut owned_content: Vec<Vec<u8>> = Vec::with_capacity(count);
    for i in 0..count {
        let name = format!("a/very/long/repetitive/directory/path/segment/file_{i:04}.txt");
        let content =
            format!("payload number {i} with some repeated filler filler filler\n").into_bytes();
        entries.push(ArchiveEntry::new_file(&name));
        expected.push((name.into_bytes(), content.clone()));
        owned_content.push(content);
    }
    let sources: Vec<SourceReader<&[u8]>> = owned_content
        .iter()
        .map(|c| SourceReader::from(c.as_slice()))
        .collect();

    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    w.push_archive_entries(entries, sources).unwrap();
    let bytes = w.finish().unwrap().into_inner();

    // Confirm the archive really uses a compressed header: the next-header body's first id is
    // K_ENCODED_HEADER (0x17), not a plain K_HEADER (0x01).
    let nh_offset = usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap();
    let first_id = bytes[32 + nh_offset];
    assert_eq!(
        first_id, 0x17,
        "sevenz-rust2 should emit a compressed header here"
    );

    let got = read_with_arca(&bytes);
    assert_eq!(got.len(), count);
    for (g, e) in got.iter().zip(expected.iter()) {
        assert_eq!(g.path(), e.0.as_slice());
        assert_eq!(g.content(), e.1.as_slice());
    }
}

/// Deterministic pseudo-random bytes; branch opcodes occur naturally so the BCJ filters transform.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u64 = 0xdead_beef_cafe_0007;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Encodes one file through `sevenz-rust2` with an explicit content-coder chain. The chain is given
/// innermost-first (the compressor, then the filters that wrap it), matching `set_content_methods`.
fn sevenz_with_methods(methods: Vec<EncoderConfiguration>, name: &str, data: &[u8]) -> Vec<u8> {
    let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
    w.set_content_methods(methods);
    w.push_archive_entry(ArchiveEntry::new_file(name), Some(data))
        .unwrap();
    w.finish().unwrap().into_inner()
}

/// A folder whose coder graph chains the delta filter with LZMA2 must decode in arca: LZMA2
/// decompresses the pack stream, then the delta stage reconstructs the original bytes. `sevenz-rust2`
/// (using `lzma_rust2`'s independent delta implementation) is the producer; arca is the consumer.
#[test]
fn arca_reads_sevenz_rust2_delta_lzma2() {
    let data = pseudo_random(40_003);
    for distance in [1u32, 4, 256] {
        let methods = vec![
            EncoderConfiguration::new(EncoderMethod::LZMA2),
            EncoderConfiguration::new(EncoderMethod::DELTA_FILTER)
                .with_options(EncoderOptions::Delta(DeltaOptions::from_distance(distance))),
        ];
        let bytes = sevenz_with_methods(methods, "delta.bin", &data);
        // sevenz-rust2 must agree the archive is a valid delta+LZMA2 chain it can also read back.
        let mut reader = SevenReader::new(Cursor::new(bytes.clone()), Password::empty())
            .expect("sevenz-rust2 opens its own delta+LZMA2 archive");
        assert_eq!(reader.read_file("delta.bin").unwrap(), data);

        let got = read_with_arca(&bytes);
        let expected = vec![EntryShape::new(
            b"delta.bin".to_vec(),
            EntryKind::File,
            data.clone(),
        )];
        assert_eq!(
            got, expected,
            "arca delta+LZMA2 mismatch at distance {distance}"
        );
    }
}

/// The same shape with a BCJ branch filter: LZMA2 over a BCJ-filtered payload. arca must resolve the
/// two-coder graph, decompress LZMA2, then invert the branch transform. Exercised for the x86
/// (stateful) filter and a couple of fixed-stride RISC families.
#[test]
fn arca_reads_sevenz_rust2_bcj_lzma2() {
    let data = pseudo_random(60_011);
    let filters = [
        ("x86", EncoderMethod::BCJ_X86_FILTER),
        ("arm", EncoderMethod::BCJ_ARM_FILTER),
        ("ppc", EncoderMethod::BCJ_PPC_FILTER),
        ("sparc", EncoderMethod::BCJ_SPARC_FILTER),
    ];
    for (label, method) in filters {
        let methods = vec![
            EncoderConfiguration::new(EncoderMethod::LZMA2),
            EncoderConfiguration::new(method),
        ];
        let bytes = sevenz_with_methods(methods, "bcj.bin", &data);
        let mut reader = SevenReader::new(Cursor::new(bytes.clone()), Password::empty())
            .unwrap_or_else(|e| panic!("sevenz-rust2 opens its own {label} archive: {e}"));
        assert_eq!(
            reader.read_file("bcj.bin").unwrap(),
            data,
            "{label} self-read"
        );

        let got = read_with_arca(&bytes);
        let expected = vec![EntryShape::new(
            b"bcj.bin".to_vec(),
            EntryKind::File,
            data.clone(),
        )];
        assert_eq!(got, expected, "arca BCJ+LZMA2 mismatch for {label}");
    }
}

/// A payload that mixes a highly compressible run with pseudo-random noise, so the general-purpose
/// coders below (Deflate/BZip2/Zstd) emit real, non-degenerate compressed folders.
fn mixed_payload() -> Vec<u8> {
    let mut data = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
    data.extend(pseudo_random(20_000));
    data.extend(b"trailing repeated tail tail tail tail tail\n".repeat(120));
    data
}

/// Round-trips one file through `sevenz-rust2` with a single content coder `method`, asserting the
/// producer can read its own archive and that arca reproduces the original bytes exactly.
#[track_caller]
fn assert_arca_reads_method(method: EncoderMethod, label: &str) {
    let data = mixed_payload();
    let bytes = sevenz_with_methods(
        vec![EncoderConfiguration::new(method)],
        "payload.bin",
        &data,
    );
    let mut reader = SevenReader::new(Cursor::new(bytes.clone()), Password::empty())
        .unwrap_or_else(|e| panic!("sevenz-rust2 opens its own {label} archive: {e}"));
    assert_eq!(
        reader.read_file("payload.bin").unwrap(),
        data,
        "{label} self-read"
    );

    let got = read_with_arca(&bytes);
    let expected = vec![EntryShape::new(
        b"payload.bin".to_vec(),
        EntryKind::File,
        data.clone(),
    )];
    assert_eq!(got, expected, "arca {label} decode mismatch");
}

/// The 7z Deflate coder (method `04 01 08`) is RAW DEFLATE — no gzip header, trailer, or checksum.
/// arca reuses the shared `PipelineCodec` raw-inflate arm (the same `miniz_oxide` core the gzip
/// decoder sits on) to decode it. Always available under the `sevenz` feature.
#[test]
fn arca_reads_sevenz_rust2_deflate() {
    assert_arca_reads_method(EncoderMethod::DEFLATE, "deflate");
}

/// The 7z BZip2 coder (method `04 02 02`), reusing arca's existing BZip2 codec through the folder
/// coder graph. Gated on arca's `bzip2` feature; `sevenz-rust2`'s bzip2 support is on by default.
#[cfg(feature = "bzip2")]
#[test]
fn arca_reads_sevenz_rust2_bzip2() {
    assert_arca_reads_method(EncoderMethod::BZIP2, "bzip2");
}

/// The 7z Zstd coder (method `04 F7 11 01`), reusing arca's existing Zstd codec (portable `ruzstd`
/// or native `compression-codecs`) through the folder coder graph. Gated on arca's `zstd` feature.
#[cfg(feature = "zstd")]
#[test]
fn arca_reads_sevenz_rust2_zstd() {
    assert_arca_reads_method(EncoderMethod::ZSTD, "zstd");
}

fn ppmd_archive(data: &[u8], memory_size: u32) -> Vec<u8> {
    sevenz_with_methods(
        vec![PpmdOptions::from_order_memory_size(8, memory_size).into()],
        "ppmd.txt",
        data,
    )
}

fn read_with_limits(bytes: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes.to_vec()), limits)?;
    let mut output = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => output.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok(output),
            _ => {},
        }
    }
}

/// A one-file 7z fixture assembled around four streams split by the independent `compcol` BCJ2
/// implementation. The container is deliberately store+BCJ2 (no branch compression), keeping the
/// fixture focused on graph wiring and making stream corruption deterministic.
struct Bcj2Fixture {
    bytes: Vec<u8>,
    rc_offset: usize,
}

fn write_7z_number(output: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut count = 0u32;
    while count < 8 {
        if value < (1u64 << (7 * (count + 1))) {
            first |= (value >> (8 * count)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        count += 1;
    }
    output.push(first);
    let mut remaining = value;
    for _ in 0..count {
        output.push(remaining as u8);
        remaining >>= 8;
    }
}

fn bcj2_archive(data: &[u8]) -> Bcj2Fixture {
    bcj2_archive_with_branches(data, false)
}

fn bcj2_lzma2_archive(data: &[u8]) -> Bcj2Fixture {
    bcj2_archive_with_branches(data, true)
}

fn bcj2_archive_with_branches(data: &[u8], lzma2_branches: bool) -> Bcj2Fixture {
    const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    const METHOD_BCJ2: [u8; 4] = [0x03, 0x03, 0x01, 0x1B];
    const LZMA2_DICT_PROP_256_KIB: u8 = 12;

    let (main, call, jump, rc) = compcol::bcj2::encode(data);
    assert_eq!(
        compcol::bcj2::decode(&main, &call, &jump, &rc, data.len()).unwrap(),
        data,
        "independent BCJ2 splitter must reproduce its input"
    );
    let streams = [main, call, jump, rc];
    let packed_streams = if lzma2_branches {
        streams
            .iter()
            .map(|stream| {
                let options = lzma_rust2::Lzma2Options::with_preset(0);
                assert_eq!(
                    options.lzma_options.dict_size,
                    1 << 18,
                    "preset zero must match the fixture's dictionary property"
                );
                let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), options);
                writer.write_all(stream).unwrap();
                writer.finish().unwrap()
            })
            .collect::<Vec<_>>()
    } else {
        streams.clone().into()
    };
    let packed_size: usize = packed_streams.iter().map(Vec::len).sum();

    // kHeader -> kMainStreamsInfo.
    let mut header = vec![0x01, 0x04];
    // PackInfo: PackPos=0, four streams, then their sizes.
    header.push(0x06);
    write_7z_number(&mut header, 0);
    write_7z_number(&mut header, 4);
    header.push(0x09);
    for stream in &packed_streams {
        write_7z_number(&mut header, stream.len() as u64);
    }
    header.push(0x00);
    // UnpackInfo: one complex coder, four inputs and one output, no properties.
    header.extend_from_slice(&[0x07, 0x0B]);
    write_7z_number(&mut header, 1);
    header.push(0); // External = false.
    write_7z_number(&mut header, if lzma2_branches { 5 } else { 1 });
    header.push(0x14); // idSize=4 | complex coder.
    header.extend_from_slice(&METHOD_BCJ2);
    write_7z_number(&mut header, 4);
    write_7z_number(&mut header, 1);
    if lzma2_branches {
        for _ in 0..4 {
            header.extend_from_slice(&[0x21, 0x21, 1, LZMA2_DICT_PROP_256_KIB]);
        }
        // Each LZMA2 output (global outputs 1..=4) feeds one BCJ2 input (global inputs 0..=3).
        for branch in 0..4 {
            write_7z_number(&mut header, branch);
            write_7z_number(&mut header, branch + 1);
        }
    }
    // The four direct pack inputs are either BCJ2's inputs or the four LZMA2 inputs.
    let packed_base = if lzma2_branches { 4 } else { 0 };
    for packed_index in packed_base..packed_base + 4 {
        write_7z_number(&mut header, packed_index);
    }
    header.push(0x0C);
    write_7z_number(&mut header, data.len() as u64);
    if lzma2_branches {
        for stream in &streams {
            write_7z_number(&mut header, stream.len() as u64);
        }
    }
    header.extend_from_slice(&[0x0A, 1]);
    header.extend_from_slice(&libarchive_oxide::filter::crc32(data).to_le_bytes());
    header.push(0x00);
    // One default substream, then end MainStreamsInfo.
    header.extend_from_slice(&[0x08, 0x00, 0x00]);

    // FilesInfo: one UTF-16LE name.
    header.push(0x05);
    write_7z_number(&mut header, 1);
    let mut name = vec![0]; // External = false.
    for unit in "bcj2.bin".encode_utf16().chain(core::iter::once(0)) {
        name.extend_from_slice(&unit.to_le_bytes());
    }
    header.push(0x11);
    write_7z_number(&mut header, name.len() as u64);
    header.extend_from_slice(&name);
    header.extend_from_slice(&[0x00, 0x00]); // end FilesInfo, end Header.

    let header_crc = libarchive_oxide::filter::crc32(&header);
    let mut signature = [0u8; 32];
    signature[..6].copy_from_slice(&SIGNATURE);
    signature[7] = 4;
    signature[12..20].copy_from_slice(&(packed_size as u64).to_le_bytes());
    signature[20..28].copy_from_slice(&(header.len() as u64).to_le_bytes());
    signature[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let start_crc = libarchive_oxide::filter::crc32(&signature[12..32]);
    signature[8..12].copy_from_slice(&start_crc.to_le_bytes());

    let rc_offset =
        32 + packed_streams[0].len() + packed_streams[1].len() + packed_streams[2].len();
    let mut bytes = signature.to_vec();
    for stream in &packed_streams {
        bytes.extend_from_slice(stream);
    }
    bytes.extend_from_slice(&header);
    Bcj2Fixture { bytes, rc_offset }
}

struct ShortSeek {
    inner: Cursor<Vec<u8>>,
    maximum: usize,
}

impl Read for ShortSeek {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let amount = output.len().min(self.maximum);
        self.inner.read(&mut output[..amount])
    }
}

impl Seek for ShortSeek {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

fn bcj2_payload() -> Vec<u8> {
    let mut data = Vec::with_capacity(1_200_000);
    for index in 0..120_000u32 {
        data.extend_from_slice(&[0x90, 0xE8]);
        data.extend_from_slice(&index.wrapping_mul(31).to_le_bytes());
        data.extend_from_slice(&[0x0F, 0x85]);
        data.extend_from_slice(&index.wrapping_mul(17).to_le_bytes());
    }
    data
}

/// `compcol` supplies the independent BCJ2 split streams, `sevenz-rust2` independently validates
/// the 7z graph/container, and arca reconstructs the same bytes through tiny source reads. The
/// payload is larger than every internal event buffer, exercising incremental suspension across
/// all four shared extents.
#[test]
fn arca_streams_compcol_bcj2_and_sevenz_rust2_accepts_container() {
    let data = bcj2_payload();
    let fixture = bcj2_lzma2_archive(&data);

    let mut reference = SevenReader::new(Cursor::new(fixture.bytes.clone()), Password::empty())
        .expect("sevenz-rust2 accepts independently assembled BCJ2 container");
    assert_eq!(reference.read_file("bcj2.bin").unwrap(), data);

    let source = ShortSeek {
        inner: Cursor::new(fixture.bytes),
        maximum: 7,
    };
    let mut reader = SeekArchiveReader::with_limits(source, Limits::default()).unwrap();
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, data);
}

/// The fixed four-window junction is charged to `codec_memory` before it allocates or reads a pack
/// stream.
#[test]
fn bcj2_workspace_is_bounded_before_allocation() {
    const BCJ2_WORKSPACE: usize = 4 * (1 << 18);
    let fixture = bcj2_archive(b"\x90\xE8\x01\x00\x00\x00 bounded BCJ2\n");
    let limits = Limits::default().with_codec_memory(Some(BCJ2_WORKSPACE - 1));
    let error =
        read_with_limits(&fixture.bytes, limits).expect_err("undersized BCJ2 budget must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

/// Branch dictionaries coexist with the junction and are charged as one graph-wide allocation,
/// rather than each decoder independently receiving the complete budget.
#[test]
fn bcj2_branch_dictionaries_are_aggregate_bounded() {
    const TOTAL_WORKSPACE: usize = (4 * (1 << 18)) + (4 * (1 << 18));
    let fixture = bcj2_lzma2_archive(b"\x90\xE8\x01\x00\x00\x00 bounded branches\n");
    let limits = Limits::default().with_codec_memory(Some(TOTAL_WORKSPACE - 1));
    let error =
        read_with_limits(&fixture.bytes, limits).expect_err("aggregate BCJ2 budget must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

/// A damaged range-control stream must be a typed malformed-input failure, never a panic or
/// silently corrupted file.
#[test]
fn bcj2_corrupt_range_stream_is_malformed() {
    let data = bcj2_payload();
    let mut fixture = bcj2_archive(&data);
    fixture.bytes[fixture.rc_offset] ^= 0xFF;
    let error = read_with_limits(&fixture.bytes, Limits::default())
        .expect_err("corrupt BCJ2 range stream must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

/// PPMd7 (variant H, method `03 04 01`) is produced independently by `sevenz-rust2` and decoded
/// incrementally by arca. A payload much larger than the reader event buffer also guards the 7z
/// no-end-marker boundary: exactly the declared folder size is returned, with no garbage suffix.
#[test]
fn arca_reads_sevenz_rust2_ppmd7() {
    let mut data = b"PPMd predicts repeated text particularly well.\n".repeat(20_000);
    data.extend(pseudo_random(65_537));
    let bytes = ppmd_archive(&data, 4 * 1024 * 1024);

    let mut reference = SevenReader::new(Cursor::new(bytes.clone()), Password::empty())
        .expect("sevenz-rust2 opens its own PPMd7 archive");
    assert_eq!(reference.read_file("ppmd.txt").unwrap(), data);
    assert_eq!(read_with_limits(&bytes, Limits::default()).unwrap(), data);
}

/// The archive-declared PPMd model is checked against `Limits::codec_memory` before the decoder
/// allocates it.
#[test]
fn ppmd7_model_memory_is_bounded_before_allocation() {
    const MODEL_MEMORY: u32 = 4 * 1024 * 1024;
    let bytes = ppmd_archive(b"bounded PPMd model\n", MODEL_MEMORY);
    let limits = Limits::default().with_codec_memory(Some(MODEL_MEMORY as usize - 1));
    let error =
        read_with_limits(&bytes, limits).expect_err("oversized PPMd model must be rejected");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

/// A PPMd7 range stream must begin with the range coder's zero byte. Corrupting that byte leaves
/// the independently generated next header intact but must fail deterministically as malformed.
#[test]
fn ppmd7_corrupt_range_initialization_is_malformed() {
    let data = b"range decoder corruption fixture\n".repeat(100);
    let mut bytes = ppmd_archive(&data, 2 * 1024 * 1024);
    assert_eq!(
        bytes.get(32),
        Some(&0),
        "fixture pack stream must start at 32"
    );
    bytes[32] = 0xFF;

    let error =
        read_with_limits(&bytes, Limits::default()).expect_err("corrupt PPMd range must fail");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

/// AES-256/SHA-256 (method `06 F1 07 01`) differential coverage. `sevenz-rust2` (with its default
/// `aes256` feature) produces a password-protected single-coder folder; arca decrypts it through the
/// coder graph, deriving the key with 7-Zip's own UTF-16LE + SHA-256 KDF, and verifies the stored
/// per-substream CRC-32 after decode. Gated on arca's `aes` feature.
#[cfg(feature = "aes")]
mod aes {
    use libarchive_oxide::SecretBytes;
    use sevenz_rust2::encoder_options::AesEncoderOptions;

    use super::*;

    /// Builds a `.7z` whose single content folder is AES-256/SHA-256 encrypted under `password`.
    /// `encrypt_header` selects between `sevenz-rust2`'s default encrypted next-header (an AES-coded
    /// `kEncodedHeader`, so even listing needs the password) and a plain header (so the encryption is
    /// confined to the content folder — the shape that exercises the per-substream CRC check).
    fn build_aes(password: &str, name: &str, data: &[u8], encrypt_header: bool) -> Vec<u8> {
        let mut w = SevenWriter::new(Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(encrypt_header);
        let pw: Password = password.into();
        w.set_content_methods(vec![AesEncoderOptions::new(pw).into()]);
        w.push_archive_entry(ArchiveEntry::new_file(name), Some(data))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    /// Reads the whole (single-entry) archive's content through arca's seek reader with `password`.
    fn read_aes(bytes: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        let mut reader = SeekArchiveReader::with_password(
            Cursor::new(bytes.to_vec()),
            SecretBytes::new(password.as_bytes().to_vec()),
        )?;
        let mut content = Vec::new();
        loop {
            match reader.next_event()? {
                ReaderEvent::Data(d) => content.extend_from_slice(d),
                ReaderEvent::Done => return Ok(content),
                _ => {},
            }
        }
    }

    /// The correct password (including a non-ASCII code point, to exercise the UTF-16LE encoding)
    /// decrypts to the original plaintext, matching what `sevenz-rust2` reads back from its own file.
    /// Uses the default *encrypted* next-header, so this also proves the AES-coded `kEncodedHeader`
    /// path decodes with the caller's password.
    #[test]
    fn correct_password_decodes_encrypted_header_and_content() {
        let data = mixed_payload();
        let password = "córrèct-horse-battery-\u{1F510}";
        let bytes = build_aes(password, "secret.bin", &data, true);

        // The independent producer must read its own archive with the same password.
        let mut reference =
            SevenReader::new(Cursor::new(bytes.clone()), Password::from(password)).unwrap();
        assert_eq!(reference.read_file("secret.bin").unwrap(), data);

        assert_eq!(read_aes(&bytes, password).unwrap(), data);
    }

    /// A wrong password decrypts the content to garbage of the right length; the stored per-substream
    /// CRC-32 mismatch is surfaced as a typed `Integrity` error rather than silently returning corrupt
    /// bytes. A plain header keeps the failure at the content coder (the CRC path), not the header.
    #[test]
    fn wrong_password_trips_integrity() {
        let data = b"top secret payload, not for prying eyes\n".repeat(16);
        let bytes = build_aes("correct-horse", "s.bin", &data, false);

        // The fixture is sound: the correct password decodes it cleanly.
        assert_eq!(read_aes(&bytes, "correct-horse").unwrap(), data);

        let error = read_aes(&bytes, "wrong-horse").expect_err("wrong password must fail");
        assert_eq!(
            error.archive_error().map(ArchiveError::kind),
            Some(ErrorKind::Integrity),
            "wrong 7z AES password must be reported as an integrity failure"
        );
    }

    /// Opening a plain-header AES archive without any password lists metadata but reports a typed
    /// capability error (never a panic, never leaked secrets) when the encrypted content is reached.
    #[test]
    fn missing_password_is_unsupported() {
        let data = b"needs a key to read\n".repeat(8);
        let bytes = build_aes("pw", "s.bin", &data, false);

        let mut reader = SeekArchiveReader::new(Cursor::new(bytes.clone())).unwrap();
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Done) => panic!("expected a typed error for the missing password"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(
            error.archive_error().map(ArchiveError::kind),
            Some(ErrorKind::Unsupported),
            "a missing 7z AES password must be a typed capability error"
        );
    }
}
