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
//! Both directions stay within arca's supported subset: a single solid LZMA2 folder. Direction (b)
//! therefore uses one solid block (`push_archive_entries`), and the small headers `sevenz-rust2`
//! emits stay as a plain (uncompressed) `kHeader`, which arca supports.
#![cfg(feature = "sevenz")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation
)]

use std::io::Cursor;

use libarchive_oxide::SeekArchiveWriter;
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader as SevenReader, ArchiveWriter as SevenWriter, EncoderConfiguration,
    EncoderMethod, Password, SourceReader,
    encoder_options::{DeltaOptions, EncoderOptions},
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
