//! Differential test against the independent pure-Rust `sevenz-rust2` crate, mirroring how the zip
//! tests lean on the `zip` crate. Two directions run:
//!
//! (a) `sevenz-rust2` reads a `.7z` produced by arca's `SevenZWriter` — validating arca's folder /
//!     substream / FilesInfo byte layout against an independent decoder.
//! (b) arca's `SevenZReader` reads a `.7z` produced by `sevenz-rust2`'s `ArchiveWriter` (solid,
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
    clippy::many_single_char_names
)]

use std::borrow::Cow;
use std::io::Cursor;

use libarchive_oxide::sevenz::{SevenZReader, SevenZWriter};
use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password,
    SourceReader,
};

/// Writes an arca 7z with a directory, two content files, and an empty file.
fn arca_archive() -> Vec<u8> {
    let mut w = SevenZWriter::new(Vec::new());
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
        let mut m = EntryMeta::new(kind, Cow::Borrowed(name));
        m.mode = if kind == EntryKind::Dir { 0o755 } else { 0o644 };
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        if !data.is_empty() {
            sink.write_chunk(&data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

#[test]
fn sevenz_rust2_reads_arca_output() {
    let bytes = arca_archive();
    let mut reader =
        ArchiveReader::new(Cursor::new(bytes), Password::empty()).expect("sevenz-rust2 opens arca");

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
    let mut w = ArchiveWriter::new(cursor).unwrap();
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

    // arca reads it back.
    let mut r = SevenZReader::new(&bytes);
    let mut got: Vec<(Vec<u8>, EntryKind, Vec<u8>)> = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let name = e.meta().path.to_vec();
        let kind = e.meta().kind;
        let mut data = Vec::new();
        let mut buf = [0u8; 8];
        loop {
            let n = e.data().read_chunk(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        got.push((name, kind, data));
    }

    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, b"pkg/a.txt");
    assert_eq!(got[0].1, EntryKind::File);
    assert_eq!(got[0].2, a);
    assert_eq!(got[1].0, b"pkg/b.txt");
    assert_eq!(got[1].2, b);
}

/// Reads every content file out of an arca `SevenZReader`, returning `(name, kind, bytes)` per entry.
fn drive_arca(bytes: &[u8]) -> Vec<(Vec<u8>, EntryKind, Vec<u8>)> {
    let mut r = SevenZReader::new(bytes);
    let mut got = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let name = e.meta().path.to_vec();
        let kind = e.meta().kind;
        let mut data = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = e.data().read_chunk(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        got.push((name, kind, data));
    }
    got
}

/// The plain-**LZMA** (method `03 01 01`) folder coder — what 7-Zip and `sevenz-rust2` use — must be
/// readable by arca, not just LZMA2. `sevenz-rust2` is told to compress content with `EncoderMethod::LZMA`.
#[test]
fn arca_reads_sevenz_rust2_lzma_folder() {
    let a = b"first lzma-coded file\n".to_vec();
    let b = b"second lzma-coded file, repeated a lot\n".repeat(40);

    let mut w = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
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

    let got = drive_arca(&bytes);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, b"pkg/a.txt");
    assert_eq!(got[0].2, a);
    assert_eq!(got[1].0, b"pkg/b.txt");
    assert_eq!(got[1].2, b);
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

    let mut w = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
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

    let got = drive_arca(&bytes);
    assert_eq!(got.len(), count);
    for (g, e) in got.iter().zip(expected.iter()) {
        assert_eq!(g.0, e.0);
        assert_eq!(g.2, e.1);
    }
}
