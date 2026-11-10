// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded XAR Store writer contracts.

#![cfg(not(target_os = "wasi"))]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Write};
use std::process::{Command, Stdio};

use libarchive_oxide::{
    ArchiveEngine, CreateOptions, FormatWriteOptions, ReaderEvent, SeekArchiveReader,
    SeekArchiveWriter, XarCompression, XarWriteOptions,
};
use libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind, Extension, FormatId, Limits,
    Owner, Timestamp,
};

fn metadata(
    kind: EntryKind,
    path: &str,
    size: u64,
    mode: u32,
    link: Option<&str>,
) -> EntryMetadata {
    EntryMetadata::builder(kind, ArchivePath::from_utf8(path))
        .size(Some(size))
        .mode(Some(mode))
        .owner(Owner {
            uid: Some(501),
            gid: Some(20),
            user: None,
            group: None,
        })
        .times(EntryTimes {
            modified: Some(Timestamp::new(1_700_000_000, 123_456_789).unwrap()),
            ..EntryTimes::default()
        })
        .link_target(link.map(ArchivePath::from_utf8))
        .build()
}

#[test]
fn seek_writer_roundtrips_store_tree_and_metadata() {
    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe())
        .expect("create XAR writer");
    let directory = metadata(EntryKind::Dir, "docs", 0, 0o750, None);
    writer.start_entry(&directory).unwrap();
    writer.end_entry().unwrap();

    let body = b"bounded XAR payload\n".repeat(8192);
    let file = metadata(
        EntryKind::File,
        "docs/a & b.txt",
        body.len() as u64,
        0o640,
        None,
    );
    writer.start_entry(&file).unwrap();
    for chunk in body.chunks(997) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();

    let symlink = metadata(
        EntryKind::Symlink,
        "latest",
        0,
        0o777,
        Some("docs/a & b.txt"),
    );
    writer.start_entry(&symlink).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap().into_inner();
    assert_eq!(&archive[..4], b"xar!");

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert_eq!(reader.format(), FormatId::Xar);
    let mut entries = Vec::new();
    let mut bodies = Vec::new();
    let mut current = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(entry) => entries.push(entry),
            ReaderEvent::Data(bytes) => current.extend_from_slice(bytes),
            ReaderEvent::EndEntry => bodies.push(std::mem::take(&mut current)),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].path().as_bytes(), b"docs");
    assert_eq!(entries[0].kind(), EntryKind::Dir);
    assert_eq!(entries[0].mode(), Some(0o750));
    assert_eq!(entries[1].path().as_bytes(), b"docs/a & b.txt");
    assert_eq!(entries[1].kind(), EntryKind::File);
    assert_eq!(entries[1].owner().uid, Some(501));
    assert_eq!(entries[1].owner().gid, Some(20));
    assert_eq!(entries[1].times().modified, file.times().modified);
    assert_eq!(entries[2].path().as_bytes(), b"latest");
    assert_eq!(entries[2].kind(), EntryKind::Symlink);
    assert_eq!(
        entries[2].link_target().unwrap().as_bytes(),
        b"docs/a & b.txt"
    );
    assert_eq!(bodies, vec![Vec::new(), body, Vec::new()]);
}

fn compressed_xar(compression: XarCompression, body: &[u8]) -> Vec<u8> {
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(compression),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("create compressed XAR writer");
    writer
        .start_entry(&metadata(
            EntryKind::File,
            "compressed.txt",
            body.len() as u64,
            0o644,
            None,
        ))
        .expect("start compressed file");
    for chunk in body.chunks(113) {
        writer.write_data(chunk).expect("compress XAR chunk");
    }
    writer.end_entry().expect("finish compressed file");
    writer.finish().expect("finish compressed XAR").into_inner()
}

fn inflated_toc(archive: &[u8]) -> Vec<u8> {
    let compressed_length = u64::from_be_bytes(archive[8..16].try_into().expect("TOC length"));
    let start = 28;
    let end = start + usize::try_from(compressed_length).expect("TOC address space");
    miniz_oxide::inflate::decompress_to_vec_zlib(&archive[start..end]).expect("inflate XAR TOC")
}

fn assert_compressed_roundtrip(compression: XarCompression, encoding: &[u8]) {
    let body = b"compressible XAR payload\n".repeat(4096);
    let archive = compressed_xar(compression, &body);
    let toc = inflated_toc(&archive);
    assert!(
        toc.windows(encoding.len()).any(|window| window == encoding),
        "TOC did not name the selected encoding: {}",
        String::from_utf8_lossy(&toc)
    );
    if compression == XarCompression::Zlib {
        let compressed_toc = u64::from_be_bytes(archive[8..16].try_into().expect("TOC length"));
        let heap_start = 28 + usize::try_from(compressed_toc).expect("heap address space");
        let independently_decoded =
            miniz_oxide::inflate::decompress_to_vec_zlib(&archive[heap_start..])
                .expect("independent zlib heap decode");
        assert_eq!(independently_decoded, body);
    }

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("open compressed XAR");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read compressed XAR") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);
}

#[test]
fn zlib_writer_roundtrips_and_emits_xar_encoding() {
    assert_compressed_roundtrip(XarCompression::Zlib, b"application/x-gzip");
}

#[cfg(feature = "bzip2")]
#[test]
fn bzip2_writer_roundtrips_and_emits_xar_encoding() {
    assert_compressed_roundtrip(XarCompression::Bzip2, b"application/x-bzip2");
}

#[test]
fn zlib_empty_entry_respects_zero_decoded_budget_despite_framing_bytes() {
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_limits(Limits::safe().with_decoded_total(Some(0)))
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(XarCompression::Zlib),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("create bounded zlib XAR");
    writer
        .start_entry(&metadata(EntryKind::File, "empty", 0, 0o644, None))
        .expect("start empty entry");
    writer.end_entry().expect("finish empty entry");
    let archive = writer.finish().expect("finish empty zlib XAR").into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("open empty zlib XAR");
    while !matches!(reader.next_event().expect("empty event"), ReaderEvent::Done) {}
}

#[test]
fn zlib_writer_preflights_codec_and_buffer_budgets() {
    for limits in [
        Limits::safe().with_codec_memory(Some(512 * 1024 - 1)),
        Limits::safe().with_in_flight_bytes(Some(0)),
    ] {
        let options = CreateOptions::new()
            .with_format(FormatId::Xar)
            .with_limits(limits)
            .with_format_options(Some(FormatWriteOptions::Xar(
                XarWriteOptions::new().with_compression(XarCompression::Zlib),
            )));
        let error = ArchiveEngine::new()
            .create_seek(Cursor::new(Vec::new()), options)
            .expect_err("zlib resources must be checked before creation");
        assert_eq!(error.kind(), ErrorKind::Limit);
    }
}

#[cfg(feature = "bzip2")]
#[test]
fn bzip2_writer_preflights_codec_budget() {
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_limits(Limits::safe().with_codec_memory(Some(8 * 1024 * 1024 - 1)))
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(XarCompression::Bzip2),
        )));
    let error = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("BZip2 resources must be checked before creation");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[cfg(not(feature = "bzip2"))]
#[test]
fn bzip2_writer_fails_closed_when_codec_is_disabled() {
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(XarCompression::Bzip2),
        )));
    let error = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("disabled BZip2 must fail before creation");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn zlib_writer_uses_an_independent_stream_for_each_entry() {
    let payloads = [
        b"first compressed XAR stream\n".repeat(3072),
        b"second compressed XAR stream\n".repeat(2049),
    ];
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(XarCompression::Zlib),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("create multi-entry zlib XAR");
    for (index, payload) in payloads.iter().enumerate() {
        let path = format!("entry-{index}.txt");
        writer
            .start_entry(&metadata(
                EntryKind::File,
                &path,
                payload.len() as u64,
                0o644,
                None,
            ))
            .expect("start compressed entry");
        for chunk in payload.chunks(127) {
            writer.write_data(chunk).expect("write compressed entry");
        }
        writer.end_entry().expect("finish compressed entry");
    }
    let archive = writer.finish().expect("finish zlib XAR").into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("open zlib XAR");
    let mut decoded = Vec::new();
    let mut current = Vec::new();
    loop {
        match reader.next_event().expect("read zlib XAR") {
            ReaderEvent::Data(bytes) => current.extend_from_slice(bytes),
            ReaderEvent::EndEntry => decoded.push(std::mem::take(&mut current)),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payloads);
}

#[test]
fn writer_preflights_entry_count_size_and_total_limits() {
    let output = Cursor::new(Vec::new());
    let mut writer =
        SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe().with_entries(Some(0)))
            .unwrap();
    let error = writer
        .start_entry(&metadata(EntryKind::File, "one", 1, 0o600, None))
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(
        output,
        FormatId::Xar,
        Limits::safe()
            .with_entry_bytes(Some(3))
            .with_decoded_total(Some(3)),
    )
    .unwrap();
    let error = writer
        .start_entry(&metadata(EntryKind::File, "large", 4, 0o600, None))
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn abort_does_not_publish_a_partial_xar() {
    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe()).unwrap();
    writer
        .start_entry(&metadata(EntryKind::File, "partial", 7, 0o600, None))
        .unwrap();
    writer.write_data(b"partial").unwrap();
    let output = writer.abort().unwrap();
    assert_eq!(output.into_inner(), [] as [u8; 0]);
}

#[test]
fn writer_emits_implicit_parents_and_rejects_duplicates() {
    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe()).unwrap();
    let file = metadata(EntryKind::File, "a/b/c.txt", 1, 0o600, None);
    writer.start_entry(&file).unwrap();
    writer.write_data(b"c").unwrap();
    writer.end_entry().unwrap();
    let error = writer.start_entry(&file).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Protocol);
    let archive = writer.finish().unwrap().into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    let mut paths = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(entry) => {
                paths.push((entry.path().as_bytes().to_vec(), entry.kind(), entry.mode()));
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(
        paths,
        vec![
            (b"a".to_vec(), EntryKind::Dir, None),
            (b"a/b".to_vec(), EntryKind::Dir, None),
            (b"a/b/c.txt".to_vec(), EntryKind::File, Some(0o600)),
        ]
    );
}

#[test]
fn writer_rejects_lossy_metadata_and_declared_size_mismatch() {
    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe()).unwrap();
    let lossy = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("extended"))
        .size(Some(0))
        .extension(Extension::new("test", b"key".to_vec(), b"value".to_vec()))
        .build();
    let error = writer.start_entry(&lossy).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let short = metadata(EntryKind::File, "short", 2, 0o600, None);
    writer.start_entry(&short).unwrap();
    writer.write_data(b"x").unwrap();
    let error = writer.end_entry().unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Protocol);
}

#[test]
fn writer_enforces_path_nesting_metadata_and_copy_limits() {
    let scenarios = [
        Limits::safe().with_path_bytes(Some(2)),
        Limits::safe().with_nesting(Some(1)),
        Limits::safe().with_metadata_bytes(Some(1)),
    ];
    for limits in scenarios {
        let output = Cursor::new(Vec::new());
        let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, limits).unwrap();
        let error = writer
            .start_entry(&metadata(EntryKind::File, "a/b", 1, 0o600, None))
            .unwrap_err();
        assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    }

    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(
        output,
        FormatId::Xar,
        Limits::safe().with_in_flight_bytes(Some(0)),
    )
    .unwrap();
    writer
        .start_entry(&metadata(EntryKind::File, "one", 1, 0o600, None))
        .unwrap();
    writer.write_data(b"1").unwrap();
    writer.end_entry().unwrap();
    let error = writer.finish().unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

fn has_bsdtar() -> bool {
    Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|output| {
            output.stdout.windows(6).any(|window| window == b"bsdtar")
                || output.stderr.windows(6).any(|window| window == b"bsdtar")
        })
}

#[test]
fn system_bsdtar_accepts_writer_output() {
    if !has_bsdtar() {
        return;
    }

    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, FormatId::Xar, Limits::safe()).unwrap();
    let body = b"independent XAR consumer";
    writer
        .start_entry(&metadata(
            EntryKind::File,
            "interop/seed.txt",
            body.len() as u64,
            0o644,
            None,
        ))
        .unwrap();
    writer.write_data(body).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let mut child = Command::new("tar")
        .args(["-tf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run bsdtar XAR consumer");
    child
        .stdin
        .take()
        .expect("bsdtar stdin")
        .write_all(&archive)
        .expect("send XAR to bsdtar");
    let consumed = child.wait_with_output().expect("wait for bsdtar consumer");
    assert!(
        consumed.status.success(),
        "bsdtar rejected XAR output: {}",
        String::from_utf8_lossy(&consumed.stderr)
    );
    let listing = String::from_utf8(consumed.stdout).expect("bsdtar listing is UTF-8");
    assert_eq!(listing.lines().collect::<Vec<_>>(), ["interop/seed.txt"]);
}
