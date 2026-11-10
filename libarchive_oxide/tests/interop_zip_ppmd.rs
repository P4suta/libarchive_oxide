// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP method 98 streaming, limits, and interoperability tests.

#![cfg(feature = "ppmd")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};

use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, CreateOptions, Error, FormatId, FormatWriteOptions, ReaderEvent,
    SeekArchiveReader, ZipCompression, ZipMethod, ZipWriteOptions,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};
use zip::write::{SimpleFileOptions, ZipWriter};

const PAYLOAD: &[u8] =
    b"PPMd predicts repeated contexts well. PPMd predicts repeated contexts well.\n";

fn create_with_arca(payload: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_limits(limits)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new().with_compression(ZipCompression::Ppmd8),
        )));
    let mut writer = ArchiveEngine::new().create(Vec::new(), options)?;
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("payload.txt"))
        .size(Some(payload.len() as u64))
        .build();
    writer.start_entry(&metadata)?;
    for chunk in payload.chunks(7) {
        writer.write_data(chunk)?;
    }
    writer.end_entry()?;
    writer.finish()
}

fn create_with_zip_crate(payload: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Ppmd)
        .compression_level(Some(4));
    writer.start_file("payload.txt", options).unwrap();
    writer.write_all(payload).unwrap();
    writer.finish().unwrap().into_inner()
}

fn read_with_arca(archive: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(archive.to_vec()), limits)?;
    let mut output = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => output.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok(output),
            _ => {},
        }
    }
}

fn local_data_offset(archive: &[u8]) -> usize {
    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    30 + name + extra
}

fn central_offset(archive: &[u8]) -> usize {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap();
    u32::from_le_bytes([
        archive[eocd + 16],
        archive[eocd + 17],
        archive[eocd + 18],
        archive[eocd + 19],
    ]) as usize
}

#[test]
fn zip_ppmd_roundtrips_and_interoperates_both_directions() {
    let payload = PAYLOAD.repeat(512);
    let archive = create_with_arca(&payload, Limits::default()).expect("arca PPMd writer");
    assert_eq!(u16::from_le_bytes([archive[8], archive[9]]), 98);
    assert_eq!(
        read_with_arca(&archive, Limits::default()).expect("arca PPMd reader"),
        payload
    );

    let mut independent = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
    let mut member = independent.by_index(0).unwrap();
    assert_eq!(member.compression(), zip::CompressionMethod::Ppmd);
    let mut decoded = Vec::new();
    member.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, payload);

    let independent = create_with_zip_crate(&payload);
    assert_eq!(
        read_with_arca(&independent, Limits::default()).expect("independent PPMd archive"),
        payload
    );
}

#[test]
fn zip_ppmd_rejects_model_above_codec_memory_limit() {
    let independent = create_with_zip_crate(PAYLOAD);
    let error = read_with_arca(
        &independent,
        Limits::default().with_codec_memory(Some(1024 * 1024)),
    )
    .expect_err("zip crate level 4 uses a model larger than 1 MiB");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn zip_ppmd_writer_rejects_insufficient_codec_memory_before_payload() {
    let error = create_with_arca(
        PAYLOAD,
        Limits::default().with_codec_memory(Some(8 * 1024 * 1024 - 1)),
    )
    .expect_err("arca PPMd writer model is 8 MiB");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn zip_ppmd_honors_decoded_total_limit() {
    let archive = create_with_zip_crate(&PAYLOAD.repeat(16));
    let error = read_with_arca(&archive, Limits::default().with_decoded_total(Some(32)))
        .expect_err("decoded output must remain bounded");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn zip_ppmd_rejects_invalid_parameters_before_allocating() {
    let mut archive = create_with_zip_crate(PAYLOAD);
    let offset = local_data_offset(&archive);
    archive[offset..offset + 2].copy_from_slice(&0_u16.to_le_bytes());
    let error = read_with_arca(&archive, Limits::default()).expect_err("order 1 is invalid");
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn zip_ppmd_rejects_corrupt_range_stream_and_crc() {
    let mut truncated = create_with_zip_crate(&PAYLOAD.repeat(64));
    let end = central_offset(&truncated);
    truncated[end - 4..end].fill(0);
    let error =
        read_with_arca(&truncated, Limits::default()).expect_err("PPMd end marker was destroyed");
    assert!(matches!(
        error.kind(),
        ErrorKind::Malformed | ErrorKind::Integrity
    ));

    let mut bad_crc = create_with_zip_crate(PAYLOAD);
    let central = central_offset(&bad_crc);
    bad_crc[central + 16..central + 20].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    let error = read_with_arca(&bad_crc, Limits::default()).expect_err("CRC must be checked");
    assert_eq!(error.kind(), ErrorKind::Integrity);
}

fn create_two_with_arca() -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Ppmd8, Limits::default());
    for (name, payload) in [
        ("first.bin", vec![b'a'; 32 * 1024]),
        ("second.bin", b"second payload".to_vec()),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(name)).build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(&payload).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn zip_ppmd_skip_recovers_source_and_continues_with_next_entry() {
    let archive = create_two_with_arca();
    let mut reader =
        SeekArchiveReader::with_limits(Cursor::new(archive), Limits::default()).unwrap();
    loop {
        if let ReaderEvent::Data(_) = reader.next_event().unwrap() {
            reader.skip_entry().unwrap();
            break;
        }
    }
    let mut second = Vec::new();
    let mut in_second = false;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"second.bin" => {
                in_second = true;
            },
            ReaderEvent::Data(bytes) if in_second => second.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(second, b"second payload");
}

#[test]
fn zip_ppmd_into_inner_recovers_source_during_decode() {
    let archive = create_two_with_arca();
    let expected_len = archive.len();
    let mut reader =
        SeekArchiveReader::with_limits(Cursor::new(archive), Limits::default()).unwrap();
    loop {
        if matches!(reader.next_event().unwrap(), ReaderEvent::Data(_)) {
            break;
        }
    }
    let source = reader
        .into_inner()
        .expect("active PPMd source is recoverable");
    assert_eq!(source.get_ref().len(), expected_len);
}

#[cfg(feature = "async")]
#[test]
fn zip_ppmd_futures_writer_uses_the_common_streaming_encoder() {
    futures_lite::future::block_on(async {
        let output = futures_lite::io::Cursor::new(Vec::new());
        let mut writer = libarchive_oxide::AsyncArchiveWriter::with_zip_method(
            output,
            ZipMethod::Ppmd8,
            Limits::default(),
        );
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("async.txt")).build();
        writer.start_entry(&metadata).await.unwrap();
        writer.write_data(PAYLOAD).await.unwrap();
        writer.end_entry().await.unwrap();
        let archive = writer.finish().await.unwrap().into_inner();
        assert_eq!(
            read_with_arca(&archive, Limits::default()).unwrap(),
            PAYLOAD
        );
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn zip_ppmd_tokio_writer_uses_the_common_streaming_encoder() {
    let mut writer = libarchive_oxide::TokioArchiveWriter::with_zip_method(
        Vec::new(),
        ZipMethod::Ppmd8,
        Limits::default(),
    );
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("tokio.txt")).build();
    writer.start_entry(&metadata).await.unwrap();
    writer.write_data(PAYLOAD).await.unwrap();
    writer.end_entry().await.unwrap();
    let archive = writer.finish().await.unwrap();
    assert_eq!(
        read_with_arca(&archive, Limits::default()).unwrap(),
        PAYLOAD
    );
}
