// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP method 95 streaming, limits, and interoperability tests.

#![cfg(feature = "xz")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};

#[cfg(any(feature = "async", feature = "tokio"))]
use libarchive_oxide::ZipMethod;
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, Error, FormatId, FormatWriteOptions, ReaderEvent,
    SeekArchiveReader, ZipCompression, ZipWriteOptions,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};
use zip::write::{SimpleFileOptions, ZipWriter};

const PAYLOAD: &[u8] = b"XZ inside ZIP keeps the complete XZ stream framing.\n";

fn create_with_arca(payload: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_limits(limits)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new().with_compression(ZipCompression::Xz),
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
        .compression_method(zip::CompressionMethod::XZ)
        .compression_level(Some(6));
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

#[test]
fn zip_xz_roundtrips_and_interoperates_both_directions() {
    let payload = PAYLOAD.repeat(512);
    let archive = create_with_arca(&payload, Limits::default()).expect("arca XZ writer");
    assert_eq!(u16::from_le_bytes([archive[8], archive[9]]), 95);
    assert_eq!(
        read_with_arca(&archive, Limits::default()).expect("arca XZ reader"),
        payload
    );

    let mut independent = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
    let mut member = independent.by_index(0).unwrap();
    assert_eq!(member.compression(), zip::CompressionMethod::XZ);
    let mut decoded = Vec::new();
    member.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, payload);

    let independent = create_with_zip_crate(&payload);
    assert_eq!(
        read_with_arca(&independent, Limits::default()).expect("independent XZ archive"),
        payload
    );
}

#[test]
fn zip_xz_writer_rejects_insufficient_codec_memory() {
    let error = create_with_arca(
        PAYLOAD,
        Limits::default().with_codec_memory(Some(1024 * 1024)),
    )
    .expect_err("preset 6 needs more than 1 MiB");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn zip_xz_reader_rejects_dictionary_above_codec_memory_limit() {
    let independent = create_with_zip_crate(PAYLOAD);
    let error = read_with_arca(
        &independent,
        Limits::default().with_codec_memory(Some(1024 * 1024)),
    )
    .expect_err("XZ dictionary must be checked before decoder allocation");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn zip_xz_honors_decoded_total_limit_and_rejects_corruption() {
    let archive = create_with_zip_crate(&PAYLOAD.repeat(32));
    let error = read_with_arca(&archive, Limits::default().with_decoded_total(Some(32)))
        .expect_err("decoded output must remain bounded");
    assert_eq!(error.kind(), ErrorKind::Limit);

    let mut corrupt = create_with_zip_crate(&PAYLOAD.repeat(8));
    let data_offset = 30
        + usize::from(u16::from_le_bytes([corrupt[26], corrupt[27]]))
        + usize::from(u16::from_le_bytes([corrupt[28], corrupt[29]]));
    corrupt[data_offset + 12] ^= 0x80;
    let error = read_with_arca(&corrupt, Limits::default()).expect_err("XZ CRC must be checked");
    assert!(matches!(
        error.kind(),
        ErrorKind::Malformed | ErrorKind::Integrity
    ));
}

#[test]
fn zip_xz_empty_member_has_valid_stream_framing() {
    let archive = create_with_arca(&[], Limits::default()).unwrap();
    assert_eq!(read_with_arca(&archive, Limits::default()).unwrap(), b"");
    let mut independent = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
    let mut member = independent.by_index(0).unwrap();
    let mut decoded = Vec::new();
    member.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, [] as [u8; 0]);
}

#[cfg(feature = "async")]
#[test]
fn zip_xz_futures_writer_uses_the_common_streaming_encoder() {
    futures_lite::future::block_on(async {
        let output = futures_lite::io::Cursor::new(Vec::new());
        let mut writer = libarchive_oxide::AsyncArchiveWriter::with_zip_method(
            output,
            ZipMethod::Xz,
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
async fn zip_xz_tokio_writer_uses_the_common_streaming_encoder() {
    let mut writer = libarchive_oxide::TokioArchiveWriter::with_zip_method(
        Vec::new(),
        ZipMethod::Xz,
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
