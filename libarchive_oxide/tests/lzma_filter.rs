// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit-only LZMA-alone outer-filter interoperability and limit contracts.

#![cfg(feature = "lzma")]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::{self, Read, Write};

#[cfg(feature = "async")]
use libarchive_oxide::AsyncArchiveWriter;
#[cfg(feature = "tokio")]
use libarchive_oxide::TokioArchiveWriter;
use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, FilterId, FilterReader,
    FormatId, Limits, ReaderEvent,
};

struct OneByte {
    bytes: Vec<u8>,
    position: usize,
}

impl OneByte {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl Read for OneByte {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Ok(1)
    }
}

fn independent_encode(payload: &[u8]) -> Vec<u8> {
    let options = lzma_rust2::LzmaOptions::with_preset(0);
    let mut writer =
        lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, Some(payload.len() as u64))
            .expect("independent LZMA-alone writer");
    writer.write_all(payload).expect("encode LZMA payload");
    writer.finish().expect("finish independent LZMA stream")
}

fn independent_encode_unknown_size(payload: &[u8]) -> Vec<u8> {
    let options = lzma_rust2::LzmaOptions::with_preset(0);
    let mut writer = lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, None)
        .expect("independent streaming LZMA-alone writer");
    writer
        .write_all(payload)
        .expect("encode streaming LZMA payload");
    writer.finish().expect("finish streaming LZMA stream")
}

fn independent_decode(encoded: &[u8]) -> Vec<u8> {
    let mut decoder =
        lzma_rust2::LzmaReader::new_mem_limit(encoded, u32::MAX, None).expect("LZMA header");
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .expect("decode LZMA stream");
    output
}

#[test]
fn explicit_reader_decodes_independent_stream_one_byte_at_a_time() {
    let payload = b"LZMA-alone remains bounded across tiny input chunks";
    let encoded = independent_encode(payload);
    let mut reader =
        FilterReader::with_filter(OneByte::new(encoded), FilterId::Lzma, Limits::safe())
            .expect("explicit LZMA reader");
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .expect("decode LZMA stream");
    assert_eq!(decoded, payload);
}

#[test]
fn archive_writer_output_is_consumed_by_an_independent_decoder() {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Lzma),
        Limits::safe(),
    )
    .expect("LZMA tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"lzma.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start tar entry");
    writer.write_data(b"payload").expect("write tar entry");
    writer.end_entry().expect("end tar entry");
    let encoded = writer.finish().expect("finish LZMA tar");

    let decoded = independent_decode(&encoded);
    let mut archive = ArchiveReader::new(decoded.as_slice());
    let mut body = Vec::new();
    loop {
        match archive.next_event().expect("read decoded tar") {
            ReaderEvent::Entry(entry) => assert_eq!(entry.path().as_bytes(), b"lzma.txt"),
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected tar event"),
        }
    }
    assert_eq!(body, b"payload");
}

#[test]
fn writers_preflight_encoder_memory() {
    let limits = Limits::safe().with_codec_memory(Some(1));
    let sync_error =
        ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, Some(FilterId::Lzma), limits)
            .expect_err("sync encoder memory limit");
    assert_eq!(sync_error.kind(), libarchive_oxide::ErrorKind::Limit);

    #[cfg(feature = "async")]
    {
        let async_error = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            FormatId::Tar,
            Some(FilterId::Lzma),
            limits,
        )
        .expect_err("async encoder memory limit");
        assert_eq!(async_error.kind(), libarchive_oxide::ErrorKind::Limit);
    }
}

#[test]
fn reader_preflights_declared_size_and_dictionary_memory() {
    let payload = b"small";
    let encoded = independent_encode(payload);

    let mut bomb = encoded.clone();
    bomb[5..13].copy_from_slice(&1_000_000_u64.to_le_bytes());
    let error = FilterReader::with_filter(
        bomb.as_slice(),
        FilterId::Lzma,
        Limits::safe().with_decoded_total(Some(1024)),
    )
    .expect_err("declared-size bomb");
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);

    let error = FilterReader::with_filter(
        encoded.as_slice(),
        FilterId::Lzma,
        Limits::safe().with_codec_memory(Some(1024)),
    )
    .expect_err("dictionary memory limit");
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
}

#[test]
fn reader_rejects_truncated_headers_and_payloads() {
    let encoded = independent_encode_unknown_size(b"truncation-check");
    for cut in 0..13 {
        let error = FilterReader::with_filter(&encoded[..cut], FilterId::Lzma, Limits::safe())
            .expect_err("truncated LZMA header");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "header cut at {cut}",
        );
    }

    let payload_cut = 13 + (encoded.len() - 13) / 2;
    let mut reader =
        FilterReader::with_filter(&encoded[..payload_cut], FilterId::Lzma, Limits::safe())
            .expect("construct payload reader");
    assert_eq!(
        reader
            .read_to_end(&mut Vec::new())
            .expect_err("truncated LZMA payload")
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[cfg(feature = "async")]
#[test]
fn futures_writer_streams_one_lzma_member() {
    futures_lite::future::block_on(async {
        let mut writer = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            FormatId::Tar,
            Some(FilterId::Lzma),
            Limits::safe(),
        )
        .expect("async LZMA writer");
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"async.txt".to_vec()),
        )
        .size(Some(7))
        .build();
        writer.start_entry(&metadata).await.expect("start entry");
        writer.write_data(b"pay").await.expect("first body chunk");
        writer.write_data(b"load").await.expect("second body chunk");
        writer.end_entry().await.expect("end entry");
        let encoded = writer.finish().await.expect("finish writer").into_inner();

        let decoded = independent_decode(&encoded);
        let mut archive = ArchiveReader::new(decoded.as_slice());
        let mut body = Vec::new();
        loop {
            match archive.next_event().expect("read async LZMA tar") {
                ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => panic!("unexpected tar event"),
            }
        }
        assert_eq!(body, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_writer_streams_one_lzma_member() {
    let mut writer = TokioArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Lzma),
        Limits::safe(),
    )
    .expect("Tokio LZMA writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"tokio.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).await.expect("start entry");
    writer.write_data(b"payload").await.expect("body");
    writer.end_entry().await.expect("end entry");
    let encoded = writer.finish().await.expect("finish writer");

    assert!(encoded.len() > 13);
    assert_eq!(independent_decode(&encoded).len(), 2048);
}
