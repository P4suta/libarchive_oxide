// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit-only Base64 outer-filter adapter contracts.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::{self, Read};

#[cfg(feature = "async")]
use libarchive_oxide::AsyncArchiveWriter;
#[cfg(feature = "tokio")]
use libarchive_oxide::TokioArchiveWriter;
use libarchive_oxide::advanced::{ProviderSet, StaticCodecProviders};
use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, FilterId, FilterReader,
    Limits, ReaderEvent,
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

fn encoded_tar() -> Vec<u8> {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Base64),
        Limits::safe(),
    )
    .expect("Base64 tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"base64.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start tar entry");
    writer.write_data(b"payload").expect("write tar entry");
    writer.end_entry().expect("end tar entry");
    writer.finish().expect("finish Base64 tar")
}

#[cfg(feature = "async")]
fn decoded_payload(encoded: &[u8]) -> Vec<u8> {
    let decoded = FilterReader::with_filter(encoded, FilterId::Base64, Limits::safe())
        .expect("explicit Base64 reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read Base64 tar") {
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => return body,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown Base64 archive event"),
        }
    }
}

#[test]
fn explicit_reader_decodes_one_byte_chunks_and_composes_with_archive_reader() {
    let encoded = encoded_tar();
    assert!(
        encoded
            .iter()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') })
    );

    let decoded =
        FilterReader::with_filter(OneByte::new(encoded), FilterId::Base64, Limits::safe())
            .expect("explicit Base64 reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read Base64 tar") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"base64.txt");
            },
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown Base64 archive event"),
        }
    }
    assert_eq!(body, b"payload");
}

#[test]
fn explicit_reader_rejects_malformed_input_and_decoded_bombs() {
    let mut malformed = FilterReader::with_filter(
        OneByte::new(b"TQ=A".to_vec()),
        FilterId::Base64,
        Limits::safe(),
    )
    .expect("explicit Base64 reader");
    assert_eq!(
        malformed
            .read_to_end(&mut Vec::new())
            .expect_err("bad padding")
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut limited = FilterReader::with_filter(
        OneByte::new(b"Zm9v".to_vec()),
        FilterId::Base64,
        Limits::safe().with_decoded_total(Some(2)),
    )
    .expect("limited Base64 reader");
    assert_eq!(
        limited
            .read_to_end(&mut Vec::new())
            .expect_err("decoded limit")
            .kind(),
        io::ErrorKind::OutOfMemory
    );
}

#[test]
fn builtin_provider_encodes_base64_and_enforces_plaintext_limit() {
    let (_, codecs) = ProviderSet::builtins().into_chains();
    let encoded = codecs
        .encode_codec_frame(FilterId::Base64, b"foobar", Limits::safe())
        .expect("provider Base64 encoder");
    assert_eq!(encoded, b"Zm9vYmFy");

    let error = codecs
        .encode_codec_frame(
            FilterId::Base64,
            b"foobar",
            Limits::safe().with_decoded_total(Some(5)),
        )
        .expect_err("plaintext limit");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[cfg(feature = "async")]
#[test]
fn futures_writer_streams_one_canonical_base64_member() {
    futures_lite::future::block_on(async {
        let mut writer = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            libarchive_oxide::FormatId::Tar,
            Some(FilterId::Base64),
            Limits::safe(),
        )
        .expect("async Base64 writer");
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"base64.txt".to_vec()),
        )
        .size(Some(7))
        .build();
        writer.start_entry(&metadata).await.expect("start entry");
        writer.write_data(b"pay").await.expect("first body chunk");
        writer.write_data(b"load").await.expect("second body chunk");
        writer.end_entry().await.expect("end entry");
        let encoded = writer.finish().await.expect("finish writer").into_inner();

        assert_eq!(decoded_payload(&encoded), b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_writer_streams_one_canonical_base64_member() {
    let mut writer = TokioArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Base64),
        Limits::safe(),
    )
    .expect("Tokio Base64 writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"base64.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).await.expect("start entry");
    writer.write_data(b"payload").await.expect("body");
    writer.end_entry().await.expect("end entry");
    let encoded = writer.finish().await.expect("finish writer");

    assert_eq!(decoded_payload(&encoded), b"payload");
}
