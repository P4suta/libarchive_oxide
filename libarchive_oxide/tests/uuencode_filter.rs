// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! POSIX uuencode outer-filter adapter contracts.

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
use libarchive_oxide_core::{AccessMode, CAPABILITY_LEDGER, CapabilitySubject, DirectionSet};

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
        Some(FilterId::Uuencode),
        Limits::safe(),
    )
    .expect("uuencode tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"uuencode.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start tar entry");
    writer.write_data(b"payload").expect("write tar entry");
    writer.end_entry().expect("end tar entry");
    writer.finish().expect("finish uuencode tar")
}

#[cfg(any(feature = "async", feature = "tokio"))]
fn decoded_payload(encoded: &[u8]) -> Vec<u8> {
    let decoded = FilterReader::with_filter(encoded, FilterId::Uuencode, Limits::safe())
        .expect("explicit uuencode reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read uuencode tar") {
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => return body,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown uuencode archive event"),
        }
    }
}

#[test]
fn auto_reader_decodes_one_byte_chunks_and_composes_with_archive_reader() {
    let encoded = encoded_tar();
    assert!(encoded.starts_with(b"begin 644 -\n"));
    assert!(encoded.ends_with(b"`\nend\n"));

    let decoded = FilterReader::new(OneByte::new(encoded)).expect("auto uuencode reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read uuencode tar") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"uuencode.txt");
            },
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown uuencode archive event"),
        }
    }
    assert_eq!(body, b"payload");
}

#[test]
fn explicit_reader_rejects_malformed_input_and_decoded_bombs() {
    let mut malformed = FilterReader::with_filter(
        OneByte::new(b"begin 644 x\n!01``\n`\nend\n".to_vec()),
        FilterId::Uuencode,
        Limits::safe(),
    )
    .expect("explicit uuencode reader");
    assert_eq!(
        malformed
            .read_to_end(&mut Vec::new())
            .expect_err("bad unused bits")
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut limited = FilterReader::with_filter(
        OneByte::new(b"begin 644 x\n#0V%T\n`\nend\n".to_vec()),
        FilterId::Uuencode,
        Limits::safe().with_decoded_total(Some(2)),
    )
    .expect("limited uuencode reader");
    assert_eq!(
        limited
            .read_to_end(&mut Vec::new())
            .expect_err("decoded limit")
            .kind(),
        io::ErrorKind::OutOfMemory
    );
}

#[test]
fn builtin_provider_encodes_canonical_uuencode_and_enforces_plaintext_limit() {
    let (_, codecs) = ProviderSet::builtins().into_chains();
    let encoded = codecs
        .encode_codec_frame(FilterId::Uuencode, b"Cat", Limits::safe())
        .expect("provider uuencode encoder");
    assert_eq!(encoded, b"begin 644 -\n#0V%T\n`\nend\n");

    let error = codecs
        .encode_codec_frame(
            FilterId::Uuencode,
            b"Cat",
            Limits::safe().with_decoded_total(Some(2)),
        )
        .expect_err("plaintext limit");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
fn capability_ledger_advertises_shared_read_write_support() {
    let record = CAPABILITY_LEDGER
        .iter()
        .find(|record| record.subject() == CapabilitySubject::Filter(FilterId::Uuencode))
        .expect("uuencode capability record");
    assert_eq!(record.access().read(), Some(AccessMode::Filter));
    assert_eq!(record.access().write(), Some(AccessMode::Filter));
    assert_eq!(record.portable(), DirectionSet::READ_WRITE);
    assert_eq!(record.native(), DirectionSet::READ_WRITE);
}

#[test]
fn writer_workspace_limit_fails_before_emitting_a_header() {
    let error = ArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Uuencode),
        Limits::safe().with_codec_memory(Some(0)),
    )
    .expect_err("workspace limit");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[cfg(feature = "async")]
#[test]
fn futures_writer_streams_one_canonical_uuencode_member() {
    futures_lite::future::block_on(async {
        let mut writer = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            libarchive_oxide::FormatId::Tar,
            Some(FilterId::Uuencode),
            Limits::safe(),
        )
        .expect("async uuencode writer");
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"uuencode.txt".to_vec()),
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
async fn tokio_writer_streams_one_canonical_uuencode_member() {
    let mut writer = TokioArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Uuencode),
        Limits::safe(),
    )
    .expect("Tokio uuencode writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"uuencode.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).await.expect("start entry");
    writer.write_data(b"payload").await.expect("body");
    writer.end_entry().await.expect("end entry");
    let encoded = writer.finish().await.expect("finish writer");

    assert_eq!(decoded_payload(&encoded), b"payload");
}
