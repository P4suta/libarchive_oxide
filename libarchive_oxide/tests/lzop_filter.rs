// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! lzop outer-filter adapter contracts.

#![cfg(feature = "lzop")]
#![allow(clippy::expect_used, clippy::panic)]

#[cfg(not(target_os = "wasi"))]
use std::io::Write as _;
use std::io::{self, Read};
#[cfg(not(target_os = "wasi"))]
use std::process::{Command, Stdio};

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

const MAGIC: &[u8; 9] = b"\x89LZO\0\r\n\x1a\n";

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
        Some(FilterId::Lzop),
        Limits::safe(),
    )
    .expect("lzop tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"lzop.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start tar entry");
    writer.write_data(b"payload").expect("write tar entry");
    writer.end_entry().expect("end tar entry");
    writer.finish().expect("finish lzop tar")
}

fn decoded_payload(encoded: &[u8]) -> Vec<u8> {
    let decoded = FilterReader::with_filter(encoded, FilterId::Lzop, Limits::safe())
        .expect("explicit lzop reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read lzop tar") {
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => return body,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown lzop archive event"),
        }
    }
}

#[test]
fn auto_reader_decodes_one_byte_chunks_and_composes_with_archive_reader() {
    let encoded = encoded_tar();
    assert!(encoded.starts_with(MAGIC));
    assert_eq!(decoded_payload(&encoded), b"payload");

    let decoded = FilterReader::new(OneByte::new(encoded)).expect("auto lzop reader");
    let mut reader = ArchiveReader::new(decoded);
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read lzop tar") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"lzop.txt");
            },
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown lzop archive event"),
        }
    }
    assert_eq!(body, b"payload");
}

#[test]
fn explicit_reader_rejects_checksum_mismatch_and_decoded_bombs() {
    let encoded = encoded_tar();
    let mut malformed = encoded.clone();
    malformed[46] ^= 1;
    let mut reader =
        FilterReader::with_filter(malformed.as_slice(), FilterId::Lzop, Limits::safe())
            .expect("explicit lzop reader");
    assert_eq!(
        reader
            .read_to_end(&mut Vec::new())
            .expect_err("bad checksum")
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut limited = FilterReader::with_filter(
        encoded.as_slice(),
        FilterId::Lzop,
        Limits::safe().with_decoded_total(Some(1)),
    )
    .expect("limited lzop reader");
    assert_eq!(
        limited
            .read_to_end(&mut Vec::new())
            .expect_err("decoded limit")
            .kind(),
        io::ErrorKind::OutOfMemory
    );
}

#[test]
fn builtin_provider_encodes_lzop_and_enforces_plaintext_limit() {
    let (_, codecs) = ProviderSet::builtins().into_chains();
    let encoded = codecs
        .encode_codec_frame(FilterId::Lzop, b"Cat", Limits::safe())
        .expect("provider lzop encoder");
    assert!(encoded.starts_with(MAGIC));
    let mut decoded =
        FilterReader::with_filter(encoded.as_slice(), FilterId::Lzop, Limits::safe()).unwrap();
    let mut plain = Vec::new();
    decoded.read_to_end(&mut plain).unwrap();
    assert_eq!(plain, b"Cat");

    let error = codecs
        .encode_codec_frame(
            FilterId::Lzop,
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
        .find(|record| record.subject() == CapabilitySubject::Filter(FilterId::Lzop))
        .expect("lzop capability record");
    assert_eq!(record.access().read(), Some(AccessMode::Filter));
    assert_eq!(record.access().write(), Some(AccessMode::Filter));
    assert_eq!(record.portable(), DirectionSet::READ_WRITE);
    assert_eq!(record.native(), DirectionSet::NONE);
}

#[test]
fn writer_workspace_limit_fails_before_emitting_a_header() {
    let error = ArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Lzop),
        Limits::safe().with_codec_memory(Some(0)),
    )
    .expect_err("workspace limit");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[cfg(not(target_os = "wasi"))]
#[test]
fn stored_writer_is_consumed_by_lzop_program_when_available() {
    let Ok(version) = Command::new("lzop").arg("--version").output() else {
        return;
    };
    if !version.status.success() {
        return;
    }

    let mut child = Command::new("lzop")
        .args(["-dc"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lzop");
    child
        .stdin
        .take()
        .expect("lzop stdin")
        .write_all(&encoded_tar())
        .expect("write lzop stream");
    let output = child.wait_with_output().expect("wait for lzop");
    assert!(
        output.status.success(),
        "lzop rejected writer output: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut reader = ArchiveReader::new(output.stdout.as_slice());
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read lzop-produced tar") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

#[cfg(feature = "async")]
#[test]
fn futures_writer_streams_one_lzop_member() {
    futures_lite::future::block_on(async {
        let mut writer = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            libarchive_oxide::FormatId::Tar,
            Some(FilterId::Lzop),
            Limits::safe(),
        )
        .expect("async lzop writer");
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"lzop.txt".to_vec()),
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

#[cfg(feature = "async")]
#[test]
fn futures_reader_auto_detects_lzop() {
    futures_lite::future::block_on(async {
        let input = futures_lite::io::Cursor::new(encoded_tar());
        let mut reader = libarchive_oxide::AsyncArchiveReader::new(input);
        let mut payload = Vec::new();
        loop {
            match reader.next_event().await.expect("async lzop event") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_writer_streams_one_lzop_member() {
    let mut writer = TokioArchiveWriter::with_filter(
        Vec::new(),
        libarchive_oxide::FormatId::Tar,
        Some(FilterId::Lzop),
        Limits::safe(),
    )
    .expect("Tokio lzop writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"lzop.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).await.expect("start entry");
    writer.write_data(b"payload").await.expect("body");
    writer.end_entry().await.expect("end entry");
    let encoded = writer.finish().await.expect("finish writer");
    assert_eq!(decoded_payload(&encoded), b"payload");
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_reader_auto_detects_lzop() {
    let encoded = encoded_tar();
    let mut reader = libarchive_oxide::TokioArchiveReader::new(encoded.as_slice());
    let mut payload = Vec::new();
    loop {
        match reader.next_event().await.expect("Tokio lzop event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}
