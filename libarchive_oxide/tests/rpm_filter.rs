// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RPM outer-wrapper adapter and nested payload-filter contracts.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::{self, Read};

use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, FilterId, FilterReader,
    FormatId, Limits, ReaderEvent, filter_for_name,
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

fn header(store: &[u8], signature: bool) -> Vec<u8> {
    let mut bytes = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(
        &u32::try_from(store.len())
            .expect("store length")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(store);
    if signature {
        bytes.resize((bytes.len() + 7) & !7, 0);
    }
    bytes
}

fn wrap_rpm(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 96];
    bytes[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    bytes.extend_from_slice(&header(b"sig", true));
    bytes.extend_from_slice(&header(b"main", false));
    bytes.extend_from_slice(payload);
    bytes
}

fn gzip_cpio() -> Vec<u8> {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Cpio,
        Some(FilterId::Gzip),
        Limits::safe(),
    )
    .expect("gzip cpio writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"rpm.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start cpio entry");
    writer.write_data(b"payload").expect("write cpio entry");
    writer.end_entry().expect("end cpio entry");
    writer.finish().expect("finish gzip cpio")
}

fn rpm_archive() -> Vec<u8> {
    wrap_rpm(&gzip_cpio())
}

fn collect_sync<R: Read>(reader: &mut ArchiveReader<R>) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read RPM cpio") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"rpm.txt");
            },
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => return body,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown RPM archive event"),
        }
    }
}

#[test]
fn explicit_and_auto_readers_unwrap_rpm_payload() {
    let encoded = rpm_archive();
    let mut explicit = FilterReader::with_filter(encoded.as_slice(), FilterId::Rpm, Limits::safe())
        .expect("explicit RPM reader");
    let mut compressed_payload = Vec::new();
    explicit
        .read_to_end(&mut compressed_payload)
        .expect("unwrap RPM payload");
    assert_eq!(compressed_payload, gzip_cpio());

    let mut reader = ArchiveReader::new(OneByte::new(encoded));
    assert_eq!(collect_sync(&mut reader), b"payload");
    assert_eq!(filter_for_name("demo.rpm"), Some(FilterId::Rpm));
}

#[test]
fn public_reader_rejects_header_bombs_and_truncation() {
    let encoded = rpm_archive();
    let mut truncated = FilterReader::with_filter(&encoded[..100], FilterId::Rpm, Limits::safe())
        .expect("construct truncated RPM reader");
    assert_eq!(
        truncated
            .read_to_end(&mut Vec::new())
            .expect_err("truncated RPM")
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut limited = FilterReader::with_filter(
        encoded.as_slice(),
        FilterId::Rpm,
        Limits::safe().with_metadata_bytes(Some(2)),
    )
    .expect("construct limited RPM reader");
    assert_eq!(
        limited
            .read_to_end(&mut Vec::new())
            .expect_err("RPM header bomb")
            .kind(),
        io::ErrorKind::OutOfMemory
    );
}

#[test]
fn capability_ledger_advertises_read_only_filter_support() {
    let record = CAPABILITY_LEDGER
        .iter()
        .find(|record| record.subject() == CapabilitySubject::Filter(FilterId::Rpm))
        .expect("RPM capability record");
    assert_eq!(record.access().read(), Some(AccessMode::Filter));
    assert_eq!(record.access().write(), None);
    assert_eq!(record.portable(), DirectionSet::READ);
    assert_eq!(record.native(), DirectionSet::READ);
}

#[test]
fn fedora_rpmbuild_fixture_unwraps_to_its_real_cpio_payload() {
    let armored = include_bytes!(
        "../../libarchive_oxide-package/tests/fixtures/rpm/rpm-4.14.2.1-minimal.rpm.gz.b64"
    );
    let mut base64 =
        FilterReader::with_filter(armored.as_slice(), FilterId::Base64, Limits::safe())
            .expect("fixture Base64 reader");
    let mut compressed_rpm = Vec::new();
    base64
        .read_to_end(&mut compressed_rpm)
        .expect("decode fixture Base64");
    let mut gzip = FilterReader::new(compressed_rpm.as_slice()).expect("fixture gzip reader");
    let mut rpm = Vec::new();
    gzip.read_to_end(&mut rpm).expect("decompress fixture RPM");

    let mut reader = ArchiveReader::new(rpm.as_slice());
    let mut path = Vec::new();
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read rpmbuild fixture") {
            ReaderEvent::Entry(metadata) => path = metadata.path().as_bytes().to_vec(),
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown rpmbuild fixture event"),
        }
    }
    assert_eq!(path, b"./usr/share/libarchive-oxide/fixture.txt");
    assert_eq!(body, b"libarchive-oxide RPM interoperability fixture\n");
}

#[cfg(feature = "async")]
#[test]
fn futures_reader_auto_detects_rpm_and_payload_compression() {
    futures_lite::future::block_on(async {
        let input = futures_lite::io::Cursor::new(rpm_archive());
        let mut reader = libarchive_oxide::AsyncArchiveReader::new(input);
        let mut body = Vec::new();
        loop {
            match reader.next_event().await.expect("async RPM event") {
                ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(body, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_reader_auto_detects_rpm_and_payload_compression() {
    let encoded = rpm_archive();
    let mut reader = libarchive_oxide::TokioArchiveReader::new(encoded.as_slice());
    let mut body = Vec::new();
    loop {
        match reader.next_event().await.expect("Tokio RPM event") {
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(body, b"payload");
}
