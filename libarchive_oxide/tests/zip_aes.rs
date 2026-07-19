// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `WinZip` AES-256 (AE-2) tests. Requires the `aes` feature.
//!
//! Coverage:
//!
//! * arca -> arca round-trip (encrypt then decrypt).
//! * wrong password errors without panicking.
//! * differential BOTH directions against the `zip` crate's independent `aes-crypto`:
//!   arca-encrypted archive decrypted by the `zip` crate, and a `zip`-crate-encrypted fixture
//!   decrypted by arca.
//!
//! The cross-implementation decrypt is the strongest correctness signal for the crypto layer.
#![cfg(feature = "aes")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{Cursor, Read, Write};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveWriter, Extractor, ReaderEvent, SecretBytes, SeekArchiveReader, StreamError, ZipMethod,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};
use zip::write::SimpleFileOptions;
use zip::{AesMode, ZipArchive};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Builds a single-file arca archive encrypted with AES-256 AE-2.
fn arca_aes(name: &[u8], data: &[u8], method: ZipMethod) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_password(
        Vec::new(),
        method,
        SecretBytes::from(PASSWORD),
        Limits::default(),
    );
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
        .size(None)
        .mode(Some(0o644))
        .build();
    writer.start_entry(&metadata).unwrap();
    for chunk in data.chunks(31) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn read_first_with_password(bytes: &[u8], password: &[u8]) -> Result<Vec<u8>, StreamError> {
    let mut reader =
        SeekArchiveReader::with_password(Cursor::new(bytes), SecretBytes::from(password))?;
    let mut output = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => output.extend_from_slice(bytes),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) => {},
            ReaderEvent::EndEntry => return Ok(output),
            _ => panic!("AES entry ended without EndEntry"),
        }
    }
}

#[test]
fn arca_roundtrip_deflate_and_store() {
    let payload = b"secret payload ".repeat(64);
    for method in [ZipMethod::Deflate, ZipMethod::Store] {
        let z = arca_aes(b"secret.txt", &payload, method);
        // The stored method must be 99 (AES) in the local header.
        assert_eq!(u16::from_le_bytes([z[8], z[9]]), 99);
        let got = read_first_with_password(&z, PASSWORD).unwrap();
        assert_eq!(got, payload);
    }
}

#[test]
fn wrong_password_errors_without_panic() {
    let z = arca_aes(b"secret.txt", b"top secret", ZipMethod::Store);
    let err = read_first_with_password(&z, b"wrong password");
    assert!(err.is_err(), "wrong password must error");
}

#[test]
fn missing_password_errors_without_panic() {
    let z = arca_aes(b"secret.txt", b"top secret", ZipMethod::Store);
    let mut reader = SeekArchiveReader::new(Cursor::new(z)).unwrap();
    let mut rejected = false;
    for _ in 0..4 {
        if reader.next_event().is_err() {
            rejected = true;
            break;
        }
    }
    assert!(rejected, "method 99 without password must error");
}

#[test]
fn zip_crate_decrypts_arca_output() {
    let payload = b"cross-impl payload ".repeat(50);
    let z = arca_aes(b"x.txt", &payload, ZipMethod::Deflate);

    let mut archive = ZipArchive::new(Cursor::new(z)).expect("zip crate opens arca AES archive");
    let mut f = archive
        .by_index_decrypt(0, PASSWORD)
        .expect("zip crate decrypts arca AE-2 entry");
    let mut got = Vec::new();
    f.read_to_end(&mut got).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn arca_decrypts_zip_crate_fixture() {
    // Build an AES-256 archive with the `zip` crate, decrypt it with arca.
    let payload = b"fixture from the zip crate ".repeat(40);
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::write::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, std::str::from_utf8(PASSWORD).unwrap());
        zw.start_file("fixture.txt", opts).unwrap();
        zw.write_all(&payload).unwrap();
        zw.finish().unwrap();
    }
    let bytes = buf.into_inner();

    let got = read_first_with_password(&bytes, PASSWORD).unwrap();
    assert_eq!(got, payload);

    // Wrong password against the external fixture must error, not panic.
    assert!(read_first_with_password(&bytes, b"nope").is_err());
}

#[test]
fn seek_reader_streams_and_authenticates_aes_before_end_entry() {
    let payload = b"authenticated streaming payload ".repeat(8_192);
    let archive = arca_aes(b"large-secret.txt", &payload, ZipMethod::Deflate);
    let mut reader =
        SeekArchiveReader::with_password(Cursor::new(archive), SecretBytes::from(PASSWORD))
            .unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected AES event: {event:?}"),
        }
    }
    assert_eq!(decoded, payload);
}

#[test]
fn aes_authentication_failure_never_commits_the_destination() {
    let mut archive = arca_aes(
        b"secret.txt",
        &b"authenticated payload ".repeat(128),
        ZipMethod::Store,
    );
    let name_length = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra_length = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let encrypted_start = 30 + name_length + extra_length + 18;
    archive[encrypted_start] ^= 0x80;

    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let mut extractor = Extractor::new(root);
    let mut reader =
        SeekArchiveReader::with_password(Cursor::new(archive), SecretBytes::from(PASSWORD))
            .unwrap();
    let result = extractor.extract_seek_matching(&mut reader, |_| true);
    assert!(result.is_err());
    assert!(!destination.path().join("secret.txt").exists());
    assert!(
        fs::read_dir(destination.path()).unwrap().all(|item| !item
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp"))
    );
}

#[test]
fn streaming_aes_writer_handles_unknown_size_without_entry_buffering() {
    let payload = b"streaming encrypted payload ".repeat(16_384);
    let mut writer = ArchiveWriter::with_zip_password(
        Vec::new(),
        ZipMethod::Deflate,
        SecretBytes::from(PASSWORD),
        Limits::default(),
    );
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("streaming.txt"))
        .size(None)
        .build();
    writer.start_entry(&metadata).unwrap();
    for chunk in payload.chunks(997) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let mut independent = ZipArchive::new(Cursor::new(archive.clone())).unwrap();
    let mut file = independent.by_index_decrypt(0, PASSWORD).unwrap();
    let mut decoded = Vec::new();
    file.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, payload);

    let mut reader =
        SeekArchiveReader::with_password(Cursor::new(archive), SecretBytes::from(PASSWORD))
            .unwrap();
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}
