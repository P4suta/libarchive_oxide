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
    ArchiveEngine, ArchiveWriter, Error, Policy, ReaderEvent, SecretBytes, SeekArchiveReader,
    ZipMethod,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, ErrorKind, Limits};
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

fn read_first_with_password(bytes: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
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

#[cfg(not(feature = "gzip"))]
fn set_aes_real_method(extra: &mut [u8], method: u16) {
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[cursor], extra[cursor + 1]]);
        let length = usize::from(u16::from_le_bytes([extra[cursor + 2], extra[cursor + 3]]));
        let end = cursor + 4 + length;
        assert!(end <= extra.len(), "truncated AES test extra field");
        if id == 0x9901 {
            assert_eq!(length, 7);
            extra[cursor + 9..cursor + 11].copy_from_slice(&method.to_le_bytes());
            return;
        }
        cursor = end;
    }
    panic!("AES test archive is missing its 0x9901 extra field");
}

#[cfg(feature = "gzip")]
fn stored_deflate64(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let chunks = data.chunks(u16::MAX as usize);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        output.push(u8::from(index + 1 == count));
        let length = u16::try_from(chunk.len()).unwrap();
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&(!length).to_le_bytes());
        output.extend_from_slice(chunk);
    }
    output
}

#[cfg(feature = "gzip")]
fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "gzip")]
fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "gzip")]
fn aes_deflate64_fixture(content: &[u8], compressed: &[u8]) -> Vec<u8> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use hmac::Mac;
    use hmac::digest::KeyInit;
    use zeroize::Zeroize;

    let salt = core::array::from_fn::<_, 16, _>(|index| u8::try_from(index).unwrap());
    let mut key_material = [0_u8; 66];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(PASSWORD, &salt, 1_000, &mut key_material);
    let verifier = [key_material[64], key_material[65]];
    let mut counter = [0_u8; 16];
    counter[0] = 1;
    let mut ciphertext = compressed.to_vec();
    let mut cipher =
        ctr::Ctr128LE::<aes::Aes256>::new_from_slices(&key_material[..32], &counter).unwrap();
    cipher.apply_keystream(&mut ciphertext);
    let mut mac =
        <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&key_material[32..64]).unwrap();
    mac.update(&ciphertext);
    let digest = mac.finalize().into_bytes();
    let authentication = &digest[..10];
    key_material.zeroize();

    let name = b"secret.bin";
    let mut extra = Vec::new();
    push_u16(&mut extra, 0x9901);
    push_u16(&mut extra, 7);
    push_u16(&mut extra, 2);
    extra.extend_from_slice(b"AE");
    extra.push(3);
    push_u16(&mut extra, 9);
    let compressed_size = u32::try_from(18 + ciphertext.len() + 10).unwrap();
    let uncompressed_size = u32::try_from(content.len()).unwrap();

    let mut output = Vec::new();
    output.extend_from_slice(b"PK\x03\x04");
    push_u16(&mut output, 51);
    push_u16(&mut output, 1);
    push_u16(&mut output, 99);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0x21);
    push_u32(&mut output, 0);
    push_u32(&mut output, compressed_size);
    push_u32(&mut output, uncompressed_size);
    push_u16(&mut output, u16::try_from(name.len()).unwrap());
    push_u16(&mut output, u16::try_from(extra.len()).unwrap());
    output.extend_from_slice(name);
    output.extend_from_slice(&extra);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&verifier);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(authentication);

    let central_offset = u32::try_from(output.len()).unwrap();
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    push_u16(&mut central, 0x031e);
    push_u16(&mut central, 51);
    push_u16(&mut central, 1);
    push_u16(&mut central, 99);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0x21);
    push_u32(&mut central, 0);
    push_u32(&mut central, compressed_size);
    push_u32(&mut central, uncompressed_size);
    push_u16(&mut central, u16::try_from(name.len()).unwrap());
    push_u16(&mut central, u16::try_from(extra.len()).unwrap());
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u32(&mut central, 0o100_644 << 16);
    push_u32(&mut central, 0);
    central.extend_from_slice(name);
    central.extend_from_slice(&extra);
    let central_size = u32::try_from(central.len()).unwrap();
    output.extend_from_slice(&central);
    output.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, 1);
    push_u16(&mut output, 1);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    output
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
#[cfg(not(feature = "gzip"))]
fn aes_wrapped_deflate64_is_unsupported_without_gzip_feature() {
    let mut archive = arca_aes(b"secret.txt", b"top secret", ZipMethod::Store);
    let local_name_length = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let local_extra_length = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let local_extra_start = 30 + local_name_length;
    set_aes_real_method(
        &mut archive[local_extra_start..local_extra_start + local_extra_length],
        9,
    );

    let central = archive
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    let central_name_length = usize::from(u16::from_le_bytes([
        archive[central + 28],
        archive[central + 29],
    ]));
    let central_extra_length = usize::from(u16::from_le_bytes([
        archive[central + 30],
        archive[central + 31],
    ]));
    let central_extra_start = central + 46 + central_name_length;
    set_aes_real_method(
        &mut archive[central_extra_start..central_extra_start + central_extra_length],
        9,
    );

    let error = read_first_with_password(&archive, PASSWORD).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let error = read_first_with_password(&archive, b"wrong password").unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let error = reader.next_event().unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );
}

#[cfg(feature = "gzip")]
#[test]
fn aes_wrapped_deflate64_roundtrips_and_authenticates() {
    let payload = b"authenticated Deflate64 payload\n".repeat(5000);
    let archive = aes_deflate64_fixture(&payload, &stored_deflate64(&payload));
    assert_eq!(
        read_first_with_password(&archive, PASSWORD).unwrap(),
        payload
    );
    let wrong_password = read_first_with_password(&archive, b"wrong password").unwrap_err();
    assert_eq!(
        wrong_password.archive_error().unwrap().kind(),
        ErrorKind::Integrity
    );

    let mut tampered = archive;
    let central = tampered
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    tampered[central - 1] ^= 0x80;
    let error = read_first_with_password(&tampered, PASSWORD).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[cfg(feature = "gzip")]
#[test]
fn aes_wrapped_deflate64_rejects_truncation_and_decoded_bombs() {
    let payload = vec![0x5a; 128 * 1024];
    let compressed = stored_deflate64(&payload);
    let truncated = aes_deflate64_fixture(&payload, &compressed[..compressed.len() - 1]);
    let error = read_first_with_password(&truncated, PASSWORD).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let archive = aes_deflate64_fixture(&payload, &compressed);
    let limits = Limits::default().with_decoded_total(Some(4096));
    let mut reader = SeekArchiveReader::with_limits_and_password(
        Cursor::new(archive),
        limits,
        SecretBytes::from(PASSWORD),
    )
    .unwrap();
    let error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("AES Deflate64 bomb unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
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
    let result = ArchiveEngine::new()
        .prepare_with_password(Cursor::new(archive), SecretBytes::from(PASSWORD))
        .and_then(|mut session| {
            let plan = session.plan(Policy::safe())?;
            session.apply(plan, root).map(drop)
        });
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
