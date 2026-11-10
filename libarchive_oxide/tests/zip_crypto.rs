// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Traditional PKWARE `ZipCrypto` streaming and interoperability tests.

#![cfg(feature = "aes")]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read, Write};

use libarchive_oxide::{
    ArchiveEngine, ArchivePath, CreateOptions, EntryKind, EntryMetadata, ErrorKind, FormatId,
    FormatWriteOptions, ReaderEvent, SecretBytes, SeekArchiveReader, ZipCompression, ZipEncryption,
    ZipWriteOptions,
};
use zip::ZipArchive;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;

const PASSWORD: &[u8] = b"legacy compatibility secret";

fn create_zipcrypto(compression: ZipCompression, payload: &[u8]) -> Vec<u8> {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new()
                .with_compression(compression)
                .with_encryption(ZipEncryption::ZipCrypto),
        )));
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("legacy.bin"))
        .size(Some(payload.len() as u64))
        .build();
    let mut writer = ArchiveEngine::new()
        .create_with_password(Vec::new(), options, SecretBytes::from(PASSWORD))
        .expect("ZipCrypto writer");
    writer.start_entry(&metadata).expect("start entry");
    for chunk in payload.chunks(29) {
        writer.write_data(chunk).expect("write entry");
    }
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish ZipCrypto archive")
}

fn read_payload(archive: Vec<u8>, password: &[u8]) -> Result<Vec<u8>, libarchive_oxide::Error> {
    let mut reader =
        SeekArchiveReader::with_password(Cursor::new(archive), SecretBytes::from(password))?;
    let mut payload = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok(payload),
            _ => {},
        }
    }
}

fn zipcrypto_update(keys: &mut [u32; 3], plaintext: u8) {
    fn crc32_byte(mut crc: u32, byte: u8) -> u32 {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
        crc
    }

    keys[0] = crc32_byte(keys[0], plaintext);
    keys[1] = keys[1]
        .wrapping_add(keys[0] & 0xff)
        .wrapping_mul(0x0808_8405)
        .wrapping_add(1);
    keys[2] = crc32_byte(keys[2], (keys[1] >> 24) as u8);
}

fn zipcrypto_stream_byte(keys: [u32; 3]) -> u8 {
    let key = keys[2].to_le_bytes();
    let value = u16::from_le_bytes([key[0], key[1]]) | 2;
    (value.wrapping_mul(value ^ 1) >> 8) as u8
}

fn force_zipcrypto_verifier_collision(
    archive: &mut [u8],
    wrong_password: &[u8],
    decrypted_payload_prefix: &[u8],
) {
    let name_length = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra_length = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let header = 30 + name_length + extra_length;
    let verifier = archive[11];
    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    for &byte in wrong_password {
        zipcrypto_update(&mut keys, byte);
    }
    for index in 0..11 {
        let stream = zipcrypto_stream_byte(keys);
        let plaintext = archive[header + index] ^ stream;
        zipcrypto_update(&mut keys, plaintext);
    }
    let stream = zipcrypto_stream_byte(keys);
    archive[header + 11] = verifier ^ stream;
    zipcrypto_update(&mut keys, verifier);
    for (index, &plaintext) in decrypted_payload_prefix.iter().enumerate() {
        let stream = zipcrypto_stream_byte(keys);
        archive[header + 12 + index] = plaintext ^ stream;
        zipcrypto_update(&mut keys, plaintext);
    }
}

#[test]
fn zipcrypto_store_and_deflate_roundtrip_with_typed_password_failure() {
    let payload = b"traditional encrypted streaming payload\n".repeat(257);
    for compression in [ZipCompression::Store, ZipCompression::Deflate] {
        let archive = create_zipcrypto(compression, &payload);
        assert_eq!(u16::from_le_bytes([archive[6], archive[7]]) & 1, 1);
        assert_eq!(
            read_payload(archive.clone(), PASSWORD).expect("decrypt"),
            payload
        );
        let error = read_payload(archive, b"wrong password").expect_err("reject password");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Integrity
        );
    }
}

#[test]
fn zipcrypto_verifier_collision_still_reports_wrong_password_as_integrity() {
    let wrong_password = b"wrong password with forced verifier collision";
    let payload = b"the one-byte verifier is not authentication\n".repeat(257);
    for (compression, decrypted_prefix) in [
        (ZipCompression::Deflate, &[][..]),
        (ZipCompression::Bzip2, &[]),
        (ZipCompression::Zstd, &[]),
        (ZipCompression::Xz, &[]),
        (ZipCompression::Lzma, &[9, 20, 5, 0, 93, 0, 0, 1, 0][..]),
        (ZipCompression::Ppmd8, &[5, 0, 0, 0, 0, 0]),
    ] {
        let mut archive = create_zipcrypto(compression, &payload);
        force_zipcrypto_verifier_collision(&mut archive, wrong_password, decrypted_prefix);

        let error = read_payload(archive, wrong_password).expect_err("reject verifier collision");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Integrity,
            "{compression:?}"
        );
    }
}

#[test]
fn zip_crate_decrypts_arca_zipcrypto_output() {
    let payload = b"arca output for an independent ZipCrypto consumer".repeat(97);
    for compression in [ZipCompression::Store, ZipCompression::Deflate] {
        let archive = create_zipcrypto(compression, &payload);
        let mut reader = ZipArchive::new(Cursor::new(archive)).expect("open arca ZIP");
        let mut file = reader
            .by_index_decrypt(0, PASSWORD)
            .expect("zip crate decrypts arca ZipCrypto");
        let mut decoded = Vec::new();
        file.read_to_end(&mut decoded).expect("read decrypted file");
        assert_eq!(decoded, payload);
    }
}

#[test]
fn arca_decrypts_zip_crate_zipcrypto_output() {
    let payload = b"independent traditional encryption fixture\n".repeat(113);
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = zip::write::ZipWriter::new(&mut output);
            let options = SimpleFileOptions::default()
                .compression_method(method)
                .with_deprecated_encryption(PASSWORD)
                .expect("non-empty legacy password");
            writer
                .start_file("fixture.bin", options)
                .expect("start file");
            writer.write_all(&payload).expect("write file");
            writer.finish().expect("finish fixture");
        }
        let archive = output.into_inner();
        assert_eq!(
            read_payload(archive.clone(), PASSWORD).expect("decrypt"),
            payload
        );
        let error = read_payload(archive, b"incorrect").expect_err("reject password");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Integrity
        );
    }
}

#[test]
fn zipcrypto_tamper_and_decoded_bomb_are_rejected() {
    let payload = vec![0x5a; 128 * 1024];
    let mut archive = create_zipcrypto(ZipCompression::Store, &payload);
    let name_length = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra_length = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let ciphertext = 30 + name_length + extra_length + 12;
    archive[ciphertext] ^= 0x80;
    let error = read_payload(archive, PASSWORD).expect_err("reject tamper");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Integrity
    );

    let archive = create_zipcrypto(ZipCompression::Deflate, &payload);
    let limits = libarchive_oxide::Limits::default().with_decoded_total(Some(4096));
    let mut reader = SeekArchiveReader::with_limits_and_password(
        Cursor::new(archive),
        limits,
        SecretBytes::from(PASSWORD),
    )
    .expect("open bounded ZipCrypto archive");
    let error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("decoded bomb unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Limit
    );
}
