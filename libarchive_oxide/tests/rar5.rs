// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RAR5 container and Store-method streaming contracts derived from the public technote.
//! Fixture scope and clean-room provenance are recorded in `fixtures/rar5/PROVENANCE.md`.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::{self, Read};
#[cfg(all(feature = "aes", feature = "rar"))]
use std::sync::Arc;

use libarchive_oxide::{
    ArchiveReader, ChecksumAlgorithm, EntryKind, EntryMetadata, ErrorKind, FormatId, Limits,
    ReaderEvent,
};
#[cfg(all(feature = "aes", feature = "rar"))]
use libarchive_oxide::{OpenOptions, PasswordCandidates, SecretBytes};
use libarchive_oxide_core::{ArchiveDecoder, DecodeEvent, EndOfInput, Rar5Decoder};
#[cfg(feature = "rar")]
use sha2::{Digest, Sha256};

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR5_A200_PACKED: &[u8] = &[
    0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15, 0x00,
];

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

fn vint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

#[cfg(feature = "rar")]
fn decode_hex(encoded: &str) -> Vec<u8> {
    let digits: Vec<_> = encoded
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("fixture contains a non-hex byte"),
        })
        .collect();
    assert_eq!(digits.len() % 2, 0, "fixture has an incomplete byte");
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| pair[0] << 4 | pair[1])
        .collect()
}

fn block(header_type: u64, flags: u64, data_size: Option<u64>, fields: &[u8]) -> Vec<u8> {
    let mut body = vint(header_type);
    body.extend_from_slice(&vint(flags));
    if flags & 0x0002 != 0 {
        body.extend_from_slice(&vint(data_size.expect("data size")));
    }
    body.extend_from_slice(fields);

    let size = vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut encoded = crc32(&checked).to_le_bytes().to_vec();
    encoded.extend_from_slice(&checked);
    encoded
}

fn block_with_extra(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    fields: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let flags = flags | 0x0001;
    let mut body = vint(header_type);
    body.extend_from_slice(&vint(flags));
    body.extend_from_slice(&vint(extra.len() as u64));
    if flags & 0x0002 != 0 {
        body.extend_from_slice(&vint(data_size.expect("data size")));
    }
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);

    let size = vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut encoded = crc32(&checked).to_le_bytes().to_vec();
    encoded.extend_from_slice(&checked);
    encoded
}

fn extra_record(record_type: u64, data: &[u8]) -> Vec<u8> {
    let mut record = vint(record_type);
    record.extend_from_slice(data);
    let mut encoded = vint(record.len() as u64);
    encoded.extend_from_slice(&record);
    encoded
}

fn file_encryption_record(version: u64, flags: u64, kdf_count: u8) -> Vec<u8> {
    let mut data = vint(version);
    data.extend_from_slice(&vint(flags));
    data.push(kdf_count);
    data.extend(0_u8..16);
    data.extend(16_u8..32);
    if flags & 0x0001 != 0 {
        data.extend(32_u8..44);
    }
    extra_record(1, &data)
}

fn header_encryption_fields(version: u64, flags: u64, kdf_count: u8) -> Vec<u8> {
    let mut fields = vint(version);
    fields.extend_from_slice(&vint(flags));
    fields.push(kdf_count);
    fields.extend(0_u8..16);
    if flags & 0x0001 != 0 {
        fields.extend(16_u8..28);
    }
    fields
}

fn encrypted_headers_archive(fields: &[u8]) -> Vec<u8> {
    encrypted_headers_archive_with_common_flags(fields, 0)
}

fn encrypted_headers_archive_with_common_flags(fields: &[u8], common_flags: u64) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&block(4, common_flags, None, fields));
    archive.extend_from_slice(&[0xa5; 16]); // IV for the first encrypted archive header.
    archive
}

fn rar5_error_kind(bytes: Vec<u8>) -> ErrorKind {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Rar5, Limits::safe())
            .expect("explicit RAR5 reader");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("malformed RAR5 unexpectedly completed"),
            Ok(_) => {},
            Err(error) => return error.archive_error().expect("archive error").kind(),
        }
    }
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar5_data_encryption_tries_ordered_password_candidates() {
    let archive = include_bytes!("fixtures/rar5/rarfile-rar5-data-password.rar").to_vec();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Rar5))
        .with_limits(Limits::safe())
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::from(&b"wrong first"[..]),
            SecretBytes::from(&b"password"[..]),
        ])));
    let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
        .expect("open encrypted RAR5 with password candidates");
    let expected: Vec<u8> = (0..512)
        .flat_map(|value| format!("{value:03}\n").into_bytes())
        .collect();
    let mut paths = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    loop {
        match reader.next_event().expect("decrypt encrypted RAR5") {
            ReaderEvent::Entry(entry) => {
                assert!(entry.is_encrypted());
                assert_eq!(entry.size(), Some(2048));
                paths.push(entry.path().as_bytes().to_vec());
                payloads.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => payloads
                .last_mut()
                .expect("data follows entry metadata")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(paths, [b"stest1.txt".to_vec(), b"stest2.txt".to_vec()]);
    assert_eq!(payloads, [expected.clone(), expected]);
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar5_encrypted_store_member_authenticates_before_output() {
    let fixture = include_bytes!("fixtures/rar5/rarfile-rar5-data-password.rar");
    // Keep the signature/main header and the complete second file through ENDARC.
    // Header CRCs and encrypted file bytes remain byte-for-byte upstream data.
    let archive = [&fixture[..24], &fixture[237..]].concat();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Rar5))
        .with_limits(Limits::safe())
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::from(&b"wrong first"[..]),
            SecretBytes::from(&b"password"[..]),
        ])));
    let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
        .expect("open encrypted RAR5 Store member");
    let expected: Vec<u8> = (0..512)
        .flat_map(|value| format!("{value:03}\n").into_bytes())
        .collect();
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("decrypt encrypted RAR5 Store") {
            ReaderEvent::Entry(entry) => assert_eq!(entry.path().as_bytes(), b"stest2.txt"),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, expected);
}

#[cfg(all(feature = "aes", feature = "rar"))]
fn rar5_password_options(passwords: &[&[u8]], limits: Limits) -> OpenOptions {
    OpenOptions::new()
        .with_format(Some(FormatId::Rar5))
        .with_limits(limits)
        .with_password_provider(Arc::new(PasswordCandidates::new(
            passwords.iter().copied().map(SecretBytes::from),
        )))
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar5_tweaked_blake2sp_authenticates_compressed_and_store_members() {
    let archive = include_bytes!("fixtures/rar5/rarfile-rar5-data-password-blake.rar").to_vec();
    let options = rar5_password_options(&[b"password"], Limits::safe());
    let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
        .expect("open BLAKE2sp-authenticated RAR5");
    let expected: Vec<u8> = (0..512)
        .flat_map(|value| format!("{value:03}\n").into_bytes())
        .collect();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    loop {
        match reader.next_event().expect("decrypt BLAKE2sp RAR5") {
            ReaderEvent::Entry(entry) => {
                assert_eq!(
                    entry.checksum().expect("BLAKE2sp metadata").algorithm(),
                    ChecksumAlgorithm::Blake2sp
                );
                payloads.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => payloads
                .last_mut()
                .expect("data follows entry metadata")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payloads, [expected.clone(), expected]);
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn encrypted_rar5_rejects_wrong_password_and_tampering_before_plaintext() {
    let fixture = include_bytes!("fixtures/rar5/rarfile-rar5-data-password.rar");
    for (archive, context) in [
        (fixture.to_vec(), "wrong password"),
        (
            {
                let mut tampered = fixture.to_vec();
                tampered[173] ^= 1;
                tampered
            },
            "ciphertext tamper",
        ),
    ] {
        let passwords: &[&[u8]] = if context == "wrong password" {
            &[b"wrong only"]
        } else {
            &[b"password"]
        };
        let options = rar5_password_options(passwords, Limits::safe());
        let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
            .expect("open rejected encrypted RAR5");
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Data(_)) => panic!("{context} exposed plaintext"),
                Ok(ReaderEvent::Done) => panic!("{context} unexpectedly completed"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Integrity,
            "{context}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn encrypted_rar5_enforces_kdf_and_buffer_budgets_before_plaintext() {
    let fixture = include_bytes!("fixtures/rar5/rarfile-rar5-data-password.rar");
    for (limits, context) in [
        (
            Limits::safe().with_kdf_iterations(Some(32_767)),
            "KDF iteration budget",
        ),
        (
            Limits::safe().with_in_flight_bytes(Some(2_175)),
            "encrypted buffer budget",
        ),
    ] {
        let options = rar5_password_options(&[b"password"], limits);
        let mut reader = ArchiveReader::with_options(OneByte::new(fixture.to_vec()), &options)
            .expect("open budgeted encrypted RAR5");
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Data(_)) => panic!("{context} exposed plaintext"),
                Ok(ReaderEvent::Done) => panic!("{context} unexpectedly completed"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Limit,
            "{context}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar5_header_encryption_tries_candidates_and_restores_all_headers() {
    let archive = include_bytes!("fixtures/rar5/rarfile-rar5-header-password.rar").to_vec();
    let options = rar5_password_options(&[b"wrong first", b"password"], Limits::safe());
    let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
        .expect("open header-encrypted RAR5");
    let expected: Vec<u8> = (0..512)
        .flat_map(|value| format!("{value:03}\n").into_bytes())
        .collect();
    let mut paths = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut comment = None;
    loop {
        match reader.next_event().expect("decrypt RAR5 headers and data") {
            ReaderEvent::ArchiveMetadata(metadata) => {
                if metadata.comment().is_some() {
                    comment = metadata.comment().map(ToOwned::to_owned);
                }
            },
            ReaderEvent::Entry(entry) => {
                assert!(entry.is_encrypted());
                paths.push(entry.path().as_bytes().to_vec());
                payloads.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => payloads
                .last_mut()
                .expect("data follows decrypted entry header")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(
        comment.as_deref(),
        Some(&b"RAR5 archive - hdr-password\n"[..])
    );
    assert_eq!(paths, [b"stest1.txt".to_vec(), b"stest2.txt".to_vec()]);
    assert_eq!(payloads, [expected.clone(), expected]);
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn encrypted_rar5_headers_fail_before_entries_on_authentication_and_limits() {
    let fixture = include_bytes!("fixtures/rar5/rarfile-rar5-header-password.rar");
    let cases = [
        (
            fixture.to_vec(),
            vec![b"wrong only".as_slice()],
            Limits::safe(),
            ErrorKind::Integrity,
            "wrong password",
        ),
        (
            {
                let mut tampered = fixture.to_vec();
                tampered[62] ^= 1;
                tampered
            },
            vec![b"password".as_slice()],
            Limits::safe(),
            ErrorKind::Integrity,
            "encrypted header tamper",
        ),
        (
            fixture[..70].to_vec(),
            vec![b"password".as_slice()],
            Limits::safe(),
            ErrorKind::Integrity,
            "encrypted header truncation",
        ),
        (
            fixture.to_vec(),
            vec![b"password".as_slice()],
            Limits::safe().with_kdf_iterations(Some(32_767)),
            ErrorKind::Limit,
            "header KDF budget",
        ),
    ];
    for (archive, passwords, limits, expected_kind, context) in cases {
        let options = rar5_password_options(&passwords, limits);
        let mut reader = ArchiveReader::with_options(OneByte::new(archive), &options)
            .expect("open rejected header-encrypted RAR5");
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Entry(_)) => panic!("{context} exposed entry metadata"),
                Ok(ReaderEvent::Data(_)) => panic!("{context} exposed plaintext"),
                Ok(ReaderEvent::Done) => panic!("{context} unexpectedly completed"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            expected_kind,
            "{context}"
        );
    }
}

fn main_header(archive_flags: u64) -> Vec<u8> {
    block(1, 0, None, &vint(archive_flags))
}

fn main_header_with_extra(archive_flags: u64, extra: &[u8]) -> Vec<u8> {
    block_with_extra(1, 0, None, &vint(archive_flags), extra)
}

fn file_header(name: &[u8], payload: &[u8], method: u64, unpacked: u64) -> Vec<u8> {
    file_header_with_compression(name, payload, method << 7, unpacked)
}

fn file_header_with_compression(
    name: &[u8],
    payload: &[u8],
    compression: u64,
    unpacked: u64,
) -> Vec<u8> {
    let mut fields = vint(0x0006); // Unix mtime and data CRC32 are present.
    fields.extend_from_slice(&vint(unpacked));
    fields.extend_from_slice(&vint(0o100_640));
    fields.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&vint(compression));
    fields.extend_from_slice(&vint(1)); // Unix host.
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block(2, 0x0002, Some(payload.len() as u64), &fields)
}

#[cfg(feature = "rar")]
fn compressed_file_header(name: &[u8], packed: &[u8], unpacked: &[u8], method: u64) -> Vec<u8> {
    let mut fields = vint(0x0004); // Data CRC32 is present.
    fields.extend_from_slice(&vint(unpacked.len() as u64));
    fields.extend_from_slice(&vint(0o100_640));
    fields.extend_from_slice(&crc32(unpacked).to_le_bytes());
    fields.extend_from_slice(&vint(method << 7)); // Generation 0, 128 KiB window.
    fields.extend_from_slice(&vint(1)); // Unix host.
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block(2, 0x0002, Some(packed.len() as u64), &fields)
}

fn windows_file_header(name: &[u8], payload: &[u8], attributes: u64) -> Vec<u8> {
    let mut fields = vint(0x0004);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(attributes));
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(0)); // Windows host.
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block(2, 0x0002, Some(payload.len() as u64), &fields)
}

fn file_header_with_extra(name: &[u8], payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut fields = vint(0x0004);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(0o100_640));
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(1));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block_with_extra(2, 0x0002, Some(payload.len() as u64), &fields, extra)
}

fn file_header_with_extra_without_crc(name: &[u8], payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut fields = vint(0);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(0o100_640));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(1));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block_with_extra(2, 0x0002, Some(payload.len() as u64), &fields, extra)
}

fn service_header(name: &[u8], payload: &[u8], method: u64) -> Vec<u8> {
    let mut fields = vint(0x0004);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&vint(method << 7));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block(3, 0x0002, Some(payload.len() as u64), &fields)
}

fn compressed_service_header(name: &[u8], packed: &[u8], unpacked: &[u8], method: u64) -> Vec<u8> {
    let mut fields = vint(0x0004);
    fields.extend_from_slice(&vint(unpacked.len() as u64));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&crc32(unpacked).to_le_bytes());
    fields.extend_from_slice(&vint(method << 7));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block(3, 0x0002, Some(packed.len() as u64), &fields)
}

fn service_header_with_extra_without_crc(name: &[u8], payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut fields = vint(0);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block_with_extra(3, 0x0002, Some(payload.len() as u64), &fields, extra)
}

fn child_service_header(name: &[u8], payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut fields = vint(0x0004);
    fields.extend_from_slice(&vint(payload.len() as u64));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(0));
    fields.extend_from_slice(&vint(name.len() as u64));
    fields.extend_from_slice(name);
    block_with_extra(3, 0x0022, Some(payload.len() as u64), &fields, extra)
}

fn end_header(flags: u64) -> Vec<u8> {
    block(5, 0, None, &vint(flags))
}

fn stored_archive(payload: &[u8]) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header(
        b"nested/stored.txt",
        payload,
        0,
        payload.len() as u64,
    ));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_extra(payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header_with_extra(b"metadata.txt", payload, extra));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_blake2sp(payload: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let mut hash = vint(0);
    hash.extend_from_slice(&digest);
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header_with_extra_without_crc(
        b"blake2sp.bin",
        payload,
        &extra_record(2, &hash),
    ));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_comment(comment: &[u8]) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&service_header(b"CMT", comment, 0));
    archive.extend_from_slice(comment);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_quick_open(cache: &[u8]) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&service_header(b"QO", cache, 0));
    archive.extend_from_slice(cache);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_recovery_record(data: &[u8], main_flags: u64) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(main_flags));
    archive.extend_from_slice(&service_header(b"RR", data, 0));
    archive.extend_from_slice(data);
    archive.extend_from_slice(&end_header(0));
    archive
}

fn archive_with_compression_info(compression: u64) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header_with_compression(
        b"dictionary",
        b"x",
        compression,
        1,
    ));
    archive
}

fn one_metadata(bytes: Vec<u8>, limits: Limits) -> Result<EntryMetadata, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    let mut metadata = None;
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(entry) => {
                assert!(metadata.replace(entry).is_none(), "one entry only");
            },
            ReaderEvent::Done => return Ok(metadata.expect("RAR5 entry metadata")),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown RAR5 event"),
        }
    }
}

fn first_entry_metadata(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<EntryMetadata, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    loop {
        if let ReaderEvent::Entry(metadata) = reader.next_event()? {
            return Ok(metadata);
        }
    }
}

fn entry_metadata(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<Vec<EntryMetadata>, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(std::io::Cursor::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    let mut metadata = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(entry) => metadata.push(entry),
            ReaderEvent::Done => return Ok(metadata),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown RAR5 event"),
        }
    }
}

fn archive_metadata(
    bytes: Vec<u8>,
) -> Result<libarchive_oxide::ArchiveMetadata, libarchive_oxide::Error> {
    archive_metadata_with_limits(bytes, Limits::safe())
}

fn archive_metadata_with_limits(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<libarchive_oxide::ArchiveMetadata, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(std::io::Cursor::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    loop {
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(metadata) => return Ok(metadata),
            ReaderEvent::Done => panic!("RAR5 main metadata is missing"),
            _ => {},
        }
    }
}

fn last_archive_metadata(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<libarchive_oxide::ArchiveMetadata, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    let mut metadata = None;
    loop {
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(current) => metadata = Some(current),
            ReaderEvent::Done => return Ok(metadata.expect("RAR5 archive metadata")),
            ReaderEvent::Entry(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {
                panic!("comment-only RAR5 emitted an entry event")
            },
            _ => panic!("unknown RAR5 event"),
        }
    }
}

fn last_archive_metadata_with_entries(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<libarchive_oxide::ArchiveMetadata, libarchive_oxide::Error> {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Rar5, limits)
            .expect("explicit RAR5 reader");
    let mut metadata = None;
    loop {
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(current) => metadata = Some(current),
            ReaderEvent::Done => return Ok(metadata.expect("RAR5 archive metadata")),
            ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Data(_) => panic!("RAR5 child-service payload escaped as entry data"),
            _ => panic!("unknown RAR5 event"),
        }
    }
}

fn direct_core_error(bytes: &[u8], limits: Limits) -> libarchive_oxide_core::ArchiveError {
    let mut decoder = Rar5Decoder::new(limits);
    let mut position = 0_usize;
    let mut scratch = [];
    for _ in 0..bytes.len().saturating_mul(2).saturating_add(64) {
        let end = if position == bytes.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        match decoder.step(&bytes[position..], &mut scratch, end) {
            Err(error) => return error,
            Ok(step) => {
                position += step.consumed;
                if matches!(step.event, DecodeEvent::Done) {
                    panic!("RAR5 direct decoder unexpectedly completed");
                }
            },
        }
    }
    panic!("RAR5 direct decoder did not terminate");
}

fn drain(bytes: Vec<u8>, limits: Limits) -> Result<Vec<u8>, libarchive_oxide::Error> {
    let mut reader = ArchiveReader::with_limits(OneByte::new(bytes), limits);
    let mut payload = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.kind(), EntryKind::File);
                assert_eq!(metadata.path().as_bytes(), b"nested/stored.txt");
                assert_eq!(metadata.size(), Some(14));
                assert_eq!(metadata.mode(), Some(0o100_640));
                assert_eq!(
                    metadata.times().modified.expect("mtime").seconds(),
                    1_700_000_000
                );
                let checksum = metadata.checksum().expect("RAR5 data CRC");
                assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Crc32);
                assert_eq!(checksum.as_bytes(), crc32(b"stored payload").to_be_bytes());
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return Ok(payload),
            _ => panic!("unknown RAR5 event"),
        }
    }
}

#[test]
fn store_streams_from_one_byte_reads_with_metadata_and_crc() {
    let archive = stored_archive(b"stored payload");
    assert_eq!(
        drain(archive, Limits::safe()).expect("read RAR5 Store"),
        b"stored payload"
    );
}

#[cfg(feature = "rar")]
#[test]
fn compressed_lz_payload_streams_through_the_builtin_codec_provider() {
    // Raw RAR5 payload produced by RARLAB `rar a -ma5 -m3`.
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut unpacked = vec![b'A'; 200];
    unpacked.push(b'\n');

    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_file_header(
        b"compressed.txt",
        PACKED,
        &unpacked,
        3,
    ));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&end_header(0));

    let mut reader = ArchiveReader::with_format_and_limits(
        OneByte::new(archive),
        FormatId::Rar5,
        Limits::safe(),
    )
    .expect("explicit RAR5 reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("decode compressed RAR5") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"compressed.txt");
                assert_eq!(metadata.size(), Some(201));
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, unpacked);
}

#[cfg(feature = "rar")]
#[test]
fn rar7_generation_one_fixture_streams_through_the_builtin_codec_provider() {
    let archive = include_bytes!("fixtures/rar5/rars-rar7-generation1.rar").to_vec();
    let mut reader = ArchiveReader::with_format_and_limits(
        OneByte::new(archive),
        FormatId::Rar5,
        Limits::safe(),
    )
    .expect("explicit RAR7 reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("decode generation-1 RAR7") {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"README.md");
                assert_eq!(metadata.size(), Some(30_173));
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }

    assert_eq!(decoded.len(), 30_173);
    assert_eq!(
        &Sha256::digest(&decoded)[..],
        &[
            0x36, 0xc2, 0x35, 0xc6, 0x69, 0xc6, 0x4e, 0xd6, 0xc6, 0x8a, 0xf4, 0x90, 0x65, 0xe9,
            0x45, 0x0c, 0x68, 0x91, 0x20, 0xb8, 0xe3, 0x3b, 0xa0, 0x66, 0x69, 0xdb, 0x48, 0xed,
            0x34, 0x3f, 0xd6, 0xea,
        ]
    );
}

#[cfg(feature = "rar")]
#[test]
fn compressed_solid_members_reuse_the_previous_dictionary() {
    let archive = decode_hex(include_str!(
        "fixtures/rar5/libarchive-v3.8.8-multiple-files-solid.rar.hex"
    ));
    let mut reader = ArchiveReader::with_format_and_limits(
        OneByte::new(archive),
        FormatId::Rar5,
        Limits::safe(),
    )
    .expect("explicit RAR5 reader");
    let mut paths = Vec::new();
    let mut decoded: Vec<Vec<u8>> = Vec::new();
    loop {
        match reader.next_event().expect("decode solid RAR5") {
            ReaderEvent::Entry(metadata) => {
                paths.push(metadata.path().as_bytes().to_vec());
                decoded.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => decoded
                .last_mut()
                .expect("entry precedes its data")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }

    assert_eq!(
        paths,
        [b"test1.bin", b"test2.bin", b"test3.bin", b"test4.bin"]
    );
    assert_eq!(decoded.len(), 4);
    for (index, bytes) in decoded.iter().enumerate() {
        let magic = i32::try_from(index + 1).expect("four fixtures");
        let expected: Vec<u8> = (1_i32..=1024)
            .flat_map(|value| (value * value - 3 * value + 1 + magic).max(0).to_le_bytes())
            .collect();
        assert_eq!(bytes, &expected, "solid member {magic}");
    }
}

#[cfg(feature = "rar")]
#[test]
fn compressed_lz_payload_verifies_the_decoded_crc() {
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut claimed = vec![b'A'; 200];
    claimed.push(b'!');
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_file_header(
        b"nested/stored.txt",
        PACKED,
        &claimed,
        3,
    ));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&end_header(0));

    let mut reader = ArchiveReader::with_format_and_limits(
        OneByte::new(archive),
        FormatId::Rar5,
        Limits::safe(),
    )
    .expect("explicit RAR5 reader");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("corrupt decoded CRC was accepted"),
            Ok(_) => {},
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::Integrity);
                break;
            },
        }
    }
}

#[test]
fn types_windows_file_attributes_without_the_directory_marker() {
    const FILE_ATTRIBUTE_READONLY: u64 = 0x0000_0001;
    const FILE_ATTRIBUTE_HIDDEN: u64 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u64 = 0x0000_0004;
    const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x0000_0010;
    const FILE_ATTRIBUTE_ARCHIVE: u64 = 0x0000_0020;
    let attributes = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_DIRECTORY
        | FILE_ATTRIBUTE_ARCHIVE;
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&windows_file_header(b"attributes", b"", attributes));
    archive.extend_from_slice(&end_header(0));

    let entry = one_metadata(archive, Limits::safe()).expect("RAR5 Windows attributes");
    assert_eq!(entry.file_flags(), attributes & !FILE_ATTRIBUTE_DIRECTORY);
}

#[cfg(windows)]
#[test]
fn engine_applies_rar5_windows_file_attributes() {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_HIDDEN: u64 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u64 = 0x0000_0004;
    const FILE_ATTRIBUTE_ARCHIVE: u64 = 0x0000_0020;
    let attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE;
    let payload = b"payload";
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&windows_file_header(b"attributes.bin", payload, attributes));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&end_header(0));

    let mut session = libarchive_oxide::ArchiveEngine::new()
        .prepare(std::io::Cursor::new(archive))
        .expect("session");
    let plan = session
        .plan(libarchive_oxide::Policy::safe())
        .expect("plan");
    let destination = tempfile::tempdir().expect("destination");
    let root = cap_std::fs::Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority())
        .expect("root capability");
    let report = session.apply(plan, root).expect("apply");

    let output = destination.path().join("attributes.bin");
    assert_eq!(std::fs::read(&output).expect("payload"), payload);
    assert_eq!(
        u64::from(
            std::fs::metadata(output)
                .expect("metadata")
                .file_attributes(),
        ) & attributes,
        attributes
    );
    assert!(report.filesystem_findings().iter().any(|finding| {
        finding.operation() == &libarchive_oxide::FilesystemOperation::FileFlags
            && finding.kind() == libarchive_oxide::FilesystemFindingKind::Applied
    }));
}

#[test]
fn header_data_and_truncation_fail_closed() {
    let archive = stored_archive(b"stored payload");
    let mut bad_header = archive.clone();
    bad_header[SIGNATURE.len()] ^= 1;
    assert_eq!(
        drain(bad_header, Limits::safe())
            .expect_err("header CRC")
            .kind(),
        ErrorKind::Integrity
    );

    let mut bad_data = archive.clone();
    let payload = bad_data
        .windows(b"stored payload".len())
        .position(|window| window == b"stored payload")
        .expect("payload offset");
    bad_data[payload] ^= 1;
    assert_eq!(
        drain(bad_data, Limits::safe())
            .expect_err("data CRC")
            .kind(),
        ErrorKind::Integrity
    );

    for cut in 1..archive.len() {
        let error = drain(archive[..cut].to_vec(), Limits::safe())
            .expect_err("every strict prefix is truncated");
        assert!(
            matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Unsupported),
            "cut={cut}: {error}"
        );
    }
}

#[test]
fn skip_if_unknown_headers_discard_their_bounded_data_and_resume() {
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&block(77, 0x0006, Some(3), b"future-fields"));
    archive.extend_from_slice(b"xyz");
    archive.extend_from_slice(&file_header(b"nested/stored.txt", b"stored payload", 0, 14));
    archive.extend_from_slice(b"stored payload");
    archive.extend_from_slice(&end_header(0));
    assert_eq!(
        drain(archive, Limits::safe()).expect("skip unknown RAR5 header and data"),
        b"stored payload"
    );

    let mut mandatory = SIGNATURE.to_vec();
    mandatory.extend_from_slice(&main_header(0));
    mandatory.extend_from_slice(&block(77, 0, None, b"future-fields"));
    assert_eq!(
        rar5_error_kind(mandatory),
        ErrorKind::Unsupported,
        "unknown header without the skip flag remains mandatory"
    );

    let mut truncated = SIGNATURE.to_vec();
    truncated.extend_from_slice(&main_header(0));
    truncated.extend_from_slice(&block(77, 0x0006, Some(3), b"future-fields"));
    truncated.extend_from_slice(b"xy");
    assert_eq!(rar5_error_kind(truncated), ErrorKind::Malformed);
}

#[test]
fn header_encryption_is_validated_and_reported_before_ciphertext() {
    for flags in [0_u64, 0x0001] {
        let fields = header_encryption_fields(0, flags, 15);
        for common_flags in [0_u64, 0x0004] {
            let mut reader = ArchiveReader::with_format_and_limits(
                OneByte::new(encrypted_headers_archive_with_common_flags(
                    &fields,
                    common_flags,
                )),
                FormatId::Rar5,
                Limits::safe(),
            )
            .expect("explicit RAR5 reader");

            let metadata = match reader
                .next_event()
                .expect("valid RAR5 header-encryption metadata")
            {
                ReaderEvent::ArchiveMetadata(metadata) => metadata,
                ReaderEvent::Entry(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {
                    panic!("encrypted RAR5 header bytes escaped as entry data")
                },
                ReaderEvent::Done => panic!("encrypted RAR5 completed before metadata"),
                _ => panic!("unknown RAR5 event"),
            };
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "rar5"
                    && extension.key() == b"header-encryption"
                    && extension.value() == fields
            }));

            let error = reader
                .next_event()
                .expect_err("encrypted RAR5 headers require a decryption provider");
            assert_eq!(
                error.archive_error().expect("archive error").kind(),
                ErrorKind::Unsupported
            );
        }
    }
}

#[test]
fn malformed_header_encryption_fails_before_ciphertext() {
    for (fields, expected) in [
        (header_encryption_fields(1, 0, 15), ErrorKind::Unsupported),
        (
            header_encryption_fields(0, 0x0002, 15),
            ErrorKind::Unsupported,
        ),
        (
            {
                let mut fields = vint(0);
                fields.extend_from_slice(&vint(0));
                fields
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut fields = vint(0);
                fields.extend_from_slice(&vint(0));
                fields.push(15);
                fields.extend_from_slice(&[0_u8; 15]);
                fields
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut fields = vint(0);
                fields.extend_from_slice(&vint(0x0001));
                fields.push(15);
                fields.extend_from_slice(&[0_u8; 16 + 11]);
                fields
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut fields = header_encryption_fields(0, 0, 15);
                fields.push(0);
                fields
            },
            ErrorKind::Malformed,
        ),
    ] {
        assert_eq!(
            rar5_error_kind(encrypted_headers_archive(&fields)),
            expected
        );
    }

    let fields = header_encryption_fields(0, 0, 15);
    let mut with_data = SIGNATURE.to_vec();
    with_data.extend_from_slice(&block(4, 0x0002, Some(0), &fields));
    assert_eq!(rar5_error_kind(with_data), ErrorKind::Malformed);

    let mut with_extra = SIGNATURE.to_vec();
    with_extra.extend_from_slice(&block_with_extra(
        4,
        0,
        None,
        &fields,
        &extra_record(99, b"forbidden"),
    ));
    assert_eq!(rar5_error_kind(with_extra), ErrorKind::Malformed);

    let mut after_main = SIGNATURE.to_vec();
    after_main.extend_from_slice(&main_header(0));
    after_main.extend_from_slice(&block(4, 0, None, &fields));
    assert_eq!(rar5_error_kind(after_main), ErrorKind::Malformed);
}

#[test]
fn declared_size_compression_and_volume_are_typed_before_payload() {
    let mut huge = SIGNATURE.to_vec();
    huge.extend_from_slice(&main_header(0));
    huge.extend_from_slice(&file_header(b"huge", b"", 0, 1024));
    let error = drain(
        huge,
        Limits::safe()
            .with_entry_bytes(Some(16))
            .with_decoded_total(Some(128)),
    )
    .expect_err("declared bomb");
    assert_eq!(error.kind(), ErrorKind::Limit, "{error:?}");

    let mut compressed = SIGNATURE.to_vec();
    compressed.extend_from_slice(&main_header(0));
    compressed.extend_from_slice(&file_header(b"compressed", b"x", 7, 1));
    assert_eq!(
        drain(compressed, Limits::safe())
            .expect_err("compressed method")
            .kind(),
        ErrorKind::Unsupported
    );

    let mut volume = SIGNATURE.to_vec();
    volume.extend_from_slice(&main_header(0x0001));
    assert_eq!(
        drain(volume, Limits::safe())
            .expect_err("volume set required")
            .kind(),
        ErrorKind::Capability
    );
}

#[test]
fn compression_dictionary_fields_are_bounded_before_codec_dispatch() {
    assert_eq!(
        drain(
            archive_with_compression_info(1 | (1 << 7) | (23 << 10)),
            Limits::safe().with_codec_memory(Some(64 * 1024 * 1024)),
        )
        .expect_err("oversized RAR7 dictionary before codec dispatch")
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        drain(
            archive_with_compression_info(1 << 7),
            Limits::safe().with_codec_memory(Some(128 * 1024)),
        )
        .expect_err("dictionary alone fits but total codec workspace does not")
        .kind(),
        if cfg!(feature = "rar") {
            ErrorKind::Limit
        } else {
            ErrorKind::Unsupported
        }
    );
    assert_eq!(
        drain(
            archive_with_compression_info(1 | (1 << 7) | (1 << 15)),
            Limits::safe().with_codec_memory(Some(128 * 1024)),
        )
        .expect_err("RAR7 fractional dictionary exceeds base budget")
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        drain(
            archive_with_compression_info(1 | (1 << 7) | (1 << 15)),
            Limits::safe().with_codec_memory(Some(132 * 1024)),
        )
        .expect_err("exact RAR7 fractional dictionary reaches bounded codec workspace")
        .kind(),
        if cfg!(feature = "rar") {
            ErrorKind::Limit
        } else {
            ErrorKind::Unsupported
        }
    );
    for compression in [(1 << 7) | (16 << 10), 1 | (1 << 7) | (23 << 10) | (1 << 15)] {
        assert_eq!(
            drain(
                archive_with_compression_info(compression),
                Limits::unlimited(),
            )
            .expect_err("invalid compression dictionary fields")
            .kind(),
            ErrorKind::Malformed
        );
    }
}

#[test]
fn solid_store_entries_require_a_declared_preceding_dictionary_and_are_reported() {
    let mut solid = SIGNATURE.to_vec();
    solid.extend_from_slice(&main_header(0x0004));
    solid.extend_from_slice(&file_header_with_compression(b"first", b"", 0, 0));
    solid.extend_from_slice(&file_header_with_compression(b"second", b"", 0x0041, 0));
    solid.extend_from_slice(&end_header(0));
    let entries = entry_metadata(solid, Limits::safe()).expect("solid Store archive");
    assert_eq!(entries.len(), 2);
    assert!(entries[1].extensions().iter().any(|extension| {
        extension.namespace() == "rar5" && extension.key() == b"solid" && extension.value() == [1]
    }));

    let mut first_is_solid = SIGNATURE.to_vec();
    first_is_solid.extend_from_slice(&main_header(0x0004));
    first_is_solid.extend_from_slice(&file_header_with_compression(b"first", b"", 0x0040, 0));
    assert_eq!(
        entry_metadata(first_is_solid, Limits::safe())
            .expect_err("first entry cannot continue a dictionary")
            .kind(),
        ErrorKind::Malformed
    );

    let mut undeclared = SIGNATURE.to_vec();
    undeclared.extend_from_slice(&main_header(0));
    undeclared.extend_from_slice(&file_header_with_compression(b"first", b"", 0, 0));
    undeclared.extend_from_slice(&file_header_with_compression(b"second", b"", 0x0040, 0));
    assert_eq!(
        entry_metadata(undeclared, Limits::safe())
            .expect_err("entry solid bit requires main solid flag")
            .kind(),
        ErrorKind::Malformed
    );

    let mut single = SIGNATURE.to_vec();
    single.extend_from_slice(&main_header(0x0004));
    single.extend_from_slice(&file_header_with_compression(b"only", b"", 0, 0));
    single.extend_from_slice(&end_header(0));
    assert_eq!(
        entry_metadata(single, Limits::safe())
            .expect("single-entry solid archive declaration")
            .len(),
        1
    );
}

#[test]
fn explicit_format_scans_a_bounded_sfx_prefix() {
    let mut sfx = vec![0x90; 4097];
    sfx.extend_from_slice(&stored_archive(b"stored payload"));
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(sfx), FormatId::Rar5, Limits::safe())
            .expect("explicit RAR5 reader");
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read SFX RAR5") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown SFX event"),
        }
    }
    assert_eq!(payload, b"stored payload");
}

#[test]
fn sfx_and_header_size_scans_have_hard_format_bounds() {
    let mut oversized_sfx = vec![0x90; 1024 * 1024 + 1];
    oversized_sfx.extend_from_slice(&stored_archive(b"stored payload"));
    let mut reader = ArchiveReader::with_format_and_limits(
        std::io::Cursor::new(oversized_sfx),
        FormatId::Rar5,
        Limits::safe(),
    )
    .expect("explicit RAR5 reader");
    assert_eq!(
        reader.next_event().expect_err("SFX beyond one MiB").kind(),
        ErrorKind::Limit
    );

    let mut oversized_header = SIGNATURE.to_vec();
    oversized_header.extend_from_slice(&0_u32.to_le_bytes());
    oversized_header.extend_from_slice(&[0x80, 0x80, 0x80]);
    assert_eq!(
        drain(oversized_header, Limits::safe())
            .expect_err("four-byte RAR5 header size")
            .kind(),
        ErrorKind::Limit
    );
}

#[test]
fn file_extra_times_owner_version_and_unknown_records_are_preserved() {
    let mut time = vint(0x001f);
    time.extend_from_slice(&1_700_000_001_u32.to_le_bytes());
    time.extend_from_slice(&1_700_000_002_u32.to_le_bytes());
    time.extend_from_slice(&1_700_000_003_u32.to_le_bytes());
    time.extend_from_slice(&123_456_789_u32.to_le_bytes());
    time.extend_from_slice(&234_567_890_u32.to_le_bytes());
    time.extend_from_slice(&345_678_901_u32.to_le_bytes());

    let mut owner = vint(0x000f);
    owner.extend_from_slice(&vint(5));
    owner.extend_from_slice(b"alice");
    owner.extend_from_slice(&vint(5));
    owner.extend_from_slice(b"staff");
    owner.extend_from_slice(&vint(1000));
    owner.extend_from_slice(&vint(1001));

    let mut version = vint(0);
    version.extend_from_slice(&vint(7));

    let mut extra = extra_record(3, &time);
    extra.extend_from_slice(&extra_record(6, &owner));
    extra.extend_from_slice(&extra_record(4, &version));
    extra.extend_from_slice(&extra_record(99, b"future-field"));

    let metadata = one_metadata(
        archive_with_extra(b"metadata payload", &extra),
        Limits::safe(),
    )
    .expect("RAR5 metadata extras");
    let times = metadata.times();
    assert_eq!(times.modified.expect("mtime").seconds(), 1_700_000_001);
    assert_eq!(times.modified.expect("mtime").nanoseconds(), 123_456_789);
    assert_eq!(times.created.expect("ctime").seconds(), 1_700_000_002);
    assert_eq!(times.accessed.expect("atime").seconds(), 1_700_000_003);
    assert_eq!(metadata.owner().uid, Some(1000));
    assert_eq!(metadata.owner().gid, Some(1001));
    assert_eq!(metadata.owner().user.as_deref(), Some(b"alice".as_slice()));
    assert_eq!(metadata.owner().group.as_deref(), Some(b"staff".as_slice()));
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"file-version"
            && extension.value() == 7_u64.to_le_bytes()
    }));
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"file-extra"
            && extension.value() == extra
    }));
}

#[test]
fn blake2sp_hash_record_is_exposed_and_verified_without_crc32() {
    // Official BLAKE2 KAT inputs are byte sequences 0..len.
    // These are the unkeyed BLAKE2sp-256 vectors for lengths zero and one.
    const ZERO_DIGEST: [u8; 32] = [
        0xa6, 0xb9, 0xee, 0xcc, 0x25, 0x22, 0x7a, 0xd7, 0x88, 0xc9, 0x9d, 0x3f, 0x23, 0x6d, 0xeb,
        0xc8, 0xda, 0x40, 0x88, 0x49, 0xe9, 0xa5, 0x17, 0x89, 0x78, 0x72, 0x7a, 0x81, 0x45, 0x7f,
        0x72, 0x39,
    ];
    let vectors = [
        (
            Vec::new(),
            [
                0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91,
                0x7e, 0x25, 0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8, 0x80, 0x15,
                0x00, 0xf2, 0xca, 0x4f,
            ],
        ),
        (vec![0], ZERO_DIGEST),
    ];
    for (payload, digest) in vectors {
        let metadata = one_metadata(archive_with_blake2sp(&payload, digest), Limits::safe())
            .expect("RAR5 BLAKE2sp KAT");
        let checksum = metadata.checksum().expect("RAR5 BLAKE2sp metadata");
        assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Blake2sp);
        assert_eq!(checksum.as_bytes(), digest);
    }

    let wrong_digest = [0_u8; 32];
    assert_eq!(
        one_metadata(archive_with_blake2sp(&[0], wrong_digest), Limits::safe(),)
            .expect_err("BLAKE2sp mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    let mut hash = vint(0);
    hash.extend_from_slice(&ZERO_DIGEST);
    let metadata = one_metadata(
        archive_with_extra(&[0], &extra_record(2, &hash)),
        Limits::safe(),
    )
    .expect("RAR5 entry with CRC32 and BLAKE2sp");
    assert_eq!(
        metadata.checksum().expect("strong hash").algorithm(),
        ChecksumAlgorithm::Blake2sp
    );
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"data-crc32"
            && extension.value() == crc32(&[0]).to_be_bytes()
    }));
}

#[test]
fn malformed_and_unknown_blake2sp_hash_records_fail_closed() {
    let mut unknown = vint(1);
    unknown.extend_from_slice(&[0_u8; 32]);
    assert_eq!(
        one_metadata(
            archive_with_extra(b"", &extra_record(2, &unknown)),
            Limits::safe(),
        )
        .expect_err("unknown hash type")
        .kind(),
        ErrorKind::Unsupported
    );

    let mut short = vint(0);
    short.extend_from_slice(&[0_u8; 31]);
    assert_eq!(
        one_metadata(
            archive_with_extra(b"", &extra_record(2, &short)),
            Limits::safe(),
        )
        .expect_err("short BLAKE2sp digest")
        .kind(),
        ErrorKind::Malformed
    );

    let mut hash = vint(0);
    hash.extend_from_slice(&[0_u8; 32]);
    let record = extra_record(2, &hash);
    let mut duplicate = record.clone();
    duplicate.extend_from_slice(&record);
    assert_eq!(
        one_metadata(archive_with_extra(b"", &duplicate), Limits::safe(),)
            .expect_err("duplicate BLAKE2sp record")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn redirection_records_become_typed_links() {
    for (redirection_type, expected_kind) in
        [(1_u64, EntryKind::Symlink), (4_u64, EntryKind::Hardlink)]
    {
        let mut redirection = vint(redirection_type);
        redirection.extend_from_slice(&vint(0));
        redirection.extend_from_slice(&vint(b"target/path".len() as u64));
        redirection.extend_from_slice(b"target/path");
        let metadata = one_metadata(
            archive_with_extra(b"", &extra_record(5, &redirection)),
            Limits::safe(),
        )
        .expect("RAR5 redirection");
        assert_eq!(metadata.kind(), expected_kind);
        assert_eq!(
            metadata.link_target().expect("link target").as_bytes(),
            b"target/path"
        );
    }
}

#[test]
fn sensitive_and_malformed_file_extras_fail_closed() {
    let error = one_metadata(
        archive_with_extra(b"", &extra_record(1, b"\0")),
        Limits::safe(),
    )
    .expect_err("encryption");
    assert_eq!(error.kind(), ErrorKind::Malformed, "{error:?}");

    let invalid_nanos = {
        let mut data = vint(0x0013);
        data.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
        data.extend_from_slice(&1_000_000_000_u32.to_le_bytes());
        extra_record(3, &data)
    };
    assert_eq!(
        one_metadata(archive_with_extra(b"", &invalid_nanos), Limits::safe())
            .expect_err("nanosecond range")
            .kind(),
        ErrorKind::Malformed
    );

    let time = extra_record(3, &vint(0x0001));
    let mut duplicate = time.clone();
    duplicate.extend_from_slice(&time);
    assert_eq!(
        one_metadata(archive_with_extra(b"", &duplicate), Limits::safe())
            .expect_err("duplicate time")
            .kind(),
        ErrorKind::Malformed
    );

    let mut file_copy = vint(5);
    file_copy.extend_from_slice(&vint(0));
    file_copy.extend_from_slice(&vint(6));
    file_copy.extend_from_slice(b"target");
    assert_eq!(
        one_metadata(
            archive_with_extra(b"", &extra_record(5, &file_copy)),
            Limits::safe(),
        )
        .expect_err("file-copy redirect")
        .kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn file_encryption_record_is_validated_and_reported_before_payload() {
    for flags in [0_u64, 0x0001, 0x0002, 0x0003] {
        let encryption = file_encryption_record(0, flags, 15);
        let archive = archive_with_extra(b"0123456789abcdef", &encryption);
        let metadata = first_entry_metadata(archive.clone(), Limits::safe())
            .expect("list encrypted RAR5 entry metadata");
        assert!(metadata.is_encrypted());
        assert!(metadata.extensions().iter().any(|extension| {
            extension.namespace() == "rar5"
                && extension.key() == b"file-extra"
                && extension.value() == encryption
        }));

        let error = one_metadata(archive, Limits::safe())
            .expect_err("encrypted RAR5 payload still requires a decryption provider");
        assert_eq!(
            error.archive_error().unwrap().kind(),
            ErrorKind::Unsupported
        );
    }
}

#[test]
fn malformed_file_encryption_records_fail_before_entry_metadata() {
    let valid = file_encryption_record(0, 0x0001, 15);
    let mut duplicate = valid.clone();
    duplicate.extend_from_slice(&valid);
    assert_eq!(
        first_entry_metadata(
            archive_with_extra(b"ciphertext", &duplicate),
            Limits::safe()
        )
        .expect_err("duplicate encryption record")
        .archive_error()
        .unwrap()
        .kind(),
        ErrorKind::Malformed
    );

    for (data, expected) in [
        (vint(1), ErrorKind::Unsupported),
        (
            {
                let mut data = vint(0);
                data.extend_from_slice(&vint(0x0004));
                data
            },
            ErrorKind::Unsupported,
        ),
        (
            {
                let mut data = vint(0);
                data.extend_from_slice(&vint(0));
                data
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut data = vint(0);
                data.extend_from_slice(&vint(0));
                data.push(15);
                data.extend_from_slice(&[0_u8; 31]);
                data
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut data = vint(0);
                data.extend_from_slice(&vint(0x0001));
                data.push(15);
                data.extend_from_slice(&[0_u8; 16 + 16 + 11]);
                data
            },
            ErrorKind::Malformed,
        ),
        (
            {
                let mut data = vint(0);
                data.extend_from_slice(&vint(0));
                data.push(15);
                data.extend_from_slice(&[0_u8; 16 + 16 + 1]);
                data
            },
            ErrorKind::Malformed,
        ),
    ] {
        let error = first_entry_metadata(
            archive_with_extra(b"ciphertext", &extra_record(1, &data)),
            Limits::safe(),
        )
        .expect_err("reject malformed encryption record");
        assert_eq!(error.archive_error().unwrap().kind(), expected);
    }
}

#[test]
fn redirection_target_and_payload_obey_limits_and_invariants() {
    let mut redirection = vint(1);
    redirection.extend_from_slice(&vint(0));
    redirection.extend_from_slice(&vint(32));
    redirection.extend_from_slice(&[b'x'; 32]);
    let extra = extra_record(5, &redirection);
    assert_eq!(
        one_metadata(
            archive_with_extra(b"", &extra),
            Limits::safe().with_path_bytes(Some(16)),
        )
        .expect_err("link target limit")
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        one_metadata(archive_with_extra(b"x", &extra), Limits::safe())
            .expect_err("redirected payload")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn main_metadata_and_locator_records_are_typed_and_raw_preserved() {
    let mut metadata_record = vint(0x000f);
    metadata_record.extend_from_slice(&vint(20));
    metadata_record.extend_from_slice(b"original.rar\0padding");
    metadata_record.extend_from_slice(&1_700_000_000_123_456_789_u64.to_le_bytes());

    let mut locator = vint(0x0003);
    locator.extend_from_slice(&vint(1234));
    locator.extend_from_slice(&vint(5678));

    let mut extra = extra_record(1, &locator);
    extra.extend_from_slice(&extra_record(2, &metadata_record));
    extra.extend_from_slice(&extra_record(77, b"future-main"));
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header_with_extra(0, &extra));
    archive.extend_from_slice(&end_header(0));

    let metadata = archive_metadata(archive).expect("RAR5 main metadata extras");
    assert_eq!(
        metadata.volume_name().expect("original name").as_bytes(),
        b"original.rar"
    );
    for (key, expected) in [
        (b"quick-open-offset".as_slice(), 1234_u64),
        (b"recovery-offset".as_slice(), 5678_u64),
    ] {
        assert!(metadata.extensions().iter().any(|extension| {
            extension.namespace() == "rar5"
                && extension.key() == key
                && extension.value() == expected.to_le_bytes()
        }));
    }
    let creation = metadata
        .extensions()
        .iter()
        .find(|extension| extension.namespace() == "rar5" && extension.key() == b"created")
        .expect("archive creation time");
    let mut expected_time = 1_700_000_000_i64.to_le_bytes().to_vec();
    expected_time.extend_from_slice(&123_456_789_u32.to_le_bytes());
    assert_eq!(creation.value(), expected_time);
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"main-extra"
            && extension.value() == extra
    }));
}

#[test]
fn main_metadata_handles_filetime_padding_zero_offsets_and_duplicates() {
    const FILETIME_EPOCH: u64 = 11_644_473_600;
    let ticks = (FILETIME_EPOCH + 1_700_000_000) * 10_000_000 + 4_567_890;
    let mut metadata_record = vint(0x0003);
    metadata_record.extend_from_slice(&vint(20));
    metadata_record.extend_from_slice(b"original.rar\0padding");
    metadata_record.extend_from_slice(&ticks.to_le_bytes());
    let mut locator = vint(0x0003);
    locator.extend_from_slice(&vint(0));
    locator.extend_from_slice(&vint(0));
    let mut extra = extra_record(1, &locator);
    let metadata_extra = extra_record(2, &metadata_record);
    extra.extend_from_slice(&metadata_extra);
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header_with_extra(0, &extra));
    archive.extend_from_slice(&end_header(0));
    let metadata = archive_metadata_with_limits(
        archive,
        Limits::safe().with_path_bytes(Some(b"original.rar".len())),
    )
    .expect("RAR5 FILETIME metadata");
    let created = metadata
        .extensions()
        .iter()
        .find(|extension| extension.key() == b"created")
        .expect("created extension");
    let mut expected = 1_700_000_000_i64.to_le_bytes().to_vec();
    expected.extend_from_slice(&456_789_000_u32.to_le_bytes());
    assert_eq!(created.value(), expected);
    assert!(
        !metadata.extensions().iter().any(|extension| {
            matches!(extension.key(), b"quick-open-offset" | b"recovery-offset")
        })
    );

    extra.extend_from_slice(&metadata_extra);
    let mut duplicate = SIGNATURE.to_vec();
    duplicate.extend_from_slice(&main_header_with_extra(0, &extra));
    assert_eq!(
        archive_metadata(duplicate)
            .expect_err("duplicate main metadata")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn archive_comment_service_streams_into_typed_metadata() {
    const ZERO_DIGEST: [u8; 32] = [
        0xa6, 0xb9, 0xee, 0xcc, 0x25, 0x22, 0x7a, 0xd7, 0x88, 0xc9, 0x9d, 0x3f, 0x23, 0x6d, 0xeb,
        0xc8, 0xda, 0x40, 0x88, 0x49, 0xe9, 0xa5, 0x17, 0x89, 0x78, 0x72, 0x7a, 0x81, 0x45, 0x7f,
        0x72, 0x39,
    ];

    let comment = "safe Rust archive — 日本語".as_bytes();
    let metadata = last_archive_metadata(archive_with_comment(comment), Limits::safe())
        .expect("RAR5 CMT service");
    assert_eq!(metadata.comment(), Some(comment));

    let mut hash = vint(0);
    hash.extend_from_slice(&ZERO_DIGEST);
    let extra = extra_record(2, &hash);
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&service_header_with_extra_without_crc(b"CMT", &[0], &extra));
    archive.push(0);
    archive.extend_from_slice(&end_header(0));
    let metadata =
        last_archive_metadata(archive, Limits::safe()).expect("RAR5 BLAKE2sp comment service");
    assert_eq!(metadata.comment(), Some([0].as_slice()));
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"comment-extra"
            && extension.value() == extra
    }));
}

#[cfg(feature = "rar")]
#[test]
fn compressed_archive_comment_uses_the_payload_codec_provider() {
    // Raw RAR5 payload produced by RARLAB `rar a -ma5 -m3`.
    let mut comment = vec![b'A'; 200];
    comment.push(b'\n');
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_service_header(
        b"CMT",
        RAR5_A200_PACKED,
        &comment,
        3,
    ));
    archive.extend_from_slice(RAR5_A200_PACKED);
    archive.extend_from_slice(&end_header(0));

    let metadata = last_archive_metadata(archive, Limits::safe())
        .expect("decode compressed RAR5 archive comment");
    assert_eq!(metadata.comment(), Some(comment.as_slice()));

    let mut quick_open = SIGNATURE.to_vec();
    quick_open.extend_from_slice(&main_header(0));
    quick_open.extend_from_slice(&compressed_service_header(
        b"QO",
        RAR5_A200_PACKED,
        &comment,
        3,
    ));
    quick_open.extend_from_slice(RAR5_A200_PACKED);
    quick_open.extend_from_slice(&end_header(0));
    let metadata = last_archive_metadata(quick_open, Limits::safe())
        .expect("decode compressed RAR5 quick-open service");
    let size = metadata
        .extensions()
        .iter()
        .find(|extension| extension.key() == b"quick-open-size")
        .expect("quick-open size metadata");
    assert_eq!(size.value(), (comment.len() as u64).to_le_bytes());
}

#[cfg(feature = "rar")]
#[test]
fn compressed_archive_comment_fails_closed_on_integrity_limits_and_truncation() {
    let mut comment = vec![b'A'; 200];
    comment.push(b'\n');

    let mut bad_crc_claim = comment.clone();
    *bad_crc_claim.last_mut().expect("non-empty comment") = b'!';
    let mut bad_crc = SIGNATURE.to_vec();
    bad_crc.extend_from_slice(&main_header(0));
    bad_crc.extend_from_slice(&compressed_service_header(
        b"CMT",
        RAR5_A200_PACKED,
        &bad_crc_claim,
        3,
    ));
    bad_crc.extend_from_slice(RAR5_A200_PACKED);
    assert_eq!(
        last_archive_metadata(bad_crc, Limits::safe())
            .expect_err("decoded service CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    let mut bounded = SIGNATURE.to_vec();
    bounded.extend_from_slice(&main_header(0));
    bounded.extend_from_slice(&compressed_service_header(
        b"CMT",
        RAR5_A200_PACKED,
        &comment,
        3,
    ));
    assert_eq!(
        last_archive_metadata(
            bounded.clone(),
            Limits::safe().with_decoded_total(Some(comment.len() as u64 - 1)),
        )
        .expect_err("decoded service budget")
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        last_archive_metadata(
            bounded.clone(),
            Limits::safe().with_metadata_bytes(Some(comment.len() - 1)),
        )
        .expect_err("retained service metadata budget")
        .kind(),
        ErrorKind::Limit
    );

    bounded.extend_from_slice(&RAR5_A200_PACKED[..RAR5_A200_PACKED.len() - 1]);
    assert_eq!(
        last_archive_metadata(bounded, Limits::safe())
            .expect_err("truncated compressed service payload")
            .kind(),
        ErrorKind::Malformed
    );
}

#[cfg(not(feature = "rar"))]
#[test]
fn compressed_archive_comment_requires_a_payload_codec_provider() {
    let mut comment = vec![b'A'; 200];
    comment.push(b'\n');
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_service_header(
        b"CMT",
        RAR5_A200_PACKED,
        &comment,
        3,
    ));
    assert_eq!(
        last_archive_metadata(archive, Limits::safe())
            .expect_err("compressed service without a codec provider")
            .kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn archive_comment_service_fails_closed_on_corruption_and_bad_contracts() {
    let comment = b"authenticated comment";
    let mut corrupt = archive_with_comment(comment);
    let offset = corrupt
        .windows(comment.len())
        .position(|window| window == comment)
        .expect("comment offset");
    corrupt[offset] ^= 1;
    assert_eq!(
        one_metadata(corrupt, Limits::safe())
            .expect_err("comment CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    assert_eq!(
        one_metadata(
            archive_with_comment(comment),
            Limits::safe().with_metadata_bytes(Some(comment.len() - 1)),
        )
        .expect_err("comment metadata budget")
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        one_metadata(archive_with_comment(&[0xff]), Limits::safe())
            .expect_err("comment UTF-8")
            .kind(),
        ErrorKind::Malformed
    );

    for (name, method, expected) in [
        (b"ACL".as_slice(), 0_u64, ErrorKind::Malformed),
        (b"future".as_slice(), 0_u64, ErrorKind::Unsupported),
    ] {
        let mut archive = SIGNATURE.to_vec();
        archive.extend_from_slice(&main_header(0));
        archive.extend_from_slice(&service_header(name, b"x", method));
        archive.push(b'x');
        assert_eq!(
            one_metadata(archive, Limits::safe())
                .expect_err("unsupported service contract")
                .kind(),
            expected
        );
    }

    let mut duplicate = archive_with_comment(b"first");
    duplicate.truncate(duplicate.len() - end_header(0).len());
    duplicate.extend_from_slice(&service_header(b"CMT", b"second", 0));
    duplicate.extend_from_slice(b"second");
    assert_eq!(
        one_metadata(duplicate, Limits::safe())
            .expect_err("duplicate archive comment")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn quick_open_service_is_checksum_verified_skipped_and_reported() {
    let cache = vec![0x5a; 64 * 1024];
    let metadata = last_archive_metadata(
        archive_with_quick_open(&cache),
        Limits::safe().with_metadata_bytes(Some(128)),
    )
    .expect("RAR5 QO service");
    assert!(metadata.comment().is_none());
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"quick-open-size"
            && extension.value() == (cache.len() as u64).to_le_bytes()
    }));
}

#[test]
fn quick_open_service_corruption_limits_and_order_fail_closed() {
    let cache = b"optional header cache";
    let mut corrupt = archive_with_quick_open(cache);
    let offset = corrupt
        .windows(cache.len())
        .position(|window| window == cache)
        .expect("quick-open offset");
    corrupt[offset] ^= 1;
    assert_eq!(
        one_metadata(corrupt, Limits::safe())
            .expect_err("quick-open CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );
    let archive = archive_with_quick_open(cache);
    let error = direct_core_error(
        &archive,
        Limits::safe().with_decoded_total(Some((cache.len() - 1) as u64)),
    );
    assert_eq!(error.kind(), ErrorKind::Limit, "{error:?}");

    let mut file_after_cache = SIGNATURE.to_vec();
    file_after_cache.extend_from_slice(&main_header(0));
    file_after_cache.extend_from_slice(&service_header(b"QO", cache, 0));
    file_after_cache.extend_from_slice(cache);
    file_after_cache.extend_from_slice(&file_header(b"late", b"x", 0, 1));
    assert_eq!(
        one_metadata(file_after_cache, Limits::safe())
            .expect_err("file after quick-open cache")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn recovery_record_is_checksum_verified_reported_and_never_repaired() {
    let recovery = vec![0xa5; 32 * 1024];
    let metadata = last_archive_metadata(
        archive_with_recovery_record(&recovery, 0x0008),
        Limits::safe().with_metadata_bytes(Some(128)),
    )
    .expect("RAR5 recovery service");
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar5"
            && extension.key() == b"recovery-record-size"
            && extension.value() == (recovery.len() as u64).to_le_bytes()
    }));
}

#[test]
fn recovery_record_flags_corruption_and_duplicates_fail_closed() {
    let recovery = b"recovery parity data";
    let mut corrupt = archive_with_recovery_record(recovery, 0x0008);
    let offset = corrupt
        .windows(recovery.len())
        .position(|window| window == recovery)
        .expect("recovery offset");
    corrupt[offset] ^= 1;
    assert_eq!(
        one_metadata(corrupt, Limits::safe())
            .expect_err("recovery CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    let mut missing = SIGNATURE.to_vec();
    missing.extend_from_slice(&main_header(0x0008));
    missing.extend_from_slice(&end_header(0));
    assert_eq!(
        one_metadata(missing, Limits::safe())
            .expect_err("declared recovery is missing")
            .kind(),
        ErrorKind::Malformed
    );
    assert_eq!(
        one_metadata(archive_with_recovery_record(recovery, 0), Limits::safe(),)
            .expect_err("undeclared recovery")
            .kind(),
        ErrorKind::Malformed
    );

    let mut duplicate = archive_with_recovery_record(recovery, 0x0008);
    duplicate.truncate(duplicate.len() - end_header(0).len());
    duplicate.extend_from_slice(&service_header(b"RR", b"again", 0));
    duplicate.extend_from_slice(b"again");
    assert_eq!(
        one_metadata(duplicate, Limits::safe())
            .expect_err("duplicate recovery")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn acl_and_alternate_stream_services_are_verified_and_associated_with_their_file() {
    let acl = b"opaque NTFS security descriptor";
    let stream = vec![0x3c; 32 * 1024];
    let stream_parameters = extra_record(7, b"Zone.Identifier");
    let mut archive = SIGNATURE.to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header(b"document.txt", b"", 0, 0));
    archive.extend_from_slice(&child_service_header(b"ACL", acl, &[]));
    archive.extend_from_slice(acl);
    archive.extend_from_slice(&child_service_header(b"STM", &stream, &stream_parameters));
    archive.extend_from_slice(&stream);
    archive.extend_from_slice(&end_header(0));

    let metadata =
        last_archive_metadata_with_entries(archive, Limits::safe().with_metadata_bytes(Some(128)))
            .expect("RAR5 child services");
    for (key, value) in [
        (b"acl-target".as_slice(), b"document.txt".as_slice()),
        (b"acl-data".as_slice(), acl.as_slice()),
        (b"stream-target".as_slice(), b"document.txt".as_slice()),
        (
            b"stream-size".as_slice(),
            (stream.len() as u64).to_le_bytes().as_slice(),
        ),
        (b"stream-extra".as_slice(), stream_parameters.as_slice()),
    ] {
        assert!(
            metadata.extensions().iter().any(|extension| {
                extension.namespace() == "rar5"
                    && extension.key() == key
                    && extension.value() == value
            }),
            "missing RAR5 child-service extension {key:?}"
        );
    }
}

#[test]
fn child_services_require_a_preceding_file_and_fail_closed_on_corruption_or_limits() {
    let acl = b"security descriptor";

    let mut orphan = SIGNATURE.to_vec();
    orphan.extend_from_slice(&main_header(0));
    orphan.extend_from_slice(&child_service_header(b"ACL", acl, &[]));
    orphan.extend_from_slice(acl);
    assert_eq!(
        last_archive_metadata_with_entries(orphan, Limits::safe())
            .expect_err("orphan ACL")
            .kind(),
        ErrorKind::Malformed
    );

    let mut independent = SIGNATURE.to_vec();
    independent.extend_from_slice(&main_header(0));
    independent.extend_from_slice(&file_header(b"file.txt", b"", 0, 0));
    independent.extend_from_slice(&service_header(b"ACL", acl, 0));
    independent.extend_from_slice(acl);
    assert_eq!(
        last_archive_metadata_with_entries(independent, Limits::safe())
            .expect_err("ACL without dependency flag")
            .kind(),
        ErrorKind::Malformed
    );

    let mut corrupt = SIGNATURE.to_vec();
    corrupt.extend_from_slice(&main_header(0));
    corrupt.extend_from_slice(&file_header(b"file.txt", b"", 0, 0));
    corrupt.extend_from_slice(&child_service_header(b"ACL", acl, &[]));
    corrupt.extend_from_slice(acl);
    let offset = corrupt
        .windows(acl.len())
        .position(|window| window == acl)
        .expect("ACL offset");
    corrupt[offset] ^= 1;
    assert_eq!(
        last_archive_metadata_with_entries(corrupt, Limits::safe())
            .expect_err("ACL CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    let stream = b"alternate stream";
    let mut corrupt_stream = SIGNATURE.to_vec();
    corrupt_stream.extend_from_slice(&main_header(0));
    corrupt_stream.extend_from_slice(&file_header(b"file.txt", b"", 0, 0));
    corrupt_stream.extend_from_slice(&child_service_header(
        b"STM",
        stream,
        &extra_record(7, b"named"),
    ));
    corrupt_stream.extend_from_slice(stream);
    let offset = corrupt_stream
        .windows(stream.len())
        .position(|window| window == stream)
        .expect("stream offset");
    corrupt_stream[offset] ^= 1;
    assert_eq!(
        last_archive_metadata_with_entries(corrupt_stream, Limits::safe())
            .expect_err("alternate stream CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );

    let mut oversized = SIGNATURE.to_vec();
    oversized.extend_from_slice(&main_header(0));
    oversized.extend_from_slice(&file_header(b"file.txt", b"", 0, 0));
    oversized.extend_from_slice(&child_service_header(b"ACL", acl, &[]));
    oversized.extend_from_slice(acl);
    assert_eq!(
        last_archive_metadata_with_entries(
            oversized,
            Limits::safe().with_metadata_bytes(Some(acl.len() - 1)),
        )
        .expect_err("ACL metadata budget")
        .kind(),
        ErrorKind::Limit
    );

    let first_stream_extra = extra_record(7, b"one");
    let second_stream_extra = extra_record(7, b"two");
    let per_stream_retained = b"file.txt".len() + first_stream_extra.len();
    let mut cumulative = SIGNATURE.to_vec();
    cumulative.extend_from_slice(&main_header(0));
    cumulative.extend_from_slice(&file_header(b"file.txt", b"", 0, 0));
    cumulative.extend_from_slice(&child_service_header(b"STM", b"", &first_stream_extra));
    cumulative.extend_from_slice(&child_service_header(b"STM", b"", &second_stream_extra));
    assert_eq!(
        last_archive_metadata_with_entries(
            cumulative,
            Limits::safe().with_metadata_bytes(Some(per_stream_retained + 1)),
        )
        .expect_err("cumulative child-service metadata budget")
        .kind(),
        ErrorKind::Limit
    );
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}
