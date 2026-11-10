// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RAR 3.x/4.x container and Store-method contracts.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{self, Cursor, Read};
#[cfg(feature = "aes")]
use std::sync::Arc;

use libarchive_oxide::{
    ArchiveReader, ChecksumAlgorithm, EntryKind, ErrorKind, FormatId, Limits, ReaderEvent,
};
#[cfg(feature = "aes")]
use libarchive_oxide::{OpenOptions, PasswordCandidates, SecretBytes};
#[cfg(feature = "rar")]
use sha2::{Digest, Sha256};

const FILE_HEAD: u8 = 0x74;
const ENDARC_HEAD: u8 = 0x7b;
#[cfg(feature = "rar")]
const MHD_SOLID: u8 = 0x08;
const MHD_PASSWORD: u16 = 0x0080;
const MHD_ENCRYPTVER: u16 = 0x0200;
const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_PASSWORD: u16 = 0x0004;
#[cfg(feature = "rar")]
const FHD_SOLID: u16 = 0x0010;
const FHD_LARGE: u16 = 0x0100;
const FHD_UNICODE: u16 = 0x0200;
const FHD_SALT: u16 = 0x0400;
const HD_ADD_SIZE_PRESENT: u16 = 0x8000;

fn header(kind: u8, flags: u16, mut body: Vec<u8>) -> Vec<u8> {
    let size = u16::try_from(7 + body.len()).expect("test header size");
    let mut bytes = vec![0, 0, kind];
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.append(&mut body);
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&bytes[2..]) & u32::from(u16::MAX))
        .expect("low RAR header CRC16");
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn main_header(flags: u16) -> Vec<u8> {
    header(0x73, flags, vec![0; 6])
}

fn file_header(name: &[u8], payload: &[u8], method: u8, flags: u16, attributes: u32) -> Vec<u8> {
    file_header_with_optional(name, payload, method, flags, attributes, &[])
}

fn file_header_with_optional(
    name: &[u8],
    payload: &[u8],
    method: u8,
    flags: u16,
    attributes: u32,
    optional: &[u8],
) -> Vec<u8> {
    file_header_with_optional_and_host(name, payload, method, flags, attributes, optional, 3)
}

fn file_header_with_optional_and_host(
    name: &[u8],
    payload: &[u8],
    method: u8,
    flags: u16,
    attributes: u32,
    optional: &[u8],
    host: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    let size = u32::try_from(payload.len()).expect("test payload size");
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.push(host);
    body.extend_from_slice(&libarchive_oxide::filter::crc32(payload).to_le_bytes());
    body.extend_from_slice(&0x5821_8822_u32.to_le_bytes()); // 2024-01-02 17:01:04.
    body.push(29);
    body.push(method);
    body.extend_from_slice(
        &u16::try_from(name.len())
            .expect("test path size")
            .to_le_bytes(),
    );
    body.extend_from_slice(&attributes.to_le_bytes());
    if flags & FHD_LARGE != 0 {
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
    }
    body.extend_from_slice(name);
    body.extend_from_slice(optional);
    header(FILE_HEAD, flags | HD_ADD_SIZE_PRESENT, body)
}

#[cfg(feature = "rar")]
fn compressed_file_header(name: &[u8], packed: &[u8], unpacked: &[u8], method: u8) -> Vec<u8> {
    compressed_file_header_with_flags(name, packed, unpacked, method, 0)
}

#[cfg(feature = "rar")]
fn compressed_file_header_with_flags(
    name: &[u8],
    packed: &[u8],
    unpacked: &[u8],
    method: u8,
    flags: u16,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(packed.len())
            .expect("test packed size")
            .to_le_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(unpacked.len())
            .expect("test unpacked size")
            .to_le_bytes(),
    );
    body.push(3); // Unix host.
    body.extend_from_slice(&libarchive_oxide::filter::crc32(unpacked).to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(29); // RAR 3.x unpack generation; RAR 1/2 remain excluded.
    body.push(method);
    body.extend_from_slice(
        &u16::try_from(name.len())
            .expect("test path size")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0o100_640_u32.to_le_bytes());
    body.extend_from_slice(name);
    header(FILE_HEAD, flags | HD_ADD_SIZE_PRESENT, body)
}

fn archive_with_file(name: &[u8], payload: &[u8], method: u8, flags: u16) -> Vec<u8> {
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header(name, payload, method, flags, 0o100_640));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
    archive
}

#[cfg(feature = "aes")]
fn encrypted_store_archive(ciphertext: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut encrypted_header = file_header_with_optional(
        b"secret.txt",
        ciphertext,
        0x30,
        FHD_PASSWORD | FHD_SALT,
        0o100_640,
        &salt,
    );
    encrypted_header[11..15].copy_from_slice(
        &u32::try_from(plaintext.len())
            .expect("test plaintext size")
            .to_le_bytes(),
    );
    encrypted_header[16..20]
        .copy_from_slice(&libarchive_oxide::filter::crc32(plaintext).to_le_bytes());
    let crc = u16::try_from(
        libarchive_oxide::filter::crc32(&encrypted_header[2..]) & u32::from(u16::MAX),
    )
    .expect("low RAR header CRC16");
    encrypted_header[..2].copy_from_slice(&crc.to_le_bytes());

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&encrypted_header);
    archive.extend_from_slice(ciphertext);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
    archive
}

#[cfg(feature = "aes")]
fn password_options(passwords: &[&[u8]], limits: Limits) -> OpenOptions {
    OpenOptions::new()
        .with_format(Some(FormatId::RarLegacy))
        .with_limits(limits)
        .with_password_provider(Arc::new(PasswordCandidates::new(
            passwords.iter().copied().map(SecretBytes::from),
        )))
}

fn archive_with_symlink(name: &[u8], target: &[u8]) -> Vec<u8> {
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header(name, target, 0x30, 0, 0o120_777));
    archive.extend_from_slice(target);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
    archive
}

fn auxiliary_block(kind: u8, flags: u16, body: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend_from_slice(&(flags | 0x8000).to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(11 + body.len())
            .expect("auxiliary header size")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("auxiliary payload size")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(body);
    let mut checked = bytes[2..].to_vec();
    checked.extend_from_slice(payload);
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&checked) & u32::from(u16::MAX))
        .expect("low auxiliary CRC16");
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn newsub_block(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = file_header(name, payload, 0x30, 0, 0o100_640);
    bytes[2] = 0x7a;
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&bytes[2..]) & u32::from(u16::MAX))
        .expect("low NEWSUB header CRC16");
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn collect(
    bytes: Vec<u8>,
    limits: Limits,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), libarchive_oxide::Error> {
    let mut reader = ArchiveReader::with_limits(Cursor::new(bytes), limits);
    let mut paths = Vec::new();
    let mut payload = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(entry) => {
                assert_eq!(entry.mode(), Some(0o100_640));
                paths.push(entry.path().as_bytes().to_vec());
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok((paths, payload)),
            _ => {},
        }
    }
}

struct OneByteReader(Cursor<Vec<u8>>);

impl Read for OneByteReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(1);
        self.0.read(&mut buffer[..length])
    }
}

fn collect_explicit<R: Read>(
    reader: R,
    limits: Limits,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), libarchive_oxide::Error> {
    let mut reader = ArchiveReader::with_format_and_limits(reader, FormatId::RarLegacy, limits)?;
    let mut paths = Vec::new();
    let mut payload = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(entry) => paths.push(entry.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok((paths, payload)),
            _ => {},
        }
    }
}

#[cfg(feature = "rar")]
fn decode_fixture_hex(encoded: &str) -> Vec<u8> {
    let compact: Vec<_> = encoded
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "fixture hex must contain byte pairs");
    compact
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(text, 16).expect("fixture contains only hexadecimal digits")
        })
        .collect()
}

#[cfg(feature = "rar")]
#[test]
fn real_rar3_solid_ppmd_members_continue_model_and_window() {
    let archive = decode_fixture_hex(include_str!(
        "fixtures/rar-legacy/ssokolow-rar3-solid.cbr.hex"
    ));
    let expected = decode_fixture_hex(include_str!(
        "fixtures/rar-legacy/ssokolow-rar3-solid-payloads.hex"
    ));
    let (paths, decoded) = collect_explicit(OneByteReader(Cursor::new(archive)), Limits::safe())
        .expect("decode CC0 RAR3 PPMd solid fixture");
    assert_eq!(paths, [b"testfile.png".to_vec(), b"testfile.jpg".to_vec()]);
    assert_eq!(decoded, expected);
}

#[cfg(feature = "rar")]
#[test]
fn real_rar3_ppmd_model_obeys_codec_memory_and_integrity_gates() {
    let archive = decode_fixture_hex(include_str!(
        "fixtures/rar-legacy/ssokolow-rar3-solid.cbr.hex"
    ));
    // The fixed RAR3 workspace is a little over 4.25 MiB.
    // Five MiB leaves less than the first block's declared 1 MiB PPMd heap.
    let error = collect_explicit(
        OneByteReader(Cursor::new(archive.clone())),
        Limits::safe().with_codec_memory(Some(5 * 1024 * 1024)),
    )
    .expect_err("PPMd model must fit the remaining codec-memory budget");
    assert_eq!(error.kind(), ErrorKind::Limit);

    let mut corrupted = archive.clone();
    corrupted[0x40 + 20] ^= 0x5a;
    let error = collect_explicit(OneByteReader(Cursor::new(corrupted)), Limits::safe())
        .expect_err("corrupt PPMd payload must not pass CRC/model validation");
    assert_eq!(error.kind(), ErrorKind::Malformed);

    let truncated = archive[..0x40 + 0x54 - 3].to_vec();
    let error = collect_explicit(OneByteReader(Cursor::new(truncated)), Limits::safe())
        .expect_err("truncated PPMd payload must fail closed");
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[cfg(feature = "rar")]
#[test]
fn real_rar4_lz_solid_members_continue_dictionary_and_tables() {
    let archive = decode_fixture_hex(include_str!(
        "fixtures/rar-legacy/junrar-rar4-solid.rar.hex"
    ));
    let mut reader = ArchiveReader::with_format_and_limits(
        OneByteReader(Cursor::new(archive)),
        FormatId::RarLegacy,
        Limits::safe(),
    )
    .expect("open explicit legacy RAR reader");
    let mut paths = Vec::new();
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut archive_solid = false;
    let mut member_solid = Vec::new();
    loop {
        match reader.next_event().expect("decode CC0 RAR3 solid fixture") {
            ReaderEvent::ArchiveMetadata(metadata) => {
                archive_solid |= metadata.extensions().iter().any(|extension| {
                    extension.namespace() == "rar-legacy"
                        && extension.key() == b"main-flags"
                        && extension
                            .value()
                            .first()
                            .is_some_and(|flags| flags & MHD_SOLID != 0)
                });
            },
            ReaderEvent::Entry(entry) => {
                paths.push(entry.path().as_bytes().to_vec());
                member_solid.push(entry.extensions().iter().any(|extension| {
                    extension.namespace() == "rar-legacy"
                        && extension.key() == b"solid"
                        && extension.value() == [1]
                }));
                bodies.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => bodies
                .last_mut()
                .expect("data follows entry metadata")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }

    assert!(archive_solid);
    let expected_paths: Vec<_> = (1..=9)
        .map(|index| format!("file{index}.txt").into_bytes())
        .collect();
    let expected_bodies: Vec<_> = (1..=9)
        .map(|index| format!("file{index}\n").into_bytes())
        .collect();
    assert_eq!(paths, expected_paths);
    assert_eq!(
        member_solid,
        [false, true, true, true, true, true, true, true, true]
    );
    assert_eq!(bodies, expected_bodies);
}

#[cfg(feature = "rar")]
#[test]
fn rejects_invalid_or_unseeded_solid_members() {
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const UNPACKED: &[u8] = b"test text document\r\n";

    for main_flags in [0, u16::from(MHD_SOLID)] {
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(main_flags));
        archive.extend_from_slice(&compressed_file_header_with_flags(
            b"orphan.txt",
            PACKED,
            UNPACKED,
            0x33,
            FHD_SOLID,
        ));
        archive.extend_from_slice(PACKED);
        archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
        assert_eq!(
            collect_explicit(Cursor::new(archive), Limits::safe())
                .expect_err("solid member must follow compatible state")
                .kind(),
            ErrorKind::Malformed
        );
    }
}

#[test]
fn detects_and_streams_rar4_store_with_crc_and_metadata() {
    let payload = b"legacy RAR Store payload".repeat(4097);
    let archive = archive_with_file(b"nested/file.txt", &payload, 0x30, FHD_LARGE);
    let mut metadata_reader =
        ArchiveReader::with_limits(Cursor::new(archive.clone()), Limits::safe());
    let entry = loop {
        if let ReaderEvent::Entry(entry) = metadata_reader
            .next_event()
            .expect("read RAR4 Store metadata")
        {
            break entry;
        }
    };
    let checksum = entry.checksum().expect("RAR4 file CRC32 metadata");
    assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Crc32);
    assert_eq!(
        checksum.as_bytes(),
        libarchive_oxide::filter::crc32(&payload).to_be_bytes()
    );

    let (paths, decoded) = collect(archive, Limits::safe()).expect("read RAR4 Store archive");
    assert_eq!(paths, [b"nested/file.txt".to_vec()]);
    assert_eq!(decoded, payload);

    assert_eq!(
        FormatId::probe(b"Rar!\x1a\x07\x00"),
        libarchive_oxide::advanced::ProbeResult::Match(FormatId::RarLegacy)
    );
}

#[cfg(feature = "rar")]
#[test]
fn compressed_lz_payload_streams_through_the_builtin_codec_provider() {
    // Raw block extracted from libarchive's BSD-licensed test_read_format_rar_compress_normal.rar fixture.
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const UNPACKED: &[u8] = b"test text document\r\n";

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_file_header(
        b"compressed.txt",
        PACKED,
        UNPACKED,
        0x33,
    ));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let (paths, decoded) = collect_explicit(OneByteReader(Cursor::new(archive)), Limits::safe())
        .expect("decode compressed RAR3");
    assert_eq!(paths, [b"compressed.txt".to_vec()]);
    assert_eq!(decoded, UNPACKED);
}

#[cfg(feature = "rar")]
#[test]
fn real_rar3_standard_vm_filter_is_chunk_invariant() {
    let archive = include_bytes!("fixtures/rar-legacy/libarchive-rar3-filter.rar");
    let (paths, decoded) =
        collect_explicit(OneByteReader(Cursor::new(archive.to_vec())), Limits::safe())
            .expect("decode BSD RAR3 standard-filter fixture");

    assert_eq!(paths, [b"bsdcat.exe".to_vec()]);
    assert_eq!(decoded.len(), 204_288);
    assert_eq!(&decoded[..12], b"MZ\x90\0\x03\0\0\0\x04\0\0\0");
    assert_eq!(
        Sha256::digest(&decoded).as_slice(),
        &[
            0xa9, 0x61, 0x53, 0x2b, 0x3a, 0x19, 0x6e, 0x0b, 0x2c, 0x01, 0x26, 0xad, 0x6f, 0x35,
            0xd5, 0x11, 0xc9, 0xfd, 0xfe, 0xad, 0xac, 0xbe, 0x78, 0xa1, 0xb1, 0x5d, 0xc2, 0x21,
            0x25, 0x1a, 0xd9, 0xa2,
        ]
    );
}

#[cfg(feature = "rar")]
#[test]
fn real_rar3_standard_vm_filter_fails_closed_on_payload_damage() {
    const PAYLOAD_START: usize = 62;
    const PACKED_BYTES: usize = 94_232;
    let archive = include_bytes!("fixtures/rar-legacy/libarchive-rar3-filter.rar");

    let truncated = archive[..PAYLOAD_START + PACKED_BYTES - 1].to_vec();
    let error = collect_explicit(OneByteReader(Cursor::new(truncated)), Limits::safe())
        .expect_err("truncated standard-filter payload must fail closed");
    assert!(matches!(
        error.kind(),
        ErrorKind::Malformed | ErrorKind::Integrity
    ));

    let mut corrupted = archive.to_vec();
    corrupted[PAYLOAD_START + PACKED_BYTES / 2] ^= 0x5a;
    let error = collect_explicit(OneByteReader(Cursor::new(corrupted)), Limits::safe())
        .expect_err("corrupt standard-filter payload must fail closed");
    assert!(matches!(
        error.kind(),
        ErrorKind::Malformed | ErrorKind::Integrity | ErrorKind::Unsupported
    ));
}

#[cfg(feature = "rar")]
#[test]
fn compressed_lz_payload_verifies_the_decoded_crc() {
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const CLAIMED: &[u8] = b"test text document\r!";
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&compressed_file_header(
        b"bad-crc.txt",
        PACKED,
        CLAIMED,
        0x33,
    ));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    assert_eq!(
        collect_explicit(OneByteReader(Cursor::new(archive)), Limits::safe())
            .expect_err("decoded RAR3 CRC mismatch")
            .kind(),
        ErrorKind::Integrity
    );
}

#[test]
fn preserves_file_header_flags_host_and_raw_attributes() {
    let flags = 0x0800 | 0x2000;
    let attributes = 0o100_640;
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header(b"metadata.bin", b"", 0x30, flags, attributes));
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let mut reader = ArchiveReader::with_limits(Cursor::new(archive), Limits::safe());
    let entry = loop {
        match reader.next_event().expect("RAR4 file-header metadata") {
            ReaderEvent::Entry(entry) => break entry,
            ReaderEvent::Done => panic!("RAR file-header entry was not exposed"),
            _ => {},
        }
    };
    for (key, expected) in [
        (&b"host-os"[..], vec![3]),
        (
            &b"file-flags"[..],
            (flags | HD_ADD_SIZE_PRESENT).to_le_bytes().to_vec(),
        ),
        (&b"file-attributes"[..], attributes.to_le_bytes().to_vec()),
    ] {
        let extension = entry
            .extensions()
            .iter()
            .find(|extension| extension.key() == key)
            .unwrap_or_else(|| panic!("missing {}", String::from_utf8_lossy(key)));
        assert_eq!(extension.value(), expected);
    }
}

#[test]
fn types_windows_file_attributes_without_the_directory_marker() {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
    let attributes = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_DIRECTORY
        | FILE_ATTRIBUTE_ARCHIVE;
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header_with_optional_and_host(
        b"attributes",
        b"",
        0x30,
        0,
        attributes,
        &[],
        2,
    ));
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let mut reader = ArchiveReader::with_limits(Cursor::new(archive), Limits::safe());
    let entry = loop {
        match reader.next_event().expect("RAR Windows attributes") {
            ReaderEvent::Entry(entry) => break entry,
            ReaderEvent::Done => panic!("RAR file-header entry was not exposed"),
            _ => {},
        }
    };
    assert_eq!(
        entry.file_flags(),
        u64::from(attributes & !FILE_ATTRIBUTE_DIRECTORY)
    );
}

#[test]
fn rejects_corrupt_headers_payloads_and_truncation() {
    let payload = b"integrity protected";
    let valid = archive_with_file(b"file.bin", payload, 0x30, 0);

    let mut bad_header = valid.clone();
    bad_header[9] ^= 1;
    let error = collect(bad_header, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Integrity);

    let mut bad_payload = valid.clone();
    let offset = bad_payload
        .windows(payload.len())
        .position(|window| window == payload)
        .expect("payload offset");
    bad_payload[offset] ^= 1;
    let error = collect(bad_payload, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Integrity);

    let error = collect(valid[..valid.len() - 5].to_vec(), Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_unknown_compression_encryption_volumes_and_oversized_entries_before_data() {
    for (method, flags, expected) in [
        (0x36, 0, ErrorKind::Unsupported),
        (0x30, FHD_PASSWORD, ErrorKind::Unsupported),
        (0x30, FHD_SPLIT_BEFORE, ErrorKind::Capability),
    ] {
        let error = collect(
            archive_with_file(b"blocked.bin", b"blocked", method, flags),
            Limits::safe(),
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            expected,
            "method={method:#x} flags={flags:#x}"
        );
    }

    let error = collect(
        archive_with_file(b"large.bin", b"1234", 0x30, 0),
        Limits::safe().with_entry_bytes(Some(3)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn encrypted_file_metadata_is_reported_before_ciphertext() {
    for (method, salted) in [(0x30, false), (0x35, true)] {
        let ciphertext = [0xa5; 16];
        let flags = FHD_PASSWORD | if salted { FHD_SALT } else { 0 };
        let salt = if salted { &b"salt1234"[..] } else { &[] };
        let mut encrypted_header = file_header_with_optional(
            b"encrypted.bin",
            &ciphertext,
            method,
            flags,
            0o100_640,
            salt,
        );
        encrypted_header[11..15].copy_from_slice(&13_u32.to_le_bytes());
        let crc = u16::try_from(
            libarchive_oxide::filter::crc32(&encrypted_header[2..]) & u32::from(u16::MAX),
        )
        .expect("low RAR header CRC16");
        encrypted_header[..2].copy_from_slice(&crc.to_le_bytes());

        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(0));
        archive.extend_from_slice(&encrypted_header);
        archive.extend_from_slice(&ciphertext);
        archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

        let mut reader = ArchiveReader::with_format_and_limits(
            OneByteReader(Cursor::new(archive)),
            FormatId::RarLegacy,
            Limits::safe(),
        )
        .expect("explicit legacy RAR reader");
        let metadata = loop {
            match reader.next_event().expect("encrypted RAR entry metadata") {
                ReaderEvent::Entry(metadata) => break metadata,
                ReaderEvent::ArchiveMetadata(_) => {},
                _ => panic!("encrypted RAR ciphertext escaped before entry metadata"),
            }
        };
        assert!(metadata.is_encrypted());
        assert_eq!(metadata.path().as_bytes(), b"encrypted.bin");
        assert_eq!(metadata.size(), Some(13));
        assert!(metadata.extensions().iter().any(|extension| {
            extension.namespace() == "rar-legacy"
                && extension.key() == b"compression-method"
                && extension.value() == [method]
        }));
        if salted {
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "rar-legacy"
                    && extension.key() == b"file-optional"
                    && extension.value() == salt
            }));
        }

        let error = reader
            .next_event()
            .expect_err("encrypted RAR data requires a decryption provider");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Unsupported
        );
    }
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar3_data_encryption_tries_ordered_password_candidates() {
    let archive = include_bytes!("fixtures/rar-legacy/rarfile-rar3-data-password.rar").to_vec();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::RarLegacy))
        .with_limits(Limits::safe())
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::from(&b"wrong first"[..]),
            SecretBytes::from(&b"password"[..]),
        ])));
    let mut reader = ArchiveReader::with_options(OneByteReader(Cursor::new(archive)), &options)
        .expect("open encrypted RAR3 with password candidates");
    let mut paths = Vec::new();
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("decrypt encrypted RAR3") {
            ReaderEvent::Entry(entry) => {
                assert!(entry.is_encrypted());
                assert_eq!(entry.size(), Some(0));
                paths.push(entry.path().as_bytes().to_vec());
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(paths, [b"file1.txt".to_vec(), b"file2.txt".to_vec()]);
    assert_eq!(payload, [] as [u8; 0]);
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn real_rar3_header_encryption_tries_ordered_password_candidates() {
    let archive = include_bytes!("fixtures/rar-legacy/rarfile-rar3-header-password.rar").to_vec();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::RarLegacy))
        .with_limits(Limits::safe())
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::from(&b"wrong first"[..]),
            SecretBytes::from(&b"password"[..]),
        ])));
    let mut reader = ArchiveReader::with_options(OneByteReader(Cursor::new(archive)), &options)
        .expect("open header-encrypted RAR3 with password candidates");
    let mut paths = Vec::new();
    loop {
        match reader.next_event().expect("decrypt RAR3 headers and data") {
            ReaderEvent::Entry(entry) => {
                assert!(entry.is_encrypted());
                paths.push(entry.path().as_bytes().to_vec());
            },
            ReaderEvent::Data(bytes) => assert_eq!(bytes, []),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(paths, [b"file1.txt".to_vec(), b"file2.txt".to_vec()]);
}

#[cfg(all(feature = "aes", feature = "rar"))]
#[test]
fn encrypted_rar3_headers_fail_before_entries_on_wrong_password_or_truncation() {
    let fixture = include_bytes!("fixtures/rar-legacy/rarfile-rar3-header-password.rar");
    let wrong = password_options(&[b"wrong only"], Limits::safe());
    let mut reader = ArchiveReader::with_options(Cursor::new(fixture.to_vec()), &wrong)
        .expect("open header-encrypted RAR3 with wrong password");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let error = reader
        .next_event()
        .expect_err("wrong header password must fail before entries");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Integrity
    );

    let mut truncated = fixture.to_vec();
    truncated.truncate(7 + 13 + 8 + 10);
    let correct = password_options(&[b"password"], Limits::safe());
    let mut reader = ArchiveReader::with_options(Cursor::new(truncated), &correct)
        .expect("open truncated header-encrypted RAR3");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let error = reader
        .next_event()
        .expect_err("truncated encrypted header must fail before entries");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Integrity
    );
}

#[cfg(feature = "aes")]
#[test]
fn encrypted_rar3_store_releases_nonempty_plaintext_only_after_crc() {
    const PLAINTEXT: &[u8] = b"authenticated RAR3 payload";
    const CIPHERTEXT: &[u8] = &[
        0x00, 0x0f, 0x00, 0xe0, 0x43, 0x12, 0xb2, 0x20, 0x41, 0x10, 0x17, 0xac, 0x8b, 0x5b, 0x8e,
        0xc3, 0xff, 0x84, 0x4a, 0xb4, 0x11, 0x3f, 0x0c, 0x29, 0xcb, 0x55, 0x76, 0x23, 0x29, 0xdb,
        0x27, 0xd6,
    ];
    let archive = encrypted_store_archive(CIPHERTEXT, PLAINTEXT);
    let options = password_options(&[b"wrong first", b"password"], Limits::safe());
    let mut reader = ArchiveReader::with_options(OneByteReader(Cursor::new(archive)), &options)
        .expect("open encrypted Store RAR3");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("decrypt encrypted Store RAR3") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, PLAINTEXT);

    let archive = encrypted_store_archive(CIPHERTEXT, PLAINTEXT);
    let wrong = password_options(&[b"wrong only"], Limits::safe());
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), &wrong)
        .expect("open encrypted Store RAR3 with wrong password");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let error = reader
        .next_event()
        .expect_err("wrong password must fail before plaintext");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Integrity
    );
}

#[cfg(feature = "aes")]
#[test]
fn encrypted_rar3_data_preflights_workspace_and_block_alignment() {
    let ciphertext = vec![0xa5; 400_000];
    let plaintext = vec![0; 400_000];
    let oversized = encrypted_store_archive(&ciphertext, &plaintext);
    let options = password_options(
        &[b"password"],
        Limits::safe().with_in_flight_bytes(Some(1024 * 1024)),
    );
    let mut reader = ArchiveReader::with_options(Cursor::new(oversized), &options)
        .expect("open bounded encrypted RAR3");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let error = reader
        .next_event()
        .expect_err("encrypted workspace must be preflighted");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Limit
    );

    let misaligned = encrypted_store_archive(&[0xa5; 15], &[0; 1]);
    let options = password_options(&[b"password"], Limits::safe());
    let mut reader = ArchiveReader::with_options(Cursor::new(misaligned), &options)
        .expect("open misaligned encrypted RAR3");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    let error = reader
        .next_event()
        .expect_err("partial AES block must be rejected");
    assert_eq!(
        error.archive_error().expect("archive error").kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn encrypted_file_salt_is_validated_before_entry_metadata() {
    let archive = archive_with_file(b"encrypted.bin", &[0xa5; 16], 0x30, FHD_PASSWORD | FHD_SALT);
    assert_eq!(
        collect(archive, Limits::safe()).unwrap_err().kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn header_encryption_is_reported_before_ciphertext() {
    for version in [None, Some(29_u8)] {
        let mut body = vec![0; 6];
        let mut flags = MHD_PASSWORD;
        if let Some(version) = version {
            flags |= MHD_ENCRYPTVER;
            body.push(version);
        }
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&header(0x73, flags, body));
        archive.extend_from_slice(&[0xa5; 16]);

        let mut reader = ArchiveReader::with_format_and_limits(
            OneByteReader(Cursor::new(archive)),
            FormatId::RarLegacy,
            Limits::safe(),
        )
        .expect("explicit legacy RAR reader");
        let ReaderEvent::ArchiveMetadata(metadata) =
            reader.next_event().expect("encrypted RAR header metadata")
        else {
            panic!("encrypted RAR header bytes escaped before archive metadata");
        };
        assert!(metadata.extensions().iter().any(|extension| {
            extension.namespace() == "rar-legacy"
                && extension.key() == b"header-encryption"
                && extension.value() == [1]
        }));
        assert_eq!(
            metadata.extensions().iter().find_map(|extension| {
                (extension.key() == b"encrypt-version").then(|| extension.value().to_vec())
            }),
            version.map(|version| vec![version])
        );

        let error = reader
            .next_event()
            .expect_err("encrypted RAR headers require a decryption provider");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            ErrorKind::Unsupported
        );
    }
}

#[test]
fn rejects_encrypted_headers_and_invalid_paths() {
    let mut encrypted = b"Rar!\x1a\x07\x00".to_vec();
    encrypted.extend_from_slice(&main_header(MHD_PASSWORD));
    let error = collect(encrypted, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    let error = collect(
        archive_with_file(b"bad\0name", b"x", 0x30, 0),
        Limits::safe(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn validates_volume_and_encrypt_version_main_flags() {
    for flags in [0x0001, 0x0100] {
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(flags));
        archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
        let error = collect(archive, Limits::safe()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Capability);
    }

    let mut truncated = b"Rar!\x1a\x07\x00".to_vec();
    truncated.extend_from_slice(&main_header(MHD_ENCRYPTVER));
    truncated.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
    let error = collect(truncated, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed);

    let mut body = vec![0; 6];
    body.push(29);
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&header(0x73, MHD_ENCRYPTVER, body));
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
    let mut reader = ArchiveReader::with_limits(Cursor::new(archive), Limits::safe());
    let encrypt_version = loop {
        match reader
            .next_event()
            .expect("RAR4 encryption-version metadata")
        {
            ReaderEvent::ArchiveMetadata(metadata) => {
                if let Some(extension) = metadata
                    .extensions()
                    .iter()
                    .find(|extension| extension.key() == b"encrypt-version")
                {
                    break extension.value().to_vec();
                }
            },
            ReaderEvent::Done => panic!("RAR encryption version was not preserved"),
            _ => {},
        }
    };
    assert_eq!(encrypt_version, [29]);
}

#[test]
fn rejects_file_headers_without_long_block_marker() {
    let payload = b"x";
    let mut file = file_header(b"file.bin", payload, 0x30, 0, 0o100_640);
    file[4] &= 0x7f;
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&file[2..]) & u32::from(u16::MAX))
        .expect("low RAR header CRC16");
    file[..2].copy_from_slice(&crc.to_le_bytes());

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let error = collect(archive, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn applies_path_budget_to_decoded_unicode_name() {
    let mut name = vec![b'x', 0, 0x04];
    for _ in 0..5 {
        name.push(0x55); // Four mode-1 code units using the 0x04 high byte.
        name.extend_from_slice(&[0; 4]);
    }
    assert_eq!(name.len(), 28);

    let error = collect(
        archive_with_file(&name, b"", 0x30, FHD_UNICODE),
        Limits::safe().with_path_bytes(Some(30)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn rejects_impossible_dos_calendar_date() {
    let payload = b"x";
    let mut file = file_header(b"file.bin", payload, 0x30, 0, 0o100_640);
    let impossible_february_31 = (44_u32 << 25) | (2 << 21) | (31 << 16);
    file[20..24].copy_from_slice(&impossible_february_31.to_le_bytes());
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&file[2..]) & u32::from(u16::MAX))
        .expect("low RAR header CRC16");
    file[..2].copy_from_slice(&crc.to_le_bytes());

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let error = collect(archive, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn streams_one_byte_at_a_time_and_bounds_sfx_scanning() {
    let payload = b"chunk boundaries".repeat(1024);
    let mut sfx = vec![0x90; 31];
    sfx.extend_from_slice(&archive_with_file(b"chunked.bin", &payload, 0x30, 0));
    let (paths, decoded) = collect_explicit(OneByteReader(Cursor::new(sfx)), Limits::safe())
        .expect("one-byte RAR stream");
    assert_eq!(paths, [b"chunked.bin".to_vec()]);
    assert_eq!(decoded, payload);

    let mut at_limit = vec![0x90; 1024 * 1024];
    at_limit.extend_from_slice(&archive_with_file(b"limit.bin", b"", 0x30, 0));
    collect_explicit(Cursor::new(at_limit), Limits::safe()).expect("1 MiB SFX prefix");

    let mut over_limit = vec![0x90; 1024 * 1024 + 1];
    over_limit.extend_from_slice(&archive_with_file(b"too-far.bin", b"", 0x30, 0));
    let error = collect_explicit(Cursor::new(over_limit), Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn enforces_header_and_total_budgets_before_payload() {
    let archive = archive_with_file(b"budget.bin", b"1234", 0x30, 0);
    for limits in [
        Limits::safe().with_metadata_bytes(Some(12)),
        Limits::safe().with_in_flight_bytes(Some(12)),
        Limits::safe().with_entries(Some(0)),
        Limits::safe().with_decoded_total(Some(3)),
    ] {
        let error = collect(archive.clone(), limits).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Limit);
    }
}

#[test]
fn preflights_stored_unix_symlink_target_before_entry() {
    let target = b"../target/file.txt";
    let archive = archive_with_symlink(b"link", target);

    let mut reader = ArchiveReader::with_format_and_limits(
        OneByteReader(Cursor::new(archive.clone())),
        FormatId::RarLegacy,
        Limits::safe(),
    )
    .expect("explicit RAR4 reader");
    let mut metadata = None;
    let mut payload_events = 0;
    loop {
        match reader.next_event().expect("stored RAR4 symlink") {
            ReaderEvent::Entry(entry) => metadata = Some(entry),
            ReaderEvent::Data(_) => payload_events += 1,
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    let metadata = metadata.expect("symlink metadata");
    assert_eq!(metadata.kind(), EntryKind::Symlink);
    assert_eq!(metadata.size(), Some(0));
    assert_eq!(metadata.mode(), Some(0o120_777));
    assert_eq!(
        metadata.link_target().expect("symlink target").as_bytes(),
        target
    );
    assert_eq!(
        payload_events, 0,
        "link target must not escape as file data"
    );

    let error = collect(
        archive,
        Limits::safe().with_path_bytes(Some(target.len() - 1)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn rejects_invalid_stored_symlink_target_before_entry() {
    for target in [&b""[..], &b"bad\0target"[..]] {
        let mut reader = ArchiveReader::with_limits(
            Cursor::new(archive_with_symlink(b"link", target)),
            Limits::safe(),
        );
        let mut entries = 0;
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Entry(_)) => entries += 1,
                Ok(ReaderEvent::Done) => panic!("invalid link target was accepted"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), ErrorKind::Malformed);
        assert_eq!(entries, 0);
    }

    let target = b"valid-target";
    let mut corrupt = archive_with_symlink(b"link", target);
    let offset = corrupt
        .windows(target.len())
        .rposition(|window| window == target)
        .expect("symlink target offset");
    corrupt[offset] ^= 1;
    let mut reader = ArchiveReader::with_limits(Cursor::new(corrupt), Limits::safe());
    let mut entries = 0;
    let error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(_)) => entries += 1,
            Ok(ReaderEvent::Done) => panic!("corrupt link target was accepted"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(entries, 0, "metadata must wait for target authentication");
}

#[test]
fn decodes_extended_mtime_ctime_and_atime() {
    let mtime_ticks = 1_234_567_u32;
    let ctime_dos = (44_u32 << 25) | (2 << 21) | (3 << 16) | (4 << 11) | (5 << 5) | 3;
    let atime_dos = (44_u32 << 25) | (3 << 21) | (4 << 16) | (5 << 11) | (6 << 5) | 4;
    let mut optional = 0xbc90_u16.to_le_bytes().to_vec();
    optional.extend_from_slice(&mtime_ticks.to_le_bytes()[..3]);
    optional.extend_from_slice(&ctime_dos.to_le_bytes());
    optional.extend_from_slice(&atime_dos.to_le_bytes());
    optional.push(42);

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&file_header_with_optional(
        b"times.bin",
        b"",
        0x30,
        0x1000,
        0o100_644,
        &optional,
    ));
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let mut reader = ArchiveReader::with_limits(Cursor::new(archive), Limits::safe());
    let entry = loop {
        match reader.next_event().expect("RAR4 extended times") {
            ReaderEvent::Entry(entry) => break entry,
            ReaderEvent::Done => panic!("missing timed entry"),
            _ => {},
        }
    };
    let times = entry.times();
    assert_eq!(
        times.modified.expect("mtime").nanoseconds(),
        mtime_ticks * 100
    );
    assert_eq!(times.changed.expect("ctime").nanoseconds(), 0);
    assert_eq!(
        times.accessed.expect("atime").nanoseconds(),
        (42_u32 << 16) * 100
    );
    assert_eq!(
        times.changed.expect("ctime").seconds(),
        super_dos_seconds(ctime_dos) + 1
    );
    assert_eq!(
        times.accessed.expect("atime").seconds(),
        super_dos_seconds(atime_dos)
    );
}

#[test]
fn rejects_truncated_or_out_of_range_extended_times() {
    for optional in [
        vec![0x00],
        vec![0x00, 0xb0, 0xff, 0xff, 0xff],
        vec![0x08, 0x00, 0x00, 0x00, 0x00],
        vec![0x00, 0x10],
    ] {
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(0));
        archive.extend_from_slice(&file_header_with_optional(
            b"bad-time.bin",
            b"",
            0x30,
            0x1000,
            0o100_640,
            &optional,
        ));
        archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));
        let error = collect(archive, Limits::safe()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }
}

fn super_dos_seconds(raw: u32) -> i64 {
    let second = i64::from(raw & 0x1f) * 2;
    let minute = i64::from((raw >> 5) & 0x3f);
    let hour = i64::from((raw >> 11) & 0x1f);
    let day = i64::from((raw >> 16) & 0x1f);
    let month = i64::from((raw >> 21) & 0x0f);
    let year = i64::from((raw >> 25) & 0x7f) + 1980;
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) * 86_400 + hour * 3600 + minute * 60 + second
}

#[test]
fn verifies_and_reports_auxiliary_blocks_before_continuing() {
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&auxiliary_block(0x78, 0x4000, b"rr", b"recovery"));
    archive.extend_from_slice(&auxiliary_block(0x6f, 0x4000, b"future", b"data"));
    archive.extend_from_slice(&newsub_block(b"RR", b"newsub-payload"));
    archive.extend_from_slice(&file_header(b"after.bin", b"ok", 0x30, 0, 0o100_640));
    archive.extend_from_slice(b"ok");
    archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

    let mut reader = ArchiveReader::with_format_and_limits(
        OneByteReader(Cursor::new(archive)),
        FormatId::RarLegacy,
        Limits::safe(),
    )
    .expect("explicit RAR4 reader");
    let mut auxiliary = Vec::new();
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("RAR4 auxiliary blocks") {
            ReaderEvent::ArchiveMetadata(metadata) => {
                for extension in metadata.extensions() {
                    if extension.key() == b"aux-block" {
                        auxiliary.push(extension.value().to_vec());
                    }
                }
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, b"ok");
    assert_eq!(auxiliary.len(), 3);
    assert_eq!(auxiliary[0][0], 0x78);
    assert_eq!(auxiliary[1][0], 0x6f);
    assert_eq!(auxiliary[2][0], 0x7a);
    assert_eq!(auxiliary[0].last(), Some(&1));
    assert_eq!(auxiliary[1].last(), Some(&1));
    assert_eq!(auxiliary[2].last(), Some(&0));
}

#[test]
fn auxiliary_payload_integrity_and_truncation_fail_before_entries() {
    let block = auxiliary_block(0x78, 0x4000, b"rr", b"recovery");
    for (mut bytes, expected) in [
        (block[..block.len() - 1].to_vec(), ErrorKind::Malformed),
        (block.clone(), ErrorKind::Integrity),
    ] {
        if expected == ErrorKind::Integrity {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(0));
        archive.extend_from_slice(&bytes);
        let mut reader = ArchiveReader::with_limits(Cursor::new(archive), Limits::safe());
        let mut entries = 0;
        let error = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Entry(_)) => entries += 1,
                Ok(ReaderEvent::Done) => panic!("invalid auxiliary block was accepted"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), expected);
        assert_eq!(entries, 0);
    }

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&main_header(0));
    archive.extend_from_slice(&header(0x6f, 0, Vec::new()));
    let error = collect(archive, Limits::safe()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn rejects_newsub_without_a_complete_long_file_header() {
    for invalid in [
        header(0x7a, 0, Vec::new()),
        auxiliary_block(0x7a, 0, &[], &[]),
    ] {
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        archive.extend_from_slice(&main_header(0));
        archive.extend_from_slice(&invalid);
        archive.extend_from_slice(&header(ENDARC_HEAD, 0, Vec::new()));

        let error = collect(archive, Limits::safe()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }
}
