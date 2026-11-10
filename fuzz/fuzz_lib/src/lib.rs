// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable fuzz invariants for the v0.2 streaming protocols.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use libarchive_oxide::advanced::{
    CabVolumeReader, MemoryReadAt, ReadAt, SourceIdentity, SourceLimits, VolumeId, VolumeResolver,
    VolumeSet,
};
use libarchive_oxide::filter::crc32;
use libarchive_oxide::filter::gzip::{GzipDecoder, GzipEncoder};
use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, ArchiveWriter, CreateOptions, Error, FilterReader,
    FormatWriteOptions, OpenOptions, PasswordCandidates, Policy, ReaderEvent, SecretBytes,
    SeekArchiveReader, SeekArchiveWriter, VolumeArchiveReader, XarCompression, XarWriteOptions,
    ZipMethod,
};
use libarchive_oxide_codecs::{
    base64::{Base64Decoder, Base64Encoder},
    lz4::Lz4Decoder,
    lzop::{LzopDecoder, LzopEncoder},
    lzw::{CompressDecoder, CompressEncoder},
    rpm::RpmDecoder,
    uuencode::{UuencodeDecoder, UuencodeEncoder},
};
use libarchive_oxide_core::{
    ArchiveDecoder, ArchiveError, ArchivePath, Codec, CodecStatus, DecodeEvent, EndOfInput,
    EntryKind, EntryMetadata, ErrorKind, Extension, FormatId, Limits, Rar5Decoder,
    RarLegacyDecoder,
};
use libarchive_oxide_package::{
    AlpineRsaPublicKey, AppPackageProfile, PackageVerifier, RpmOpenPgpPublicKey, ZipPackageProfile,
};

const MAX_ENTRIES: usize = 200_000;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const CODEC_CAP: usize = 64 * 1024 * 1024;
const CODEC_ROUNDTRIP_MAX: usize = 256 * 1024;
const DEFLATE64_ROUNDTRIP_MAX: usize = 16 * 1024;
const ZSTD_ROUNDTRIP_MAX: usize = 16 * 1024;
const XZ_ROUNDTRIP_MAX: usize = 16 * 1024;
const ZIPCRYPTO_ROUNDTRIP_MAX: usize = 16 * 1024;
const LZMA2_DICT: u32 = 8 * 1024 * 1024;
const MAX_ROUNDTRIP_ENTRIES: usize = 48;
const MAX_NAME_LEN: usize = 40;
const MAX_ROUNDTRIP_DATA: usize = 4096;
const ALPINE_KEY_ID: &[u8] = b"alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub";
const CAB_VOLUME_FRAME_MAGIC: &[u8; 5] = b"OXCV\x01";
const MAX_CAB_FUZZ_VOLUMES: usize = 16;
const ZIP_VOLUME_FRAME_MAGIC: &[u8; 5] = b"OXZV\x01";
const MAX_ZIP_FUZZ_VOLUMES: usize = 16;
const ALPINE_PUBLIC_KEY: &[u8] = include_bytes!(
    "../../../libarchive_oxide-package/tests/fixtures/alpine_apk_v2/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
);
const RPM_PUBLIC_KEY: &[u8] = include_bytes!(
    "../../../libarchive_oxide-package/tests/fixtures/rpm_signature/rpm.org-rsa-2048-test.pub"
);

fn fuzz_limits() -> Limits {
    Limits::default()
        .with_decoded_total(Some(MAX_TOTAL_BYTES))
        .with_entry_bytes(Some(MAX_TOTAL_BYTES))
        .with_entries(Some(MAX_ENTRIES as u64))
        .with_metadata_bytes(Some(8 * 1024 * 1024))
        .with_in_flight_bytes(Some(256 * 1024))
}

fn drive_sequential(data: &[u8]) {
    let mut reader = ArchiveReader::with_limits(Cursor::new(data), fuzz_limits());
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                let _ = metadata.link_target().map(|path| path.as_bytes());
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_seek(data: &[u8]) {
    let Ok(mut reader) = SeekArchiveReader::with_limits(Cursor::new(data), fuzz_limits()) else {
        return;
    };
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                let _ = metadata.link_target().map(|path| path.as_bytes());
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_explicit_raw(data: &[u8]) {
    let Ok(mut reader) =
        ArchiveReader::with_format_and_limits(Cursor::new(data), FormatId::Raw, fuzz_limits())
    else {
        return;
    };
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > 1 || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_warc(data: &[u8]) {
    let Ok(mut explicit) =
        ArchiveReader::with_format_and_limits(Cursor::new(data), FormatId::Warc, fuzz_limits())
    else {
        return;
    };
    while !matches!(explicit.next_event(), Ok(ReaderEvent::Done) | Err(_)) {}

    // Keep every existing read_tar corpus seed useful for the WARC deep path without adding another libFuzzer target: arbitrary bytes become a bounded, correctly framed content block, while the explicit pass above still exercises malformed headers and trailers.
    let mut framed = format!(
        "WARC/1.1\r\nWARC-Type: resource\r\nContent-Length: {}\r\n\r\n",
        data.len()
    )
    .into_bytes();
    framed.extend_from_slice(data);
    framed.extend_from_slice(b"\r\n\r\n");
    drive_sequential(&framed);
}

fn drive_mtree(data: &[u8]) {
    let Ok(mut explicit) =
        ArchiveReader::with_format_and_limits(Cursor::new(data), FormatId::Mtree, fuzz_limits())
    else {
        return;
    };
    while !matches!(explicit.next_event(), Ok(ReaderEvent::Done) | Err(_)) {}
}

/// Tar/WARC/mtree auto-detection plus explicit raw/WARC/mtree decoding must not panic.
pub fn read_tar(data: &[u8]) {
    drive_sequential(data);
    drive_explicit_raw(data);
    drive_warc(data);
    drive_mtree(data);
}

/// cpio decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_cpio(data: &[u8]) {
    drive_sequential(data);
}

/// ar decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_ar(data: &[u8]) {
    drive_sequential(data);
}

fn drive_explicit_rar5(data: &[u8]) {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Rar5))
        .with_limits(fuzz_limits())
        .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::from(
            &b"password"[..],
        )])));
    let Ok(mut reader) = ArchiveReader::with_options(Cursor::new(data), &options) else {
        return;
    };
    let mut events = 0_usize;
    let mut payload = 0_u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_physical_rar5(data: &[u8]) {
    let mut decoder = Rar5Decoder::with_volume_provider(fuzz_limits());
    let mut input = data;
    let mut scratch = [0_u8; 1];
    let maximum_steps = data.len().saturating_mul(2).saturating_add(128);
    for _ in 0..maximum_steps {
        let scratch_len = scratch.len();
        let Ok(step) = decoder.step(input, &mut scratch, EndOfInput::End) else {
            return;
        };
        if step.consumed > input.len() || step.produced > scratch_len {
            panic!("RAR5 physical decoder reported out-of-range progress");
        }
        let consumed = step.consumed;
        let done = matches!(step.event, DecodeEvent::Done);
        let stalled = consumed == 0 && matches!(step.event, DecodeEvent::NeedInput);
        input = &input[consumed..];
        if done || stalled {
            return;
        }
    }
}

fn drive_explicit_rar_legacy(data: &[u8]) {
    let Ok(mut reader) = ArchiveReader::with_format_and_limits(
        Cursor::new(data),
        FormatId::RarLegacy,
        fuzz_limits(),
    ) else {
        return;
    };
    let mut events = 0_usize;
    let mut payload = 0_u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_physical_rar_legacy(data: &[u8]) {
    let mut decoder = RarLegacyDecoder::with_volume_provider(fuzz_limits());
    let mut input = data;
    let mut scratch = [0_u8; 1];
    let maximum_steps = data.len().saturating_mul(2).saturating_add(128);
    for _ in 0..maximum_steps {
        let scratch_len = scratch.len();
        let Ok(step) = decoder.step(input, &mut scratch, EndOfInput::End) else {
            return;
        };
        if step.consumed > input.len() || step.produced > scratch_len {
            panic!("legacy RAR physical decoder reported out-of-range progress");
        }
        let consumed = step.consumed;
        let done = matches!(step.event, DecodeEvent::Done);
        let stalled = consumed == 0 && matches!(step.event, DecodeEvent::NeedInput);
        input = &input[consumed..];
        if done || stalled {
            return;
        }
    }
}

fn rar_legacy_header(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = vec![0, 0, kind];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(
        &u16::try_from(7 + body.len())
            .expect("bounded synthetic RAR4 header")
            .to_le_bytes(),
    );
    header.extend_from_slice(body);
    let checksum =
        u16::try_from(crc32(&header[2..]) & u32::from(u16::MAX)).expect("low RAR header CRC16");
    header[..2].copy_from_slice(&checksum.to_le_bytes());
    header
}

fn rar_legacy_auxiliary(kind: u8, payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len()).expect("bounded synthetic RAR4 auxiliary payload");
    let mut body = size.to_le_bytes().to_vec();
    body.extend_from_slice(b"rr");
    let mut block = rar_legacy_header(kind, 0xc000, &body);
    let mut checked = block[2..].to_vec();
    checked.extend_from_slice(payload);
    let checksum =
        u16::try_from(crc32(&checked) & u32::from(u16::MAX)).expect("low RAR block CRC16");
    block[..2].copy_from_slice(&checksum.to_le_bytes());
    block.extend_from_slice(payload);
    block
}

fn rar_legacy_store_archive(payload: &[u8]) -> Vec<u8> {
    const NAME: &[u8] = b"fuzz.bin";
    let size = u32::try_from(payload.len()).expect("capped synthetic RAR4 payload");
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar_legacy_header(0x73, 0x0200, &[0, 0, 0, 0, 0, 0, 29]));
    archive.extend_from_slice(&rar_legacy_auxiliary(0x78, b"recovery"));
    let mut body = Vec::new();
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.push(3);
    body.extend_from_slice(&crc32(payload).to_le_bytes());
    body.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    body.push(29);
    body.push(0x30);
    body.extend_from_slice(
        &u16::try_from(NAME.len())
            .expect("bounded synthetic RAR4 path")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0o100_644_u32.to_le_bytes());
    body.extend_from_slice(NAME);
    body.extend_from_slice(&0xb000_u16.to_le_bytes());
    body.extend_from_slice(&1_234_567_u32.to_le_bytes()[..3]);
    archive.extend_from_slice(&rar_legacy_header(0x74, 0x9000, &body));
    archive.extend_from_slice(payload);

    const LINK_NAME: &[u8] = b"fuzz-link";
    const LINK_TARGET: &[u8] = b"../fuzz.bin";
    let link_size = u32::try_from(LINK_TARGET.len()).expect("fixed RAR4 link target");
    let mut link = Vec::new();
    link.extend_from_slice(&link_size.to_le_bytes());
    link.extend_from_slice(&link_size.to_le_bytes());
    link.push(3);
    link.extend_from_slice(&crc32(LINK_TARGET).to_le_bytes());
    link.extend_from_slice(&0_u32.to_le_bytes());
    link.push(29);
    link.push(0x30);
    link.extend_from_slice(
        &u16::try_from(LINK_NAME.len())
            .expect("fixed RAR4 link name")
            .to_le_bytes(),
    );
    link.extend_from_slice(&0o120_777_u32.to_le_bytes());
    link.extend_from_slice(LINK_NAME);
    archive.extend_from_slice(&rar_legacy_header(0x74, 0x8000, &link));
    archive.extend_from_slice(LINK_TARGET);
    archive.extend_from_slice(&rar_legacy_header(0x7b, 0, &[]));
    archive
}

#[cfg(feature = "rar")]
fn assert_valid_rar3_compressed() {
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const PLAIN: &[u8] = b"test text document\r\n";
    const NAME: &[u8] = b"compressed.txt";
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar_legacy_header(0x73, 0, &[0; 6]));
    let mut body = Vec::new();
    body.extend_from_slice(&(PACKED.len() as u32).to_le_bytes());
    body.extend_from_slice(&(PLAIN.len() as u32).to_le_bytes());
    body.push(3);
    body.extend_from_slice(&crc32(PLAIN).to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(29);
    body.push(0x33);
    body.extend_from_slice(&(NAME.len() as u16).to_le_bytes());
    body.extend_from_slice(&0o100_644_u32.to_le_bytes());
    body.extend_from_slice(NAME);
    archive.extend_from_slice(&rar_legacy_header(0x74, 0x8000, &body));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&rar_legacy_header(0x7b, 0, &[]));

    let mut reader = ArchiveReader::with_format_and_limits(
        Cursor::new(archive),
        FormatId::RarLegacy,
        fuzz_limits(),
    )
    .expect("valid compressed RAR3 reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("valid compressed RAR3 archive") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, PLAIN);
}

fn rar_legacy_encrypted_archive(data: &[u8]) -> (Vec<u8>, u8, bool) {
    const NAME: &[u8] = b"encrypted-fuzz.bin";
    let ciphertext = &data[..data.len().min(CODEC_ROUNDTRIP_MAX)];
    let packed_size = u32::try_from(ciphertext.len()).expect("capped encrypted RAR4 payload");
    let unpacked_size = packed_size.saturating_sub(1);
    let method = 0x30 + data.first().copied().unwrap_or_default() % 6;
    let salted = data.get(1).copied().unwrap_or_default() & 1 != 0;

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar_legacy_header(0x73, 0, &[0; 6]));
    let mut body = Vec::new();
    body.extend_from_slice(&packed_size.to_le_bytes());
    body.extend_from_slice(&unpacked_size.to_le_bytes());
    body.push(3);
    body.extend_from_slice(&crc32(ciphertext).to_le_bytes());
    body.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    body.push(29);
    body.push(method);
    body.extend_from_slice(
        &u16::try_from(NAME.len())
            .expect("fixed encrypted RAR4 path")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0o100_644_u32.to_le_bytes());
    body.extend_from_slice(NAME);
    if salted {
        body.extend_from_slice(b"salt1234");
    }
    let flags = 0x8004 | if salted { 0x0400 } else { 0 };
    archive.extend_from_slice(&rar_legacy_header(0x74, flags, &body));
    archive.extend_from_slice(ciphertext);
    (archive, method, salted)
}

fn assert_valid_rar_legacy_encrypted_metadata(archive: Vec<u8>, method: u8, salted: bool) {
    let mut reader = ArchiveReader::with_format_and_limits(
        Cursor::new(archive),
        FormatId::RarLegacy,
        fuzz_limits(),
    )
    .expect("built-in RAR4 reader");
    let metadata = loop {
        match reader
            .next_event()
            .expect("valid encrypted RAR4 entry metadata")
        {
            ReaderEvent::Entry(metadata) => break metadata,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("encrypted RAR4 ciphertext escaped before entry metadata"),
        }
    };
    assert!(metadata.is_encrypted());
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "rar-legacy"
            && extension.key() == b"compression-method"
            && extension.value() == [method]
    }));
    assert_eq!(
        metadata
            .extensions()
            .iter()
            .any(|extension| extension.key() == b"file-optional"),
        salted
    );
    let error = reader
        .next_event()
        .expect_err("encrypted RAR4 data requires a decryption provider");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

fn rar_legacy_encrypted_headers_archive(data: &[u8]) -> (Vec<u8>, Option<u8>) {
    let version = (data.first().copied().unwrap_or_default() & 1 != 0)
        .then(|| data.get(1).copied().unwrap_or(29));
    let mut body = vec![0; 6];
    let mut flags = 0x0080;
    if let Some(version) = version {
        flags |= 0x0200;
        body.push(version);
    }
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar_legacy_header(0x73, flags, &body));
    archive.extend_from_slice(&[0xa5; 16]);
    (archive, version)
}

fn assert_valid_rar_legacy_encrypted_headers_metadata(archive: Vec<u8>, version: Option<u8>) {
    let mut reader = ArchiveReader::with_format_and_limits(
        Cursor::new(archive),
        FormatId::RarLegacy,
        fuzz_limits(),
    )
    .expect("built-in RAR4 reader");
    let ReaderEvent::ArchiveMetadata(metadata) = reader
        .next_event()
        .expect("valid encrypted RAR4 header metadata")
    else {
        panic!("encrypted RAR4 header bytes escaped before archive metadata");
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
        .expect_err("encrypted RAR4 headers require a decryption provider");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn rar_legacy_split_volume(
    first_volume: bool,
    next_volume: bool,
    part: &[u8],
    logical_size: u32,
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    const NAME: &[u8] = b"split-fuzz.bin";
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    let main_flags = 0x0001 | if first_volume { 0x0100 } else { 0 };
    archive.extend_from_slice(&rar_legacy_header(0x73, main_flags, &[0, 0, 0, 0, 0, 0]));

    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(part.len())
            .expect("capped synthetic RAR4 split part")
            .to_le_bytes(),
    );
    body.extend_from_slice(&logical_size.to_le_bytes());
    body.push(3);
    body.extend_from_slice(&checksum.to_le_bytes());
    body.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    body.push(29);
    body.push(0x30);
    body.extend_from_slice(
        &u16::try_from(NAME.len())
            .expect("bounded synthetic RAR4 path")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0o100_644_u32.to_le_bytes());
    body.extend_from_slice(NAME);
    let split_flags = u16::from(split_before) | (u16::from(split_after) << 1);
    archive.extend_from_slice(&rar_legacy_header(0x74, 0x8000 | split_flags, &body));
    archive.extend_from_slice(part);
    archive.extend_from_slice(&rar_legacy_header(0x7b, u16::from(next_volume), &[]));
    archive
}

fn rar_legacy_fuzz_source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    let identity = SourceIdentity::try_new(format!("fuzz-rar-legacy-volume-{index}").into_bytes())
        .expect("bounded legacy RAR fuzz identity");
    Arc::new(MemoryReadAt::new(bytes, identity))
}

fn assert_valid_rar_legacy_split(payload: &[u8]) {
    let logical_size = u32::try_from(payload.len()).expect("capped synthetic RAR4 payload");
    let split_at = payload.len() / 2;
    let (first, second) = payload.split_at(split_at);
    let first_volume =
        rar_legacy_split_volume(true, true, first, logical_size, false, true, crc32(first));
    let second_volume = rar_legacy_split_volume(
        false,
        false,
        second,
        logical_size,
        true,
        false,
        crc32(payload),
    );
    let resolver = Arc::new(FuzzVolumeResolver {
        volumes: [(VolumeId::new(1), rar_legacy_fuzz_source(1, second_volume))]
            .into_iter()
            .collect(),
    });
    let volumes = Arc::new(
        VolumeSet::new(
            rar_legacy_fuzz_source(0, first_volume),
            resolver,
            SourceLimits::safe(),
        )
        .expect("bounded legacy RAR fuzz volume set"),
    );
    let options = OpenOptions::new()
        .with_limits(fuzz_limits())
        .with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options)
        .expect("synthetic split legacy RAR volume reader");
    let mut decoded = Vec::new();
    let mut entries = 0;
    let mut ends = 0;
    loop {
        match reader
            .next_event()
            .expect("synthetic split legacy RAR event")
        {
            ReaderEvent::Entry(_) => entries += 1,
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => return,
        }
    }
    assert_eq!((entries, ends), (1, 1));
    assert_eq!(decoded, payload);
}

/// RAR 3.x/4.x arbitrary container/physical-volume parsing plus valid complete and split Store envelopes must remain bounded and panic-free.
pub fn read_rar_legacy(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    drive_explicit_rar_legacy(decoded.as_deref().unwrap_or(data));
    drive_physical_rar_legacy(decoded.as_deref().unwrap_or(data));

    let payload = &data[..data.len().min(CODEC_ROUNDTRIP_MAX)];
    let archive = rar_legacy_store_archive(payload);
    let mut reader = ArchiveReader::with_format_and_limits(
        Cursor::new(archive),
        FormatId::RarLegacy,
        fuzz_limits(),
    )
    .expect("built-in RAR4 reader");
    let mut decoded_payload = Vec::new();
    let mut saw_link = false;
    let mut saw_auxiliary = false;
    let mut saw_encrypt_version = false;
    let mut saw_file_header_metadata = false;
    loop {
        match reader.next_event().expect("synthetic RAR4 Store archive") {
            ReaderEvent::Data(bytes) => decoded_payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::Entry(metadata) if metadata.kind() == EntryKind::Symlink => {
                assert_eq!(
                    metadata.link_target().map(ArchivePath::as_bytes),
                    Some(&b"../fuzz.bin"[..])
                );
                saw_link = true;
            },
            ReaderEvent::ArchiveMetadata(metadata) => {
                saw_auxiliary |= metadata.extensions().iter().any(|extension| {
                    extension.key() == b"aux-block"
                        && extension.value().first() == Some(&0x78)
                        && extension.value().last() == Some(&1)
                });
                saw_encrypt_version |= metadata.extensions().iter().any(|extension| {
                    extension.key() == b"encrypt-version" && extension.value() == [29]
                });
            },
            ReaderEvent::Entry(metadata) => {
                saw_file_header_metadata |= metadata
                    .extensions()
                    .iter()
                    .any(|extension| extension.key() == b"host-os" && extension.value() == [3])
                    && metadata
                        .extensions()
                        .iter()
                        .any(|extension| extension.key() == b"file-flags");
            },
            ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded_payload, payload);
    assert!(saw_link);
    assert!(saw_auxiliary);
    assert!(saw_encrypt_version);
    assert!(saw_file_header_metadata);
    let (encrypted, method, salted) = rar_legacy_encrypted_archive(data);
    assert_valid_rar_legacy_encrypted_metadata(encrypted, method, salted);
    let (encrypted_headers, version) = rar_legacy_encrypted_headers_archive(data);
    assert_valid_rar_legacy_encrypted_headers_metadata(encrypted_headers, version);
    assert_valid_rar_legacy_split(payload);
    #[cfg(feature = "rar")]
    assert_valid_rar3_compressed();
}

fn rar5_vint(mut value: u64) -> Vec<u8> {
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

fn rar5_block(header_type: u64, flags: u64, data_size: Option<u64>, fields: &[u8]) -> Vec<u8> {
    let mut body = rar5_vint(header_type);
    body.extend_from_slice(&rar5_vint(flags));
    if flags & 0x02 != 0 {
        body.extend_from_slice(&rar5_vint(data_size.unwrap_or_default()));
    }
    body.extend_from_slice(fields);
    let size = rar5_vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut block = crc32(&checked).to_le_bytes().to_vec();
    block.extend_from_slice(&checked);
    block
}

fn rar5_extra_record(record_type: u64, data: &[u8]) -> Vec<u8> {
    let mut record = rar5_vint(record_type);
    record.extend_from_slice(data);
    let mut encoded = rar5_vint(record.len() as u64);
    encoded.extend_from_slice(&record);
    encoded
}

fn rar5_data_block_with_extra(
    header_type: u64,
    flags: u64,
    data_size: u64,
    fields: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut body = rar5_vint(header_type);
    body.extend_from_slice(&rar5_vint(flags | 0x01));
    body.extend_from_slice(&rar5_vint(extra.len() as u64));
    body.extend_from_slice(&rar5_vint(data_size));
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);
    let size = rar5_vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut block = crc32(&checked).to_le_bytes().to_vec();
    block.extend_from_slice(&checked);
    block
}

fn rar5_main_block(extra: &[u8], archive_flags: u64) -> Vec<u8> {
    let mut body = rar5_vint(1);
    body.extend_from_slice(&rar5_vint(0x01));
    body.extend_from_slice(&rar5_vint(extra.len() as u64));
    body.extend_from_slice(&rar5_vint(archive_flags));
    body.extend_from_slice(extra);
    let size = rar5_vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut block = crc32(&checked).to_le_bytes().to_vec();
    block.extend_from_slice(&checked);
    block
}

fn rar5_store_archive(payload: &[u8], blake2sp: Option<[u8; 32]>, encrypted: bool) -> Vec<u8> {
    let name = b"fuzz.bin";
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut locator = rar5_vint(0x03);
    locator.extend_from_slice(&rar5_vint(payload.len() as u64));
    locator.extend_from_slice(&rar5_vint(crc32(payload).into()));
    let mut metadata = rar5_vint(0x0f);
    metadata.extend_from_slice(&rar5_vint(8));
    metadata.extend_from_slice(b"fuzz.rar");
    metadata.extend_from_slice(
        &1_700_000_000_000_000_000_u64
            .saturating_add(payload.len() as u64)
            .to_le_bytes(),
    );
    let mut main_extra = rar5_extra_record(1, &locator);
    main_extra.extend_from_slice(&rar5_extra_record(2, &metadata));
    main_extra.extend_from_slice(&rar5_extra_record(99, b"future"));
    archive.extend_from_slice(&rar5_main_block(&main_extra, 0x000c));

    let comment = b"fuzz comment";
    let mut comment_fields = rar5_vint(0x04);
    comment_fields.extend_from_slice(&rar5_vint(comment.len() as u64));
    comment_fields.extend_from_slice(&rar5_vint(0));
    comment_fields.extend_from_slice(&crc32(comment).to_le_bytes());
    comment_fields.extend_from_slice(&rar5_vint(0));
    comment_fields.extend_from_slice(&rar5_vint(0));
    comment_fields.extend_from_slice(&rar5_vint(3));
    comment_fields.extend_from_slice(b"CMT");
    archive.extend_from_slice(&rar5_block(
        3,
        0x02,
        Some(comment.len() as u64),
        &comment_fields,
    ));
    archive.extend_from_slice(comment);

    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(payload.len() as u64));
    fields.extend_from_slice(&rar5_vint(0o100_644));
    fields.extend_from_slice(&crc32(payload).to_le_bytes());
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&rar5_vint(1));
    fields.extend_from_slice(&rar5_vint(name.len() as u64));
    fields.extend_from_slice(name);

    let mut time = rar5_vint(0x13);
    time.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
    time.extend_from_slice(
        &u32::try_from(payload.len() % 1_000_000_000)
            .unwrap_or_default()
            .to_le_bytes(),
    );
    let mut owner = rar5_vint(0x0c);
    owner.extend_from_slice(&rar5_vint(payload.len() as u64));
    owner.extend_from_slice(&rar5_vint(crc32(payload).into()));
    let mut extra = rar5_extra_record(3, &time);
    extra.extend_from_slice(&rar5_extra_record(6, &owner));
    if encrypted {
        let mut encryption = rar5_vint(0);
        encryption.extend_from_slice(&rar5_vint(0x03));
        encryption.push(payload.first().copied().unwrap_or(15));
        encryption.extend(0_u8..16);
        encryption.extend(16_u8..32);
        encryption.extend(32_u8..44);
        extra.extend_from_slice(&rar5_extra_record(1, &encryption));
    }
    if let Some(digest) = blake2sp {
        let mut hash = rar5_vint(0);
        hash.extend_from_slice(&digest);
        extra.extend_from_slice(&rar5_extra_record(2, &hash));
    }
    extra.extend_from_slice(&rar5_extra_record(99, b"fuzz"));
    archive.extend_from_slice(&rar5_data_block_with_extra(
        2,
        0x03,
        payload.len() as u64,
        &fields,
        &extra,
    ));
    archive.extend_from_slice(payload);

    let acl = b"opaque security descriptor";
    let mut acl_fields = rar5_vint(0x04);
    acl_fields.extend_from_slice(&rar5_vint(acl.len() as u64));
    acl_fields.extend_from_slice(&rar5_vint(0));
    acl_fields.extend_from_slice(&crc32(acl).to_le_bytes());
    acl_fields.extend_from_slice(&rar5_vint(0));
    acl_fields.extend_from_slice(&rar5_vint(0));
    acl_fields.extend_from_slice(&rar5_vint(3));
    acl_fields.extend_from_slice(b"ACL");
    archive.extend_from_slice(&rar5_block(3, 0x22, Some(acl.len() as u64), &acl_fields));
    archive.extend_from_slice(acl);

    let stream = b"alternate stream payload";
    let mut stream_fields = rar5_vint(0x04);
    stream_fields.extend_from_slice(&rar5_vint(stream.len() as u64));
    stream_fields.extend_from_slice(&rar5_vint(0));
    stream_fields.extend_from_slice(&crc32(stream).to_le_bytes());
    stream_fields.extend_from_slice(&rar5_vint(0));
    stream_fields.extend_from_slice(&rar5_vint(0));
    stream_fields.extend_from_slice(&rar5_vint(3));
    stream_fields.extend_from_slice(b"STM");
    let stream_extra = rar5_extra_record(7, b"Zone.Identifier");
    archive.extend_from_slice(&rar5_data_block_with_extra(
        3,
        0x22,
        stream.len() as u64,
        &stream_fields,
        &stream_extra,
    ));
    archive.extend_from_slice(stream);

    let second_name = b"solid-empty.bin";
    let mut second_fields = rar5_vint(0x04);
    second_fields.extend_from_slice(&rar5_vint(0));
    second_fields.extend_from_slice(&rar5_vint(0o100_644));
    second_fields.extend_from_slice(&crc32(b"").to_le_bytes());
    second_fields.extend_from_slice(&rar5_vint(0x0041 | (31 << 15)));
    second_fields.extend_from_slice(&rar5_vint(1));
    second_fields.extend_from_slice(&rar5_vint(second_name.len() as u64));
    second_fields.extend_from_slice(second_name);
    archive.extend_from_slice(&rar5_block(2, 0x02, Some(0), &second_fields));

    let quick_open = b"ignored quick-open cache";
    let mut quick_open_fields = rar5_vint(0x04);
    quick_open_fields.extend_from_slice(&rar5_vint(quick_open.len() as u64));
    quick_open_fields.extend_from_slice(&rar5_vint(0));
    quick_open_fields.extend_from_slice(&crc32(quick_open).to_le_bytes());
    quick_open_fields.extend_from_slice(&rar5_vint(0));
    quick_open_fields.extend_from_slice(&rar5_vint(0));
    quick_open_fields.extend_from_slice(&rar5_vint(2));
    quick_open_fields.extend_from_slice(b"QO");
    archive.extend_from_slice(&rar5_block(
        3,
        0x02,
        Some(quick_open.len() as u64),
        &quick_open_fields,
    ));
    archive.extend_from_slice(quick_open);

    let recovery = b"recovery parity";
    let mut recovery_fields = rar5_vint(0x04);
    recovery_fields.extend_from_slice(&rar5_vint(recovery.len() as u64));
    recovery_fields.extend_from_slice(&rar5_vint(0));
    recovery_fields.extend_from_slice(&crc32(recovery).to_le_bytes());
    recovery_fields.extend_from_slice(&rar5_vint(0));
    recovery_fields.extend_from_slice(&rar5_vint(0));
    recovery_fields.extend_from_slice(&rar5_vint(2));
    recovery_fields.extend_from_slice(b"RR");
    archive.extend_from_slice(&rar5_block(
        3,
        0x02,
        Some(recovery.len() as u64),
        &recovery_fields,
    ));
    archive.extend_from_slice(recovery);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(0)));
    archive
}

fn assert_valid_rar5_store(archive: Vec<u8>, expected: &[u8]) {
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Rar5, fuzz_limits())
            .expect("built-in RAR5 reader");
    let mut decoded_payload = Vec::new();
    loop {
        match reader.next_event().expect("synthetic RAR5 Store archive") {
            ReaderEvent::Data(bytes) => decoded_payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded_payload, expected);
}

#[cfg(feature = "rar")]
fn assert_valid_rar5_compressed() {
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut plain = vec![b'A'; 200];
    plain.push(b'\n');
    let name = b"compressed.txt";
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    archive.extend_from_slice(&rar5_block(1, 0, None, &rar5_vint(0)));
    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(plain.len() as u64));
    fields.extend_from_slice(&rar5_vint(0o100_644));
    fields.extend_from_slice(&crc32(&plain).to_le_bytes());
    fields.extend_from_slice(&rar5_vint(3 << 7));
    fields.extend_from_slice(&rar5_vint(1));
    fields.extend_from_slice(&rar5_vint(name.len() as u64));
    fields.extend_from_slice(name);
    archive.extend_from_slice(&rar5_block(2, 0x02, Some(PACKED.len() as u64), &fields));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(0)));
    assert_valid_rar5_store(archive, &plain);
}

#[cfg(feature = "rar")]
fn assert_valid_rar5_compressed_service() {
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut plain = vec![b'A'; 200];
    plain.push(b'\n');
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    archive.extend_from_slice(&rar5_block(1, 0, None, &rar5_vint(0)));
    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(plain.len() as u64));
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&crc32(&plain).to_le_bytes());
    fields.extend_from_slice(&rar5_vint(3 << 7));
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&rar5_vint(3));
    fields.extend_from_slice(b"CMT");
    archive.extend_from_slice(&rar5_block(3, 0x02, Some(PACKED.len() as u64), &fields));
    archive.extend_from_slice(PACKED);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(0)));

    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Rar5, fuzz_limits())
            .expect("built-in RAR5 compressed-service reader");
    let mut comment = None;
    loop {
        match reader
            .next_event()
            .expect("synthetic compressed RAR5 service")
        {
            ReaderEvent::ArchiveMetadata(metadata) => {
                if metadata.comment().is_some() {
                    comment = metadata.comment().map(ToOwned::to_owned);
                }
            },
            ReaderEvent::Done => break,
            ReaderEvent::Entry(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {
                panic!("RAR5 service payload escaped as entry data")
            },
            _ => return,
        }
    }
    assert_eq!(comment.as_deref(), Some(plain.as_slice()));
}

fn assert_valid_rar5_encrypted_metadata(archive: Vec<u8>) {
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Rar5, fuzz_limits())
            .expect("built-in RAR5 reader");
    loop {
        match reader
            .next_event()
            .expect("valid RAR5 encryption record metadata")
        {
            ReaderEvent::Entry(metadata) => {
                assert!(metadata.is_encrypted());
                break;
            },
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("encrypted RAR5 emitted payload before entry metadata"),
        }
    }
    let error = reader
        .next_event()
        .expect_err("encrypted RAR5 payload requires a decryption provider");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

fn rar5_header_encryption_archive(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let flags = u64::from(data.first().copied().unwrap_or_default() & 1);
    let mut fields = rar5_vint(0);
    fields.extend_from_slice(&rar5_vint(flags));
    fields.push(data.get(1).copied().unwrap_or(15));
    fields.extend(0_u8..16);
    if flags != 0 {
        fields.extend(16_u8..28);
    }

    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    archive.extend_from_slice(&rar5_block(4, 0, None, &fields));
    archive.extend_from_slice(&[0xa5; 16]);
    (archive, fields)
}

fn assert_valid_rar5_header_encryption_metadata(archive: Vec<u8>, fields: &[u8]) {
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Rar5, fuzz_limits())
            .expect("built-in RAR5 reader");
    let ReaderEvent::ArchiveMetadata(metadata) = reader
        .next_event()
        .expect("valid RAR5 header-encryption metadata")
    else {
        panic!("encrypted RAR5 header bytes escaped before archive metadata");
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
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

fn rar5_split_volume(
    index: u64,
    next_volume: bool,
    part: &[u8],
    logical_size: u64,
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    let name = b"split-fuzz.bin";
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = rar5_vint(0x03);
    main.extend_from_slice(&rar5_vint(index));
    archive.extend_from_slice(&rar5_block(1, 0, None, &main));

    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(logical_size));
    fields.extend_from_slice(&rar5_vint(0o100_644));
    fields.extend_from_slice(&checksum.to_le_bytes());
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&rar5_vint(1));
    fields.extend_from_slice(&rar5_vint(name.len() as u64));
    fields.extend_from_slice(name);
    let flags = 0x02 | (u64::from(split_before) * 0x08) | (u64::from(split_after) * 0x10);
    archive.extend_from_slice(&rar5_block(2, flags, Some(part.len() as u64), &fields));
    archive.extend_from_slice(part);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(u64::from(next_volume))));
    archive
}

fn rar5_fuzz_source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    let identity = SourceIdentity::try_new(format!("fuzz-rar5-volume-{index}").into_bytes())
        .expect("bounded RAR5 fuzz identity");
    Arc::new(MemoryReadAt::new(bytes, identity))
}

fn assert_valid_rar5_split(payload: &[u8]) {
    let split_at = payload.len() / 2;
    let (first, second) = payload.split_at(split_at);
    let first_volume = rar5_split_volume(
        0,
        true,
        first,
        payload.len() as u64,
        false,
        true,
        crc32(first),
    );
    let second_volume = rar5_split_volume(
        1,
        false,
        second,
        payload.len() as u64,
        true,
        false,
        crc32(payload),
    );
    let resolver = Arc::new(FuzzVolumeResolver {
        volumes: [(VolumeId::new(1), rar5_fuzz_source(1, second_volume))]
            .into_iter()
            .collect(),
    });
    let volumes = Arc::new(
        VolumeSet::new(
            rar5_fuzz_source(0, first_volume),
            resolver,
            SourceLimits::safe(),
        )
        .expect("bounded RAR5 fuzz volume set"),
    );
    let options = OpenOptions::new()
        .with_limits(fuzz_limits())
        .with_volumes(volumes);
    let mut reader =
        VolumeArchiveReader::with_options(&options).expect("synthetic split RAR5 volume reader");
    let mut decoded = Vec::new();
    let mut entries = 0;
    let mut ends = 0;
    loop {
        match reader.next_event().expect("synthetic split RAR5 event") {
            ReaderEvent::Entry(_) => entries += 1,
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => return,
        }
    }
    assert_eq!((entries, ends), (1, 1));
    assert_eq!(decoded, payload);
}

#[cfg(feature = "rar")]
fn drive_rar5_payload(data: &[u8]) {
    const KNOWN_BLOCK: [u8; 16] = [
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    const MAX_INPUT: usize = 64 * 1024;
    const MAX_OUTPUT: u64 = 64 * 1024;

    let limits = fuzz_limits()
        .with_entry_bytes(Some(MAX_OUTPUT))
        .with_decoded_total(Some(MAX_OUTPUT))
        .with_in_flight_bytes(Some(MAX_INPUT))
        .with_codec_memory(Some(4 * 1024 * 1024));
    let arbitrary = &data[..data.len().min(MAX_INPUT)];
    let declared = data
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(1, |bytes| u64::from(u16::from_le_bytes(bytes)) + 1);
    if let Ok(codec) =
        libarchive_oxide_rar::Rar5Decoder::new(arbitrary.len() as u64, declared, 128 * 1024, limits)
    {
        codec_decode_no_panic(codec, arbitrary);
    }

    let mut mutated = KNOWN_BLOCK;
    for (slot, byte) in mutated.iter_mut().zip(data.iter().copied()) {
        *slot ^= byte;
    }
    if let Ok(codec) =
        libarchive_oxide_rar::Rar5Decoder::new(mutated.len() as u64, 201, 128 * 1024, limits)
    {
        codec_decode_no_panic(codec, &mutated);
    }
}

fn is_rar5_container_seed(data: &[u8]) -> bool {
    const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
    data.windows(SIGNATURE.len())
        .take((1024usize * 1024).saturating_add(1))
        .any(|window| window == SIGNATURE)
}

/// RAR5 arbitrary container, physical-volume, and payload parsing plus valid complete and split Store envelopes must remain bounded and panic-free.
pub fn read_rar5(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let container = decoded.as_deref().unwrap_or(data);
    let is_container_seed = is_rar5_container_seed(container);
    #[cfg(feature = "rar")]
    if !is_container_seed {
        drive_rar5_payload(data);
    }
    drive_explicit_rar5(container);
    drive_physical_rar5(container);

    // Committed archive mutants already exercise their container, physical,
    // crypto, and payload paths above.
    // Rebuilding the same unrelated valid Store/split/service envelopes for every byte mutation only duplicates the arbitrary/payload-seed invariants thousands of times.
    if is_container_seed {
        return;
    }

    let payload = &data[..data.len().min(CODEC_ROUNDTRIP_MAX)];
    assert_valid_rar5_store(rar5_store_archive(payload, None, false), payload);
    assert_valid_rar5_encrypted_metadata(rar5_store_archive(payload, None, true));
    let (encrypted_headers, fields) = rar5_header_encryption_archive(data);
    assert_valid_rar5_header_encryption_metadata(encrypted_headers, &fields);
    assert_valid_rar5_split(payload);
    #[cfg(feature = "rar")]
    {
        assert_valid_rar5_compressed();
        assert_valid_rar5_compressed_service();
    }

    const ZERO_BLAKE2SP: [u8; 32] = [
        0xa6, 0xb9, 0xee, 0xcc, 0x25, 0x22, 0x7a, 0xd7, 0x88, 0xc9, 0x9d, 0x3f, 0x23, 0x6d, 0xeb,
        0xc8, 0xda, 0x40, 0x88, 0x49, 0xe9, 0xa5, 0x17, 0x89, 0x78, 0x72, 0x7a, 0x81, 0x45, 0x7f,
        0x72, 0x39,
    ];
    assert_valid_rar5_store(rar5_store_archive(&[0], Some(ZERO_BLAKE2SP), false), &[0]);
}

fn lha_crc16(data: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
    }
    crc
}

fn lha_store_archive(payload: &[u8]) -> Vec<u8> {
    const NAME: &[u8] = b"fuzz.bin";
    let size = u32::try_from(payload.len()).expect("capped LHA fuzz payload");
    let mut archive = Vec::with_capacity(24 + NAME.len() + payload.len());
    archive.push(u8::try_from(22 + NAME.len()).expect("fixed LHA header"));
    archive.push(0);
    archive.extend_from_slice(b"-lh0-");
    archive.extend_from_slice(&size.to_le_bytes());
    archive.extend_from_slice(&size.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.push(0x20);
    archive.push(0);
    archive.push(u8::try_from(NAME.len()).expect("fixed LHA name"));
    archive.extend_from_slice(NAME);
    archive.extend_from_slice(&lha_crc16(payload).to_le_bytes());
    archive[1] = archive[2..]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));
    archive.extend_from_slice(payload);
    archive.push(0);
    archive
}

fn assert_valid_lha_lh2() {
    static VALIDATED: OnceLock<()> = OnceLock::new();
    VALIDATED.get_or_init(|| {
        const ARCHIVE: &[u8] =
            include_bytes!("../../../libarchive_oxide/tests/fixtures/lha/compcol-lh2.lzh");
        let mut expected = Vec::new();
        for index in 0..60_u32 {
            expected
                .extend_from_slice(format!("line {index}: the quick brown fox jumps. ").as_bytes());
            if index % 20 == 0 {
                expected.extend(std::iter::repeat_n(b'=', 300));
            }
            expected.push(b'\n');
        }
        let mut reader = SeekArchiveReader::with_limits(Cursor::new(ARCHIVE), fuzz_limits())
            .expect("synthetic bounded LHA LH2 archive");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().expect("synthetic LHA LH2 events") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => return,
            }
        }
        assert_eq!(decoded, expected);
    });
}

/// LHA arbitrary level/method headers and a valid bounded Store envelope must not panic.
pub fn read_lha(data: &[u8]) {
    assert_valid_lha_lh2();
    if let Some(decoded) = decode_hex_corpus_seed(data) {
        drive_seek(&decoded);
    } else {
        drive_seek(data);
        let mut recognizable = data[..data.len().min(CODEC_ROUNDTRIP_MAX)].to_vec();
        recognizable.resize(recognizable.len().max(7), 0);
        recognizable[2..7].copy_from_slice(b"-lh5-");
        drive_seek(&recognizable);
    }

    let payload = &data[..data.len().min(CODEC_ROUNDTRIP_MAX)];
    let mut sfx = vec![0x90; 97];
    sfx[..2].copy_from_slice(b"MZ");
    sfx.extend_from_slice(&lha_store_archive(payload));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(sfx), fuzz_limits())
        .expect("synthetic LHA SFX Store archive");
    let mut decoded = Vec::new();
    let mut saw_prefix = false;
    loop {
        match reader.next_event().expect("synthetic LHA SFX events") {
            ReaderEvent::ArchiveMetadata(metadata) => {
                saw_prefix |= metadata.extensions().iter().any(|extension| {
                    extension.key() == b"sfx-prefix-bytes"
                        && extension.value() == 97_u64.to_le_bytes()
                });
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
    assert!(saw_prefix);
}

fn zip_fuzz_source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    let identity = SourceIdentity::try_new(format!("fuzz-zip-volume-{index}").into_bytes())
        .expect("bounded ZIP fuzz identity");
    Arc::new(MemoryReadAt::new(bytes, identity))
}

fn drive_zip_volumes(parts: &[&[u8]]) {
    let Some((primary, additional)) = parts.split_first() else {
        return;
    };
    let resolved = additional
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            (
                VolumeId::new(
                    u32::try_from(index + 1).expect("bounded ZIP fuzz volume identifier"),
                ),
                zip_fuzz_source(index + 1, bytes.to_vec()),
            )
        })
        .collect();
    let resolver = Arc::new(FuzzVolumeResolver { volumes: resolved });
    let Ok(volumes) = VolumeSet::new(
        zip_fuzz_source(0, primary.to_vec()),
        resolver,
        SourceLimits::safe(),
    ) else {
        return;
    };
    let options = OpenOptions::new()
        .with_limits(fuzz_limits())
        .with_volumes(Arc::new(volumes));
    let Ok(mut reader) = VolumeArchiveReader::with_options(&options) else {
        return;
    };
    while !matches!(reader.next_event(), Ok(ReaderEvent::Done) | Err(_)) {}
}

fn drive_zip_stream(data: &[u8]) {
    let Ok(mut reader) =
        ArchiveReader::with_format_and_limits(Cursor::new(data), FormatId::Zip, fuzz_limits())
    else {
        return;
    };
    while !matches!(reader.next_event(), Ok(ReaderEvent::Done) | Err(_)) {}
}

fn framed_zip_volumes(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut remaining = data.strip_prefix(ZIP_VOLUME_FRAME_MAGIC)?;
    let (&count, rest) = remaining.split_first()?;
    let count = usize::from(count);
    if !(1..=MAX_ZIP_FUZZ_VOLUMES).contains(&count) {
        return None;
    }
    remaining = rest;
    let mut volumes = Vec::new();
    volumes.try_reserve_exact(count).ok()?;
    for _ in 0..count {
        let length =
            usize::try_from(u32::from_le_bytes(remaining.get(..4)?.try_into().ok()?)).ok()?;
        remaining = remaining.get(4..)?;
        volumes.push(remaining.get(..length)?);
        remaining = remaining.get(length..)?;
    }
    remaining.is_empty().then_some(volumes)
}

fn valid_split_zip(payload: &[u8]) -> [Vec<u8>; 2] {
    const NAME: &[u8] = b"fuzz.bin";
    let size = u32::try_from(payload.len()).expect("capped split ZIP payload");
    let name_len = u16::try_from(NAME.len()).expect("fixed split ZIP name");
    let checksum = crc32(payload);
    let mut first = b"PK\x07\x08PK\x03\x04".to_vec();
    for value in [20_u16, 0, 0, 0, 0] {
        first.extend_from_slice(&value.to_le_bytes());
    }
    first.extend_from_slice(&checksum.to_le_bytes());
    first.extend_from_slice(&size.to_le_bytes());
    first.extend_from_slice(&size.to_le_bytes());
    first.extend_from_slice(&name_len.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(NAME);
    first.extend_from_slice(payload);

    let mut central = b"PK\x01\x02".to_vec();
    for value in [20_u16, 20, 0, 0, 0, 0] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    central.extend_from_slice(&checksum.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&name_len.to_le_bytes());
    for value in [0_u16, 0, 0, 0] {
        central.extend_from_slice(&value.to_le_bytes());
    }
    central.extend_from_slice(&0_u32.to_le_bytes());
    central.extend_from_slice(&4_u32.to_le_bytes());
    central.extend_from_slice(NAME);
    let central_size = u32::try_from(central.len()).expect("bounded split ZIP central directory");
    let mut terminal = central;
    terminal.extend_from_slice(b"PK\x05\x06");
    for value in [1_u16, 1, 1, 1] {
        terminal.extend_from_slice(&value.to_le_bytes());
    }
    terminal.extend_from_slice(&central_size.to_le_bytes());
    terminal.extend_from_slice(&0_u32.to_le_bytes());
    terminal.extend_from_slice(&0_u16.to_le_bytes());
    [first, terminal]
}

fn assert_valid_split_zip(payload: &[u8]) {
    let parts = valid_split_zip(payload);
    let resolver = Arc::new(FuzzVolumeResolver {
        volumes: [(VolumeId::new(1), zip_fuzz_source(1, parts[1].clone()))]
            .into_iter()
            .collect(),
    });
    let volumes = Arc::new(
        VolumeSet::new(
            zip_fuzz_source(0, parts[0].clone()),
            resolver,
            SourceLimits::safe(),
        )
        .expect("bounded split ZIP fuzz volume set"),
    );
    let mut reader = VolumeArchiveReader::with_options(
        &OpenOptions::new()
            .with_limits(fuzz_limits())
            .with_volumes(volumes),
    )
    .expect("synthetic split ZIP reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("synthetic split ZIP event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
}

fn valid_forward_deflate64_zip(payload: &[u8], descriptor: Option<bool>) -> Vec<u8> {
    const NAME: &[u8] = b"fuzz.d64";
    let mut compressed = Vec::new();
    if payload.is_empty() {
        compressed.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let mut remaining = payload;
        while !remaining.is_empty() {
            let count = remaining.len().min(usize::from(u16::MAX));
            compressed.push(u8::from(count == remaining.len()));
            let length = u16::try_from(count).expect("bounded Deflate64 block");
            compressed.extend_from_slice(&length.to_le_bytes());
            compressed.extend_from_slice(&(!length).to_le_bytes());
            compressed.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
        }
    }
    let size = u32::try_from(payload.len()).expect("capped Deflate64 payload");
    let compressed_size =
        u32::try_from(compressed.len()).expect("capped Deflate64 compressed payload");
    let name_len = u16::try_from(NAME.len()).expect("fixed Deflate64 fuzz name");
    let checksum = crc32(payload);
    let mut archive = b"PK\x03\x04".to_vec();
    for value in [21_u16, u16::from(descriptor.is_some()) << 3, 9, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in if descriptor.is_some() {
        [0, 0, 0]
    } else {
        [checksum, compressed_size, size]
    } {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_len.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(NAME);
    archive.extend_from_slice(&compressed);
    if let Some(signed) = descriptor {
        if signed {
            archive.extend_from_slice(b"PK\x07\x08");
        }
        for value in [checksum, compressed_size, size] {
            archive.extend_from_slice(&value.to_le_bytes());
        }
    }

    let central_offset = u32::try_from(archive.len()).expect("bounded Deflate64 local records");
    archive.extend_from_slice(b"PK\x01\x02");
    for value in [
        0x031e_u16,
        21,
        u16::from(descriptor.is_some()) << 3,
        9,
        0,
        0,
    ] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [checksum, compressed_size, size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_len.to_le_bytes());
    for value in [0_u16; 4] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(NAME);
    let central_size =
        u32::try_from(archive.len()).expect("bounded Deflate64 central directory") - central_offset;
    archive.extend_from_slice(b"PK\x05\x06");
    for value in [0_u16, 0, 1, 1] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

fn assert_valid_forward_deflate64(payload: &[u8]) {
    for descriptor in [None, Some(true), Some(false)] {
        let archive = valid_forward_deflate64_zip(payload, descriptor);
        let mut reader = ArchiveReader::with_format_and_limits(
            Cursor::new(archive),
            FormatId::Zip,
            fuzz_limits(),
        )
        .expect("synthetic forward Deflate64 reader");
        let mut decoded = Vec::new();
        loop {
            match reader
                .next_event()
                .expect("synthetic forward Deflate64 event")
            {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => return,
            }
        }
        assert_eq!(decoded, payload);
    }
}

fn valid_forward_zipcrypto_deflate64_zip(
    payload: &[u8],
    password: &[u8],
    descriptor: Option<bool>,
) -> Vec<u8> {
    fn update(keys: &mut [u32; 3], plaintext: u8) {
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
        keys[2] = crc32_byte(keys[2], keys[1].to_le_bytes()[3]);
    }

    fn stream_byte(keys: [u32; 3]) -> u8 {
        let key = keys[2].to_le_bytes();
        let value = u16::from_le_bytes([key[0], key[1]]) | 2;
        (value.wrapping_mul(value ^ 1) >> 8).to_le_bytes()[0]
    }

    let mut archive = valid_forward_deflate64_zip(payload, descriptor);
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("synthetic Deflate64 EOCD");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20]
            .try_into()
            .expect("Deflate64 central offset"),
    ))
    .expect("bounded Deflate64 central offset");
    let compressed = usize::try_from(u32::from_le_bytes(
        archive[central + 20..central + 24]
            .try_into()
            .expect("Deflate64 compressed-size field"),
    ))
    .expect("bounded Deflate64 compressed size");
    let checksum = u32::from_le_bytes(
        archive[central + 16..central + 20]
            .try_into()
            .expect("Deflate64 checksum field"),
    );
    let name = usize::from(u16::from_le_bytes(
        archive[26..28].try_into().expect("Deflate64 name length"),
    ));
    let extra = usize::from(u16::from_le_bytes(
        archive[28..30].try_into().expect("Deflate64 extra length"),
    ));
    let data = 30 + name + extra;
    let mut plaintext = vec![0x5a; 12];
    plaintext[11] = if descriptor.is_some() {
        archive[11]
    } else {
        checksum.to_le_bytes()[3]
    };
    plaintext.extend_from_slice(&archive[data..data + compressed]);
    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    for &byte in password {
        update(&mut keys, byte);
    }
    for byte in &mut plaintext {
        let clear = *byte;
        *byte ^= stream_byte(keys);
        update(&mut keys, clear);
    }
    let encrypted_size = u32::try_from(plaintext.len()).expect("bounded encrypted Deflate64");
    archive.splice(data..data + compressed, plaintext);

    let local_flags = u16::from_le_bytes(archive[6..8].try_into().expect("local flags")) | 1;
    archive[6..8].copy_from_slice(&local_flags.to_le_bytes());
    if descriptor.is_none() {
        archive[18..22].copy_from_slice(&encrypted_size.to_le_bytes());
    }
    if let Some(signed) = descriptor {
        let descriptor_start = data + usize::try_from(encrypted_size).expect("encrypted size");
        let compressed_offset = descriptor_start + if signed { 8 } else { 4 };
        archive[compressed_offset..compressed_offset + 4]
            .copy_from_slice(&encrypted_size.to_le_bytes());
    }
    let shifted_central = central + 12;
    let central_flags = u16::from_le_bytes(
        archive[shifted_central + 8..shifted_central + 10]
            .try_into()
            .expect("central flags"),
    ) | 1;
    archive[shifted_central + 8..shifted_central + 10]
        .copy_from_slice(&central_flags.to_le_bytes());
    archive[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&encrypted_size.to_le_bytes());
    let shifted_eocd = eocd + 12;
    archive[shifted_eocd + 16..shifted_eocd + 20].copy_from_slice(
        &u32::try_from(shifted_central)
            .expect("bounded shifted central directory")
            .to_le_bytes(),
    );
    archive
}

fn assert_valid_forward_zstd(payload: &[u8]) {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Zstd, fuzz_limits());
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"fuzz.zst".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();
    writer
        .start_entry(&metadata)
        .expect("synthetic forward Zstandard entry");
    writer
        .write_data(payload)
        .expect("synthetic forward Zstandard payload");
    writer
        .end_entry()
        .expect("synthetic forward Zstandard end entry");
    let archive = writer
        .finish()
        .expect("synthetic forward Zstandard archive");
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Zip, fuzz_limits())
            .expect("synthetic forward Zstandard reader");
    let mut decoded = Vec::new();
    loop {
        match reader
            .next_event()
            .expect("synthetic forward Zstandard event")
        {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
}

fn descriptor_zip_to_known_size(mut archive: Vec<u8>) -> Vec<u8> {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("synthetic ZIP end record");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20]
            .try_into()
            .expect("synthetic ZIP central offset"),
    ))
    .expect("bounded synthetic ZIP central offset");
    let descriptor = central - 16;
    assert_eq!(&archive[descriptor..descriptor + 4], b"PK\x07\x08");
    let flags = u16::from_le_bytes(archive[6..8].try_into().expect("local flags")) & !8;
    archive[6..8].copy_from_slice(&flags.to_le_bytes());
    let sizes = archive[descriptor + 4..descriptor + 16].to_vec();
    archive[14..26].copy_from_slice(&sizes);
    archive.drain(descriptor..central);

    let central = descriptor;
    let flags = u16::from_le_bytes(
        archive[central + 8..central + 10]
            .try_into()
            .expect("central flags"),
    ) & !8;
    archive[central + 8..central + 10].copy_from_slice(&flags.to_le_bytes());
    let shifted_eocd = eocd - 16;
    archive[shifted_eocd + 16..shifted_eocd + 20].copy_from_slice(
        &u32::try_from(central)
            .expect("bounded shifted central offset")
            .to_le_bytes(),
    );
    archive
}

fn assert_valid_forward_lzma(payload: &[u8]) {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Lzma, fuzz_limits());
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"fuzz.lzma".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();
    writer
        .start_entry(&metadata)
        .expect("synthetic forward LZMA entry");
    writer
        .write_data(payload)
        .expect("synthetic forward LZMA payload");
    writer
        .end_entry()
        .expect("synthetic forward LZMA end entry");
    let descriptor = writer.finish().expect("synthetic forward LZMA archive");
    let archive = if payload.first().is_some_and(|byte| byte & 1 != 0) {
        descriptor_zip_to_known_size(descriptor)
    } else {
        descriptor
    };
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Zip, fuzz_limits())
            .expect("synthetic forward LZMA reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("synthetic forward LZMA event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
}

fn assert_valid_forward_ppmd(payload: &[u8]) {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Ppmd8, fuzz_limits());
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"fuzz.ppmd".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();
    writer
        .start_entry(&metadata)
        .expect("synthetic forward PPMd entry");
    writer
        .write_data(payload)
        .expect("synthetic forward PPMd payload");
    writer
        .end_entry()
        .expect("synthetic forward PPMd end entry");
    let descriptor = writer.finish().expect("synthetic forward PPMd archive");
    let archive = if payload.first().is_some_and(|byte| byte & 1 != 0) {
        descriptor_zip_to_known_size(descriptor)
    } else {
        descriptor
    };
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Zip, fuzz_limits())
            .expect("synthetic forward PPMd reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("synthetic forward PPMd event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
}

fn assert_valid_forward_xz(payload: &[u8]) {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Xz, fuzz_limits());
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"fuzz.xz".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();
    writer
        .start_entry(&metadata)
        .expect("synthetic forward XZ entry");
    writer
        .write_data(payload)
        .expect("synthetic forward XZ payload");
    writer.end_entry().expect("synthetic forward XZ end entry");
    let archive = writer.finish().expect("synthetic forward XZ archive");
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(archive), FormatId::Zip, fuzz_limits())
            .expect("synthetic forward XZ reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("synthetic forward XZ event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(decoded, payload);
}

fn assert_valid_forward_zipcrypto(payload: &[u8]) {
    const PASSWORD: &[u8] = b"fuzz ZipCrypto password";

    fn assert_archive(archive: Vec<u8>, payload: &[u8]) {
        const PASSWORD: &[u8] = b"fuzz ZipCrypto password";
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Zip))
            .with_limits(fuzz_limits())
            .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::from(
                PASSWORD,
            )])));
        let mut reader =
            ArchiveReader::with_options(Cursor::new(archive), &options).expect("ZipCrypto reader");
        let mut decoded = Vec::new();
        loop {
            match reader
                .next_event()
                .expect("synthetic forward ZipCrypto event")
            {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => return,
            }
        }
        assert_eq!(decoded, payload);
    }

    for method in [
        ZipMethod::Store,
        ZipMethod::Deflate,
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let mut writer = ArchiveWriter::with_zipcrypto_password(
            Vec::new(),
            method,
            SecretBytes::from(PASSWORD),
            fuzz_limits(),
        );
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"fuzz.enc".to_vec()),
        )
        .size(Some(payload.len() as u64))
        .build();
        writer
            .start_entry(&metadata)
            .expect("synthetic forward ZipCrypto entry");
        for chunk in payload.chunks(31) {
            writer
                .write_data(chunk)
                .expect("synthetic forward ZipCrypto payload");
        }
        writer
            .end_entry()
            .expect("synthetic forward ZipCrypto end entry");
        let archive = writer
            .finish()
            .expect("synthetic forward ZipCrypto archive");
        assert_archive(archive, payload);
    }
    for descriptor in [None, Some(true), Some(false)] {
        assert_archive(
            valid_forward_zipcrypto_deflate64_zip(payload, PASSWORD, descriptor),
            payload,
        );
    }
}

fn assert_valid_forward_aes(payload: &[u8]) {
    const PASSWORD: &[u8] = b"fuzz WinZip AES password";

    for method in [
        ZipMethod::Store,
        ZipMethod::Deflate,
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let mut writer = ArchiveWriter::with_zip_password(
            Vec::new(),
            method,
            SecretBytes::from(PASSWORD),
            fuzz_limits(),
        );
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"fuzz.aes".to_vec()),
        )
        .size(Some(payload.len() as u64))
        .build();
        writer
            .start_entry(&metadata)
            .expect("synthetic forward AES entry");
        for chunk in payload.chunks(31) {
            writer
                .write_data(chunk)
                .expect("synthetic forward AES payload");
        }
        writer.end_entry().expect("synthetic forward AES end entry");
        let archive = writer.finish().expect("synthetic forward AES archive");
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Zip))
            .with_limits(fuzz_limits())
            .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::from(
                PASSWORD,
            )])));
        let mut reader =
            ArchiveReader::with_options(Cursor::new(archive), &options).expect("AES reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().expect("synthetic forward AES event") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => return,
            }
        }
        assert_eq!(decoded, payload);
    }
}

/// ZIP forward-only, seek, and volume decoders must not panic on arbitrary input.
pub fn read_zip(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let bytes = decoded.as_deref().unwrap_or(data);
    drive_zip_stream(bytes);
    drive_seek(bytes);
    if let Some(parts) = framed_zip_volumes(bytes) {
        drive_zip_volumes(&parts);
    }
    assert_valid_split_zip(&data[..data.len().min(CODEC_ROUNDTRIP_MAX)]);
    assert_valid_forward_deflate64(&data[..data.len().min(DEFLATE64_ROUNDTRIP_MAX)]);
    assert_valid_forward_zstd(&data[..data.len().min(ZSTD_ROUNDTRIP_MAX)]);
    assert_valid_forward_lzma(&data[..data.len().min(XZ_ROUNDTRIP_MAX)]);
    assert_valid_forward_ppmd(&data[..data.len().min(XZ_ROUNDTRIP_MAX)]);
    assert_valid_forward_xz(&data[..data.len().min(XZ_ROUNDTRIP_MAX)]);
    assert_valid_forward_zipcrypto(&data[..data.len().min(ZIPCRYPTO_ROUNDTRIP_MAX)]);
    assert_valid_forward_aes(&data[..data.len().min(ZIPCRYPTO_ROUNDTRIP_MAX)]);
}

/// 7z seek decoder: arbitrary indexes and coder metadata must not panic.
pub fn read_7z(data: &[u8]) {
    if let Some(decoded) = decode_hex_corpus_seed(data) {
        drive_seek(&decoded);
    } else {
        drive_seek(data);
    }
}

/// Lets text-only patches carry exact binary archive seeds.
/// Ordinary fuzzer input is passed through unchanged; only an even-length ASCII `hex:` corpus record is decoded.
fn decode_hex_corpus_seed(data: &[u8]) -> Option<Vec<u8>> {
    let hex = data.strip_prefix(b"hex:")?;
    let hex = hex.strip_suffix(b"\n").unwrap_or(hex);
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut decoded = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn iso_fuzz_both_u16(value: u16) -> [u8; 4] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [little[0], little[1], big[0], big[1]]
}

fn iso_fuzz_both_u32(value: u32) -> [u8; 8] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [
        little[0], little[1], little[2], little[3], big[0], big[1], big[2], big[3],
    ]
}

fn iso_fuzz_record(identifier: &[u8], lba: u32, size: u32, flags: u8) -> Vec<u8> {
    let padding = usize::from(identifier.len().is_multiple_of(2));
    let length = 33 + identifier.len() + padding;
    let mut record = vec![0; length];
    record[0] = u8::try_from(length).expect("bounded ISO fuzz directory record");
    record[2..10].copy_from_slice(&iso_fuzz_both_u32(lba));
    record[10..18].copy_from_slice(&iso_fuzz_both_u32(size));
    record[18..25].copy_from_slice(&[126, 7, 19, 12, 0, 0, 0]);
    record[25] = flags;
    record[28..32].copy_from_slice(&iso_fuzz_both_u16(1));
    record[32] = u8::try_from(identifier.len()).expect("bounded ISO fuzz identifier");
    record[33..33 + identifier.len()].copy_from_slice(identifier);
    record
}

fn iso_multi_extent_envelope(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let payload = if data.is_empty() {
        vec![0]
    } else {
        data[..data.len().min(1024)].to_vec()
    };
    let split = payload.len().div_ceil(2);
    let mut image = vec![0; 24 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_fuzz_both_u32(24));
    pvd[120..124].copy_from_slice(&iso_fuzz_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_fuzz_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_fuzz_both_u16(2048));
    let root = iso_fuzz_record(&[0], 20, 2048, 0x02);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    records.extend_from_slice(&iso_fuzz_record(&[0], 20, 2048, 0x02));
    records.extend_from_slice(&iso_fuzz_record(&[1], 20, 2048, 0x02));
    records.extend_from_slice(&iso_fuzz_record(
        b"FUZZ.BIN;1",
        21,
        u32::try_from(split).expect("bounded first ISO fuzz section"),
        0x80,
    ));
    records.extend_from_slice(&iso_fuzz_record(
        b"FUZZ.BIN;1",
        23,
        u32::try_from(payload.len() - split).expect("bounded final ISO fuzz section"),
        0,
    ));
    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[21 * SECTOR..21 * SECTOR + split].copy_from_slice(&payload[..split]);
    image[22 * SECTOR..23 * SECTOR].fill(0xa5);
    image[23 * SECTOR..23 * SECTOR + payload.len() - split].copy_from_slice(&payload[split..]);
    (image, payload)
}

fn iso_interleaved_envelope(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let source = if data.is_empty() {
        &[0][..]
    } else {
        &data[..data.len().min(1024)]
    };
    let payload = source
        .iter()
        .copied()
        .cycle()
        .take(4097)
        .collect::<Vec<_>>();
    let mut image = vec![0; 27 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_fuzz_both_u32(27));
    pvd[120..124].copy_from_slice(&iso_fuzz_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_fuzz_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_fuzz_both_u16(2048));
    let root = iso_fuzz_record(&[0], 20, 2048, 0x02);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    records.extend_from_slice(&iso_fuzz_record(&[0], 20, 2048, 0x02));
    records.extend_from_slice(&iso_fuzz_record(&[1], 20, 2048, 0x02));
    let mut file = iso_fuzz_record(b"STRIPED.BIN;1", 21, 4097, 0);
    file[26] = 1;
    file[27] = 1;
    records.extend_from_slice(&file);
    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&payload[..SECTOR]);
    image[22 * SECTOR..23 * SECTOR].fill(0xa5);
    image[23 * SECTOR..24 * SECTOR].copy_from_slice(&payload[SECTOR..2 * SECTOR]);
    image[24 * SECTOR..25 * SECTOR].fill(0x5a);
    image[25 * SECTOR] = payload[2 * SECTOR];
    (image, payload)
}

fn iso_extended_attribute_envelope(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let (mut image, payload) = iso_interleaved_envelope(data);
    let record = image
        .windows(b"STRIPED.BIN;1".len())
        .position(|bytes| bytes == b"STRIPED.BIN;1")
        .and_then(|position| position.checked_sub(33))
        .expect("structured ISO file record");
    image[record + 1] = 1;
    image[record + 25] |= 0x10;
    image[record + 26] = 0;
    image[record + 27] = 0;

    let application = &data[..data.len().min(1024)];
    let mut attributes = [0_u8; SECTOR];
    attributes[0..4].copy_from_slice(&iso_fuzz_both_u16(1000));
    attributes[4..8].copy_from_slice(&iso_fuzz_both_u16(1001));
    attributes[8..10].copy_from_slice(&0xfeaa_u16.to_be_bytes());
    attributes[10..27].copy_from_slice(b"2026081501020300\0");
    attributes[27..44].copy_from_slice(b"2026081602030400\x04");
    attributes[84..116].fill(b' ');
    attributes[180] = 1;
    attributes[246..250].copy_from_slice(&iso_fuzz_both_u16(
        u16::try_from(application.len()).expect("bounded application use"),
    ));
    attributes[250..250 + application.len()].copy_from_slice(application);
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&attributes);
    image[22 * SECTOR..22 * SECTOR + payload.len()].copy_from_slice(&payload);
    (image, payload)
}

fn assert_iso_envelope(image: Vec<u8>, payload: &[u8], path: &[u8]) {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(image), fuzz_limits())
        .expect("synthetic structured ISO image");
    let mut decoded = Vec::new();
    let mut entries = 0;
    loop {
        match reader.next_event().expect("structured ISO events") {
            ReaderEvent::Entry(metadata) => {
                entries += 1;
                assert_eq!(metadata.path().as_bytes(), path);
                assert_eq!(metadata.size(), Some(payload.len() as u64));
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => return,
        }
    }
    assert_eq!(entries, 1);
    assert_eq!(decoded, payload);
}

/// ISO seek decoder: arbitrary volume/directory records plus recognizable multi-extent, interleaved, and extended-attribute envelopes must remain bounded and panic-free.
pub fn read_iso(data: &[u8]) {
    drive_seek(data);
    let (image, payload) = iso_multi_extent_envelope(data);
    assert_iso_envelope(image, &payload, b"FUZZ.BIN");
    let (image, payload) = iso_interleaved_envelope(data);
    assert_iso_envelope(image, &payload, b"STRIPED.BIN");
    let (image, payload) = iso_extended_attribute_envelope(data);
    assert_iso_envelope(image, &payload, b"STRIPED.BIN");
}

/// UDF seek decoder: arbitrary anchors, physical/metadata/virtual maps, VATs, ICBs, and extents must remain bounded and panic-free.
pub fn read_udf(data: &[u8]) {
    drive_seek(data);
}

struct FuzzVolumeResolver {
    volumes: BTreeMap<VolumeId, Arc<dyn ReadAt>>,
}

impl VolumeResolver for FuzzVolumeResolver {
    fn resolve(&self, volume: VolumeId) -> std::io::Result<Option<Arc<dyn ReadAt>>> {
        Ok(self.volumes.get(&volume).cloned())
    }
}

/// Parses the stable multi-volume corpus envelope:
/// `OXCV 01`, one-byte volume count, then repeated little-endian `u32` length and exact volume bytes.
/// Malformed envelopes fall back to ordinary single-CAB fuzzing so every input still exercises a parser.
fn framed_cab_volumes(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut remaining = data.strip_prefix(CAB_VOLUME_FRAME_MAGIC)?;
    let (&count, rest) = remaining.split_first()?;
    let count = usize::from(count);
    if !(1..=MAX_CAB_FUZZ_VOLUMES).contains(&count) {
        return None;
    }
    remaining = rest;
    let mut volumes = Vec::new();
    volumes.try_reserve_exact(count).ok()?;
    for _ in 0..count {
        let length_bytes = remaining.get(..4)?;
        let length = usize::try_from(u32::from_le_bytes(length_bytes.try_into().ok()?)).ok()?;
        remaining = remaining.get(4..)?;
        let volume = remaining.get(..length)?;
        volumes.push(volume);
        remaining = remaining.get(length..)?;
    }
    remaining.is_empty().then_some(volumes)
}

fn cab_fuzz_source(index: usize, bytes: &[u8]) -> Option<Arc<dyn ReadAt>> {
    let identity = SourceIdentity::try_new(format!("fuzz-cab-volume-{index}").into_bytes()).ok()?;
    Some(Arc::new(MemoryReadAt::new(bytes.to_vec(), identity)))
}

fn drive_cab_volumes(volumes: &[&[u8]]) {
    let Some(primary_bytes) = volumes.first() else {
        return;
    };
    let Some(primary) = cab_fuzz_source(0, primary_bytes) else {
        return;
    };
    let mut resolved = BTreeMap::new();
    for (index, bytes) in volumes.iter().enumerate().skip(1) {
        let Ok(volume_index) = u32::try_from(index) else {
            return;
        };
        let Some(source) = cab_fuzz_source(index, bytes) else {
            return;
        };
        resolved.insert(VolumeId::new(volume_index), source);
    }
    let resolver = Arc::new(FuzzVolumeResolver { volumes: resolved });
    let Ok(source) = VolumeSet::new(primary, resolver, SourceLimits::safe()) else {
        return;
    };
    let Ok(mut reader) = CabVolumeReader::with_limits(&source, fuzz_limits()) else {
        return;
    };
    let mut events = 0_usize;
    let mut payload = 0_u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

/// CAB single/volume-set decoders: arbitrary tables, continuation chains, and CFDATA blocks must remain bounded and panic-free.
pub fn read_cab(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let bytes = decoded.as_deref().unwrap_or(data);
    if let Some(volumes) = framed_cab_volumes(bytes) {
        drive_cab_volumes(&volumes);
    } else {
        drive_seek(bytes);
    }
}

/// XAR seek decoder: arbitrary headers, XML TOCs, extents, and codecs must not panic.
pub fn read_xar(data: &[u8]) {
    if let Some(decoded) = decode_hex_corpus_seed(data) {
        drive_seek(&decoded);
    } else {
        drive_seek(data);
    }
}

/// RPM structure, payload-integrity, and nested archive validation must stay bounded and panic-free.
pub fn package_rpm(data: &[u8]) {
    static KEY: OnceLock<Option<RpmOpenPgpPublicKey>> = OnceLock::new();
    let decoded = decode_hex_corpus_seed(data);
    let bytes = decoded.as_deref().unwrap_or(data);
    codec_decode_no_panic(RpmDecoder::new(fuzz_limits()), bytes);
    if let Ok(reader) = FilterReader::with_filter(
        Cursor::new(bytes),
        libarchive_oxide_core::FilterId::Rpm,
        fuzz_limits(),
    ) {
        let _ = read_capped(reader, CODEC_CAP);
    }
    let mut verifier = PackageVerifier::default().with_limits(fuzz_limits());
    if let Some(key) = KEY
        .get_or_init(|| RpmOpenPgpPublicKey::from_bytes(RPM_PUBLIC_KEY).ok())
        .clone()
    {
        verifier = verifier.with_rpm_openpgp_public_key(key);
    }
    let _report = verifier.rpm(Cursor::new(bytes));
}

/// Alpine concatenated-gzip/tar validation must stay bounded and panic-free.
pub fn package_alpine(data: &[u8]) {
    static KEY: OnceLock<Option<AlpineRsaPublicKey>> = OnceLock::new();
    let bytes = decode_hex_corpus_seed(data).unwrap_or_else(|| data.to_vec());
    let mut verifier = PackageVerifier::default().with_limits(fuzz_limits());
    if let Some(key) = KEY
        .get_or_init(|| {
            AlpineRsaPublicKey::from_pem(ALPINE_KEY_ID.to_vec(), ALPINE_PUBLIC_KEY).ok()
        })
        .clone()
    {
        verifier = verifier.with_alpine_rsa_public_key(key);
    }
    let _report = verifier.alpine_apk(Cursor::new(bytes));
}

/// ZIP ecosystem integrity validation across all profiles must stay bounded and panic-free.
pub fn package_zip(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let input = decoded.as_deref().unwrap_or(data);
    let (selector, bytes) = input
        .split_first()
        .map_or((0, input), |(head, tail)| (*head, tail));
    let profile = match selector % 4 {
        0 => ZipPackageProfile::Jar,
        1 => ZipPackageProfile::NuGet,
        2 => ZipPackageProfile::Wheel,
        _ => ZipPackageProfile::Epub,
    };
    let _report = PackageVerifier::default()
        .with_limits(fuzz_limits())
        .zip(profile, Cursor::new(bytes));
}

const CTS_APK_V4: &[u8] = include_bytes!(
    "../../../libarchive_oxide-package/tests/fixtures/android_apk_v4/v4-digest-v2v3.apk"
);
const CTS_APK_V4_IDSIG: &[u8] = include_bytes!(
    "../../../libarchive_oxide-package/tests/fixtures/android_apk_v4/v4-digest-v2v3.apk.idsig"
);

/// APK, IPA, MSIX, and explicit APK-v4 sidecar validators must reject hostile signing blocks and metadata without panics.
pub fn package_app(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let input = decoded.as_deref().unwrap_or(data);
    if let Some((&0xfe, mutations)) = input.split_first() {
        let mut idsig = CTS_APK_V4_IDSIG.to_vec();
        for mutation in mutations.as_chunks::<5>().0.iter().take(64) {
            let Some(offset_bytes) = mutation.get(..4) else {
                continue;
            };
            let Ok(offset) = <[u8; 4]>::try_from(offset_bytes) else {
                continue;
            };
            let offset = usize::try_from(u32::from_le_bytes(offset)).unwrap_or(usize::MAX);
            let Some(mask) = mutation.get(4).copied() else {
                continue;
            };
            if let Some(byte) = idsig.get_mut(offset % CTS_APK_V4_IDSIG.len()) {
                *byte ^= mask;
            }
        }
        let _report = PackageVerifier::default()
            .with_limits(fuzz_limits())
            .android_apk_with_v4_sidecar(Cursor::new(CTS_APK_V4), Cursor::new(idsig));
        return;
    }
    if let Some((&0xff, envelope)) = input.split_first() {
        let Some(length_bytes) = envelope.get(..4) else {
            return;
        };
        let Ok(length_bytes) = <[u8; 4]>::try_from(length_bytes) else {
            return;
        };
        let apk_length = usize::try_from(u32::from_le_bytes(length_bytes)).unwrap_or(usize::MAX);
        let Some(payload) = envelope.get(4..) else {
            return;
        };
        let split = apk_length.min(payload.len());
        let (apk, idsig) = payload.split_at(split);
        let _report = PackageVerifier::default()
            .with_limits(fuzz_limits())
            .android_apk_with_v4_sidecar(Cursor::new(apk), Cursor::new(idsig));
        return;
    }
    let (selector, bytes) = if input.starts_with(b"PK") {
        let selector = if input
            .windows(b"AppxBlockMap.xml".len())
            .any(|window| window == b"AppxBlockMap.xml")
        {
            2
        } else if input
            .windows(b"Payload/".len())
            .any(|window| window == b"Payload/")
        {
            1
        } else {
            0
        };
        (selector, input)
    } else {
        input
            .split_first()
            .map_or((0, input), |(head, tail)| (*head, tail))
    };
    let profile = match selector % 3 {
        0 => AppPackageProfile::AndroidApk,
        1 => AppPackageProfile::Ipa,
        _ => AppPackageProfile::Msix,
    };
    let _report = PackageVerifier::default()
        .with_limits(fuzz_limits())
        .app(profile, Cursor::new(bytes));
}

/// Safe-extraction planning must classify arbitrary platform/path spellings without escape or panic.
pub fn extraction_plan(data: &[u8]) {
    let mut name = data
        .iter()
        .copied()
        .take(96)
        .map(|byte| if byte == 0 { b'_' } else { byte })
        .collect::<Vec<_>>();
    while matches!(name.last(), Some(b'\r' | b'\n')) {
        name.pop();
    }
    if name.is_empty() {
        name.extend_from_slice(b"entry");
    }
    let selector = name[0] % 4;
    let mut alias = match selector {
        0 => name
            .iter()
            .map(|byte| byte.to_ascii_uppercase())
            .collect::<Vec<_>>(),
        1 => {
            let mut candidate = name.clone();
            candidate.push(b'.');
            candidate
        },
        2 => {
            let mut candidate = name.clone();
            candidate.push(b' ');
            candidate
        },
        _ => b"cafe\xcc\x81.txt".to_vec(),
    };
    if selector == 3 {
        name = "café.txt".as_bytes().to_vec();
    }
    alias.truncate(96);
    let body = data.iter().copied().rev().take(512).collect::<Vec<_>>();
    let Ok(mut writer) =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Tar, fuzz_limits())
    else {
        return;
    };
    for path in [name, alias] {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path))
            .size(Some(body.len() as u64))
            .mode(Some(0o644))
            .build();
        if writer.start_entry(&metadata).is_err()
            || writer.write_data(&body).is_err()
            || writer.end_entry().is_err()
        {
            return;
        }
    }
    let Ok(archive) = writer.finish() else {
        return;
    };
    let Ok(mut session) = ArchiveEngine::new()
        .with_limits(fuzz_limits())
        .with_spool_limits(64 * 1024, 2 * 1024 * 1024)
        .prepare(Cursor::new(archive))
    else {
        return;
    };
    if let Ok(plan) = session.plan(Policy::safe()) {
        for entry in plan.entries() {
            let _ = (entry.descriptor(), entry.disposition());
        }
    }
}

/// Synthesized archive member.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEntry {
    /// Raw candidate name (normalized before use).
    pub name: Vec<u8>,
    /// Raw candidate payload (bounded before use).
    pub data: Vec<u8>,
}

fn normalize_files(entries: &[FuzzEntry]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for (index, entry) in entries.iter().take(MAX_ROUNDTRIP_ENTRIES).enumerate() {
        let mut name: Vec<u8> = entry
            .name
            .iter()
            .copied()
            .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            .take(MAX_NAME_LEN)
            .collect();
        while matches!(name.first(), Some(b'.' | b'-')) {
            name.remove(0);
        }
        if name.is_empty() {
            name = format!("f{index}").into_bytes();
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            let mut unique = format!("{index}_").into_bytes();
            unique.extend_from_slice(&name);
            if !seen.insert(unique.to_ascii_lowercase()) {
                continue;
            }
            name = unique;
        }
        output.push((
            name,
            entry
                .data
                .iter()
                .copied()
                .take(MAX_ROUNDTRIP_DATA)
                .collect(),
        ));
    }
    output
}

fn metadata(name: &[u8], size: usize) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
        .size(Some(size as u64))
        .mode(Some(0o644))
        .build()
}

fn expected_map(files: &[(Vec<u8>, Vec<u8>)]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    files.iter().cloned().collect()
}

macro_rules! collect_events {
    ($reader:expr) => {{
        let reader = &mut $reader;
        let mut files = BTreeMap::new();
        let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
        loop {
            match reader.next_event() {
                Ok(ReaderEvent::Entry(metadata)) => {
                    current = (metadata.kind() == EntryKind::File)
                        .then(|| (metadata.path().as_bytes().to_vec(), Vec::new()));
                },
                Ok(ReaderEvent::Data(bytes)) => match current.as_mut() {
                    Some((_, body)) => body.extend_from_slice(bytes),
                    None => break None,
                },
                Ok(ReaderEvent::EndEntry) => {
                    if let Some((name, body)) = current.take() {
                        files.insert(name, body);
                    }
                },
                Ok(ReaderEvent::ArchiveMetadata(_)) => {},
                Ok(ReaderEvent::Done) => break Some(files),
                Ok(_) | Err(_) => break None,
            }
        }
    }};
}

fn collect_sequential(bytes: Vec<u8>) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut reader = ArchiveReader::with_limits(Cursor::new(bytes), fuzz_limits());
    collect_events!(reader)
}

fn collect_seek(bytes: Vec<u8>) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), fuzz_limits()).ok()?;
    collect_events!(reader)
}

fn roundtrip_sequential(entries: &[FuzzEntry], format: FormatId) {
    let files = normalize_files(entries);
    let Ok(mut writer) = ArchiveWriter::with_format_and_limits(Vec::new(), format, fuzz_limits())
    else {
        return;
    };
    for (name, body) in &files {
        writer
            .start_entry(&metadata(name, body.len()))
            .expect("normalized v0.2 metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("bounded data command must be accepted");
        }
        writer
            .end_entry()
            .expect("declared size must close exactly");
    }
    let archive = writer.finish().expect("streaming writer must finish");
    assert_eq!(
        collect_sequential(archive),
        Some(expected_map(&files)),
        "{format:?} streaming read/write"
    );
}

fn roundtrip_seek(entries: &[FuzzEntry], format: FormatId) {
    let files = normalize_files(entries);
    let destination = Cursor::new(Vec::new());
    let Ok(mut writer) = SeekArchiveWriter::with_format(destination, format, fuzz_limits()) else {
        return;
    };
    for (name, body) in &files {
        writer
            .start_entry(&metadata(name, body.len()))
            .expect("normalized seek metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("seek writer data command must be accepted");
        }
        writer.end_entry().expect("seek entry must close");
    }
    let archive = writer
        .finish()
        .expect("seek writer must finish")
        .into_inner();
    assert_eq!(
        collect_seek(archive),
        Some(expected_map(&files)),
        "{format:?} seek read/write"
    );
}

fn roundtrip_warc(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    if files.is_empty() {
        return;
    }
    let Ok(mut writer) =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Warc, fuzz_limits())
    else {
        return;
    };
    for (index, (name, body)) in files.iter().enumerate() {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.clone()))
                .size(Some(body.len() as u64))
                .mode(Some(0o644))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Type".to_vec(),
                    b"resource".to_vec(),
                ))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Record-ID".to_vec(),
                    format!("<urn:uuid:fuzz-{index:08}>").into_bytes(),
                ))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Date".to_vec(),
                    b"2000-01-01T00:00:00Z".to_vec(),
                ))
                .build();
        writer
            .start_entry(&metadata)
            .expect("bounded WARC metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("bounded WARC data command must be accepted");
        }
        writer
            .end_entry()
            .expect("WARC declared size must close exactly");
    }
    let archive = writer.finish().expect("WARC writer must finish");
    let actual = collect_sequential(archive).expect("WARC writer output must decode");
    assert_eq!(
        actual.into_values().collect::<Vec<_>>(),
        files.into_iter().map(|(_, body)| body).collect::<Vec<_>>(),
        "WARC streaming read/write"
    );
}

/// tar and WARC streaming round trips.
pub fn roundtrip_tar(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Tar);
    roundtrip_warc(entries);
}

/// cpio streaming round trip.
pub fn roundtrip_cpio(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Cpio);
}

/// ar streaming round trip.
pub fn roundtrip_ar(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Ar);
}

/// 7z seek-back writer and streaming reader round trip.
pub fn roundtrip_7z(entries: &[FuzzEntry]) {
    roundtrip_seek(entries, FormatId::SevenZip);
}

/// ISO seek-back writer and streaming reader round trip.
pub fn roundtrip_iso(entries: &[FuzzEntry]) {
    roundtrip_seek(entries, FormatId::Iso9660);
}

/// XAR Store/zlib/BZip2 seek writer and reader round trip.
pub fn roundtrip_xar(entries: &[FuzzEntry]) {
    let selector = entries
        .first()
        .and_then(|entry| entry.data.first().copied())
        .unwrap_or(0);
    let compression = match selector % 3 {
        0 => XarCompression::Store,
        1 => XarCompression::Zlib,
        _ => XarCompression::Bzip2,
    };
    let files = normalize_files(entries);
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_limits(fuzz_limits())
        .with_format_options(Some(FormatWriteOptions::Xar(
            XarWriteOptions::new().with_compression(compression),
        )));
    let Ok(mut writer) = ArchiveEngine::new().create_seek(Cursor::new(Vec::new()), options) else {
        // The no-default-feature replay build intentionally exercises the typed feature-off BZip2 path.
        return;
    };
    for (name, body) in &files {
        writer
            .start_entry(&metadata(name, body.len()))
            .expect("normalized XAR metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("bounded XAR data command must be accepted");
        }
        writer.end_entry().expect("XAR entry must close");
    }
    let archive = writer
        .finish()
        .expect("XAR writer must finish")
        .into_inner();
    assert_eq!(
        collect_seek(archive),
        Some(expected_map(&files)),
        "XAR {compression:?} seek read/write"
    );
}

fn codec_decode_no_panic<C: Codec>(mut codec: C, data: &[u8]) {
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut total = 0usize;
    loop {
        let Ok(step) = codec.process(input, &mut output, EndOfInput::End) else {
            return;
        };
        if step.consumed > input.len() || step.produced > output.len() {
            panic!("codec reported out-of-range progress");
        }
        input = &input[step.consumed..];
        total = total.saturating_add(step.produced);
        if total > CODEC_CAP || matches!(step.status, CodecStatus::Done) {
            return;
        }
        if step.consumed == 0 && step.produced == 0 {
            return;
        }
    }
}

fn gzip_encode(data: &[u8]) -> Option<Vec<u8>> {
    let mut codec = GzipEncoder::new(fuzz_limits());
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut encoded = Vec::new();
    loop {
        let step = codec.process(input, &mut output, EndOfInput::End).ok()?;
        input = input.get(step.consumed..)?;
        encoded.extend_from_slice(output.get(..step.produced)?);
        if matches!(step.status, CodecStatus::Done) {
            return Some(encoded);
        }
        if step.consumed == 0 && step.produced == 0 {
            return None;
        }
    }
}

fn gzip_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut codec = GzipDecoder::new(fuzz_limits());
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut decoded = Vec::new();
    loop {
        let step = codec.process(input, &mut output, EndOfInput::End).ok()?;
        input = input.get(step.consumed..)?;
        decoded.extend_from_slice(output.get(..step.produced)?);
        if decoded.len() > CODEC_CAP {
            return None;
        }
        if matches!(step.status, CodecStatus::Done) {
            return Some(decoded);
        }
        if step.consumed == 0 && step.produced == 0 {
            return None;
        }
    }
}

/// gzip codec protocol and round-trip target.
pub fn codec_gzip(data: &[u8]) {
    filtered_decode_no_panic(data);
    codec_decode_no_panic(GzipDecoder::new(fuzz_limits()), data);
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(encoded) = gzip_encode(&plain) {
        assert_eq!(gzip_decode(&encoded), Some(plain));
    }
}

fn codec_transform<C: Codec>(mut codec: C, data: &[u8]) -> Option<Vec<u8>> {
    let mut input = data;
    let mut output = [0_u8; 7];
    let mut transformed = Vec::new();
    loop {
        let step = codec.process(input, &mut output, EndOfInput::End).ok()?;
        input = input.get(step.consumed..)?;
        transformed.extend_from_slice(output.get(..step.produced)?);
        if transformed.len() > CODEC_CAP {
            return None;
        }
        if matches!(step.status, CodecStatus::Done) {
            return Some(transformed);
        }
        if step.consumed == 0 && step.produced == 0 {
            return None;
        }
    }
}

/// Strict RFC 4648 Base64 protocol, explicit adapter, and round-trip target.
pub fn codec_base64(data: &[u8]) {
    codec_decode_no_panic(Base64Decoder::new(fuzz_limits()), data);
    if let Ok(reader) = FilterReader::with_filter(
        Cursor::new(data),
        libarchive_oxide_core::FilterId::Base64,
        fuzz_limits(),
    ) {
        let _ = read_capped(reader, CODEC_CAP);
    }
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(encoded) = codec_transform(Base64Encoder::new(fuzz_limits()), &plain) {
        assert_eq!(
            codec_transform(Base64Decoder::new(fuzz_limits()), &encoded),
            Some(plain)
        );
    }
}

/// POSIX uuencode framing, adapters, and encoder/decoder round-trip target.
pub fn codec_uuencode(data: &[u8]) {
    if let Ok(decoder) = UuencodeDecoder::new(fuzz_limits()) {
        codec_decode_no_panic(decoder, data);
    }
    if let Ok(reader) = FilterReader::with_filter(
        Cursor::new(data),
        libarchive_oxide_core::FilterId::Uuencode,
        fuzz_limits(),
    ) {
        let _ = read_capped(reader, CODEC_CAP);
    }
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    let Ok(encoder) = UuencodeEncoder::new(fuzz_limits()) else {
        return;
    };
    if let Some(encoded) = codec_transform(encoder, &plain) {
        let Ok(decoder) = UuencodeDecoder::new(fuzz_limits()) else {
            return;
        };
        assert_eq!(codec_transform(decoder, &encoded), Some(plain));
    }
}

/// lzop framing, Safe Rust LZO1X decode, and stored-block round-trip target.
pub fn codec_lzop(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let input = decoded.as_deref().unwrap_or(data);
    codec_decode_no_panic(LzopDecoder::new(fuzz_limits()), input);
    if let Ok(reader) = FilterReader::with_filter(
        Cursor::new(input),
        libarchive_oxide_core::FilterId::Lzop,
        fuzz_limits(),
    ) {
        let _ = read_capped(reader, CODEC_CAP);
    }
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    let Ok(encoder) = LzopEncoder::new(fuzz_limits()) else {
        return;
    };
    if let Some(encoded) = codec_transform(encoder, &plain) {
        assert_eq!(
            codec_transform(LzopDecoder::new(fuzz_limits()), &encoded),
            Some(plain)
        );
    }
}

/// Unix `compress(1)` LZW protocol target with bounded dictionary and output.
pub fn codec_lzw(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let input = decoded.as_deref().unwrap_or(data);
    filtered_decode_no_panic(input);
    let Ok(decoder) = CompressDecoder::with_limits(fuzz_limits()) else {
        return;
    };
    codec_decode_no_panic(decoder, input);

    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    let Ok(encoder) = CompressEncoder::with_limits(fuzz_limits()) else {
        return;
    };
    if let Some(encoded) = codec_transform(encoder, &plain) {
        let Ok(decoder) = CompressDecoder::with_limits(fuzz_limits()) else {
            return;
        };
        assert_eq!(codec_transform(decoder, &encoded), Some(plain));
    }
}

fn filtered_decode_no_panic(data: &[u8]) {
    let Ok(reader) = FilterReader::with_limits(Cursor::new(data), fuzz_limits()) else {
        return;
    };
    let _ = read_capped(reader, CODEC_CAP);
}

/// bzip2 incremental filter target.
pub fn codec_bzip2(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// zstd incremental filter target.
pub fn codec_zstd(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// XZ incremental filter target.
pub fn codec_xz(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// Strict lzip member parser and bounded LZMA filter target.
pub fn codec_lzip(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    filtered_decode_no_panic(decoded.as_deref().unwrap_or(data));
}

/// Explicit-only LZMA-alone header, dictionary, size, and payload target.
pub fn codec_lzma(data: &[u8]) {
    let decoded = decode_hex_corpus_seed(data);
    let input = decoded.as_deref().unwrap_or(data);
    let limits = fuzz_limits()
        .with_decoded_total(Some(CODEC_CAP as u64))
        .with_codec_memory(Some(CODEC_CAP));
    if let Ok(reader) = FilterReader::with_filter(
        Cursor::new(input),
        libarchive_oxide_core::FilterId::Lzma,
        limits,
    ) {
        let _ = read_capped(reader, CODEC_CAP);
    }
}

/// LZ4 filter and direct sans-I/O progress-contract target.
pub fn codec_lz4(data: &[u8]) {
    filtered_decode_no_panic(data);
    let mut codec = Lz4Decoder::with_limits(fuzz_limits());
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut total = 0usize;
    loop {
        let Ok(step) = codec.process(input, &mut output, EndOfInput::End) else {
            return;
        };
        if step.consumed > input.len() || step.produced > output.len() {
            panic!("LZ4 codec reported out-of-range progress");
        }
        if step.status == CodecStatus::NeedInput && step.consumed != input.len() {
            panic!("LZ4 codec requested input while supplied bytes remained");
        }
        if step.status == CodecStatus::NeedOutput && step.produced != output.len() {
            panic!("LZ4 codec requested output before filling the supplied buffer");
        }
        if step.status == CodecStatus::Done && step.consumed != input.len() {
            panic!("LZ4 codec completed while supplied bytes remained");
        }
        input = &input[step.consumed..];
        total = total.saturating_add(step.produced);
        if total > CODEC_CAP || matches!(step.status, CodecStatus::Done) {
            return;
        }
        if step.consumed == 0 && step.produced == 0 {
            return;
        }
    }
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Some(output),
            Ok(read) if output.len().saturating_add(read) <= cap => {
                output.extend_from_slice(&buffer[..read]);
            },
            Ok(_) | Err(_) => return None,
        }
    }
}

fn lzma2_decode_capped(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let reader = lzma_rust2::Lzma2Reader::new(Cursor::new(data.to_vec()), LZMA2_DICT, None);
    read_capped(reader, cap)
}

fn lzma2_encode(plain: &[u8]) -> Option<Vec<u8>> {
    let options = lzma_rust2::Lzma2Options::with_preset(6);
    let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), options);
    writer.write_all(plain).ok()?;
    writer.finish().ok()
}

/// LZMA2 codec target used by 7z.
pub fn codec_lzma2(data: &[u8]) {
    let _ = lzma2_decode_capped(data, CODEC_CAP);
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(encoded) = lzma2_encode(&plain) {
        assert_eq!(lzma2_decode_capped(&encoded, CODEC_CAP), Some(plain));
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════ Structured 7z coder-graph fuzz (read_7z_graph) ════════════════════════════════════════════════════════════════════════════════════════════════
//
// Rather than mutate raw bytes, this target *synthesizes* a 7z `StreamsInfo` from an `arbitrary` spec — number of folders, per-coder method / arity / properties, bind pairs, packed indices, and coder/substream sizes — then frames it in a valid signature header (correct start- and next-header CRCs) so the reader's checksum gate is passed and the coder-graph parser is reached on every input.
// It then drives the seek reader and asserts the RM-303 invariant: no panic, bounded work, and every failure is a *typed* archive error (`Malformed` / `Unsupported` / `Integrity` / `Limit`) — never an untyped I/O error, a wrong answer, or an unbounded allocation.
// Cycles, stream overlaps, and truncation (via the `truncate` knob, recomputed under the header CRC) are the stressors the graph resolver and length arithmetic must survive.

/// Upper bounds keeping a synthesized archive small regardless of input size.
const GRAPH_MAX_FOLDERS: usize = 6;
const GRAPH_MAX_CODERS: usize = 6;
const GRAPH_MAX_ARITY: usize = 6;
const GRAPH_MAX_PROPS: usize = 8;
const GRAPH_MAX_UNPACK: usize = 24;
const GRAPH_MAX_SUBSTREAMS: usize = 6;
const GRAPH_MAX_PACKDATA: usize = 4096;

/// 7z signature magic (`'7' 'z' 0xBC 0xAF 0x27 0x1C`).
const GRAPH_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

// 7z next-header property ids used by the synthesizer.
const G_K_END: u8 = 0x00;
const G_K_HEADER: u8 = 0x01;
const G_K_MAIN_STREAMS_INFO: u8 = 0x04;
const G_K_FILES_INFO: u8 = 0x05;
const G_K_PACK_INFO: u8 = 0x06;
const G_K_UNPACK_INFO: u8 = 0x07;
const G_K_SUBSTREAMS_INFO: u8 = 0x08;
const G_K_SIZE: u8 = 0x09;
const G_K_CRC: u8 = 0x0A;
const G_K_FOLDER: u8 = 0x0B;
const G_K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const G_K_NUM_UNPACK_STREAM: u8 = 0x0D;
const G_K_NAME: u8 = 0x11;

/// Candidate coder method ids: decodable coders, filters, and the two deferred/unsupported ids (PPMd, BCJ2) plus an unknown id — so the synthesizer builds graphs arca decodes *and* graphs it must type as `Unsupported`.
const GRAPH_METHOD_IDS: &[&[u8]] = &[
    &[0x21],                   // LZMA2
    &[0x03, 0x01, 0x01],       // LZMA
    &[0x03],                   // Delta filter
    &[0x03, 0x03, 0x01, 0x03], // BCJ x86
    &[0x0A],                   // BCJ ARM64
    &[0x04, 0x01, 0x08],       // Deflate (raw)
    &[0x04, 0x02, 0x02],       // BZip2
    &[0x04, 0xF7, 0x11, 0x01], // Zstd
    &[0x06, 0xF1, 0x07, 0x01], // AES-256
    &[0x03, 0x04, 0x01],       // PPMd7 (bounded decode)
    &[0x03, 0x03, 0x01, 0x1B], // BCJ2 (bounded four-stream decode)
    &[0x00],                   // Copy / unknown
];

/// One coder in a synthesized folder.
#[derive(Debug, Arbitrary)]
struct GraphCoder {
    method: u8,
    complex: bool,
    alt: u8,
    num_in: u8,
    num_out: u8,
    props: Vec<u8>,
}

/// One synthesized folder: its coders plus the bind-pair / packed-stream index pools the encoder draws from (cycled to the arity the emitted coders imply).
#[derive(Debug, Arbitrary)]
struct GraphFolder {
    coders: Vec<GraphCoder>,
    bind_in: Vec<u8>,
    bind_out: Vec<u8>,
    packed: Vec<u8>,
}

/// A full `StreamsInfo` skeleton.
#[derive(Debug, Arbitrary)]
struct GraphSpec {
    pack_pos: u8,
    pack_sizes: Vec<u16>,
    folders: Vec<GraphFolder>,
    unpack_sizes: Vec<u16>,
    include_folder_crc: bool,
    include_substreams: bool,
    num_unpack_streams: Vec<u8>,
    substream_sizes: Vec<u16>,
    include_substream_crc: bool,
    include_files_info: bool,
    truncate: u16,
    pack_data: Vec<u8>,
}

/// Writes a 7z variable-length number (`WriteNumber`), mirroring the reader's `ReadNumber`.
#[allow(clippy::cast_possible_truncation)]
fn graph_number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0u32;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    let mut v = value;
    for _ in 0..i {
        out.push(v as u8);
        v >>= 8;
    }
}

impl GraphCoder {
    /// Emits this coder and returns the `(num_in, num_out)` arca will parse from the emitted bytes.
    fn emit(&self, out: &mut Vec<u8>) -> (usize, usize) {
        let id = GRAPH_METHOD_IDS[self.method as usize % GRAPH_METHOD_IDS.len()];
        let id_size = id.len() as u8; // every candidate id is <= 4 bytes
        let has_props = !self.props.is_empty();
        let mut flags = id_size & 0x0F;
        if self.complex {
            flags |= 0x10;
        }
        if has_props {
            flags |= 0x20;
        }
        // Rarely set the "alternative methods" bit (~6%), which the reader must type as Unsupported.
        if self.alt < 16 {
            flags |= 0x80;
        }
        out.push(flags);
        out.extend_from_slice(id);
        let (num_in, num_out) = if self.complex {
            let ni = (self.num_in as usize % GRAPH_MAX_ARITY) + 1;
            let no = (self.num_out as usize % GRAPH_MAX_ARITY) + 1;
            graph_number(out, ni as u64);
            graph_number(out, no as u64);
            (ni, no)
        } else {
            (1, 1)
        };
        if has_props {
            let props: Vec<u8> = self.props.iter().copied().take(GRAPH_MAX_PROPS).collect();
            graph_number(out, props.len() as u64);
            out.extend_from_slice(&props);
        }
        (num_in, num_out)
    }
}

impl GraphSpec {
    /// Serializes the spec into a framed 7z archive image.
    #[allow(clippy::cast_possible_truncation)]
    fn encode(&self) -> Vec<u8> {
        let folders: Vec<&GraphFolder> = self.folders.iter().take(GRAPH_MAX_FOLDERS).collect();

        let mut streams = Vec::new();
        // ── PackInfo ──
        streams.push(G_K_PACK_INFO);
        graph_number(&mut streams, u64::from(self.pack_pos));
        let pack_sizes: Vec<u64> = self
            .pack_sizes
            .iter()
            .take(GRAPH_MAX_UNPACK)
            .map(|&s| u64::from(s))
            .collect();
        graph_number(&mut streams, pack_sizes.len() as u64);
        streams.push(G_K_SIZE);
        for &size in &pack_sizes {
            graph_number(&mut streams, size);
        }
        streams.push(G_K_END);

        // ── UnpackInfo ──
        streams.push(G_K_UNPACK_INFO);
        streams.push(G_K_FOLDER);
        graph_number(&mut streams, folders.len() as u64);
        streams.push(0x00); // folder definitions are inline (external == 0)
        let mut total_outputs = 0usize;
        for folder in &folders {
            let coders: Vec<&GraphCoder> = folder.coders.iter().take(GRAPH_MAX_CODERS).collect();
            let num_coders = coders.len().max(1);
            graph_number(&mut streams, num_coders as u64);
            let mut total_in = 0usize;
            let mut total_out = 0usize;
            for i in 0..num_coders {
                // At least one coder even if the pool is empty (an LZMA2 stand-in).
                let (ni, no) = match coders.get(i) {
                    Some(coder) => coder.emit(&mut streams),
                    None => {
                        streams.push(0x01); // id_size 1, simple coder
                        streams.push(0x21); // LZMA2
                        (1, 1)
                    },
                };
                total_in += ni;
                total_out += no;
            }
            total_outputs += total_out;
            // (numOut - 1) bind pairs, drawn from the folder's index pools (cycled), kept roughly in range so some resolve cleanly and some overlap / cycle.
            let num_bind = total_out.saturating_sub(1);
            for k in 0..num_bind {
                let in_index = pool_index(&folder.bind_in, k, total_in);
                let out_index = pool_index(&folder.bind_out, k, total_out);
                graph_number(&mut streams, in_index as u64);
                graph_number(&mut streams, out_index as u64);
            }
            // Packed inputs = total_in - num_bind; >1 are listed explicitly, 1 is implicit.
            let num_packed = total_in.saturating_sub(num_bind);
            if num_packed > 1 {
                for k in 0..num_packed {
                    let idx = pool_index(&folder.packed, k, total_in.max(1));
                    graph_number(&mut streams, idx as u64);
                }
            }
        }
        streams.push(G_K_CODERS_UNPACK_SIZE);
        for i in 0..total_outputs {
            let size = self
                .unpack_sizes
                .get(i % self.unpack_sizes.len().max(1))
                .map_or(0, |&s| u64::from(s));
            graph_number(&mut streams, size);
        }
        if self.include_folder_crc {
            streams.push(G_K_CRC);
            streams.push(0x00); // not all defined
            let bytes = folders.len().div_ceil(8);
            streams.extend(std::iter::repeat_n(0u8, bytes)); // none defined
        }
        streams.push(G_K_END);

        // ── SubStreamsInfo (optional) ──
        if self.include_substreams && !folders.is_empty() {
            streams.push(G_K_SUBSTREAMS_INFO);
            let counts: Vec<usize> = (0..folders.len())
                .map(|f| {
                    self.num_unpack_streams
                        .get(f % self.num_unpack_streams.len().max(1))
                        .map_or(1, |&n| usize::from(n) % GRAPH_MAX_SUBSTREAMS)
                })
                .collect();
            streams.push(G_K_NUM_UNPACK_STREAM);
            for &c in &counts {
                graph_number(&mut streams, c as u64);
            }
            streams.push(G_K_SIZE);
            let mut si = 0usize;
            for &c in &counts {
                for _ in 0..c.saturating_sub(1) {
                    let size = self
                        .substream_sizes
                        .get(si % self.substream_sizes.len().max(1))
                        .map_or(0, |&s| u64::from(s));
                    graph_number(&mut streams, size);
                    si += 1;
                }
            }
            if self.include_substream_crc {
                streams.push(G_K_CRC);
                let total: usize = counts.iter().sum();
                streams.push(0x01); // all defined
                for _ in 0..total {
                    // Deliberately (almost certainly) wrong CRCs: a reached decode must surface a typed `Integrity` error, never a silent wrong answer.
                    streams.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
                }
            }
            streams.push(G_K_END);
        }
        streams.push(G_K_END); // end StreamsInfo

        // ── Assemble the plain kHeader body ──
        let mut next = vec![G_K_HEADER, G_K_MAIN_STREAMS_INFO];
        next.extend_from_slice(&streams);
        // Optional minimal FilesInfo (empty names) so a consistent graph reaches the decode path.
        if self.include_files_info && !folders.is_empty() {
            next.push(G_K_FILES_INFO);
            let num_files = folders.len();
            graph_number(&mut next, num_files as u64);
            graph_number(&mut next, u64::from(G_K_NAME));
            let mut name_body = vec![0x00u8]; // names are inline (external == 0)
            for _ in 0..num_files {
                name_body.extend_from_slice(&[0x00, 0x00]); // empty UTF-16 name (terminator only)
            }
            graph_number(&mut next, name_body.len() as u64);
            next.extend_from_slice(&name_body);
            graph_number(&mut next, u64::from(G_K_END));
        }
        next.push(G_K_END); // end kHeader

        // Truncation knob: cut the header short *before* computing its CRC, so the outer checksum gate still passes and the reader hits the truncation inside the graph parser.
        if self.truncate != 0 && !next.is_empty() {
            let keep = (self.truncate as usize) % next.len();
            next.truncate(keep);
        }

        // ── Frame it: signature header + pack region + next header ──
        let pack: Vec<u8> = self
            .pack_data
            .iter()
            .copied()
            .take(GRAPH_MAX_PACKDATA)
            .collect();
        let mut file = vec![0u8; 32];
        file[..6].copy_from_slice(&GRAPH_SIGNATURE);
        file[6] = 0; // format version major
        file[7] = 4; // format version minor
        file.extend_from_slice(&pack);
        let header_offset = pack.len() as u64;
        let header_size = next.len() as u64;
        let header_crc = crc32(&next);
        file.extend_from_slice(&next);
        file[12..20].copy_from_slice(&header_offset.to_le_bytes());
        file[20..28].copy_from_slice(&header_size.to_le_bytes());
        file[28..32].copy_from_slice(&header_crc.to_le_bytes());
        let start_crc = crc32(&file[12..32]);
        file[8..12].copy_from_slice(&start_crc.to_le_bytes());
        file
    }
}

/// Picks an index from a pool (cycled), kept within `[0, modulus)` so it lands near the real stream range — some in-range (resolvable), some colliding (overlap/cycle the resolver must reject).
fn pool_index(pool: &[u8], k: usize, modulus: usize) -> usize {
    let modulus = modulus.max(1);
    match pool.get(k % pool.len().max(1)) {
        Some(&raw) => usize::from(raw) % modulus,
        None => k % modulus,
    }
}

/// Asserts a 7z read failure is a *typed* archive error of an expected kind — the RM-303 contract that a hostile coder graph never panics, never leaks an untyped error, and never silently lies.
fn assert_graph_typed(error: &Error) {
    match error.archive_error().map(ArchiveError::kind) {
        Some(
            ErrorKind::Malformed | ErrorKind::Unsupported | ErrorKind::Integrity | ErrorKind::Limit,
        ) => {},
        other => panic!(
            "7z coder-graph fuzz surfaced a non-typed / unexpected error: archive={other:?}, io={:?}",
            error
                .io_error()
                .map(|source| (source.kind(), source.to_string()))
        ),
    }
}

/// Structured 7z coder-graph target: synthesize a `StreamsInfo`, frame it, and drive the reader.
pub fn read_7z_graph(data: &[u8]) {
    let mut input = arbitrary::Unstructured::new(data);
    let Ok(spec) = GraphSpec::arbitrary(&mut input) else {
        return;
    };
    let archive = spec.encode();
    let mut reader = match SeekArchiveReader::with_limits(Cursor::new(archive), fuzz_limits()) {
        Ok(reader) => reader,
        Err(error) => {
            assert_graph_typed(&error);
            return;
        },
    };
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
            Err(error) => {
                assert_graph_typed(&error);
                return;
            },
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

/// All stable replay targets; every entry except `codec_lzip` also has a libFuzzer shim.
pub const TARGETS: &[&str] = &[
    "read_tar",
    "read_cpio",
    "read_ar",
    "read_zip",
    "read_7z",
    "read_7z_graph",
    "read_iso",
    "read_udf",
    "read_cab",
    "read_xar",
    "read_rar_legacy",
    "read_rar5",
    "read_lha",
    "roundtrip_tar",
    "roundtrip_cpio",
    "roundtrip_ar",
    "roundtrip_7z",
    "roundtrip_iso",
    "roundtrip_xar",
    "codec_gzip",
    "codec_base64",
    "codec_uuencode",
    "codec_lzop",
    "codec_lzw",
    "codec_bzip2",
    "codec_zstd",
    "codec_xz",
    "codec_lzip",
    "codec_lzma",
    "codec_lz4",
    "codec_lzma2",
    "package_rpm",
    "package_alpine",
    "package_zip",
    "package_app",
    "extraction_plan",
];

/// Runs a portable fuzz target.
pub fn run_target(name: &str, data: &[u8]) {
    match name {
        "read_tar" => read_tar(data),
        "read_cpio" => read_cpio(data),
        "read_ar" => read_ar(data),
        "read_zip" => read_zip(data),
        "read_7z" => read_7z(data),
        "read_7z_graph" => read_7z_graph(data),
        "read_iso" => read_iso(data),
        "read_udf" => read_udf(data),
        "read_cab" => read_cab(data),
        "read_xar" => read_xar(data),
        "read_rar_legacy" => read_rar_legacy(data),
        "read_rar5" => read_rar5(data),
        "read_lha" => read_lha(data),
        "roundtrip_tar" => roundtrip_tar(&entries_from_bytes(data)),
        "roundtrip_cpio" => roundtrip_cpio(&entries_from_bytes(data)),
        "roundtrip_ar" => roundtrip_ar(&entries_from_bytes(data)),
        "roundtrip_7z" => roundtrip_7z(&entries_from_bytes(data)),
        "roundtrip_iso" => roundtrip_iso(&entries_from_bytes(data)),
        "roundtrip_xar" => roundtrip_xar(&entries_from_bytes(data)),
        "codec_gzip" => codec_gzip(data),
        "codec_base64" => codec_base64(data),
        "codec_uuencode" => codec_uuencode(data),
        "codec_lzop" => codec_lzop(data),
        "codec_lzw" => codec_lzw(data),
        "codec_bzip2" => codec_bzip2(data),
        "codec_zstd" => codec_zstd(data),
        "codec_xz" => codec_xz(data),
        "codec_lzip" => codec_lzip(data),
        "codec_lzma" => codec_lzma(data),
        "codec_lz4" => codec_lz4(data),
        "codec_lzma2" => codec_lzma2(data),
        "package_rpm" => package_rpm(data),
        "package_alpine" => package_alpine(data),
        "package_zip" => package_zip(data),
        "package_app" => package_app(data),
        "extraction_plan" => extraction_plan(data),
        _ => {},
    }
}

fn entries_from_bytes(data: &[u8]) -> Vec<FuzzEntry> {
    let mut input = arbitrary::Unstructured::new(data);
    Vec::<FuzzEntry>::arbitrary(&mut input).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{is_rar5_container_seed, read_7z_graph};

    #[test]
    fn seven_graph_invalid_bcj2_arity_failure_remains_typed() {
        read_7z_graph(&[
            0, 79, 41, 0, 0, 255, 255, 46, 2, 255, 206, 206, 206, 206, 207, 206, 206, 206, 206,
            206, 3, 0, 255, 255, 255, 124, 158, 255, 39, 92, 251, 3, 0, 0, 0, 3, 0, 0, 0, 0, 255,
            255, 255, 255, 255, 255, 255, 255, 206, 206, 206, 255,
        ]);
    }

    #[test]
    fn seven_graph_fuzz_failure_remains_typed() {
        read_7z_graph(&[
            0, 1, 33, 0, 0, 141, 255, 2, 254, 255, 255, 114, 0, 117, 0, 252, 255, 6, 0, 1, 1, 0, 0,
            141, 255, 253, 255, 254, 16, 0, 4, 253, 137, 20, 0, 253, 255, 6, 0, 1, 1, 0, 0, 141,
            255, 254, 253, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 209, 209, 209, 209, 209, 209, 209,
            209, 209, 209, 209, 209, 209, 209, 209, 61, 61, 61, 61, 61, 61, 61, 61, 61, 133, 45,
            61, 61, 61, 61, 61, 61, 16, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 209, 209, 209,
            209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209,
            209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209,
            209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 197, 61, 61, 61,
            61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 133, 45, 61, 61, 61, 61, 61, 61, 16, 0, 4,
            255, 255, 255, 255, 255, 255, 255, 255, 61, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 240, 197, 162, 109, 255, 253, 137, 20, 0, 61, 61, 45, 61, 61, 61, 61,
            61, 255, 255, 255, 255, 255, 5, 13, 0, 112, 0, 46, 0, 98, 0, 105, 0, 110, 0, 0, 0, 0,
            0,
        ]);
    }

    #[test]
    fn rar5_container_seed_detection_accepts_sfx_and_rejects_payload_bytes() {
        let mut sfx = vec![0x90; 32];
        sfx.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        assert!(is_rar5_container_seed(&sfx));
        assert!(!is_rar5_container_seed(b"raw RAR payload bytes"));
    }
}
