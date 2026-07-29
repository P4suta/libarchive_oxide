// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZIP method 9 (Deflate64) read-only interoperability and negative contracts.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::unwrap_used
)]

use std::io::Cursor;

use libarchive_oxide::{ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::{EntryKind, ErrorKind, Limits};

const REGULAR_ATTRIBUTES: u32 = 0o100_644_u32 << 16;

fn stored_deflate64(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    if data.is_empty() {
        encoded.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        return encoded;
    }
    let mut remaining = data;
    while !remaining.is_empty() {
        let count = remaining.len().min(u16::MAX as usize);
        let final_block = count == remaining.len();
        encoded.push(u8::from(final_block));
        let length = count as u16;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&(!length).to_le_bytes());
        encoded.extend_from_slice(&remaining[..count]);
        remaining = &remaining[count..];
    }
    encoded
}

fn raw_method9_zip(
    name: &[u8],
    compressed: &[u8],
    declared_size: u32,
    declared_crc: u32,
    external_attributes: u32,
) -> Vec<u8> {
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    archive.extend_from_slice(&21_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&9_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&declared_crc.to_le_bytes());
    archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    archive.extend_from_slice(&declared_size.to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(name);
    archive.extend_from_slice(compressed);
    let central_offset = archive.len() as u32;
    archive.extend_from_slice(b"PK\x01\x02");
    archive.extend_from_slice(&0x031e_u16.to_le_bytes());
    archive.extend_from_slice(&21_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&9_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&declared_crc.to_le_bytes());
    archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    archive.extend_from_slice(&declared_size.to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&external_attributes.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(name);
    let central_size = archive.len() as u32 - central_offset;
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&1_u16.to_le_bytes());
    archive.extend_from_slice(&1_u16.to_le_bytes());
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

fn method9_zip(data: &[u8]) -> Vec<u8> {
    raw_method9_zip(
        b"payload.bin",
        &stored_deflate64(data),
        data.len() as u32,
        libarchive_oxide::filter::crc32(data),
        REGULAR_ATTRIBUTES,
    )
}

fn read_all(bytes: Vec<u8>, limits: Limits) -> Result<Vec<u8>, libarchive_oxide::Error> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits)?;
    let mut output = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => output.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok(output),
            _ => {},
        }
    }
}

fn le_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn le_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn append_trailing_byte_to_official_wide_member() -> Vec<u8> {
    let mut archive = include_bytes!("fixtures/zip/7zip/deflate64.zip").to_vec();
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap();
    let central_offset = le_u32_at(&archive, eocd + 16) as usize;
    let mut central = central_offset;
    let (wide_central, local, compressed_size) = loop {
        assert_eq!(&archive[central..central + 4], b"PK\x01\x02");
        let name_length = le_u16_at(&archive, central + 28) as usize;
        let extra_length = le_u16_at(&archive, central + 30) as usize;
        let comment_length = le_u16_at(&archive, central + 32) as usize;
        let name = &archive[central + 46..central + 46 + name_length];
        if name == b"wide-window.bin" {
            break (
                central,
                le_u32_at(&archive, central + 42) as usize,
                le_u32_at(&archive, central + 20),
            );
        }
        central += 46 + name_length + extra_length + comment_length;
    };
    assert_eq!(le_u16_at(&archive, local + 8), 9);
    let data_start = local
        + 30
        + le_u16_at(&archive, local + 26) as usize
        + le_u16_at(&archive, local + 28) as usize;
    let data_end = data_start + compressed_size as usize;
    assert_eq!(
        data_end, central_offset,
        "wide-window.bin must be the last local member"
    );

    archive.insert(data_end, 0);
    archive[local + 18..local + 22].copy_from_slice(&(compressed_size + 1).to_le_bytes());
    let shifted_central = wide_central + 1;
    archive[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&(compressed_size + 1).to_le_bytes());
    let shifted_eocd = eocd + 1;
    archive[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&((central_offset + 1) as u32).to_le_bytes());
    archive
}

#[cfg(feature = "gzip")]
#[test]
fn method9_reads_empty_and_multi_block_stored_streams() {
    assert_eq!(read_all(method9_zip(&[]), Limits::safe()).unwrap(), b"");
    let data = (0..150_000).map(|index| index as u8).collect::<Vec<_>>();
    let mut reader = SeekArchiveReader::new(Cursor::new(method9_zip(&data))).unwrap();
    let mut decoded = Vec::new();
    let mut chunks = 0;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => {
                chunks += 1;
                decoded.extend_from_slice(bytes);
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, data);
    assert!(
        chunks >= 3,
        "150,000 decoded bytes must span multiple fixed-size output chunks"
    );
}

#[cfg(feature = "gzip")]
#[test]
fn official_7zip_fixture_exercises_the_64k_window() {
    let archive = include_bytes!("fixtures/zip/7zip/deflate64.zip");
    let mut reader = SeekArchiveReader::new(Cursor::new(archive.as_slice())).unwrap();
    let mut wide = Vec::new();
    let mut current_is_wide = false;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => {
                current_is_wide = metadata.path().as_bytes() == b"wide-window.bin";
            },
            ReaderEvent::Data(bytes) if current_is_wide => wide.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    let mut base = vec![0_u8; 50_000];
    let mut state = 0x1234_5678_u32;
    for byte in &mut base {
        state ^= state.wrapping_shl(13);
        state ^= state.wrapping_shr(17);
        state ^= state.wrapping_shl(5);
        *byte = state as u8;
    }
    let expected = base.repeat(3);
    assert_eq!(wide, expected);
}

#[cfg(feature = "gzip")]
#[test]
fn method9_reports_size_and_crc_integrity_errors() {
    let data = vec![0x5a; 100_000];
    let compressed = stored_deflate64(&data);
    let wrong_size = raw_method9_zip(
        b"payload.bin",
        &compressed,
        data.len() as u32 + 1,
        libarchive_oxide::filter::crc32(&data),
        REGULAR_ATTRIBUTES,
    );
    let error = read_all(wrong_size, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let too_small = raw_method9_zip(
        b"payload.bin",
        &compressed,
        data.len() as u32 - 1,
        libarchive_oxide::filter::crc32(&data),
        REGULAR_ATTRIBUTES,
    );
    let error = read_all(too_small, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let wrong_crc = raw_method9_zip(
        b"payload.bin",
        &compressed,
        data.len() as u32,
        0xdead_beef,
        REGULAR_ATTRIBUTES,
    );
    let error = read_all(wrong_crc, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[cfg(feature = "gzip")]
#[test]
fn method9_reports_typed_malformed_truncation_and_early_end() {
    let invalid = raw_method9_zip(b"payload.bin", &[0x07], 0, 0, REGULAR_ATTRIBUTES);
    let error = read_all(invalid, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let data = vec![0x5a; 100_000];
    let mut truncated = stored_deflate64(&data);
    truncated.pop();
    let truncated = raw_method9_zip(
        b"payload.bin",
        &truncated,
        data.len() as u32,
        libarchive_oxide::filter::crc32(&data),
        REGULAR_ATTRIBUTES,
    );
    let error = read_all(truncated, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut trailing = stored_deflate64(&data);
    trailing.push(0);
    let trailing = raw_method9_zip(
        b"payload.bin",
        &trailing,
        data.len() as u32,
        libarchive_oxide::filter::crc32(&data),
        REGULAR_ATTRIBUTES,
    );
    let error = read_all(trailing, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[cfg(feature = "gzip")]
#[test]
fn method9_rejects_dynamic_stream_lookahead_past_the_exact_extent() {
    let error = read_all(
        append_trailing_byte_to_official_wide_member(),
        Limits::safe(),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
    assert!(
        error
            .to_string()
            .contains("stream ended before its compressed extent")
    );
}

#[cfg(feature = "gzip")]
#[test]
fn method9_enforces_entry_and_decoded_limits() {
    let data = vec![0x5a; 100_000];
    let limits = Limits::safe().with_decoded_total(Some(1024));
    let error = read_all(method9_zip(&data), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let limits = Limits::safe().with_entry_bytes(Some(1024));
    let error = read_all(method9_zip(&data), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[cfg(feature = "gzip")]
#[test]
fn method9_hydrates_and_validates_symbolic_link_metadata() {
    let target = b"target/file.txt";
    let compressed = stored_deflate64(target);
    let symlink_attributes = 0o120_777_u32 << 16;
    let archive = raw_method9_zip(
        b"l",
        &compressed,
        target.len() as u32,
        libarchive_oxide::filter::crc32(target),
        symlink_attributes,
    );
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("method 9 symbolic link did not yield entry metadata");
    };
    assert_eq!(metadata.kind(), EntryKind::Symlink);
    assert_eq!(metadata.link_target().unwrap().as_bytes(), target);

    let bad_crc = raw_method9_zip(
        b"l",
        &compressed,
        target.len() as u32,
        0xdead_beef,
        symlink_attributes,
    );
    let error = SeekArchiveReader::new(Cursor::new(bad_crc)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let bad_size = raw_method9_zip(
        b"l",
        &compressed,
        target.len() as u32 - 1,
        libarchive_oxide::filter::crc32(target),
        symlink_attributes,
    );
    let error = SeekArchiveReader::new(Cursor::new(bad_size)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let mut trailing = compressed.clone();
    trailing.push(0);
    let trailing = raw_method9_zip(
        b"l",
        &trailing,
        target.len() as u32,
        libarchive_oxide::filter::crc32(target),
        symlink_attributes,
    );
    let error = SeekArchiveReader::new(Cursor::new(trailing)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let bounded = raw_method9_zip(
        b"l",
        &compressed,
        target.len() as u32,
        libarchive_oxide::filter::crc32(target),
        symlink_attributes,
    );
    let limits = Limits::safe().with_path_bytes(Some(target.len() - 1));
    let error = SeekArchiveReader::with_limits(Cursor::new(bounded), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let bounded_metadata = raw_method9_zip(b"l", &[0xff], 4096, 0, symlink_attributes);
    let limits = Limits::safe().with_metadata_bytes(Some(2048));
    let error = SeekArchiveReader::with_limits(Cursor::new(bounded_metadata), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    assert!(
        error
            .to_string()
            .contains("symbolic-link targets exceed metadata limit")
    );
}

#[cfg(not(feature = "gzip"))]
#[test]
fn method9_is_listable_but_unsupported_without_gzip_feature() {
    let mut reader = SeekArchiveReader::new(Cursor::new(method9_zip(b"payload"))).unwrap();
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
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
}
