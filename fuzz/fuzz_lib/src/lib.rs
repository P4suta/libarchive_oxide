// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable fuzz invariants for the v0.2 streaming protocols.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};

use arbitrary::Arbitrary;
use libarchive_oxide::filter::gzip::{GzipDecoder, GzipEncoder};
use libarchive_oxide::{
    ArchiveReader, ArchiveWriter, FilterReader, ReaderEvent, SeekArchiveReader, SeekArchiveWriter,
};
use libarchive_oxide_core::{
    ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata, FormatId, Limits,
};

const MAX_ENTRIES: usize = 200_000;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const CODEC_CAP: usize = 64 * 1024 * 1024;
const CODEC_ROUNDTRIP_MAX: usize = 256 * 1024;
const LZMA2_DICT: u32 = 8 * 1024 * 1024;
const MAX_ROUNDTRIP_ENTRIES: usize = 48;
const MAX_NAME_LEN: usize = 40;
const MAX_ROUNDTRIP_DATA: usize = 4096;

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

/// tar decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_tar(data: &[u8]) {
    drive_sequential(data);
}

/// cpio decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_cpio(data: &[u8]) {
    drive_sequential(data);
}

/// ar decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_ar(data: &[u8]) {
    drive_sequential(data);
}

/// ZIP seek decoder: arbitrary indexes and payloads must not panic.
pub fn read_zip(data: &[u8]) {
    drive_seek(data);
}

/// 7z seek decoder: arbitrary indexes and coder metadata must not panic.
pub fn read_7z(data: &[u8]) {
    drive_seek(data);
}

/// ISO seek decoder: arbitrary volume and directory records must not panic.
pub fn read_iso(data: &[u8]) {
    drive_seek(data);
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

/// tar streaming round trip.
pub fn roundtrip_tar(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Tar);
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

/// LZ4 incremental filter target.
pub fn codec_lz4(data: &[u8]) {
    filtered_decode_no_panic(data);
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

/// All portable fuzz targets.
pub const TARGETS: &[&str] = &[
    "read_tar",
    "read_cpio",
    "read_ar",
    "read_zip",
    "read_7z",
    "read_iso",
    "roundtrip_tar",
    "roundtrip_cpio",
    "roundtrip_ar",
    "roundtrip_7z",
    "roundtrip_iso",
    "codec_gzip",
    "codec_bzip2",
    "codec_zstd",
    "codec_xz",
    "codec_lz4",
    "codec_lzma2",
];

/// Runs a portable fuzz target.
pub fn run_target(name: &str, data: &[u8]) {
    match name {
        "read_tar" => read_tar(data),
        "read_cpio" => read_cpio(data),
        "read_ar" => read_ar(data),
        "read_zip" => read_zip(data),
        "read_7z" => read_7z(data),
        "read_iso" => read_iso(data),
        "roundtrip_tar" => roundtrip_tar(&entries_from_bytes(data)),
        "roundtrip_cpio" => roundtrip_cpio(&entries_from_bytes(data)),
        "roundtrip_ar" => roundtrip_ar(&entries_from_bytes(data)),
        "roundtrip_7z" => roundtrip_7z(&entries_from_bytes(data)),
        "roundtrip_iso" => roundtrip_iso(&entries_from_bytes(data)),
        "codec_gzip" => codec_gzip(data),
        "codec_bzip2" => codec_bzip2(data),
        "codec_zstd" => codec_zstd(data),
        "codec_xz" => codec_xz(data),
        "codec_lz4" => codec_lz4(data),
        "codec_lzma2" => codec_lzma2(data),
        _ => {},
    }
}

fn entries_from_bytes(data: &[u8]) -> Vec<FuzzEntry> {
    let mut input = arbitrary::Unstructured::new(data);
    Vec::<FuzzEntry>::arbitrary(&mut input).unwrap_or_default()
}
