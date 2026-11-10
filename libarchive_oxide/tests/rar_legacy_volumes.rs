// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RAR 3.x/4.x physical-volume sequencing over the bounded source model.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use libarchive_oxide::advanced::{
    MemoryReadAt, RangeReadError, RangeReadErrorKind, ReadAt, SourceIdentity, SourceLimits,
    VolumeId, VolumeResolver, VolumeSet,
};
use libarchive_oxide::{
    ArchiveEngine, Error, ErrorKind, FormatId, Limits, OpenOptions, ReaderEvent,
    VolumeArchiveReader,
};
#[cfg(feature = "rar")]
use libarchive_oxide_rar::{RAR3_AUXILIARY_BYTES, RAR3_DICTIONARY_BYTES};

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const MHD_VOLUME: u16 = 0x0001;
const MHD_FIRSTVOLUME: u16 = 0x0100;
const HD_ADD_SIZE_PRESENT: u16 = 0x8000;

struct Resolver {
    volumes: BTreeMap<VolumeId, Arc<dyn ReadAt>>,
    requests: AtomicU64,
}

impl VolumeResolver for Resolver {
    fn resolve(&self, volume: VolumeId) -> std::io::Result<Option<Arc<dyn ReadAt>>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.volumes.get(&volume).cloned())
    }
}

fn source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(MemoryReadAt::new(
        bytes,
        SourceIdentity::try_new(format!("rar-legacy-volume-{index}-v1").into_bytes())
            .expect("valid source identity"),
    ))
}

fn volume_set(parts: Vec<Vec<u8>>) -> (Arc<VolumeSet>, Arc<Resolver>) {
    let mut parts = parts.into_iter().enumerate();
    let (_, primary) = parts.next().expect("RAR set has a primary volume");
    let resolver = Arc::new(Resolver {
        volumes: parts
            .map(|(index, bytes)| {
                (
                    VolumeId::new(u32::try_from(index).expect("small volume index")),
                    source(index, bytes),
                )
            })
            .collect(),
        requests: AtomicU64::new(0),
    });
    let volumes = Arc::new(
        VolumeSet::new(source(0, primary), resolver.clone(), SourceLimits::safe())
            .expect("bounded RAR volume set"),
    );
    (volumes, resolver)
}

fn header(kind: u8, flags: u16, mut body: Vec<u8>) -> Vec<u8> {
    let size = u16::try_from(7 + body.len()).expect("test header size");
    let mut bytes = vec![0, 0, kind];
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.append(&mut body);
    let crc = u16::try_from(libarchive_oxide::filter::crc32(&bytes[2..]) & u32::from(u16::MAX))
        .expect("low RAR header CRC16")
        .to_le_bytes();
    bytes[..2].copy_from_slice(&crc);
    bytes
}

fn physical_volume(first: bool, next: bool, name: &[u8], payload: &[u8]) -> Vec<u8> {
    physical_volume_with_file_flags(first, next, name, payload, 0)
}

fn physical_volume_with_file_flags(
    first: bool,
    next: bool,
    name: &[u8],
    payload: &[u8],
    file_flags: u16,
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let main_flags = MHD_VOLUME | if first { MHD_FIRSTVOLUME } else { 0 };
    archive.extend_from_slice(&header(0x73, main_flags, vec![0; 6]));

    let size = u32::try_from(payload.len()).expect("small payload");
    let mut file = Vec::new();
    file.extend_from_slice(&size.to_le_bytes());
    file.extend_from_slice(&size.to_le_bytes());
    file.push(3); // Unix host
    file.extend_from_slice(&libarchive_oxide::filter::crc32(payload).to_le_bytes());
    file.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    file.push(29);
    file.push(0x30); // Store
    file.extend_from_slice(&u16::try_from(name.len()).expect("small path").to_le_bytes());
    file.extend_from_slice(&0o100_640_u32.to_le_bytes());
    file.extend_from_slice(name);
    archive.extend_from_slice(&header(0x74, HD_ADD_SIZE_PRESENT | file_flags, file));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&header(0x7b, u16::from(next), Vec::new()));
    archive
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn split_physical_volume(
    first_volume: bool,
    next_volume: bool,
    name: &[u8],
    part: &[u8],
    logical_payload: &[u8],
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let main_flags = MHD_VOLUME | if first_volume { MHD_FIRSTVOLUME } else { 0 };
    archive.extend_from_slice(&header(0x73, main_flags, vec![0; 6]));

    let mut file = Vec::new();
    file.extend_from_slice(&u32::try_from(part.len()).expect("small part").to_le_bytes());
    file.extend_from_slice(
        &u32::try_from(logical_payload.len())
            .expect("small logical payload")
            .to_le_bytes(),
    );
    file.push(3); // Unix host
    file.extend_from_slice(&checksum.to_le_bytes());
    file.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    file.push(29);
    file.push(0x30); // Store
    file.extend_from_slice(&u16::try_from(name.len()).expect("small path").to_le_bytes());
    file.extend_from_slice(&0o100_640_u32.to_le_bytes());
    file.extend_from_slice(name);
    let split_flags = u16::from(split_before) | (u16::from(split_after) << 1);
    archive.extend_from_slice(&header(0x74, HD_ADD_SIZE_PRESENT | split_flags, file));
    archive.extend_from_slice(part);
    archive.extend_from_slice(&header(0x7b, u16::from(next_volume), Vec::new()));
    archive
}

#[cfg(feature = "rar")]
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn split_compressed_physical_volume(
    first_volume: bool,
    next_volume: bool,
    name: &[u8],
    packed_part: &[u8],
    unpacked_size: u64,
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let main_flags = MHD_VOLUME | if first_volume { MHD_FIRSTVOLUME } else { 0 };
    archive.extend_from_slice(&header(0x73, main_flags, vec![0; 6]));

    let mut file = Vec::new();
    file.extend_from_slice(
        &u32::try_from(packed_part.len())
            .expect("small packed part")
            .to_le_bytes(),
    );
    file.extend_from_slice(
        &u32::try_from(unpacked_size)
            .expect("small unpacked payload")
            .to_le_bytes(),
    );
    file.push(3); // Unix host
    file.extend_from_slice(&checksum.to_le_bytes());
    file.extend_from_slice(&0x5821_8822_u32.to_le_bytes());
    file.push(29);
    file.push(0x33); // Normal RAR3 LZ77/Huffman compression.
    file.extend_from_slice(&u16::try_from(name.len()).expect("small path").to_le_bytes());
    file.extend_from_slice(&0o100_640_u32.to_le_bytes());
    file.extend_from_slice(name);
    let split_flags = u16::from(split_before) | (u16::from(split_after) << 1);
    archive.extend_from_slice(&header(0x74, HD_ADD_SIZE_PRESENT | split_flags, file));
    archive.extend_from_slice(packed_part);
    archive.extend_from_slice(&header(0x7b, u16::from(next_volume), Vec::new()));
    archive
}

#[test]
fn path_open_discovers_legacy_rar_extension_volumes() {
    let first_payload = b"first legacy volume";
    let second_payload = b"second legacy volume";
    let logical = [first_payload.as_slice(), second_payload.as_slice()].concat();
    let directory = tempfile::tempdir().expect("legacy RAR adjacent-volume directory");
    let primary = directory.path().join("bundle.rar");
    fs::write(
        &primary,
        split_physical_volume(
            true,
            true,
            b"split.txt",
            first_payload,
            &logical,
            false,
            true,
            libarchive_oxide::filter::crc32(first_payload),
        ),
    )
    .expect("write primary legacy RAR volume");
    fs::write(
        directory.path().join("bundle.r00"),
        split_physical_volume(
            false,
            false,
            b"split.txt",
            second_payload,
            &logical,
            true,
            false,
            libarchive_oxide::filter::crc32(&logical),
        ),
    )
    .expect("write second legacy RAR volume");

    let mut session = ArchiveEngine::new()
        .open_path_with_options(
            &primary,
            &OpenOptions::new().with_adjacent_volume_discovery(true),
        )
        .expect("open old-style adjacent legacy RAR volumes");
    let inspection = session
        .inspect()
        .expect("inspect old-style adjacent legacy RAR volumes");
    assert_eq!(inspection.format(), FormatId::RarLegacy);
    assert_eq!(inspection.entries().len(), 1);
    assert_eq!(
        inspection.entries()[0].metadata().size(),
        Some(logical.len() as u64)
    );
}

#[test]
fn common_volume_reader_streams_complete_store_entries_across_legacy_rar_volumes() {
    let first_payload = b"first physical legacy RAR volume";
    let second_payload = b"second physical legacy RAR volume";
    let (volumes, resolver) = volume_set(vec![
        physical_volume(true, true, b"first.txt", first_payload),
        physical_volume(false, false, b"second.txt", second_payload),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("legacy RAR volume reader");
    assert_eq!(reader.format(), FormatId::RarLegacy);

    let mut paths = Vec::new();
    let mut payload = Vec::new();
    let mut archive_metadata = 0;
    loop {
        match reader.next_event().expect("legacy RAR volume event") {
            ReaderEvent::ArchiveMetadata(_) => archive_metadata += 1,
            ReaderEvent::Entry(entry) => paths.push(entry.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::EndEntry => {},
            _ => panic!("unexpected future legacy RAR volume event"),
        }
    }

    assert_eq!(paths, [b"first.txt".to_vec(), b"second.txt".to_vec()]);
    assert_eq!(payload, [first_payload.as_slice(), second_payload].concat());
    assert_eq!(archive_metadata, 1);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

fn typed_range(error: &Error) -> Option<RangeReadErrorKind> {
    error
        .io_error()
        .and_then(|io| io.get_ref())
        .and_then(|source| source.downcast_ref::<RangeReadError>())
        .copied()
        .map(RangeReadError::kind)
}

fn drive_to_error(volumes: Arc<VolumeSet>, limits: Limits) -> Error {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::RarLegacy))
        .with_limits(limits)
        .with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("open legacy RAR set");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("legacy RAR set unexpectedly completed"),
            Ok(_) => {},
            Err(error) => return error,
        }
    }
}

#[test]
fn legacy_rar_volume_reader_types_missing_and_misordered_volumes() {
    let (missing, resolver) = volume_set(vec![physical_volume(true, true, b"first.txt", b"first")]);
    let error = drive_to_error(missing, Limits::safe());
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    let (misordered, _) = volume_set(vec![
        physical_volume(true, true, b"first.txt", b"first"),
        physical_volume(true, false, b"second.txt", b"second"),
    ]);
    let error = drive_to_error(misordered, Limits::safe());
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn legacy_rar_volume_reader_applies_logical_limits() {
    let parts = || {
        vec![
            physical_volume(true, true, b"first.txt", b"1234"),
            physical_volume(false, false, b"second.txt", b"5678"),
        ]
    };
    let (volumes, _) = volume_set(parts());
    let error = drive_to_error(volumes, Limits::safe().with_entries(Some(1)));
    assert_eq!(error.kind(), ErrorKind::Limit);

    let (volumes, _) = volume_set(parts());
    let error = drive_to_error(volumes, Limits::safe().with_decoded_total(Some(6)));
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn legacy_rar_volume_reader_streams_one_store_entry_split_across_volumes() {
    let first = b"legacy first half ";
    let second = b"legacy second half";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let (volumes, resolver) = volume_set(vec![
        split_physical_volume(
            true,
            true,
            b"split.bin",
            first,
            &logical,
            false,
            true,
            libarchive_oxide::filter::crc32(first),
        ),
        split_physical_volume(
            false,
            false,
            b"split.bin",
            second,
            &logical,
            true,
            false,
            libarchive_oxide::filter::crc32(&logical),
        ),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("legacy RAR volume reader");
    let mut entries = 0;
    let mut ends = 0;
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("split legacy RAR event") {
            ReaderEvent::Entry(entry) => {
                entries += 1;
                assert_eq!(entry.path().as_bytes(), b"split.bin");
                assert_eq!(entry.size(), Some(logical.len() as u64));
                assert!(
                    entry.checksum().is_none(),
                    "first part CRC covers packed bytes"
                );
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("unexpected future legacy RAR event"),
        }
    }
    assert_eq!((entries, ends), (1, 1));
    assert_eq!(payload, logical);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rar")]
#[test]
fn legacy_rar_volume_reader_decodes_one_compressed_entry_split_across_volumes() {
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const UNPACKED: &[u8] = b"test text document\r\n";
    let (volumes, resolver) = volume_set(vec![
        split_compressed_physical_volume(
            true,
            true,
            b"split-compressed.txt",
            &PACKED[..15],
            UNPACKED.len() as u64,
            false,
            true,
            libarchive_oxide::filter::crc32(&PACKED[..15]),
        ),
        split_compressed_physical_volume(
            false,
            false,
            b"split-compressed.txt",
            &PACKED[15..],
            UNPACKED.len() as u64,
            true,
            false,
            libarchive_oxide::filter::crc32(UNPACKED),
        ),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("legacy RAR volume reader");

    let mut entries = 0;
    let mut ends = 0;
    let mut payload = Vec::new();
    loop {
        match reader
            .next_event()
            .expect("split compressed legacy RAR event")
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(entry) => {
                entries += 1;
                assert_eq!(entry.path().as_bytes(), b"split-compressed.txt");
                assert_eq!(entry.size(), Some(UNPACKED.len() as u64));
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            _ => panic!("unexpected future legacy RAR volume event"),
        }
    }

    assert_eq!((entries, ends), (1, 1));
    assert_eq!(payload, UNPACKED);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rar")]
#[test]
fn legacy_rar_split_compressed_checks_crc_volume_and_retained_memory_limits() {
    const PACKED: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];
    const UNPACKED: &[u8] = b"test text document\r\n";
    let parts = |first_crc, final_crc| {
        vec![
            split_compressed_physical_volume(
                true,
                true,
                b"split-compressed.txt",
                &PACKED[..15],
                UNPACKED.len() as u64,
                false,
                true,
                first_crc,
            ),
            split_compressed_physical_volume(
                false,
                false,
                b"split-compressed.txt",
                &PACKED[15..],
                UNPACKED.len() as u64,
                true,
                false,
                final_crc,
            ),
        ]
    };
    let packed_crc = libarchive_oxide::filter::crc32(&PACKED[..15]);
    let unpacked_crc = libarchive_oxide::filter::crc32(UNPACKED);

    let (bad_part, resolver) = volume_set(parts(packed_crc ^ 1, unpacked_crc));
    assert_eq!(
        drive_to_error(bad_part, Limits::safe()).kind(),
        ErrorKind::Integrity
    );
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);

    let (bad_final, resolver) = volume_set(parts(packed_crc, unpacked_crc ^ 1));
    assert_eq!(
        drive_to_error(bad_final, Limits::safe()).kind(),
        ErrorKind::Integrity
    );
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    let (missing, resolver) = volume_set(vec![
        parts(packed_crc, unpacked_crc)
            .into_iter()
            .next()
            .expect("first compressed legacy RAR volume"),
    ]);
    let error = drive_to_error(missing, Limits::safe());
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    // RAR3 owns two packed copies plus the complete output and its fixed dictionary/auxiliary workspace.
    // The volume assembler retains one more packed copy until the codec acknowledges it.
    let retained_peak =
        RAR3_DICTIONARY_BYTES + RAR3_AUXILIARY_BYTES + PACKED.len() * 3 + UNPACKED.len();
    let (too_large, _) = volume_set(parts(packed_crc, unpacked_crc));
    assert_eq!(
        drive_to_error(
            too_large,
            Limits::safe().with_codec_memory(Some(retained_peak - 1)),
        )
        .kind(),
        ErrorKind::Limit
    );

    let (exact, _) = volume_set(parts(packed_crc, unpacked_crc));
    let options = OpenOptions::new()
        .with_limits(Limits::safe().with_codec_memory(Some(retained_peak)))
        .with_volumes(exact);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("exact memory limit");
    while !matches!(
        reader.next_event().expect("exact split memory limit"),
        ReaderEvent::Done
    ) {}
}

#[test]
fn legacy_rar_volume_reader_verifies_split_part_and_logical_crc32() {
    let first = b"first";
    let second = b"second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let parts = |first_crc, final_crc| {
        vec![
            split_physical_volume(
                true,
                true,
                b"split.bin",
                first,
                &logical,
                false,
                true,
                first_crc,
            ),
            split_physical_volume(
                false,
                false,
                b"split.bin",
                second,
                &logical,
                true,
                false,
                final_crc,
            ),
        ]
    };
    let crc = libarchive_oxide::filter::crc32;

    let (volumes, resolver) = volume_set(parts(crc(first) ^ 1, crc(&logical)));
    let error = drive_to_error(volumes, Limits::safe());
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);

    let (volumes, resolver) = volume_set(parts(crc(first), crc(&logical) ^ 1));
    let error = drive_to_error(volumes, Limits::safe());
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn legacy_rar_volume_reader_rejects_mismatched_or_unfinished_split_continuations() {
    let first = b"first";
    let second = b"second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let crc = libarchive_oxide::filter::crc32;
    let (mismatched, _) = volume_set(vec![
        split_physical_volume(
            true,
            true,
            b"split.bin",
            first,
            &logical,
            false,
            true,
            crc(first),
        ),
        split_physical_volume(
            false,
            false,
            b"other.bin",
            second,
            &logical,
            true,
            false,
            crc(&logical),
        ),
    ]);
    assert_eq!(
        drive_to_error(mismatched, Limits::safe()).kind(),
        ErrorKind::Malformed
    );

    let (unfinished, resolver) = volume_set(vec![split_physical_volume(
        true,
        false,
        b"split.bin",
        first,
        &logical,
        false,
        true,
        crc(first),
    )]);
    assert_eq!(
        drive_to_error(unfinished, Limits::safe()).kind(),
        ErrorKind::Malformed
    );
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn legacy_rar_volume_reader_sequences_middle_parts_and_types_missing_volumes() {
    let first = b"first";
    let middle = b"middle";
    let final_part = b"final";
    let logical = [first.as_slice(), middle.as_slice(), final_part.as_slice()].concat();
    let crc = libarchive_oxide::filter::crc32;
    let first_volume = split_physical_volume(
        true,
        true,
        b"three.bin",
        first,
        &logical,
        false,
        true,
        crc(first),
    );
    let middle_volume = split_physical_volume(
        false,
        true,
        b"three.bin",
        middle,
        &logical,
        true,
        true,
        u32::MAX, // RAR 3/4 sentinel for an omitted non-final packed CRC.
    );
    let final_volume = split_physical_volume(
        false,
        false,
        b"three.bin",
        final_part,
        &logical,
        true,
        false,
        crc(&logical),
    );

    let (volumes, resolver) = volume_set(vec![first_volume.clone(), middle_volume, final_volume]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("legacy RAR volume reader");
    let mut data = Vec::new();
    let mut entries = 0;
    let mut ends = 0;
    loop {
        match reader.next_event().expect("three-part legacy RAR event") {
            ReaderEvent::Entry(_) => entries += 1,
            ReaderEvent::Data(bytes) => data.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("unexpected future legacy RAR event"),
        }
    }
    assert_eq!((entries, ends), (1, 1));
    assert_eq!(data, logical);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 2);

    let (missing, resolver) = volume_set(vec![first_volume]);
    let error = drive_to_error(missing, Limits::safe());
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn legacy_rar_volume_reader_rejects_previous_flag_on_first_logical_part() {
    let payload = b"orphan continuation";
    let (volumes, resolver) = volume_set(vec![split_physical_volume(
        true,
        false,
        b"orphan.bin",
        payload,
        payload,
        true,
        false,
        libarchive_oxide::filter::crc32(payload),
    )]);
    assert_eq!(
        drive_to_error(volumes, Limits::safe()).kind(),
        ErrorKind::Malformed
    );
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn legacy_rar_split_entry_uses_one_logical_entry_and_byte_budget() {
    let first = b"budget-first";
    let second = b"budget-second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let crc = libarchive_oxide::filter::crc32;
    let parts = || {
        vec![
            split_physical_volume(
                true,
                true,
                b"budget.bin",
                first,
                &logical,
                false,
                true,
                crc(first),
            ),
            split_physical_volume(
                false,
                false,
                b"budget.bin",
                second,
                &logical,
                true,
                false,
                crc(&logical),
            ),
        ]
    };
    let exact = logical.len() as u64;
    let (volumes, _) = volume_set(parts());
    let options = OpenOptions::new()
        .with_limits(
            Limits::safe()
                .with_entries(Some(1))
                .with_entry_bytes(Some(exact))
                .with_decoded_total(Some(exact)),
        )
        .with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("bounded split reader");
    loop {
        if matches!(
            reader.next_event().expect("exact split budget"),
            ReaderEvent::Done
        ) {
            break;
        }
    }

    for limits in [
        Limits::safe().with_entries(Some(0)),
        Limits::safe().with_entry_bytes(Some(exact - 1)),
        Limits::safe().with_decoded_total(Some(exact - 1)),
    ] {
        let (volumes, _) = volume_set(parts());
        assert_eq!(drive_to_error(volumes, limits).kind(), ErrorKind::Limit);
    }
}
