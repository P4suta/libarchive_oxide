// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RAR5 physical-volume sequencing over the common bounded source model.

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
use libarchive_oxide_core::Rar5SplitVerifier;

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

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
        SourceIdentity::try_new(format!("rar5-volume-{index}-v1").into_bytes())
            .expect("valid source identity"),
    ))
}

fn volume_set(parts: Vec<Vec<u8>>) -> (Arc<VolumeSet>, Arc<Resolver>) {
    let mut parts = parts.into_iter().enumerate();
    let (_, primary) = parts.next().expect("RAR5 set has a primary volume");
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
            .expect("bounded RAR5 volume set"),
    );
    (volumes, resolver)
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

fn block(header_type: u64, flags: u64, data_size: Option<u64>, fields: &[u8]) -> Vec<u8> {
    block_with_extra(header_type, flags, data_size, fields, &[])
}

fn block_with_extra(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    fields: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut body = vint(header_type);
    body.extend_from_slice(&vint(flags));
    if flags & 0x0001 != 0 {
        body.extend_from_slice(&vint(extra.len() as u64));
    }
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

fn physical_volume(index: u64, next: bool, name: &[u8], payload: &[u8]) -> Vec<u8> {
    physical_volume_with_file_flags(index, next, name, payload, 0x0002)
}

fn physical_volume_with_file_flags(
    index: u64,
    next: bool,
    name: &[u8],
    payload: &[u8],
    common_flags: u64,
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let mut main = vint(0x03); // volume archive with an explicit volume number
    main.extend_from_slice(&vint(index));
    archive.extend_from_slice(&block(1, 0, None, &main));

    let mut file = vint(0x0004); // data CRC32
    file.extend_from_slice(&vint(payload.len() as u64));
    file.extend_from_slice(&vint(0o100_640));
    file.extend_from_slice(&crc32(payload).to_le_bytes());
    file.extend_from_slice(&vint(0)); // Store
    file.extend_from_slice(&vint(1)); // Unix host
    file.extend_from_slice(&vint(name.len() as u64));
    file.extend_from_slice(name);
    archive.extend_from_slice(&block(2, common_flags, Some(payload.len() as u64), &file));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&block(5, 0, None, &vint(u64::from(next))));
    archive
}

#[test]
fn path_open_discovers_modern_rar_names_and_hashes_every_volume() {
    let open = |second_payload: &[u8]| {
        let first_payload = b"same primary ";
        let logical = [first_payload.as_slice(), second_payload].concat();
        let first = split_physical_volume(
            0,
            true,
            b"split.txt",
            first_payload,
            &logical,
            false,
            true,
            crc32(first_payload),
        );
        let second = split_physical_volume(
            1,
            false,
            b"split.txt",
            second_payload,
            &logical,
            true,
            false,
            crc32(&logical),
        );
        let directory = tempfile::tempdir().expect("RAR5 adjacent-volume directory");
        let primary = directory.path().join("bundle.part001.rar");
        fs::write(&primary, &first).expect("write first RAR5 volume");
        fs::write(directory.path().join("bundle.part002.rar"), second)
            .expect("write second RAR5 volume");
        let mut session = ArchiveEngine::new()
            .open_path_with_options(
                &primary,
                &OpenOptions::new().with_adjacent_volume_discovery(true),
            )
            .expect("open adjacent RAR5 volumes");
        let digest = session.digest();
        let inspection = session.inspect().expect("inspect adjacent RAR5 volumes");
        assert_eq!(inspection.digest(), digest);
        assert_eq!(inspection.format(), FormatId::Rar5);
        assert_eq!(inspection.entries().len(), 1);
        assert_eq!(
            inspection.entries()[0].metadata().size(),
            Some(logical.len() as u64)
        );
        digest
    };

    let first_digest = open(b"second payload A");
    let same_digest = open(b"second payload A");
    let changed_digest = open(b"second payload B");
    assert_eq!(first_digest, same_digest);
    assert_ne!(first_digest, changed_digest);
}

#[test]
fn path_open_rejects_non_primary_or_incoherent_rar_names() {
    let directory = tempfile::tempdir().expect("RAR5 adjacent-volume directory");
    let part_two = directory.path().join("bundle.part002.rar");
    fs::write(
        &part_two,
        physical_volume(0, false, b"entry.txt", b"payload"),
    )
    .expect("write non-primary RAR5 path");
    let discover = OpenOptions::new().with_adjacent_volume_discovery(true);
    let error = ArchiveEngine::new()
        .open_path_with_options(&part_two, &discover)
        .expect_err("RAR discovery must start at part one");
    assert_eq!(error.kind(), ErrorKind::Capability);

    let unsuffixed = directory.path().join("bundle.rar");
    fs::write(
        &unsuffixed,
        physical_volume(0, false, b"entry.txt", b"payload"),
    )
    .expect("write unsuffixed RAR5 path");
    let error = ArchiveEngine::new()
        .open_path_with_options(
            &unsuffixed,
            &discover.clone().with_format(Some(FormatId::Rar5)),
        )
        .expect_err("RAR5 cannot use the legacy extension sequence");
    assert_eq!(error.kind(), ErrorKind::Capability);
    ArchiveEngine::new()
        .open_path_with_options(&unsuffixed, &discover)
        .expect_err("automatic discovery must not reinterpret legacy naming as RAR5");

    let missing = directory.path().join("missing.part001.rar");
    fs::write(&missing, physical_volume(0, true, b"entry.txt", b"payload"))
        .expect("write RAR5 volume requiring a missing continuation");
    let error = ArchiveEngine::new()
        .open_path_with_options(&missing, &discover)
        .expect_err("missing adjacent RAR volume must remain typed");
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
}

#[allow(clippy::too_many_arguments)]
fn split_physical_volume(
    index: u64,
    next_volume: bool,
    name: &[u8],
    part: &[u8],
    logical_payload: &[u8],
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    split_physical_volume_with_extra(
        index,
        next_volume,
        name,
        part,
        logical_payload,
        split_before,
        split_after,
        checksum,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn split_physical_volume_with_extra(
    index: u64,
    next_volume: bool,
    name: &[u8],
    part: &[u8],
    logical_payload: &[u8],
    split_before: bool,
    split_after: bool,
    checksum: u32,
    extra: &[u8],
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let mut main = vint(0x03);
    main.extend_from_slice(&vint(index));
    archive.extend_from_slice(&block(1, 0, None, &main));

    let mut file = vint(0x0004); // data CRC32
    file.extend_from_slice(&vint(logical_payload.len() as u64));
    file.extend_from_slice(&vint(0o100_640));
    file.extend_from_slice(&checksum.to_le_bytes());
    file.extend_from_slice(&vint(0)); // Store
    file.extend_from_slice(&vint(1)); // Unix host
    file.extend_from_slice(&vint(name.len() as u64));
    file.extend_from_slice(name);
    let flags = 0x0002
        | u64::from(!extra.is_empty())
        | (u64::from(split_before) * 0x0008)
        | (u64::from(split_after) * 0x0010);
    archive.extend_from_slice(&block_with_extra(
        2,
        flags,
        Some(part.len() as u64),
        &file,
        extra,
    ));
    archive.extend_from_slice(part);
    archive.extend_from_slice(&block(5, 0, None, &vint(u64::from(next_volume))));
    archive
}

#[cfg(feature = "rar")]
#[allow(clippy::too_many_arguments)]
fn split_compressed_physical_volume(
    index: u64,
    next_volume: bool,
    name: &[u8],
    packed_part: &[u8],
    unpacked_size: u64,
    split_before: bool,
    split_after: bool,
    checksum: u32,
) -> Vec<u8> {
    compressed_physical_volume(
        index,
        name,
        packed_part,
        unpacked_size,
        checksum,
        CompressedVolumeOptions {
            end: if next_volume {
                PhysicalEnd::Continue
            } else {
                PhysicalEnd::Final
            },
            compression: 3 << 7,
            archive: ArchiveCompression::Independent,
            part: PhysicalPart::from_flags(split_before, split_after),
        },
    )
}

#[cfg(feature = "rar")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhysicalEnd {
    Continue,
    Final,
}

#[cfg(feature = "rar")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveCompression {
    Independent,
    Solid,
}

#[cfg(feature = "rar")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhysicalPart {
    Complete,
    First,
    Middle,
    Final,
}

#[cfg(feature = "rar")]
impl PhysicalPart {
    const fn from_flags(before: bool, after: bool) -> Self {
        match (before, after) {
            (false, false) => Self::Complete,
            (false, true) => Self::First,
            (true, true) => Self::Middle,
            (true, false) => Self::Final,
        }
    }

    const fn before(self) -> bool {
        matches!(self, Self::Middle | Self::Final)
    }

    const fn after(self) -> bool {
        matches!(self, Self::First | Self::Middle)
    }
}

#[cfg(feature = "rar")]
#[derive(Clone, Copy)]
struct CompressedVolumeOptions {
    end: PhysicalEnd,
    compression: u64,
    archive: ArchiveCompression,
    part: PhysicalPart,
}

#[cfg(feature = "rar")]
fn compressed_physical_volume(
    index: u64,
    name: &[u8],
    packed_part: &[u8],
    unpacked_size: u64,
    checksum: u32,
    options: CompressedVolumeOptions,
) -> Vec<u8> {
    let mut archive = SIGNATURE.to_vec();
    let mut main = vint(0x03 | (u64::from(options.archive == ArchiveCompression::Solid) << 2));
    main.extend_from_slice(&vint(index));
    archive.extend_from_slice(&block(1, 0, None, &main));

    let mut file = vint(0x0004); // data CRC32
    file.extend_from_slice(&vint(unpacked_size));
    file.extend_from_slice(&vint(0o100_640));
    file.extend_from_slice(&checksum.to_le_bytes());
    file.extend_from_slice(&vint(options.compression));
    file.extend_from_slice(&vint(1)); // Unix host
    file.extend_from_slice(&vint(name.len() as u64));
    file.extend_from_slice(name);
    let flags = 0x0002
        | (u64::from(options.part.before()) * 0x0008)
        | (u64::from(options.part.after()) * 0x0010);
    archive.extend_from_slice(&block(2, flags, Some(packed_part.len() as u64), &file));
    archive.extend_from_slice(packed_part);
    archive.extend_from_slice(&block(
        5,
        0,
        None,
        &vint(u64::from(options.end == PhysicalEnd::Continue)),
    ));
    archive
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

#[cfg(feature = "rar")]
fn solid_payload(magic: i32) -> Vec<u8> {
    (1_i32..=1024)
        .flat_map(|value| (value * value - 3 * value + 1 + magic).max(0).to_le_bytes())
        .collect()
}

#[cfg(feature = "rar")]
fn official_solid_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let fixture = decode_hex(include_str!(
        "fixtures/rar5/libarchive-v3.8.8-multiple-files-solid.rar.hex"
    ));
    (
        fixture[68..445].to_vec(),
        fixture[489..514].to_vec(),
        solid_payload(1),
        solid_payload(2),
    )
}

fn blake2sp_extra(bytes: &[u8]) -> Vec<u8> {
    let mut verifier = Rar5SplitVerifier::new();
    verifier.update(bytes);
    let mut record = vint(2); // file hash extra record
    record.extend_from_slice(&vint(0)); // BLAKE2sp
    record.extend_from_slice(&verifier.blake2sp());
    let mut extra = vint(record.len() as u64);
    extra.extend_from_slice(&record);
    extra
}

#[test]
fn common_volume_reader_streams_complete_store_entries_across_rar5_volumes() {
    let first_payload = b"first physical RAR5 volume";
    let second_payload = b"second physical RAR5 volume";
    let (volumes, resolver) = volume_set(vec![
        physical_volume(0, true, b"first.txt", first_payload),
        physical_volume(1, false, b"second.txt", second_payload),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");
    assert_eq!(reader.format(), FormatId::Rar5);

    let mut paths = Vec::new();
    let mut payload = Vec::new();
    let mut archive_metadata = 0;
    loop {
        match reader.next_event().expect("RAR5 volume event") {
            ReaderEvent::ArchiveMetadata(_) => archive_metadata += 1,
            ReaderEvent::Entry(entry) => paths.push(entry.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::EndEntry => {},
            _ => panic!("unexpected future RAR5 volume event"),
        }
    }

    assert_eq!(paths, [b"first.txt".to_vec(), b"second.txt".to_vec()]);
    assert_eq!(payload, [first_payload.as_slice(), second_payload].concat());
    assert_eq!(archive_metadata, 1, "one logical archive metadata event");
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

fn drive_to_error(volumes: Arc<VolumeSet>) -> Error {
    drive_to_error_with_limits(volumes, Limits::safe())
}

fn drive_to_error_with_limits(volumes: Arc<VolumeSet>, limits: Limits) -> Error {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Rar5))
        .with_limits(limits)
        .with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("open RAR5 volume set");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("RAR5 volume set unexpectedly completed"),
            Ok(_) => {},
            Err(error) => return error,
        }
    }
}

#[test]
fn rar5_volume_reader_applies_entry_and_decoded_limits_across_the_logical_set() {
    let parts = || {
        vec![
            physical_volume(0, true, b"first.txt", b"1234"),
            physical_volume(1, false, b"second.txt", b"5678"),
        ]
    };
    let (volumes, _) = volume_set(parts());
    let error = drive_to_error_with_limits(volumes, Limits::safe().with_entries(Some(1)));
    assert_eq!(error.kind(), ErrorKind::Limit);

    let (volumes, _) = volume_set(parts());
    let error = drive_to_error_with_limits(volumes, Limits::safe().with_decoded_total(Some(6)));
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn rar5_volume_reader_types_missing_and_out_of_sequence_volumes() {
    let (missing, resolver) = volume_set(vec![physical_volume(0, true, b"first.txt", b"first")]);
    let error = drive_to_error(missing);
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    let (wrong, _) = volume_set(vec![
        physical_volume(0, true, b"first.txt", b"first"),
        physical_volume(7, false, b"second.txt", b"second"),
    ]);
    let error = drive_to_error(wrong);
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn rar5_volume_reader_streams_one_store_entry_split_across_volumes() {
    let first = b"first half ";
    let second = b"second half";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let (volumes, resolver) = volume_set(vec![
        split_physical_volume(
            0,
            true,
            b"split.bin",
            first,
            &logical,
            false,
            true,
            crc32(first),
        ),
        split_physical_volume(
            1,
            false,
            b"split.bin",
            second,
            &logical,
            true,
            false,
            crc32(&logical),
        ),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");

    let mut entries = 0;
    let mut ends = 0;
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("split RAR5 volume event") {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(entry) => {
                entries += 1;
                assert_eq!(entry.path().as_bytes(), b"split.bin");
                assert_eq!(entry.size(), Some(logical.len() as u64));
                assert!(
                    entry.checksum().is_none(),
                    "first part CRC is packed-data CRC"
                );
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            _ => panic!("unexpected future RAR5 volume event"),
        }
    }

    assert_eq!(entries, 1);
    assert_eq!(ends, 1);
    assert_eq!(payload, logical);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rar")]
#[test]
fn rar5_volume_reader_streams_one_compressed_entry_split_across_volumes() {
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut unpacked = vec![b'A'; 200];
    unpacked.push(b'\n');
    let (volumes, resolver) = volume_set(vec![
        split_compressed_physical_volume(
            0,
            true,
            b"split-compressed.txt",
            &PACKED[..8],
            unpacked.len() as u64,
            false,
            true,
            crc32(&PACKED[..8]),
        ),
        split_compressed_physical_volume(
            1,
            false,
            b"split-compressed.txt",
            &PACKED[8..],
            unpacked.len() as u64,
            true,
            false,
            crc32(&unpacked),
        ),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");

    let mut entries = 0;
    let mut ends = 0;
    let mut payload = Vec::new();
    loop {
        match reader
            .next_event()
            .expect("split compressed RAR5 volume event")
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(entry) => {
                entries += 1;
                assert_eq!(entry.path().as_bytes(), b"split-compressed.txt");
                assert_eq!(entry.size(), Some(unpacked.len() as u64));
            },
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            _ => panic!("unexpected future RAR5 volume event"),
        }
    }

    assert_eq!(entries, 1);
    assert_eq!(ends, 1);
    assert_eq!(payload, unpacked);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rar")]
#[test]
fn rar5_volume_reader_continues_solid_state_into_a_split_member() {
    let (first_packed, second_packed, first, second) = official_solid_pair();
    let split = 12;
    let (volumes, resolver) = volume_set(vec![
        compressed_physical_volume(
            0,
            b"test1.bin",
            &first_packed,
            first.len() as u64,
            crc32(&first),
            CompressedVolumeOptions {
                end: PhysicalEnd::Continue,
                compression: 0x0e80,
                archive: ArchiveCompression::Solid,
                part: PhysicalPart::Complete,
            },
        ),
        compressed_physical_volume(
            1,
            b"test2.bin",
            &second_packed[..split],
            second.len() as u64,
            crc32(&second_packed[..split]),
            CompressedVolumeOptions {
                end: PhysicalEnd::Continue,
                compression: 0x0ec0,
                archive: ArchiveCompression::Solid,
                part: PhysicalPart::First,
            },
        ),
        compressed_physical_volume(
            2,
            b"test2.bin",
            &second_packed[split..],
            second.len() as u64,
            crc32(&second),
            CompressedVolumeOptions {
                end: PhysicalEnd::Final,
                compression: 0x0ec0,
                archive: ArchiveCompression::Solid,
                part: PhysicalPart::Final,
            },
        ),
    ]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");

    let mut paths = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    loop {
        match reader.next_event().expect("solid split RAR5 event") {
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Entry(entry) => {
                paths.push(entry.path().as_bytes().to_vec());
                payloads.push(Vec::new());
            },
            ReaderEvent::Data(bytes) => payloads
                .last_mut()
                .expect("entry precedes its payload")
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => panic!("unexpected future RAR5 volume event"),
        }
    }

    assert_eq!(paths, [b"test1.bin".to_vec(), b"test2.bin".to_vec()]);
    assert_eq!(payloads, [first, second]);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 2);
}

#[cfg(feature = "rar")]
#[test]
fn rar5_solid_volumes_reject_missing_state_changed_dictionary_and_flag_drift() {
    let (first_packed, second_packed, first, second) = official_solid_pair();

    let (missing_state, _) = volume_set(vec![compressed_physical_volume(
        0,
        b"test2.bin",
        &second_packed,
        second.len() as u64,
        crc32(&second),
        CompressedVolumeOptions {
            end: PhysicalEnd::Final,
            compression: 0x0ec0,
            archive: ArchiveCompression::Solid,
            part: PhysicalPart::Complete,
        },
    )]);
    assert_eq!(drive_to_error(missing_state).kind(), ErrorKind::Malformed);

    for (second_compression, second_archive_solid) in [(0x12c0, true), (0x0ec0, false)] {
        let (volumes, _) = volume_set(vec![
            compressed_physical_volume(
                0,
                b"test1.bin",
                &first_packed,
                first.len() as u64,
                crc32(&first),
                CompressedVolumeOptions {
                    end: PhysicalEnd::Continue,
                    compression: 0x0e80,
                    archive: ArchiveCompression::Solid,
                    part: PhysicalPart::Complete,
                },
            ),
            compressed_physical_volume(
                1,
                b"test2.bin",
                &second_packed,
                second.len() as u64,
                crc32(&second),
                CompressedVolumeOptions {
                    end: PhysicalEnd::Final,
                    compression: second_compression,
                    archive: if second_archive_solid {
                        ArchiveCompression::Solid
                    } else {
                        ArchiveCompression::Independent
                    },
                    part: PhysicalPart::Complete,
                },
            ),
        ]);
        assert_eq!(drive_to_error(volumes).kind(), ErrorKind::Malformed);
    }
}

#[cfg(feature = "rar")]
#[test]
fn rar5_split_compressed_checks_each_part_final_plaintext_and_missing_volume() {
    const PACKED: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];
    let mut unpacked = vec![b'A'; 200];
    unpacked.push(b'\n');
    let parts = |first_crc, final_crc| {
        vec![
            split_compressed_physical_volume(
                0,
                true,
                b"split-compressed.txt",
                &PACKED[..8],
                unpacked.len() as u64,
                false,
                true,
                first_crc,
            ),
            split_compressed_physical_volume(
                1,
                false,
                b"split-compressed.txt",
                &PACKED[8..],
                unpacked.len() as u64,
                true,
                false,
                final_crc,
            ),
        ]
    };

    let (bad_part, resolver) = volume_set(parts(crc32(&PACKED[..8]) ^ 1, crc32(&unpacked)));
    let error = drive_to_error(bad_part);
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);

    let (bad_final, resolver) = volume_set(parts(crc32(&PACKED[..8]), crc32(&unpacked) ^ 1));
    let error = drive_to_error(bad_final);
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    let (missing, resolver) = volume_set(vec![
        parts(crc32(&PACKED[..8]), crc32(&unpacked))
            .into_iter()
            .next()
            .expect("first compressed volume"),
    ]);
    let error = drive_to_error(missing);
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn rar5_volume_reader_verifies_split_part_and_logical_checksums() {
    let first = b"first";
    let second = b"second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let parts = |first_crc, final_crc| {
        vec![
            split_physical_volume(
                0,
                true,
                b"split.bin",
                first,
                &logical,
                false,
                true,
                first_crc,
            ),
            split_physical_volume(
                1,
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

    let (volumes, resolver) = volume_set(parts(crc32(first) ^ 1, crc32(&logical)));
    let error = drive_to_error(volumes);
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);

    let (volumes, resolver) = volume_set(parts(crc32(first), crc32(&logical) ^ 1));
    let error = drive_to_error(volumes);
    assert_eq!(error.kind(), ErrorKind::Integrity);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn rar5_volume_reader_verifies_split_blake2sp_and_crc32() {
    let first = b"first BLAKE2sp part";
    let second = b"second BLAKE2sp part";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let parts = |final_extra: Vec<u8>| {
        vec![
            split_physical_volume_with_extra(
                0,
                true,
                b"split-hash.bin",
                first,
                &logical,
                false,
                true,
                crc32(first),
                &blake2sp_extra(first),
            ),
            split_physical_volume_with_extra(
                1,
                false,
                b"split-hash.bin",
                second,
                &logical,
                true,
                false,
                crc32(&logical),
                &final_extra,
            ),
        ]
    };

    let (volumes, _) = volume_set(parts(blake2sp_extra(&logical)));
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");
    loop {
        if matches!(
            reader.next_event().expect("valid split hashes"),
            ReaderEvent::Done
        ) {
            break;
        }
    }

    let mut corrupted = blake2sp_extra(&logical);
    let last = corrupted.last_mut().expect("digest byte");
    *last ^= 1;
    let (volumes, _) = volume_set(parts(corrupted));
    assert_eq!(drive_to_error(volumes).kind(), ErrorKind::Integrity);
}

#[test]
fn rar5_volume_reader_sequences_middle_parts_and_types_missing_split_volumes() {
    let first = b"first";
    let middle = b"middle";
    let final_part = b"final";
    let logical = [first.as_slice(), middle.as_slice(), final_part.as_slice()].concat();
    let first_volume = split_physical_volume(
        0,
        true,
        b"three.bin",
        first,
        &logical,
        false,
        true,
        crc32(first),
    );
    let middle_volume = split_physical_volume(
        1,
        true,
        b"three.bin",
        middle,
        &logical,
        true,
        true,
        crc32(middle),
    );
    let final_volume = split_physical_volume(
        2,
        false,
        b"three.bin",
        final_part,
        &logical,
        true,
        false,
        crc32(&logical),
    );

    let (volumes, resolver) = volume_set(vec![first_volume.clone(), middle_volume, final_volume]);
    let options = OpenOptions::new().with_volumes(volumes);
    let mut reader = VolumeArchiveReader::with_options(&options).expect("RAR5 volume reader");
    let mut data = Vec::new();
    let mut entries = 0;
    let mut ends = 0;
    loop {
        match reader.next_event().expect("three-part RAR5 event") {
            ReaderEvent::Entry(_) => entries += 1,
            ReaderEvent::Data(bytes) => data.extend_from_slice(bytes),
            ReaderEvent::EndEntry => ends += 1,
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("unexpected future RAR5 volume event"),
        }
    }
    assert_eq!((entries, ends), (1, 1));
    assert_eq!(data, logical);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 2);

    let (missing, resolver) = volume_set(vec![first_volume]);
    let error = drive_to_error(missing);
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn rar5_volume_reader_rejects_a_previous_flag_on_the_first_logical_part() {
    let payload = b"orphan continuation";
    let (volumes, resolver) = volume_set(vec![split_physical_volume(
        0,
        false,
        b"orphan.bin",
        payload,
        payload,
        true,
        false,
        crc32(payload),
    )]);
    assert_eq!(drive_to_error(volumes).kind(), ErrorKind::Malformed);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn rar5_split_entry_uses_one_logical_entry_and_one_logical_byte_budget() {
    let first = b"budget-first";
    let second = b"budget-second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let parts = || {
        vec![
            split_physical_volume(
                0,
                true,
                b"budget.bin",
                first,
                &logical,
                false,
                true,
                crc32(first),
            ),
            split_physical_volume(
                1,
                false,
                b"budget.bin",
                second,
                &logical,
                true,
                false,
                crc32(&logical),
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
        assert_eq!(
            drive_to_error_with_limits(volumes, limits).kind(),
            ErrorKind::Limit
        );
    }
}

#[test]
fn rar5_volume_reader_rejects_mismatched_or_unfinished_split_continuations() {
    let first = b"first";
    let second = b"second";
    let logical = [first.as_slice(), second.as_slice()].concat();
    let (mismatched, _) = volume_set(vec![
        split_physical_volume(
            0,
            true,
            b"split.bin",
            first,
            &logical,
            false,
            true,
            crc32(first),
        ),
        split_physical_volume(
            1,
            false,
            b"other.bin",
            second,
            &logical,
            true,
            false,
            crc32(&logical),
        ),
    ]);
    assert_eq!(drive_to_error(mismatched).kind(), ErrorKind::Malformed);

    let (unfinished, resolver) = volume_set(vec![split_physical_volume(
        0,
        false,
        b"split.bin",
        first,
        &logical,
        false,
        true,
        crc32(first),
    )]);
    assert_eq!(drive_to_error(unfinished).kind(), ErrorKind::Malformed);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 0);
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
