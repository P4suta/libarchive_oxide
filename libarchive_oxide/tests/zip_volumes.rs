// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standard split-ZIP reads over the common bounded volume model.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::sync::Arc;

use libarchive_oxide::advanced::{
    MemoryReadAt, RangeReadError, RangeReadErrorKind, ReadAt, SourceIdentity, SourceLimits,
    VolumeId, VolumeResolver, VolumeSet, ZipVolumeProvider,
};
use libarchive_oxide::{
    ArchiveEngine, Error, ErrorKind, FormatId, OpenOptions, ReaderEvent, SeekArchiveReader,
    VolumeArchiveReader,
};

struct Resolver {
    volumes: BTreeMap<VolumeId, Arc<dyn ReadAt>>,
}

type ExpectedEntries = Vec<(Vec<u8>, Vec<u8>)>;

impl VolumeResolver for Resolver {
    fn resolve(&self, volume: VolumeId) -> std::io::Result<Option<Arc<dyn ReadAt>>> {
        Ok(self.volumes.get(&volume).cloned())
    }
}

fn source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(MemoryReadAt::new(
        bytes,
        SourceIdentity::try_new(format!("split-zip-volume-{index}-v1").into_bytes())
            .expect("valid source identity"),
    ))
}

fn volume_set(parts: Vec<Vec<u8>>) -> Arc<VolumeSet> {
    let mut parts = parts.into_iter().enumerate();
    let (_, primary) = parts.next().expect("split ZIP has a primary volume");
    let resolver = Arc::new(Resolver {
        volumes: parts
            .map(|(index, bytes)| {
                (
                    VolumeId::new(u32::try_from(index).expect("small volume index")),
                    source(index, bytes),
                )
            })
            .collect(),
    });
    Arc::new(
        VolumeSet::new(source(0, primary), resolver, SourceLimits::safe())
            .expect("create bounded ZIP volume set"),
    )
}

fn u16le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn u32le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn u64le(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn local_header(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut output = b"PK\x03\x04".to_vec();
    u16le(&mut output, 20);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u32le(&mut output, libarchive_oxide::filter::crc32(payload));
    u32le(
        &mut output,
        u32::try_from(payload.len()).expect("small payload"),
    );
    u32le(
        &mut output,
        u32::try_from(payload.len()).expect("small payload"),
    );
    u16le(
        &mut output,
        u16::try_from(name.len()).expect("small filename"),
    );
    u16le(&mut output, 0);
    output.extend_from_slice(name);
    output
}

fn central_header(name: &[u8], payload: &[u8], disk: u16, offset: u32) -> Vec<u8> {
    let mut output = b"PK\x01\x02".to_vec();
    u16le(&mut output, 20);
    u16le(&mut output, 20);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u32le(&mut output, libarchive_oxide::filter::crc32(payload));
    u32le(
        &mut output,
        u32::try_from(payload.len()).expect("small payload"),
    );
    u32le(
        &mut output,
        u32::try_from(payload.len()).expect("small payload"),
    );
    u16le(
        &mut output,
        u16::try_from(name.len()).expect("small filename"),
    );
    u16le(&mut output, 0);
    u16le(&mut output, 0);
    u16le(&mut output, disk);
    u16le(&mut output, 0);
    u32le(&mut output, 0);
    u32le(&mut output, offset);
    output.extend_from_slice(name);
    output
}

fn standard_split_zip() -> (Vec<Vec<u8>>, ExpectedEntries) {
    let first_name = b"first.txt";
    let first_payload = b"payload crossing a physical ZIP boundary";
    let second_name = b"second.txt";
    let second_payload = b"payload beginning on disk one";
    let split = 13;

    let mut disk_zero = b"PK\x07\x08".to_vec();
    disk_zero.extend_from_slice(&local_header(first_name, first_payload));
    disk_zero.extend_from_slice(&first_payload[..split]);

    let mut disk_one = first_payload[split..].to_vec();
    let second_offset = u32::try_from(disk_one.len()).expect("small second local offset");
    disk_one.extend_from_slice(&local_header(second_name, second_payload));
    disk_one.extend_from_slice(second_payload);

    let mut central = central_header(first_name, first_payload, 0, 4);
    central.extend_from_slice(&central_header(
        second_name,
        second_payload,
        1,
        second_offset,
    ));
    let central_size = u32::try_from(central.len()).expect("small central directory");
    let mut disk_two = central;
    disk_two.extend_from_slice(b"PK\x05\x06");
    u16le(&mut disk_two, 2);
    u16le(&mut disk_two, 2);
    u16le(&mut disk_two, 2);
    u16le(&mut disk_two, 2);
    u32le(&mut disk_two, central_size);
    u32le(&mut disk_two, 0);
    u16le(&mut disk_two, 0);

    (
        vec![disk_zero, disk_one, disk_two],
        vec![
            (first_name.to_vec(), first_payload.to_vec()),
            (second_name.to_vec(), second_payload.to_vec()),
        ],
    )
}

fn zip64_split_zip() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let name = b"zip64.txt";
    let payload = b"small payload using ZIP64 multi-disk sentinels";
    let mut disk_zero = b"PK\x07\x08".to_vec();
    disk_zero.extend_from_slice(&local_header(name, payload));
    disk_zero.extend_from_slice(payload);

    let mut extra = Vec::new();
    u16le(&mut extra, 0x0001);
    u16le(&mut extra, 28);
    u64le(
        &mut extra,
        u64::try_from(payload.len()).expect("small payload"),
    );
    u64le(
        &mut extra,
        u64::try_from(payload.len()).expect("small payload"),
    );
    u64le(&mut extra, 4);
    u32le(&mut extra, 0);

    let mut central = b"PK\x01\x02".to_vec();
    u16le(&mut central, 45);
    u16le(&mut central, 45);
    u16le(&mut central, 0);
    u16le(&mut central, 0);
    u16le(&mut central, 0);
    u16le(&mut central, 0);
    u32le(&mut central, libarchive_oxide::filter::crc32(payload));
    u32le(&mut central, u32::MAX);
    u32le(&mut central, u32::MAX);
    u16le(
        &mut central,
        u16::try_from(name.len()).expect("small filename"),
    );
    u16le(
        &mut central,
        u16::try_from(extra.len()).expect("small extra field"),
    );
    u16le(&mut central, 0);
    u16le(&mut central, u16::MAX);
    u16le(&mut central, 0);
    u32le(&mut central, 0);
    u32le(&mut central, u32::MAX);
    central.extend_from_slice(name);
    central.extend_from_slice(&extra);

    let central_size = u64::try_from(central.len()).expect("small central directory");
    let mut final_disk = central;
    let zip64_offset = u64::try_from(final_disk.len()).expect("small ZIP64 offset");
    final_disk.extend_from_slice(b"PK\x06\x06");
    u64le(&mut final_disk, 44);
    u16le(&mut final_disk, 45);
    u16le(&mut final_disk, 45);
    u32le(&mut final_disk, 1);
    u32le(&mut final_disk, 1);
    u64le(&mut final_disk, 1);
    u64le(&mut final_disk, 1);
    u64le(&mut final_disk, central_size);
    u64le(&mut final_disk, 0);
    final_disk.extend_from_slice(b"PK\x06\x07");
    u32le(&mut final_disk, 1);
    u64le(&mut final_disk, zip64_offset);
    u32le(&mut final_disk, 2);
    final_disk.extend_from_slice(b"PK\x05\x06");
    u16le(&mut final_disk, u16::MAX);
    u16le(&mut final_disk, u16::MAX);
    u16le(&mut final_disk, u16::MAX);
    u16le(&mut final_disk, u16::MAX);
    u32le(&mut final_disk, u32::MAX);
    u32le(&mut final_disk, u32::MAX);
    u16le(&mut final_disk, 0);
    (vec![disk_zero, final_disk], name.to_vec(), payload.to_vec())
}

fn typed_range(error: &Error) -> Option<RangeReadErrorKind> {
    error
        .io_error()
        .and_then(|io| io.get_ref())
        .and_then(|source| source.downcast_ref::<RangeReadError>())
        .copied()
        .map(RangeReadError::kind)
}

#[test]
fn common_volume_reader_streams_standard_split_zip_with_disk_relative_offsets() {
    let (parts, expected) = standard_split_zip();
    let mut reader = VolumeArchiveReader::new(volume_set(parts)).expect("open split ZIP");
    assert_eq!(reader.format(), FormatId::Zip);

    let mut actual = Vec::<(Vec<u8>, Vec<u8>)>::new();
    loop {
        match reader.next_event().expect("read split ZIP event") {
            ReaderEvent::Entry(entry) => {
                actual.push((entry.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(bytes) => actual
                .last_mut()
                .expect("payload follows entry")
                .1
                .extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(actual, expected);

    let _provider = ZipVolumeProvider::new();
}

#[test]
fn common_volume_reader_honors_zip64_disk_start_and_relative_offsets() {
    let (parts, expected_name, expected_payload) = zip64_split_zip();
    let mut reader = VolumeArchiveReader::new(volume_set(parts)).expect("open split ZIP64");
    let mut actual_payload = Vec::new();
    loop {
        match reader.next_event().expect("read split ZIP64 event") {
            ReaderEvent::Entry(entry) => assert_eq!(entry.path().as_bytes(), expected_name),
            ReaderEvent::Data(bytes) => actual_payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(actual_payload, expected_payload);
}

#[test]
fn split_zip_rejects_unavailable_entry_and_end_record_disks() {
    let (mut parts, _) = standard_split_zip();
    let second_central_disk = (46 + b"first.txt".len()) + 34;
    parts[2][second_central_disk..second_central_disk + 2].copy_from_slice(&9_u16.to_le_bytes());
    let error = VolumeArchiveReader::new(volume_set(parts))
        .expect_err("central entry must not reference an unavailable disk");
    assert_eq!(error.kind(), ErrorKind::Malformed);

    let (mut parts, _) = standard_split_zip();
    let eocd = parts[2]
        .windows(4)
        .position(|window| window == b"PK\x05\x06")
        .expect("split ZIP EOCD");
    parts[2][eocd + 4..eocd + 6].copy_from_slice(&3_u16.to_le_bytes());
    let error = VolumeArchiveReader::new(volume_set(parts))
        .expect_err("EOCD final disk must match the supplied volume set");
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn ordinary_seek_reader_rejects_multi_disk_fields_without_a_volume_set() {
    let (parts, _) = standard_split_zip();
    let mut joined = parts.concat();
    joined.drain(..4);
    let error = SeekArchiveReader::new(Cursor::new(joined))
        .expect_err("ordinary seek input must not reinterpret multi-disk offsets");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn path_open_discovers_z_segments_from_the_terminal_zip_name() {
    let (parts, expected) = standard_split_zip();
    let directory = tempfile::tempdir().expect("split ZIP adjacent-volume directory");
    fs::write(directory.path().join("bundle.z01"), &parts[0]).expect("write ZIP disk zero");
    fs::write(directory.path().join("bundle.z02"), &parts[1]).expect("write ZIP disk one");
    let terminal = directory.path().join("bundle.zip");
    fs::write(&terminal, &parts[2]).expect("write ZIP terminal disk");

    let discover = OpenOptions::new().with_adjacent_volume_discovery(true);
    let mut session = ArchiveEngine::new()
        .open_path_with_options(&terminal, &discover)
        .expect("open conventional adjacent split ZIP names");
    let inspection = session.inspect().expect("inspect adjacent split ZIP");
    assert_eq!(inspection.format(), FormatId::Zip);
    assert_eq!(inspection.entries().len(), expected.len());

    fs::remove_file(directory.path().join("bundle.z02")).expect("remove required ZIP disk");
    let error = ArchiveEngine::new()
        .open_path_with_options(&terminal, &discover)
        .expect_err("missing intermediate ZIP disk must fail closed");
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));

    fs::write(directory.path().join("bundle.z02"), &parts[1]).expect("restore required ZIP disk");
    let error = ArchiveEngine::new()
        .open_path_with_options(
            &terminal,
            &discover.with_source_limits(SourceLimits::safe().with_volumes(Some(2))),
        )
        .expect_err("declared ZIP disk count must respect the source limit");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeCountExceeded)
    );
}
