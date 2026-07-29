// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end Microsoft Cabinet set and cross-cabinet continuation evidence.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use flate2::{Compression, write::DeflateEncoder};
use libarchive_oxide::advanced::{
    CabVolumeProvider, CabVolumeReader, MemoryReadAt, RangeReadError, RangeReadErrorKind, Registry,
    SourceIdentity, SourceLimits, VolumeId, VolumeResolver, VolumeSet,
};
use libarchive_oxide::{Error, Limits, ReaderEvent};

const METHOD_STORE: u16 = 0;
const METHOD_MSZIP: u16 = 1;
#[cfg(feature = "cab-quantum")]
const METHOD_QUANTUM: u16 = 0x1222;
#[cfg(feature = "cab-lzx")]
const METHOD_LZX: u16 = 0x1503;
const SET_ID: u16 = 0x4F58;

#[derive(Clone)]
struct Record {
    payload: Vec<u8>,
    uncompressed: u16,
}

struct Fixture {
    method: u16,
    file_size: u32,
    file_name: Vec<u8>,
    date: u16,
    time: u16,
    attributes: u16,
}

#[cfg(any(feature = "cab-lzx", feature = "cab-quantum"))]
struct ParsedFixture {
    metadata: Fixture,
    records: Vec<Record>,
}

struct Resolver {
    volumes: BTreeMap<VolumeId, Arc<dyn libarchive_oxide::advanced::ReadAt>>,
    requests: AtomicU64,
}

struct MutableSnapshotReadAt {
    bytes: Vec<u8>,
    original_identity: SourceIdentity,
    changed_identity: SourceIdentity,
    use_changed_identity: AtomicBool,
    reported_length: AtomicU64,
}

impl MutableSnapshotReadAt {
    fn new(bytes: Vec<u8>) -> Self {
        let length = u64::try_from(bytes.len()).expect("fixture length fits u64");
        Self {
            bytes,
            original_identity: SourceIdentity::try_new(b"mutable-cab-v1".to_vec()).unwrap(),
            changed_identity: SourceIdentity::try_new(b"mutable-cab-v2".to_vec()).unwrap(),
            use_changed_identity: AtomicBool::new(false),
            reported_length: AtomicU64::new(length),
        }
    }
}

impl libarchive_oxide::advanced::ReadAt for MutableSnapshotReadAt {
    fn len(&self) -> u64 {
        self.reported_length.load(Ordering::Relaxed)
    }

    fn identity(&self) -> &SourceIdentity {
        if self.use_changed_identity.load(Ordering::Relaxed) {
            &self.changed_identity
        } else {
            &self.original_identity
        }
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> std::io::Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| std::io::Error::other("fixture offset exceeds address space"))?;
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let count = output.len().min(self.bytes.len() - start);
        output[..count].copy_from_slice(&self.bytes[start..start + count]);
        Ok(count)
    }
}

impl VolumeResolver for Resolver {
    fn resolve(
        &self,
        volume: VolumeId,
    ) -> std::io::Result<Option<Arc<dyn libarchive_oxide::advanced::ReadAt>>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.volumes.get(&volume).cloned())
    }
}

fn source(index: usize, bytes: Vec<u8>) -> Arc<dyn libarchive_oxide::advanced::ReadAt> {
    Arc::new(MemoryReadAt::new(
        bytes,
        SourceIdentity::try_new(format!("cab-volume-{index}-v1").into_bytes())
            .expect("valid fixture identity"),
    ))
}

fn volume_set(
    cabinets: Vec<Vec<u8>>,
    source_limits: SourceLimits,
) -> (Arc<VolumeSet>, Arc<Resolver>) {
    let mut iter = cabinets.into_iter().enumerate();
    let (_, primary_bytes) = iter.next().expect("CAB set has a primary volume");
    let primary = source(0, primary_bytes);
    let resolver = Arc::new(Resolver {
        volumes: iter
            .map(|(index, bytes)| {
                (
                    VolumeId::new(u32::try_from(index).expect("small fixture index")),
                    source(index, bytes),
                )
            })
            .collect(),
        requests: AtomicU64::new(0),
    });
    let volumes = Arc::new(
        VolumeSet::new(primary, resolver.clone(), source_limits).expect("bounded fixture set"),
    );
    (volumes, resolver)
}

fn volume_set_with_mutable_primary(
    cabinets: &[Vec<u8>],
) -> (Arc<VolumeSet>, Arc<MutableSnapshotReadAt>) {
    let primary = Arc::new(MutableSnapshotReadAt::new(cabinets[0].clone()));
    let primary_source: Arc<dyn libarchive_oxide::advanced::ReadAt> = primary.clone();
    let resolver = Arc::new(Resolver {
        volumes: BTreeMap::from([(VolumeId::new(1), source(1, cabinets[1].clone()))]),
        requests: AtomicU64::new(0),
    });
    let volumes = Arc::new(
        VolumeSet::new(primary_source, resolver, SourceLimits::safe())
            .expect("bounded mutable fixture set"),
    );
    (volumes, primary)
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn cab_checksum(data: &[u8], seed: u32) -> u32 {
    let mut checksum = seed;
    let mut words = data.chunks_exact(4);
    for word in &mut words {
        checksum ^= u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
    }
    checksum
        ^ words
            .remainder()
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte))
}

fn encode_record(record: &Record, reserved: &[u8]) -> Vec<u8> {
    let cb_data = u16::try_from(record.payload.len()).expect("fixture CFDATA fits u16");
    let mut sizes = Vec::new();
    push_u16(&mut sizes, cb_data);
    push_u16(&mut sizes, record.uncompressed);
    let checksum = cab_checksum(
        reserved,
        cab_checksum(&sizes, cab_checksum(&record.payload, 0)),
    );
    let mut encoded = Vec::new();
    push_u32(&mut encoded, checksum);
    encoded.extend_from_slice(&sizes);
    encoded.extend_from_slice(reserved);
    encoded.extend_from_slice(&record.payload);
    encoded
}

fn cabinet_name(index: usize) -> String {
    format!("set{}.cab", index + 1)
}

fn folder_table_offset(cabinet: &[u8]) -> usize {
    let flags = u16::from_le_bytes(cabinet[30..32].try_into().expect("fixture flags"));
    let mut cursor = 36_usize;
    if flags & 4 != 0 {
        let header_reserve = usize::from(u16::from_le_bytes(cabinet[36..38].try_into().unwrap()));
        cursor += 4 + header_reserve;
    }
    let string_count = usize::from(flags & 1 != 0) * 2 + usize::from(flags & 2 != 0) * 2;
    for _ in 0..string_count {
        let terminator = cabinet[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .expect("fixture cabinet string terminator");
        cursor += terminator + 1;
    }
    cursor
}

fn build_set(fixture: &Fixture, volume_records: &[Vec<Record>]) -> Vec<Vec<u8>> {
    let reserves = vec![Vec::new(); volume_records.len()];
    build_set_with_reserves(fixture, volume_records, &reserves)
}

fn build_set_with_reserves(
    fixture: &Fixture,
    volume_records: &[Vec<Record>],
    reserves: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    assert!(!volume_records.is_empty());
    assert_eq!(volume_records.len(), reserves.len());
    let volume_count = volume_records.len();
    volume_records
        .iter()
        .zip(reserves)
        .enumerate()
        .map(|(index, (records, reserved))| {
            let mut optional = Vec::new();
            let mut flags = 0_u16;
            if !reserved.is_empty() {
                flags |= 4;
            }
            if index != 0 {
                flags |= 1;
                optional.extend_from_slice(cabinet_name(0).as_bytes());
                optional.push(0);
                optional.extend_from_slice(b"Disk 1");
                optional.push(0);
            }
            if index + 1 != volume_count {
                flags |= 2;
                optional.extend_from_slice(cabinet_name(index + 1).as_bytes());
                optional.push(0);
                optional.extend_from_slice(format!("Disk {}", index + 2).as_bytes());
                optional.push(0);
            }
            let reserve_header_size = usize::from(!reserved.is_empty()) * 4;
            let header_size = 36 + reserve_header_size + optional.len();
            let coff_files = header_size + 8;
            let file_table_size = 16 + fixture.file_name.len() + 1;
            let data_offset = coff_files + file_table_size;
            let data: Vec<u8> = records
                .iter()
                .flat_map(|record| encode_record(record, reserved))
                .collect();
            let cabinet_size = data_offset + data.len();

            let mut output = Vec::new();
            output.extend_from_slice(b"MSCF");
            push_u32(&mut output, 0);
            push_u32(
                &mut output,
                u32::try_from(cabinet_size).expect("small fixture cabinet"),
            );
            push_u32(&mut output, 0);
            push_u32(
                &mut output,
                u32::try_from(coff_files).expect("small fixture file table"),
            );
            push_u32(&mut output, 0);
            output.push(3);
            output.push(1);
            push_u16(&mut output, 1);
            push_u16(&mut output, 1);
            push_u16(&mut output, flags);
            push_u16(&mut output, SET_ID);
            push_u16(
                &mut output,
                u16::try_from(index).expect("small fixture cabinet index"),
            );
            if !reserved.is_empty() {
                push_u16(&mut output, 0);
                output.push(0);
                output.push(
                    u8::try_from(reserved.len()).expect("fixture CFDATA reserve fits one byte"),
                );
            }
            output.extend_from_slice(&optional);

            push_u32(
                &mut output,
                u32::try_from(data_offset).expect("small fixture data offset"),
            );
            push_u16(
                &mut output,
                u16::try_from(records.len()).expect("small fixture record count"),
            );
            push_u16(&mut output, fixture.method);

            push_u32(&mut output, fixture.file_size);
            push_u32(&mut output, 0);
            let folder = match (index, volume_count) {
                (_, 1) => 0,
                (0, _) => 0xFFFE,
                (current, total) if current + 1 == total => 0xFFFD,
                _ => 0xFFFF,
            };
            push_u16(&mut output, folder);
            push_u16(&mut output, fixture.date);
            push_u16(&mut output, fixture.time);
            push_u16(&mut output, fixture.attributes);
            output.extend_from_slice(&fixture.file_name);
            output.push(0);
            output.extend_from_slice(&data);
            assert_eq!(output.len(), cabinet_size);
            output
        })
        .collect()
}

fn split_record(record: &Record, at: usize) -> (Record, Record) {
    assert!(at != 0 && at < record.payload.len());
    (
        Record {
            payload: record.payload[..at].to_vec(),
            uncompressed: 0,
        },
        Record {
            payload: record.payload[at..].to_vec(),
            uncompressed: record.uncompressed,
        },
    )
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("encode fixture");
    encoder.finish().expect("finish fixture")
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    let compact: String = encoded
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(any(feature = "cab-lzx", feature = "cab-quantum"))]
fn fixture_from_single(bytes: &[u8]) -> ParsedFixture {
    assert_eq!(&bytes[..4], b"MSCF");
    let coff_files =
        usize::try_from(u32::from_le_bytes(bytes[16..20].try_into().unwrap())).unwrap();
    assert_eq!(u16::from_le_bytes(bytes[26..28].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(bytes[28..30].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(bytes[30..32].try_into().unwrap()), 0);
    let data_offset =
        usize::try_from(u32::from_le_bytes(bytes[36..40].try_into().unwrap())).unwrap();
    let record_count = u16::from_le_bytes(bytes[40..42].try_into().unwrap());
    let method = u16::from_le_bytes(bytes[42..44].try_into().unwrap());
    let file_size = u32::from_le_bytes(bytes[coff_files..coff_files + 4].try_into().unwrap());
    let date = u16::from_le_bytes(bytes[coff_files + 10..coff_files + 12].try_into().unwrap());
    let time = u16::from_le_bytes(bytes[coff_files + 12..coff_files + 14].try_into().unwrap());
    let attributes =
        u16::from_le_bytes(bytes[coff_files + 14..coff_files + 16].try_into().unwrap());
    let name_start = coff_files + 16;
    let name_end = bytes[name_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| name_start + offset)
        .unwrap();
    let mut records = Vec::new();
    let mut cursor = data_offset;
    for _ in 0..record_count {
        let cb_data = usize::from(u16::from_le_bytes(
            bytes[cursor + 4..cursor + 6].try_into().unwrap(),
        ));
        let uncompressed = u16::from_le_bytes(bytes[cursor + 6..cursor + 8].try_into().unwrap());
        records.push(Record {
            payload: bytes[cursor + 8..cursor + 8 + cb_data].to_vec(),
            uncompressed,
        });
        cursor += 8 + cb_data;
    }
    ParsedFixture {
        metadata: Fixture {
            method,
            file_size,
            file_name: bytes[name_start..name_end].to_vec(),
            date,
            time,
            attributes,
        },
        records,
    }
}

fn collect_one(volumes: &VolumeSet, limits: Limits) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut reader = CabVolumeReader::with_limits(volumes, limits)?;
    let mut path = Vec::new();
    let mut content = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(metadata) => path.extend_from_slice(metadata.path().as_bytes()),
            ReaderEvent::Data(bytes) => content.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok((path, content)),
            _ => {},
        }
    }
}

fn cab_set_opens_with_metadata_budget(cabinets: &[Vec<u8>], budget: usize) -> bool {
    let (volumes, _) = volume_set(cabinets.to_vec(), SourceLimits::safe());
    CabVolumeReader::with_limits(
        volumes.as_ref(),
        Limits::safe().with_metadata_bytes(Some(budget)),
    )
    .is_ok()
}

fn minimum_cab_set_metadata_budget(cabinets: &[Vec<u8>]) -> usize {
    let mut high = 1_usize;
    while !cab_set_opens_with_metadata_budget(cabinets, high) {
        high = high.checked_mul(2).expect("fixture metadata budget bound");
    }
    let mut low = 0_usize;
    while low < high {
        let middle = low + (high - low) / 2;
        if cab_set_opens_with_metadata_budget(cabinets, middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

fn drive_to_error(volumes: &VolumeSet, limits: Limits) -> Error {
    let mut reader = match CabVolumeReader::with_limits(volumes, limits) {
        Ok(reader) => reader,
        Err(error) => return error,
    };
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("fixture unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => return error,
        }
    }
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
fn store_split_cfdata_round_trips_through_registry_provider() {
    let payload = b"store bytes cross a physical cabinet boundary".to_vec();
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 11);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"nested/store.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[vec![first], vec![second]]);
    let (volumes, resolver) = volume_set(cabinets, SourceLimits::safe());
    let mut builder = Registry::builder();
    builder
        .register_random_access_format(Box::new(CabVolumeProvider::new()))
        .expect("register CAB set provider");
    let registry = builder.build();
    assert_eq!(
        registry
            .detect_random_access(&volumes, Limits::safe())
            .expect("probe CAB set"),
        Some(libarchive_oxide::FormatId::Cab),
    );
    let mut reader = registry
        .open_random_access(libarchive_oxide::FormatId::Cab, volumes, Limits::safe())
        .expect("open CAB set");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read CAB set") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn microsoft_makecab_store_set_matches_extrac32_oracle() {
    let first = decode_hex(include_str!("fixtures/cab/makecab/makecab-store1.cab.hex"));
    let second = decode_hex(include_str!("fixtures/cab/makecab/makecab-store2.cab.hex"));
    let (volumes, resolver) = volume_set(vec![first, second], SourceLimits::safe());
    let (path, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode Microsoft CAB set");
    assert_eq!(path, b"makecab-store.bin");
    assert_eq!(decoded, vec![0; 20_500]);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn mszip_split_cfdata_round_trips_after_payload_reassembly() {
    let expected = b"MSZIP compressed bytes are split before DEFLATE runs".repeat(16);
    let mut payload = b"CK".to_vec();
    payload.extend_from_slice(&raw_deflate(&expected));
    let record = Record {
        payload,
        uncompressed: u16::try_from(expected.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 5);
    let fixture = Fixture {
        method: METHOD_MSZIP,
        file_size: u32::try_from(expected.len()).unwrap(),
        file_name: b"mszip.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let (volumes, _) = volume_set(
        build_set(&fixture, &[vec![first], vec![second]]),
        SourceLimits::safe(),
    );
    let (path, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode split MSZIP");
    assert_eq!(path, b"mszip.bin");
    assert_eq!(decoded, expected);
}

#[test]
fn store_file_and_folder_continue_across_three_cabinets() {
    let payload = b"three-volume PreviousAndNext continuation evidence".repeat(4);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, remainder) = split_record(&record, 17);
    let (middle, last) = split_record(&remainder, 23);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"three-volumes.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let (volumes, resolver) = volume_set(
        build_set(&fixture, &[vec![first], vec![middle], vec![last]]),
        SourceLimits::safe(),
    );
    let (path, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode three-volume CAB");
    assert_eq!(path, b"three-volumes.bin");
    assert_eq!(decoded, payload);
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 2);
}

#[test]
fn cb_cabinet_is_a_hard_per_volume_boundary_but_trailing_bytes_are_allowed() {
    let payload = b"authoritative cbCabinet boundary".repeat(3);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 19);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"bounded.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[vec![first], vec![second]]);

    let mut with_trailing = cabinets.clone();
    with_trailing[0].extend_from_slice(b"transport trailer one");
    with_trailing[1].extend_from_slice(b"transport trailer two");
    let (volumes, _) = volume_set(with_trailing, SourceLimits::safe());
    let (_, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("ignore bytes after cbCabinet");
    assert_eq!(decoded, payload);

    let mut short_second = cabinets;
    let declared = u32::try_from(short_second[1].len() - 1).unwrap();
    short_second[1][8..12].copy_from_slice(&declared.to_le_bytes());
    let (volumes, _) = volume_set(short_second, SourceLimits::safe());
    let error = CabVolumeReader::new(volumes.as_ref())
        .expect_err("second volume payload outside cbCabinet must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);
}

#[test]
fn continued_folder_rejects_a_compression_method_change() {
    let payload = b"method consistency".repeat(4);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 13);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"method.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let mut cabinets = build_set(&fixture, &[vec![first], vec![second]]);
    let folder = folder_table_offset(&cabinets[1]);
    cabinets[1][folder + 6..folder + 8].copy_from_slice(&METHOD_MSZIP.to_le_bytes());
    let (volumes, _) = volume_set(cabinets, SourceLimits::safe());
    let error =
        CabVolumeReader::new(volumes.as_ref()).expect_err("continued method change must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);
}

#[test]
fn each_volume_uses_its_own_cfdata_reserve_and_checksum_domain() {
    let payload = b"different physical CFDATA reserve sizes remain lazy and checksummed".repeat(3);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 29);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"reserved.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let reserves = vec![vec![0x11], vec![0x22, 0x33, 0x44]];
    let cabinets = build_set_with_reserves(&fixture, &[vec![first], vec![second]], &reserves);
    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe());
    let (_, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode differing CFDATA reserves");
    assert_eq!(decoded, payload);

    let mut corrupted = cabinets;
    let folder = folder_table_offset(&corrupted[1]);
    let data = usize::try_from(u32::from_le_bytes(
        corrupted[1][folder..folder + 4].try_into().unwrap(),
    ))
    .unwrap();
    corrupted[1][data + 8] ^= 0x80;
    let (volumes, _) = volume_set(corrupted, SourceLimits::safe());
    let error = drive_to_error(volumes.as_ref(), Limits::safe());
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);
}

#[test]
fn joined_payload_reads_revalidate_each_volume_snapshot() {
    let payload = b"lazy source snapshot".repeat(5);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 23);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"snapshot.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[vec![first], vec![second]]);

    let (volumes, primary) = volume_set_with_mutable_primary(&cabinets);
    let mut reader = CabVolumeReader::new(volumes.as_ref()).expect("open immutable snapshot");
    primary.use_changed_identity.store(true, Ordering::Relaxed);
    let identity_error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("changed source identity unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(
        typed_range(&identity_error),
        Some(RangeReadErrorKind::IdentityChanged),
    );

    let (volumes, primary) = volume_set_with_mutable_primary(&cabinets);
    let mut reader = CabVolumeReader::new(volumes.as_ref()).expect("open immutable snapshot");
    primary.reported_length.fetch_sub(1, Ordering::Relaxed);
    let length_error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("changed source length unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(
        typed_range(&length_error),
        Some(RangeReadErrorKind::LengthChanged),
    );
}

#[test]
fn joined_cfdata_segment_capacity_is_in_the_exact_metadata_boundary() {
    let record_count = 128_usize;
    let records = (0..record_count)
        .map(|index| Record {
            payload: vec![u8::try_from(index % 251).unwrap()],
            uncompressed: 1,
        })
        .collect::<Vec<_>>();
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(record_count).unwrap(),
        file_name: b"many-segments.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[records]);
    let minimum = minimum_cab_set_metadata_budget(&cabinets);
    assert!(cab_set_opens_with_metadata_budget(&cabinets, minimum));
    assert!(minimum != 0);
    assert!(
        !cab_set_opens_with_metadata_budget(&cabinets, minimum - 1),
        "one byte below the retained/peak metadata boundary must fail"
    );

    let one_record = build_set(
        &Fixture {
            method: METHOD_STORE,
            file_size: 1,
            file_name: b"one-segment.bin".to_vec(),
            date: 0,
            time: 0,
            attributes: 0,
        },
        &[vec![Record {
            payload: vec![0],
            uncompressed: 1,
        }]],
    );
    let one_minimum = minimum_cab_set_metadata_budget(&one_record);
    assert!(
        minimum > one_minimum + record_count,
        "VirtualSegment capacity must materially increase the aggregate budget"
    );
}

#[cfg(feature = "cab-lzx")]
#[test]
fn lzx_dictionary_and_split_frame_continue_across_cabinets() {
    let single = decode_hex(include_str!("fixtures/cab/makecab/lzx-history.hex"));
    let fixture = fixture_from_single(&single);
    assert_eq!(fixture.metadata.method, METHOD_LZX);
    let (partial, continuation) = split_record(&fixture.records[1], 17);
    let first = vec![fixture.records[0].clone(), partial];
    let second = vec![continuation, fixture.records[2].clone()];
    let (volumes, _) = volume_set(
        build_set(&fixture.metadata, &[first, second]),
        SourceLimits::safe(),
    );
    let (path, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode continued LZX");
    assert_eq!(path, b"lzx-history.bin");
    let expected: Vec<u8> = (0_usize..96 * 1024)
        .map(|index| u8::try_from((index % 4096) % 251).unwrap())
        .collect();
    assert_eq!(decoded, expected);
}

#[cfg(feature = "cab-quantum")]
#[test]
fn quantum_models_and_split_frame_continue_across_cabinets() {
    let single = decode_hex(include_str!(
        "fixtures/cab/libmspack/cve-2010-2801-qtm-flush.hex"
    ));
    let fixture = fixture_from_single(&single);
    assert_eq!(fixture.metadata.method, METHOD_QUANTUM);
    let (partial, continuation) = split_record(&fixture.records[8], 2);
    let mut first = fixture.records[..8].to_vec();
    first.push(partial);
    let mut second = vec![continuation];
    second.extend_from_slice(&fixture.records[9..]);
    let (volumes, _) = volume_set(
        build_set(&fixture.metadata, &[first, second]),
        SourceLimits::safe(),
    );
    let (path, decoded) =
        collect_one(volumes.as_ref(), Limits::safe()).expect("decode continued Quantum");
    assert_eq!(path, b"zeroes");
    assert_eq!(decoded, vec![0; 524_159]);
}

#[test]
fn missing_wrong_duplicate_out_of_order_and_cyclic_volumes_fail_closed() {
    let payload = b"volume validation".to_vec();
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 5);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"validate.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[vec![first], vec![second]]);

    let missing = Arc::new(
        VolumeSet::new(
            source(0, cabinets[0].clone()),
            Arc::new(Resolver {
                volumes: BTreeMap::new(),
                requests: AtomicU64::new(0),
            }),
            SourceLimits::safe(),
        )
        .unwrap(),
    );
    let error = CabVolumeReader::new(missing.as_ref()).expect_err("missing continuation must fail");
    assert_eq!(typed_range(&error), Some(RangeReadErrorKind::MissingVolume));

    let mut wrong_set = cabinets.clone();
    wrong_set[1][32..34].copy_from_slice(&0x9999_u16.to_le_bytes());
    let (volumes, _) = volume_set(wrong_set, SourceLimits::safe());
    let error = CabVolumeReader::new(volumes.as_ref()).expect_err("wrong setID must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);

    let mut out_of_order = cabinets.clone();
    out_of_order[1][34..36].copy_from_slice(&2_u16.to_le_bytes());
    let (volumes, _) = volume_set(out_of_order, SourceLimits::safe());
    let error = CabVolumeReader::new(volumes.as_ref()).expect_err("out-of-order cabinet must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);

    let duplicate_source = source(0, cabinets[0].clone());
    let duplicate = Arc::new(
        VolumeSet::new(
            duplicate_source.clone(),
            Arc::new(Resolver {
                volumes: BTreeMap::from([(VolumeId::new(1), duplicate_source)]),
                requests: AtomicU64::new(0),
            }),
            SourceLimits::safe(),
        )
        .unwrap(),
    );
    let error = CabVolumeReader::new(duplicate.as_ref()).expect_err("duplicate source must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);

    let mut cyclic_name = cabinets;
    let next_name_offset = 36;
    cyclic_name[0][next_name_offset..next_name_offset + 8].copy_from_slice(b"set1.cab");
    let (volumes, _) = volume_set(cyclic_name, SourceLimits::safe());
    let error = CabVolumeReader::new(volumes.as_ref()).expect_err("cyclic name must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);
}

#[test]
fn continuation_corruption_and_resource_limits_are_typed() {
    let payload = b"checksummed store corruption is detected in volume two".repeat(8);
    let record = Record {
        payload: payload.clone(),
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (first, second) = split_record(&record, 31);
    let fixture = Fixture {
        method: METHOD_STORE,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"limits-and-corruption.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let cabinets = build_set(&fixture, &[vec![first], vec![second]]);
    let aggregate_volume_bytes = cabinets.iter().map(Vec::len).sum::<usize>();

    let mut corrupted = cabinets.clone();
    let last = corrupted[1].len() - 1;
    corrupted[1][last] ^= 0x80;
    let (volumes, _) = volume_set(corrupted, SourceLimits::safe());
    let error = drive_to_error(volumes.as_ref(), Limits::safe());
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);

    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe().with_volumes(Some(1)));
    let error = CabVolumeReader::new(volumes.as_ref()).expect_err("volume-count limit must fail");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeCountExceeded),
    );

    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe());
    let error =
        CabVolumeReader::with_limits(volumes.as_ref(), Limits::safe().with_path_bytes(Some(4)))
            .expect_err("cabinet/file path limit must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);

    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe());
    let error = CabVolumeReader::with_limits(
        volumes.as_ref(),
        Limits::safe().with_metadata_bytes(Some(64)),
    )
    .expect_err("CAB set metadata limit must fail");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);

    let volume_budget = u64::try_from(aggregate_volume_bytes - 1).unwrap();
    let (volumes, _) = volume_set(
        cabinets.clone(),
        SourceLimits::safe().with_volume_bytes(Some(volume_budget)),
    );
    let error =
        CabVolumeReader::new(volumes.as_ref()).expect_err("aggregate volume-byte limit must fail");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeBytesExceeded),
    );

    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe());
    let error = drive_to_error(
        volumes.as_ref(),
        Limits::safe().with_decoded_total(Some(u64::try_from(payload.len() - 1).unwrap())),
    );
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);

    let in_flight_budget = payload.len().checked_mul(2).unwrap() - 1;
    let (volumes, _) = volume_set(cabinets.clone(), SourceLimits::safe());
    let error = drive_to_error(
        volumes.as_ref(),
        Limits::safe().with_in_flight_bytes(Some(in_flight_budget)),
    );
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);

    let mut compressed = b"CK".to_vec();
    compressed.extend_from_slice(&raw_deflate(&payload));
    let mszip_record = Record {
        payload: compressed,
        uncompressed: u16::try_from(payload.len()).unwrap(),
    };
    let (mszip_first, mszip_second) = split_record(&mszip_record, 4);
    let mszip_fixture = Fixture {
        method: METHOD_MSZIP,
        file_size: u32::try_from(payload.len()).unwrap(),
        file_name: b"memory.bin".to_vec(),
        date: 0,
        time: 0,
        attributes: 0,
    };
    let (volumes, _) = volume_set(
        build_set(&mszip_fixture, &[vec![mszip_first], vec![mszip_second]]),
        SourceLimits::safe(),
    );
    let error = drive_to_error(volumes.as_ref(), Limits::safe().with_codec_memory(Some(0)));
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}
