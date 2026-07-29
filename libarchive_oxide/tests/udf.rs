// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic UDF 1.02 through 2.60 images, Metadata/Sparable/Virtual Partition
//! translation, and public-path contract tests.

#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::range_plus_one,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use libarchive_oxide::advanced::legacy::ProviderSet;
#[cfg(feature = "async")]
use libarchive_oxide::advanced::{AsyncRangeArchiveReader, AsyncRangeSource};
use libarchive_oxide::advanced::{ProviderCapability, RangeArchiveReader, ReadAt, SourceIdentity};
use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, CreateOptions, ReaderEvent, SeekArchiveReader, SeekArchiveWriter,
};
use libarchive_oxide_core::{EntryKind, ErrorKind, FormatId, Limits, ProbeResult};

#[derive(Debug)]
struct MemoryRange {
    bytes: Vec<u8>,
    identity: SourceIdentity,
}

impl MemoryRange {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            identity: SourceIdentity::try_new(b"udf-test-image".to_vec())
                .expect("valid source identity"),
        }
    }
}

impl ReadAt for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset"))?;
        let Some(bytes) = self.bytes.get(start..) else {
            return Ok(0);
        };
        let count = bytes.len().min(output.len()).min(4096);
        output[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    }
}

#[cfg(feature = "async")]
impl AsyncRangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    async fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        ReadAt::read_at(self, offset, output)
    }
}

#[derive(Debug)]
struct ZeroPaddedImage {
    bytes: Vec<u8>,
    length: u64,
    position: u64,
}

impl ZeroPaddedImage {
    fn new(bytes: Vec<u8>, length: u64) -> Self {
        assert!(length >= bytes.len() as u64);
        Self {
            bytes,
            length,
            position: 0,
        }
    }
}

impl Read for ZeroPaddedImage {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let count = usize::try_from(remaining.min(output.len() as u64))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read length"))?;
        output[..count].fill(0);
        if self.position < self.bytes.len() as u64 {
            let start = usize::try_from(self.position)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read offset"))?;
            let existing = count.min(self.bytes.len() - start);
            output[..existing].copy_from_slice(&self.bytes[start..start + existing]);
        }
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read overflow"))?;
        Ok(count)
    }
}

impl Seek for ZeroPaddedImage {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?;
        Ok(self.position)
    }
}

const BLOCK: usize = 2048;
const BLOCKS: usize = 700;
const PARTITION_START: u32 = 300;
const MAIN_VDS: u32 = 257;
const RESERVE_VDS: u32 = 620;
const MKUDFFS_SPARABLE_201: &[u8] = include_bytes!("fixtures/udf/mkudffs-sparable-2.01.udf");
const UDF_NON_SYSTEM_STREAMS: [(&str, u32, &[u8]); 4] = [
    ("*UDF Macintosh Resource Fork", 30, b"mac-resource"),
    ("*UDF OS/2 EA", 31, b"os2-ea"),
    ("*UDF NT ACL", 32, b"nt-acl"),
    ("*UDF UNIX ACL", 33, b"unix-acl"),
];

#[derive(Clone, Copy)]
struct BuildOptions {
    revision: u16,
    bridge: bool,
    corrupt_main: bool,
    corrupt_first_anchor: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            revision: 0x0201,
            bridge: false,
            corrupt_main: false,
            corrupt_first_anchor: false,
        }
    }
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn finish_tag(descriptor: &mut [u8], tag: u16, location: u32, used: usize) {
    descriptor[0..2].copy_from_slice(&tag.to_le_bytes());
    descriptor[2..4].copy_from_slice(&2_u16.to_le_bytes());
    descriptor[5] = 0;
    descriptor[6..8].copy_from_slice(&1_u16.to_le_bytes());
    let crc_length = used.saturating_sub(16).min(usize::from(u16::MAX));
    let crc = crc16(&descriptor[16..16 + crc_length]);
    descriptor[8..10].copy_from_slice(&crc.to_le_bytes());
    descriptor[10..12].copy_from_slice(&(crc_length as u16).to_le_bytes());
    descriptor[12..16].copy_from_slice(&location.to_le_bytes());
    descriptor[4] = descriptor[..16]
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .fold(0_u8, |sum, (_, byte)| sum.wrapping_add(*byte));
}

fn tagged_block(tag: u16, location: u32, used: usize) -> Vec<u8> {
    let mut descriptor = vec![0_u8; BLOCK];
    finish_tag(&mut descriptor, tag, location, used);
    descriptor
}

fn write_block(image: &mut [u8], block: u32, bytes: &[u8]) {
    let start = block as usize * BLOCK;
    image[start..start + bytes.len()].copy_from_slice(bytes);
}

fn dstring(field: &mut [u8], value: &str) {
    assert!(value.len() + 1 < field.len());
    field[0] = 8;
    field[1..1 + value.len()].copy_from_slice(value.as_bytes());
    let last = field.len() - 1;
    field[last] = (value.len() + 1) as u8;
}

fn entity_id(field: &mut [u8], identifier: &[u8]) {
    field[0] = 0;
    let count = identifier.len().min(23);
    field[1..1 + count].copy_from_slice(&identifier[..count]);
}

fn osta_charspec(field: &mut [u8]) {
    field.fill(0);
    field[0] = 0;
    field[1..1 + b"OSTA Compressed Unicode".len()].copy_from_slice(b"OSTA Compressed Unicode");
}

fn long_ad(bytes: &mut [u8], offset: usize, length: u32, lbn: u32, partition: u16) {
    bytes[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&lbn.to_le_bytes());
    bytes[offset + 8..offset + 10].copy_from_slice(&partition.to_le_bytes());
}

fn fid_long_ad(
    bytes: &mut [u8],
    offset: usize,
    length: u32,
    lbn: u32,
    partition: u16,
    unique_id: u32,
) {
    long_ad(bytes, offset, length, lbn, partition);
    bytes[offset + 12..offset + 16].copy_from_slice(&unique_id.to_le_bytes());
}

fn short_ad(length: u32, kind: u32, lbn: u32) -> [u8; 8] {
    let mut descriptor = [0_u8; 8];
    descriptor[..4].copy_from_slice(&(length | kind << 30).to_le_bytes());
    descriptor[4..].copy_from_slice(&lbn.to_le_bytes());
    descriptor
}

fn long_allocation_ad(length: u32, kind: u32, lbn: u32, partition: u16) -> [u8; 16] {
    let mut descriptor = [0_u8; 16];
    descriptor[..4].copy_from_slice(&(length | kind << 30).to_le_bytes());
    descriptor[4..8].copy_from_slice(&lbn.to_le_bytes());
    descriptor[8..10].copy_from_slice(&partition.to_le_bytes());
    descriptor
}

fn extended_allocation_ad(
    extent_length: u32,
    kind: u32,
    recorded_length: u32,
    information_length: u32,
    lbn: u32,
    partition: u16,
) -> [u8; 20] {
    let mut descriptor = [0_u8; 20];
    descriptor[..4].copy_from_slice(&(extent_length | kind << 30).to_le_bytes());
    descriptor[4..8].copy_from_slice(&recorded_length.to_le_bytes());
    descriptor[8..12].copy_from_slice(&information_length.to_le_bytes());
    descriptor[12..16].copy_from_slice(&lbn.to_le_bytes());
    descriptor[16..18].copy_from_slice(&partition.to_le_bytes());
    descriptor
}

fn timestamp() -> [u8; 12] {
    let mut value = [0_u8; 12];
    value[..2].copy_from_slice(&0x1000_u16.to_le_bytes());
    value[2..4].copy_from_slice(&2026_u16.to_le_bytes());
    value[4..9].copy_from_slice(&[7, 28, 12, 34, 56]);
    value[9..].copy_from_slice(&[12, 34, 56]);
    value
}

fn file_entry(
    location: u32,
    file_type: u8,
    allocation_type: u16,
    information_length: u64,
    allocation: &[u8],
    unique_id: u64,
    links: u16,
) -> Vec<u8> {
    let mut descriptor = vec![0_u8; BLOCK];
    descriptor[20..22].copy_from_slice(&4_u16.to_le_bytes());
    descriptor[27] = file_type;
    descriptor[34..36].copy_from_slice(&allocation_type.to_le_bytes());
    descriptor[36..40].copy_from_slice(&1000_u32.to_le_bytes());
    descriptor[40..44].copy_from_slice(&100_u32.to_le_bytes());
    descriptor[44..48].copy_from_slice(&0x1fff_u32.to_le_bytes());
    descriptor[48..50].copy_from_slice(&links.to_le_bytes());
    descriptor[56..64].copy_from_slice(&information_length.to_le_bytes());
    let logical_blocks_recorded = if allocation_type == 3 {
        0
    } else {
        information_length.div_ceil(BLOCK as u64)
    };
    descriptor[64..72].copy_from_slice(&logical_blocks_recorded.to_le_bytes());
    descriptor[72..84].copy_from_slice(&timestamp());
    descriptor[84..96].copy_from_slice(&timestamp());
    descriptor[96..108].copy_from_slice(&timestamp());
    entity_id(&mut descriptor[128..160], b"*libarchive-oxide");
    descriptor[160..168].copy_from_slice(&unique_id.to_le_bytes());
    descriptor[168..172].copy_from_slice(&0_u32.to_le_bytes());
    descriptor[172..176].copy_from_slice(&(allocation.len() as u32).to_le_bytes());
    descriptor[176..176 + allocation.len()].copy_from_slice(allocation);
    finish_tag(&mut descriptor, 261, location, 176 + allocation.len());
    descriptor
}

fn file_entry_with_extended_attributes(
    location: u32,
    data: &[u8],
    extended_attributes: &[u8],
    unique_id: u64,
) -> Vec<u8> {
    let mut descriptor = file_entry(location, 5, 3, data.len() as u64, data, unique_id, 1);
    descriptor.copy_within(176..176 + data.len(), 176 + extended_attributes.len());
    descriptor[176..176 + extended_attributes.len()].copy_from_slice(extended_attributes);
    descriptor[168..172].copy_from_slice(&(extended_attributes.len() as u32).to_le_bytes());
    finish_tag(
        &mut descriptor,
        261,
        location,
        176 + extended_attributes.len() + data.len(),
    );
    descriptor
}

fn extended_attributes(location: u32) -> Vec<u8> {
    let mut attributes = vec![0_u8; 76];
    attributes[16..20].copy_from_slice(&24_u32.to_le_bytes());
    attributes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    attributes[24..28].copy_from_slice(&2048_u32.to_le_bytes());
    attributes[28] = 1;
    attributes[32..36].copy_from_slice(&52_u32.to_le_bytes());
    attributes[36..40].copy_from_slice(&4_u32.to_le_bytes());
    entity_id(&mut attributes[40..72], b"*libarchive-oxide");
    attributes[72..76].copy_from_slice(b"\xde\xad\xbe\xef");
    finish_tag(&mut attributes, 262, location, 24);
    attributes
}

fn unaligned_extended_attributes(location: u32) -> Vec<u8> {
    let mut attributes = vec![0_u8; 77];
    attributes[16..20].copy_from_slice(&24_u32.to_le_bytes());
    attributes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    attributes[24..28].copy_from_slice(&2048_u32.to_le_bytes());
    attributes[28] = 1;
    attributes[32..36].copy_from_slice(&53_u32.to_le_bytes());
    attributes[36..40].copy_from_slice(&5_u32.to_le_bytes());
    entity_id(&mut attributes[40..72], b"*libarchive-oxide");
    attributes[72..77].copy_from_slice(b"odd!!");
    finish_tag(&mut attributes, 262, location, 24);
    attributes
}

fn extended_file_entry(location: u32, file_type: u8, data: &[u8], unique_id: u64) -> Vec<u8> {
    let mut descriptor = vec![0_u8; BLOCK];
    descriptor[20..22].copy_from_slice(&4_u16.to_le_bytes());
    descriptor[27] = file_type;
    descriptor[34..36].copy_from_slice(&3_u16.to_le_bytes());
    descriptor[36..40].copy_from_slice(&2000_u32.to_le_bytes());
    descriptor[40..44].copy_from_slice(&200_u32.to_le_bytes());
    descriptor[44..48].copy_from_slice(&0x1fff_u32.to_le_bytes());
    descriptor[48..50].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
    descriptor[64..72].copy_from_slice(&(data.len() as u64).to_le_bytes());
    descriptor[80..92].copy_from_slice(&timestamp());
    descriptor[92..104].copy_from_slice(&timestamp());
    descriptor[104..116].copy_from_slice(&timestamp());
    descriptor[116..128].copy_from_slice(&timestamp());
    entity_id(&mut descriptor[168..200], b"*libarchive-oxide");
    descriptor[200..208].copy_from_slice(&unique_id.to_le_bytes());
    descriptor[208..212].copy_from_slice(&0_u32.to_le_bytes());
    descriptor[212..216].copy_from_slice(&(data.len() as u32).to_le_bytes());
    descriptor[216..216 + data.len()].copy_from_slice(data);
    finish_tag(&mut descriptor, 266, location, 216 + data.len());
    descriptor
}

fn stream_extended_file_entry(
    location: u32,
    file_type: u8,
    data: &[u8],
    unique_id: u64,
) -> Vec<u8> {
    let mut descriptor = extended_file_entry(location, file_type, data, unique_id);
    let flags = if file_type == 5 {
        3_u16 | (1 << 13)
    } else {
        3_u16
    };
    descriptor[34..36].copy_from_slice(&flags.to_le_bytes());
    descriptor[48..50].copy_from_slice(&1_u16.to_le_bytes());
    finish_tag(&mut descriptor, 266, location, 216 + data.len());
    descriptor
}

fn compressed_name(value: &str) -> Vec<u8> {
    if value.is_ascii() {
        let mut encoded = vec![8];
        encoded.extend_from_slice(value.as_bytes());
        return encoded;
    }
    let mut encoded = vec![16];
    for unit in value.encode_utf16() {
        encoded.extend_from_slice(&unit.to_be_bytes());
    }
    encoded
}

fn fid(name: &str, directory: bool, location: u32, icb_lbn: u32) -> Vec<u8> {
    let name = compressed_name(name);
    let length = (38 + name.len() + 3) & !3;
    let mut descriptor = vec![0_u8; length];
    descriptor[16..18].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[18] = if directory { 0x02 } else { 0 };
    descriptor[19] = name.len() as u8;
    fid_long_ad(&mut descriptor, 20, BLOCK as u32, icb_lbn, 0, icb_lbn);
    descriptor[36..38].copy_from_slice(&0_u16.to_le_bytes());
    descriptor[38..38 + name.len()].copy_from_slice(&name);
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn stream_fid(name: &str, metadata: bool, location: u32, icb_lbn: u32, unique_id: u32) -> Vec<u8> {
    let mut descriptor = fid(name, false, location, icb_lbn);
    descriptor[18] = if metadata { 0x10 } else { 0 };
    descriptor[32..36].copy_from_slice(&unique_id.to_le_bytes());
    let length = descriptor.len();
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn stream_fid_with_implementation_use(
    name: &str,
    location: u32,
    icb_lbn: u32,
    unique_id: u32,
    implementation_length: usize,
) -> Vec<u8> {
    assert!(implementation_length.is_multiple_of(4));
    let name = compressed_name(name);
    let length = (38 + implementation_length + name.len() + 3) & !3;
    let mut descriptor = vec![0_u8; length];
    descriptor[16..18].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[18] = 0x10;
    descriptor[19] = name.len() as u8;
    fid_long_ad(&mut descriptor, 20, BLOCK as u32, icb_lbn, 0, unique_id);
    descriptor[36..38].copy_from_slice(&(implementation_length as u16).to_le_bytes());
    let name_start = 38 + implementation_length;
    entity_id(&mut descriptor[38..70], b"*libarchive-oxide");
    descriptor[name_start..name_start + name.len()].copy_from_slice(&name);
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn replace_system_stream_directory_payload(image: &mut [u8], fid: &[u8]) {
    let directory_lbn = 20_u32;
    let data_lbn = 23_u32;
    let mut directory = parent_fid(data_lbn, directory_lbn, 0);
    directory.extend_from_slice(fid);
    write_block(image, PARTITION_START + data_lbn, &directory);

    let mut entry = stream_extended_file_entry(directory_lbn, 13, &[], 0);
    entry[34..36].copy_from_slice(&0_u16.to_le_bytes());
    entry[56..64].copy_from_slice(&(directory.len() as u64).to_le_bytes());
    entry[64..72].copy_from_slice(&(directory.len() as u64).to_le_bytes());
    entry[72..80].copy_from_slice(
        &(directory.len() as u64)
            .div_ceil(BLOCK as u64)
            .to_le_bytes(),
    );
    entry[212..216].copy_from_slice(&8_u32.to_le_bytes());
    entry[216..224].copy_from_slice(&short_ad(directory.len() as u32, 0, data_lbn));
    finish_tag(&mut entry, 266, directory_lbn, 224);
    write_block(image, PARTITION_START + directory_lbn, &entry);
}

fn parent_fid(location: u32, parent_icb_lbn: u32, unique_id: u32) -> Vec<u8> {
    let mut descriptor = vec![0_u8; 40];
    descriptor[16..18].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[18] = 0x0a;
    descriptor[19] = 0;
    fid_long_ad(
        &mut descriptor,
        20,
        BLOCK as u32,
        parent_icb_lbn,
        0,
        unique_id,
    );
    descriptor[36..38].copy_from_slice(&0_u16.to_le_bytes());
    finish_tag(&mut descriptor, 257, location, 40);
    descriptor
}

fn named_stream_directory() -> Vec<u8> {
    let mut directory = parent_fid(18, 7, 7);
    directory.extend_from_slice(&stream_fid("search:index", false, 18, 19, 7));
    for (name, lbn, _) in UDF_NON_SYSTEM_STREAMS {
        directory.extend_from_slice(&stream_fid(name, false, 18, lbn, 7));
    }
    directory
}

fn refinish_inline_fid(
    image: &mut [u8],
    directory_lbn: u32,
    directory_length: usize,
    fid_offset: usize,
    fid_length: usize,
) {
    let entry_offset = (PARTITION_START + directory_lbn) as usize * BLOCK;
    let fid_start = entry_offset + 216 + fid_offset;
    finish_tag(
        &mut image[fid_start..fid_start + fid_length],
        257,
        directory_lbn,
        fid_length,
    );
    finish_tag(
        &mut image[entry_offset..entry_offset + BLOCK],
        266,
        directory_lbn,
        216 + directory_length,
    );
}

fn vrs(image: &mut [u8], bridge: bool, revision: u16) {
    let start = if bridge { 17 } else { 16 };
    if bridge {
        image[16 * BLOCK] = 1;
        image[16 * BLOCK + 1..16 * BLOCK + 6].copy_from_slice(b"CD001");
        image[16 * BLOCK + 6] = 1;
    }
    for (block, identifier) in [
        (start, b"BEA01".as_slice()),
        (
            start + 1,
            if revision == 0x0102 {
                b"NSR02".as_slice()
            } else {
                b"NSR03".as_slice()
            },
        ),
        (start + 2, b"TEA01".as_slice()),
    ] {
        let offset = block * BLOCK;
        image[offset] = 0;
        image[offset + 1..offset + 6].copy_from_slice(identifier);
        image[offset + 6] = 1;
    }
}

fn volume_sequence(image: &mut [u8], start: u32, revision: u16) {
    let mut pvd = tagged_block(1, start, 512);
    pvd[16..20].copy_from_slice(&1_u32.to_le_bytes());
    dstring(&mut pvd[24..56], "UDFTEST");
    osta_charspec(&mut pvd[200..264]);
    pvd[56..58].copy_from_slice(&1_u16.to_le_bytes());
    pvd[58..60].copy_from_slice(&1_u16.to_le_bytes());
    finish_tag(&mut pvd, 1, start, 512);
    write_block(image, start, &pvd);

    let mut partition = tagged_block(5, start + 1, 512);
    partition[16..20].copy_from_slice(&2_u32.to_le_bytes());
    partition[20..22].copy_from_slice(&1_u16.to_le_bytes());
    partition[22..24].copy_from_slice(&0_u16.to_le_bytes());
    entity_id(
        &mut partition[24..56],
        if revision == 0x0102 {
            b"+NSR02"
        } else {
            b"+NSR03"
        },
    );
    partition[184..188].copy_from_slice(&1_u32.to_le_bytes());
    partition[188..192].copy_from_slice(&PARTITION_START.to_le_bytes());
    partition[192..196].copy_from_slice(&300_u32.to_le_bytes());
    finish_tag(&mut partition, 5, start + 1, 512);
    write_block(image, start + 1, &partition);

    let mut logical = tagged_block(6, start + 2, 446);
    logical[16..20].copy_from_slice(&3_u32.to_le_bytes());
    osta_charspec(&mut logical[20..84]);
    dstring(&mut logical[84..212], "UDFVOL");
    logical[212..216].copy_from_slice(&(BLOCK as u32).to_le_bytes());
    entity_id(&mut logical[216..248], b"*OSTA UDF Compliant");
    logical[240..242].copy_from_slice(&revision.to_le_bytes());
    long_ad(&mut logical, 248, BLOCK as u32, 0, 0);
    logical[264..268].copy_from_slice(&6_u32.to_le_bytes());
    logical[268..272].copy_from_slice(&1_u32.to_le_bytes());
    logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
    finish_tag(&mut logical, 6, start + 2, 446);
    write_block(image, start + 2, &logical);

    let terminator = tagged_block(8, start + 3, 16);
    write_block(image, start + 3, &terminator);
}

fn anchor(image: &mut [u8], block: u32) {
    let mut descriptor = tagged_block(2, block, 512);
    descriptor[16..20].copy_from_slice(&(4_u32 * BLOCK as u32).to_le_bytes());
    descriptor[20..24].copy_from_slice(&MAIN_VDS.to_le_bytes());
    descriptor[24..28].copy_from_slice(&(4_u32 * BLOCK as u32).to_le_bytes());
    descriptor[28..32].copy_from_slice(&RESERVE_VDS.to_le_bytes());
    finish_tag(&mut descriptor, 2, block, 512);
    write_block(image, block, &descriptor);
}

fn udf_image(options: BuildOptions) -> Vec<u8> {
    let mut image = vec![0_u8; BLOCKS * BLOCK];
    vrs(&mut image, options.bridge, options.revision);
    volume_sequence(&mut image, MAIN_VDS, options.revision);
    volume_sequence(&mut image, RESERVE_VDS, options.revision);
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        anchor(&mut image, block);
    }

    let mut root_directory = parent_fid(2, 1, 0);
    for descriptor in [
        fid("chain.bin", false, 2, 15),
        fid("extent.bin", false, 2, 4),
        fid("hard.bin", false, 2, 4),
        fid("inline.txt", false, 2, 3),
        fid("link", false, 2, 8),
        fid("long.bin", false, 2, 13),
        fid("multi.bin", false, 2, 9),
        fid("nested", true, 2, 5),
    ] {
        root_directory.extend_from_slice(&descriptor);
    }
    let mut nested_directory = parent_fid(6, 1, 0);
    nested_directory.extend_from_slice(&fid("日本.txt", false, 6, 7));

    let mut file_set = tagged_block(256, 0, 512);
    file_set[16..28].copy_from_slice(&timestamp());
    osta_charspec(&mut file_set[48..112]);
    dstring(&mut file_set[112..240], "UDFVOL");
    osta_charspec(&mut file_set[240..304]);
    dstring(&mut file_set[304..336], "UDFSET");
    long_ad(&mut file_set, 400, BLOCK as u32, 1, 0);
    entity_id(&mut file_set[416..448], b"*OSTA UDF Compliant");
    file_set[440..442].copy_from_slice(&options.revision.to_le_bytes());
    finish_tag(&mut file_set, 256, 0, 512);
    write_block(&mut image, PARTITION_START, &file_set);

    let root_ad = short_ad(root_directory.len() as u32, 0, 2);
    write_block(
        &mut image,
        PARTITION_START + 1,
        &file_entry(1, 4, 0, root_directory.len() as u64, &root_ad, 0, 1),
    );
    write_block(&mut image, PARTITION_START + 2, &root_directory);
    write_block(
        &mut image,
        PARTITION_START + 3,
        &file_entry_with_extended_attributes(3, b"inline", &extended_attributes(3), 3),
    );

    let extent_payload = b"extent payload";
    write_block(&mut image, PARTITION_START + 10, extent_payload);
    write_block(
        &mut image,
        PARTITION_START + 4,
        &file_entry(
            4,
            5,
            0,
            extent_payload.len() as u64,
            &short_ad(extent_payload.len() as u32, 0, 10),
            4,
            2,
        ),
    );

    write_block(
        &mut image,
        PARTITION_START + 5,
        &file_entry(
            5,
            4,
            0,
            nested_directory.len() as u64,
            &short_ad(nested_directory.len() as u32, 0, 6),
            5,
            1,
        ),
    );
    write_block(&mut image, PARTITION_START + 6, &nested_directory);
    write_block(
        &mut image,
        PARTITION_START + 7,
        &extended_file_entry(7, 5, "深い内容".as_bytes(), 7),
    );

    let mut symlink = vec![5, 11, 0, 0, 8];
    symlink.extend_from_slice(b"extent.bin");
    write_block(
        &mut image,
        PARTITION_START + 8,
        &file_entry(8, 12, 3, symlink.len() as u64, &symlink, 8, 1),
    );

    let multi_head = vec![b'a'; BLOCK];
    write_block(&mut image, PARTITION_START + 11, &multi_head);
    write_block(&mut image, PARTITION_START + 12, b"world");
    let mut multi_ads = Vec::new();
    multi_ads.extend_from_slice(&short_ad(BLOCK as u32, 0, 11));
    multi_ads.extend_from_slice(&short_ad(BLOCK as u32, 2, 0));
    multi_ads.extend_from_slice(&short_ad(5, 0, 12));
    let mut multi_entry = file_entry(9, 5, 0, (BLOCK as u64 * 2) + 5, &multi_ads, 9, 1);
    multi_entry[64..72].copy_from_slice(&2_u64.to_le_bytes());
    finish_tag(&mut multi_entry, 261, 9, 200);
    write_block(&mut image, PARTITION_START + 9, &multi_entry);

    write_block(&mut image, PARTITION_START + 14, b"long-ad");
    write_block(
        &mut image,
        PARTITION_START + 13,
        &file_entry(13, 5, 1, 7, &long_allocation_ad(7, 0, 14, 0), 13, 1),
    );

    write_block(&mut image, PARTITION_START + 17, b"chain");
    write_block(
        &mut image,
        PARTITION_START + 15,
        &file_entry(15, 5, 0, 5, &short_ad(BLOCK as u32, 3, 16), 15, 1),
    );
    let mut allocation_extent = tagged_block(258, 16, 32);
    allocation_extent[20..24].copy_from_slice(&8_u32.to_le_bytes());
    allocation_extent[24..32].copy_from_slice(&short_ad(5, 0, 17));
    finish_tag(&mut allocation_extent, 258, 16, 32);
    write_block(&mut image, PARTITION_START + 16, &allocation_extent);

    if options.corrupt_main {
        image[MAIN_VDS as usize * BLOCK + 4] ^= 0x80;
    }
    if options.corrupt_first_anchor {
        image[256 * BLOCK + 4] ^= 0x40;
    }
    image
}

#[derive(Clone, Copy)]
enum MetadataMirror {
    None,
    Shared,
    Duplicate,
}

#[derive(Clone, Copy)]
struct MetadataBuildOptions {
    revision: u16,
    mirror: MetadataMirror,
    bitmap: bool,
    logical_base: u32,
    split: bool,
}

impl Default for MetadataBuildOptions {
    fn default() -> Self {
        Self {
            revision: 0x0250,
            mirror: MetadataMirror::Duplicate,
            bitmap: false,
            logical_base: 0,
            split: false,
        }
    }
}

fn metadata_partition_map(options: MetadataBuildOptions) -> [u8; 64] {
    let mut map = [0_u8; 64];
    map[0] = 2;
    map[1] = 64;
    entity_id(&mut map[4..36], b"*UDF Metadata Partition");
    map[28..30].copy_from_slice(&options.revision.to_le_bytes());
    map[36..38].copy_from_slice(&1_u16.to_le_bytes());
    map[38..40].copy_from_slice(&0_u16.to_le_bytes());
    map[40..44].copy_from_slice(&4_u32.to_le_bytes());
    map[44..48].copy_from_slice(
        &if matches!(options.mirror, MetadataMirror::None) {
            u32::MAX
        } else {
            5_u32
        }
        .to_le_bytes(),
    );
    map[48..52].copy_from_slice(&if options.bitmap { 6_u32 } else { u32::MAX }.to_le_bytes());
    map[52..56].copy_from_slice(&32_u32.to_le_bytes());
    map[56..58].copy_from_slice(&32_u16.to_le_bytes());
    map[58] = u8::from(matches!(options.mirror, MetadataMirror::Duplicate));
    map
}

fn install_metadata_lvd(image: &mut [u8], start: u32, options: MetadataBuildOptions) {
    let logical_offset = (start + 2) as usize * BLOCK;
    let logical = &mut image[logical_offset..logical_offset + BLOCK];
    long_ad(logical, 248, BLOCK as u32, options.logical_base, 1);
    logical[264..268].copy_from_slice(&70_u32.to_le_bytes());
    logical[268..272].copy_from_slice(&2_u32.to_le_bytes());
    logical[440..510].fill(0);
    logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
    logical[446..510].copy_from_slice(&metadata_partition_map(options));
    finish_tag(logical, 6, start + 2, 510);
}

fn metadata_file_entry(
    location: u32,
    file_type: u8,
    total_blocks: u32,
    allocations: &[u8],
) -> Vec<u8> {
    file_entry(
        location,
        file_type,
        0,
        u64::from(total_blocks) * BLOCK as u64,
        allocations,
        0,
        0,
    )
}

fn minimal_metadata_contents(options: MetadataBuildOptions, total_blocks: u32) -> Vec<u8> {
    let mut contents = vec![0_u8; total_blocks as usize * BLOCK];
    let base = options.logical_base;
    let mut file_set = tagged_block(256, base, 512);
    file_set[16..28].copy_from_slice(&timestamp());
    osta_charspec(&mut file_set[48..112]);
    dstring(&mut file_set[112..240], "UDFVOL");
    osta_charspec(&mut file_set[240..304]);
    dstring(&mut file_set[304..336], "UDFSET");
    long_ad(&mut file_set, 400, BLOCK as u32, base + 1, 1);
    entity_id(&mut file_set[416..448], b"*OSTA UDF Compliant");
    file_set[440..442].copy_from_slice(&options.revision.to_le_bytes());
    finish_tag(&mut file_set, 256, base, 512);
    write_block(&mut contents, base, &file_set);

    let mut parent = parent_fid(base + 2, base + 1, 0);
    parent[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let parent_length = parent.len();
    finish_tag(&mut parent, 257, base + 2, parent_length);
    let mut child = fid("metadata.txt", false, base + 2, base + 3);
    child[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let child_length = child.len();
    finish_tag(&mut child, 257, base + 2, child_length);
    let mut directory = parent;
    directory.extend_from_slice(&child);
    write_block(
        &mut contents,
        base + 1,
        &file_entry(
            base + 1,
            4,
            0,
            directory.len() as u64,
            &short_ad(directory.len() as u32, 0, base + 2),
            0,
            1,
        ),
    );
    write_block(&mut contents, base + 2, &directory);
    write_block(
        &mut contents,
        base + 3,
        &file_entry(base + 3, 5, 3, 8, b"metadata", u64::from(base + 3), 1),
    );
    contents
}

fn copy_metadata_extent(
    image: &mut [u8],
    contents: &[u8],
    logical_start: u32,
    physical_start: u32,
    blocks: u32,
) {
    let source = logical_start as usize * BLOCK;
    let destination = (PARTITION_START + physical_start) as usize * BLOCK;
    let length = blocks as usize * BLOCK;
    image[destination..destination + length].copy_from_slice(&contents[source..source + length]);
}

fn udf_metadata_image(options: MetadataBuildOptions) -> Vec<u8> {
    let mut image = udf_image(BuildOptions {
        revision: options.revision,
        ..BuildOptions::default()
    });
    install_metadata_lvd(&mut image, MAIN_VDS, options);
    install_metadata_lvd(&mut image, RESERVE_VDS, options);

    let total_blocks = if options.split { 64 } else { 32 };
    let contents = minimal_metadata_contents(options, total_blocks);
    let mut main_ads = Vec::new();
    main_ads.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 32));
    copy_metadata_extent(&mut image, &contents, 0, 32, 32);
    if options.split {
        main_ads.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 96));
        copy_metadata_extent(&mut image, &contents, 32, 96, 32);
    }
    write_block(
        &mut image,
        PARTITION_START + 4,
        &metadata_file_entry(4, 250, total_blocks, &main_ads),
    );

    if !matches!(options.mirror, MetadataMirror::None) {
        let mut mirror_ads = Vec::new();
        if matches!(options.mirror, MetadataMirror::Duplicate) {
            mirror_ads.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 64));
            copy_metadata_extent(&mut image, &contents, 0, 64, 32);
            if options.split {
                mirror_ads.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 128));
                copy_metadata_extent(&mut image, &contents, 32, 128, 32);
            }
        } else {
            mirror_ads.clone_from(&main_ads);
        }
        write_block(
            &mut image,
            PARTITION_START + 5,
            &metadata_file_entry(5, 251, total_blocks, &mirror_ads),
        );
    }

    if options.bitmap {
        let bitmap_bytes = total_blocks.div_ceil(8);
        let mut bitmap = vec![0_u8; 24 + bitmap_bytes as usize];
        bitmap[16..20].copy_from_slice(&total_blocks.to_le_bytes());
        bitmap[20..24].copy_from_slice(&bitmap_bytes.to_le_bytes());
        finish_tag(&mut bitmap, 264, 6, 24);
        write_block(
            &mut image,
            PARTITION_START + 6,
            &file_entry(6, 252, 3, bitmap.len() as u64, &bitmap, 0, 0),
        );
    }
    image
}

const VIRTUAL_FILE_SET_PHYSICAL: u32 = 40;
const HISTORICAL_FILE_SET_PHYSICAL: u32 = 41;
const VIRTUAL_CHILD_PHYSICAL: u32 = 42;
const VIRTUAL_DIRECTORY_PHYSICAL: u32 = 43;
const HISTORICAL_DIRECTORY_PHYSICAL: u32 = 44;
const VIRTUAL_ROOT_PHYSICAL: u32 = 80;
const HISTORICAL_ROOT_PHYSICAL: u32 = 81;
const VAT_SECOND_ALLOCATION_EXTENT_PHYSICAL: u32 = 292;
const VAT_ALLOCATION_EXTENT_PHYSICAL: u32 = 293;
const VAT_SECOND_EXTENT_PHYSICAL: u32 = 294;
const VAT_FIRST_EXTENT_PHYSICAL: u32 = 296;
const VAT_PREVIOUS_ICB: u32 = 298;
const VAT_LATEST_ICB: u32 = 299;

#[derive(Clone, Copy)]
enum VatStorage {
    Inline,
    External(VatAllocation),
}

#[derive(Clone, Copy)]
enum VatAllocation {
    Short,
    Long,
    Continuation,
    ChainedContinuation,
}

#[derive(Clone, Copy)]
enum VatHistory {
    None,
    Previous,
}

#[derive(Clone, Copy)]
struct VirtualBuildOptions {
    revision: u16,
    storage: VatStorage,
    history: VatHistory,
}

impl Default for VirtualBuildOptions {
    fn default() -> Self {
        Self {
            revision: 0x0260,
            storage: VatStorage::Inline,
            history: VatHistory::None,
        }
    }
}

fn virtual_partition_map(revision: u16) -> [u8; 64] {
    let mut map = [0_u8; 64];
    map[0] = 2;
    map[1] = 64;
    entity_id(&mut map[4..36], b"*UDF Virtual Partition");
    map[28..30].copy_from_slice(&revision.to_le_bytes());
    map[36..38].copy_from_slice(&1_u16.to_le_bytes());
    map[38..40].copy_from_slice(&0_u16.to_le_bytes());
    map
}

fn install_virtual_volume_descriptors(image: &mut [u8], start: u32, revision: u16) {
    let partition_offset = (start + 1) as usize * BLOCK;
    let partition = &mut image[partition_offset..partition_offset + BLOCK];
    partition[184..188].copy_from_slice(&2_u32.to_le_bytes());
    finish_tag(partition, 5, start + 1, 512);

    let logical_offset = (start + 2) as usize * BLOCK;
    let logical = &mut image[logical_offset..logical_offset + BLOCK];
    long_ad(logical, 248, BLOCK as u32, 0, 1);
    logical[264..268].copy_from_slice(&70_u32.to_le_bytes());
    logical[268..272].copy_from_slice(&2_u32.to_le_bytes());
    logical[440..510].fill(0);
    logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
    logical[446..510].copy_from_slice(&virtual_partition_map(revision));
    finish_tag(logical, 6, start + 2, 510);
}

fn virtual_parent_fid(location: u32, parent_lbn: u32) -> Vec<u8> {
    let mut descriptor = parent_fid(location, parent_lbn, 0);
    descriptor[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let length = descriptor.len();
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn virtual_child_fid(location: u32, child_lbn: u32) -> Vec<u8> {
    let mut descriptor = fid("virtual.txt", false, location, child_lbn);
    descriptor[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let length = descriptor.len();
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn vat_entries(storage: VatStorage) -> Vec<u32> {
    let count = match storage {
        VatStorage::Inline => 3,
        VatStorage::External(_) => 520,
    };
    let mut entries = vec![u32::MAX; count];
    entries[..3].copy_from_slice(&[
        VIRTUAL_FILE_SET_PHYSICAL,
        VIRTUAL_ROOT_PHYSICAL,
        VIRTUAL_CHILD_PHYSICAL,
    ]);
    entries
}

fn vat_body(revision: u16, entries: &[u32], previous_icb: Option<u32>) -> Vec<u8> {
    let previous_icb = previous_icb.unwrap_or(u32::MAX);
    if revision == 0x0150 {
        let entries_length = entries.len() * 4;
        let mut body = vec![0_u8; entries_length + 36];
        for (index, entry) in entries.iter().enumerate() {
            let offset = index * 4;
            body[offset..offset + 4].copy_from_slice(&entry.to_le_bytes());
        }
        entity_id(
            &mut body[entries_length..entries_length + 32],
            b"*UDF Virtual Alloc Tbl",
        );
        body[entries_length + 24..entries_length + 26].copy_from_slice(&revision.to_le_bytes());
        body[entries_length + 32..entries_length + 36].copy_from_slice(&previous_icb.to_le_bytes());
        return body;
    }

    let mut body = vec![0_u8; 152 + entries.len() * 4];
    body[0..2].copy_from_slice(&152_u16.to_le_bytes());
    body[2..4].copy_from_slice(&0_u16.to_le_bytes());
    dstring(&mut body[4..132], "UDFVOL");
    body[132..136].copy_from_slice(&previous_icb.to_le_bytes());
    body[136..140].copy_from_slice(&1_u32.to_le_bytes());
    body[140..144].copy_from_slice(&1_u32.to_le_bytes());
    body[144..146].copy_from_slice(&revision.to_le_bytes());
    body[146..148].copy_from_slice(&revision.to_le_bytes());
    body[148..150].copy_from_slice(&revision.to_le_bytes());
    for (index, entry) in entries.iter().enumerate() {
        let offset = 152 + index * 4;
        body[offset..offset + 4].copy_from_slice(&entry.to_le_bytes());
    }
    body
}

fn write_vat(
    image: &mut [u8],
    revision: u16,
    location: u32,
    entries: &[u32],
    previous_icb: Option<u32>,
    storage: VatStorage,
) {
    let body = vat_body(revision, entries, previous_icb);
    let file_type = if revision == 0x0150 { 0 } else { 248 };
    let entry = match storage {
        VatStorage::Inline => file_entry(
            location,
            file_type,
            3,
            body.len() as u64,
            &body,
            u64::from(location),
            0,
        ),
        VatStorage::External(allocation) => {
            assert!(body.len() > BLOCK);
            write_block(
                image,
                PARTITION_START + VAT_FIRST_EXTENT_PHYSICAL,
                &body[..BLOCK],
            );
            write_block(
                image,
                PARTITION_START + VAT_SECOND_EXTENT_PHYSICAL,
                &body[BLOCK..],
            );
            let (allocation_type, allocations) = match allocation {
                VatAllocation::Short => {
                    let mut allocations = Vec::new();
                    allocations.extend_from_slice(&short_ad(
                        BLOCK as u32,
                        0,
                        VAT_FIRST_EXTENT_PHYSICAL,
                    ));
                    allocations.extend_from_slice(&short_ad(
                        (body.len() - BLOCK) as u32,
                        0,
                        VAT_SECOND_EXTENT_PHYSICAL,
                    ));
                    (0, allocations)
                },
                VatAllocation::Long => {
                    let mut allocations = Vec::new();
                    allocations.extend_from_slice(&long_allocation_ad(
                        BLOCK as u32,
                        0,
                        VAT_FIRST_EXTENT_PHYSICAL,
                        0,
                    ));
                    allocations.extend_from_slice(&long_allocation_ad(
                        (body.len() - BLOCK) as u32,
                        0,
                        VAT_SECOND_EXTENT_PHYSICAL,
                        0,
                    ));
                    (1, allocations)
                },
                VatAllocation::Continuation => {
                    let mut allocation_extent =
                        tagged_block(258, VAT_ALLOCATION_EXTENT_PHYSICAL, 40);
                    allocation_extent[20..24].copy_from_slice(&16_u32.to_le_bytes());
                    allocation_extent[24..32].copy_from_slice(&short_ad(
                        BLOCK as u32,
                        0,
                        VAT_FIRST_EXTENT_PHYSICAL,
                    ));
                    allocation_extent[32..40].copy_from_slice(&short_ad(
                        (body.len() - BLOCK) as u32,
                        0,
                        VAT_SECOND_EXTENT_PHYSICAL,
                    ));
                    finish_tag(
                        &mut allocation_extent,
                        258,
                        VAT_ALLOCATION_EXTENT_PHYSICAL,
                        40,
                    );
                    write_block(
                        image,
                        PARTITION_START + VAT_ALLOCATION_EXTENT_PHYSICAL,
                        &allocation_extent,
                    );
                    (0, short_ad(40, 3, VAT_ALLOCATION_EXTENT_PHYSICAL).to_vec())
                },
                VatAllocation::ChainedContinuation => {
                    let mut second_extent =
                        tagged_block(258, VAT_SECOND_ALLOCATION_EXTENT_PHYSICAL, 40);
                    second_extent[16..20]
                        .copy_from_slice(&VAT_ALLOCATION_EXTENT_PHYSICAL.to_le_bytes());
                    second_extent[20..24].copy_from_slice(&16_u32.to_le_bytes());
                    second_extent[24..32].copy_from_slice(&short_ad(
                        BLOCK as u32,
                        0,
                        VAT_FIRST_EXTENT_PHYSICAL,
                    ));
                    second_extent[32..40].copy_from_slice(&short_ad(
                        (body.len() - BLOCK) as u32,
                        0,
                        VAT_SECOND_EXTENT_PHYSICAL,
                    ));
                    finish_tag(
                        &mut second_extent,
                        258,
                        VAT_SECOND_ALLOCATION_EXTENT_PHYSICAL,
                        40,
                    );
                    write_block(
                        image,
                        PARTITION_START + VAT_SECOND_ALLOCATION_EXTENT_PHYSICAL,
                        &second_extent,
                    );

                    let mut first_extent = tagged_block(258, VAT_ALLOCATION_EXTENT_PHYSICAL, 32);
                    first_extent[20..24].copy_from_slice(&8_u32.to_le_bytes());
                    first_extent[24..32].copy_from_slice(&short_ad(
                        40,
                        3,
                        VAT_SECOND_ALLOCATION_EXTENT_PHYSICAL,
                    ));
                    finish_tag(&mut first_extent, 258, VAT_ALLOCATION_EXTENT_PHYSICAL, 32);
                    write_block(
                        image,
                        PARTITION_START + VAT_ALLOCATION_EXTENT_PHYSICAL,
                        &first_extent,
                    );
                    (0, short_ad(32, 3, VAT_ALLOCATION_EXTENT_PHYSICAL).to_vec())
                },
            };
            file_entry(
                location,
                file_type,
                allocation_type,
                body.len() as u64,
                &allocations,
                u64::from(location),
                0,
            )
        },
    };
    write_block(image, PARTITION_START + location, &entry);
}

fn udf_virtual_image(options: VirtualBuildOptions) -> Vec<u8> {
    let mut image = udf_image(BuildOptions {
        revision: options.revision,
        ..BuildOptions::default()
    });
    install_virtual_volume_descriptors(&mut image, MAIN_VDS, options.revision);
    install_virtual_volume_descriptors(&mut image, RESERVE_VDS, options.revision);

    let mut file_set = tagged_block(256, 0, 512);
    file_set[16..28].copy_from_slice(&timestamp());
    osta_charspec(&mut file_set[48..112]);
    dstring(&mut file_set[112..240], "UDFVOL");
    osta_charspec(&mut file_set[240..304]);
    dstring(&mut file_set[304..336], "UDFSET");
    long_ad(&mut file_set, 400, BLOCK as u32, 1, 1);
    entity_id(&mut file_set[416..448], b"*OSTA UDF Compliant");
    file_set[440..442].copy_from_slice(&options.revision.to_le_bytes());
    finish_tag(&mut file_set, 256, 0, 512);
    write_block(
        &mut image,
        PARTITION_START + VIRTUAL_FILE_SET_PHYSICAL,
        &file_set,
    );

    let mut directory = virtual_parent_fid(VIRTUAL_DIRECTORY_PHYSICAL, 1);
    directory.extend_from_slice(&virtual_child_fid(VIRTUAL_DIRECTORY_PHYSICAL, 2));
    write_block(
        &mut image,
        PARTITION_START + VIRTUAL_DIRECTORY_PHYSICAL,
        &directory,
    );
    write_block(
        &mut image,
        PARTITION_START + VIRTUAL_ROOT_PHYSICAL,
        &file_entry(
            1,
            4,
            1,
            directory.len() as u64,
            &long_allocation_ad(directory.len() as u32, 0, VIRTUAL_DIRECTORY_PHYSICAL, 0),
            0,
            1,
        ),
    );
    write_block(
        &mut image,
        PARTITION_START + VIRTUAL_CHILD_PHYSICAL,
        &file_entry(2, 5, 3, 11, b"virtual-vat", 2, 1),
    );

    let entries = vat_entries(options.storage);
    if matches!(options.history, VatHistory::Previous) {
        write_block(
            &mut image,
            PARTITION_START + HISTORICAL_FILE_SET_PHYSICAL,
            &file_set,
        );
        let historical_directory = virtual_parent_fid(HISTORICAL_DIRECTORY_PHYSICAL, 1);
        write_block(
            &mut image,
            PARTITION_START + HISTORICAL_DIRECTORY_PHYSICAL,
            &historical_directory,
        );
        write_block(
            &mut image,
            PARTITION_START + HISTORICAL_ROOT_PHYSICAL,
            &file_entry(
                1,
                4,
                1,
                historical_directory.len() as u64,
                &long_allocation_ad(
                    historical_directory.len() as u32,
                    0,
                    HISTORICAL_DIRECTORY_PHYSICAL,
                    0,
                ),
                0,
                1,
            ),
        );
        let historical_entries = [
            HISTORICAL_FILE_SET_PHYSICAL,
            HISTORICAL_ROOT_PHYSICAL,
            u32::MAX,
        ];
        write_vat(
            &mut image,
            options.revision,
            VAT_PREVIOUS_ICB,
            &historical_entries,
            None,
            VatStorage::Inline,
        );
    }
    write_vat(
        &mut image,
        options.revision,
        VAT_LATEST_ICB,
        &entries,
        matches!(options.history, VatHistory::Previous).then_some(VAT_PREVIOUS_ICB),
        options.storage,
    );
    image
}

fn mutate_virtual_maps(image: &mut [u8], mut update: impl FnMut(&mut [u8])) {
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical_offset = (start + 2) as usize * BLOCK;
        let logical = &mut image[logical_offset..logical_offset + BLOCK];
        update(&mut logical[446..510]);
        finish_tag(logical, 6, start + 2, 510);
    }
}

fn mutate_inline_vat(image: &mut [u8], mut update: impl FnMut(&mut [u8])) {
    let offset = (PARTITION_START + VAT_LATEST_ICB) as usize * BLOCK;
    let information_length =
        u64::from_le_bytes(image[offset + 56..offset + 64].try_into().unwrap()) as usize;
    update(&mut image[offset + 176..offset + 176 + information_length]);
    finish_tag(
        &mut image[offset..offset + BLOCK],
        261,
        VAT_LATEST_ICB,
        176 + information_length,
    );
}

fn mutate_metadata_maps(image: &mut [u8], mut update: impl FnMut(&mut [u8])) {
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical_offset = (start + 2) as usize * BLOCK;
        let logical = &mut image[logical_offset..logical_offset + BLOCK];
        update(&mut logical[446..510]);
        finish_tag(logical, 6, start + 2, 510);
    }
}

const SPARABLE_PACKET_BLOCKS: u16 = 16;
const SPARABLE_PARTITION_START: u32 = 304;
const SPARABLE_PARTITION_BLOCKS: u32 = 288;
const SPARABLE_TABLE_LOCATIONS: [u32; 2] = [64, 96];
const SPARABLE_STALE_PACKETS: [u32; 4] = [128, 144, 160, 176];
const SPARABLE_LATEST_PACKETS: [u32; 4] = [192, 208, 224, 240];

#[derive(Clone, Copy)]
struct SparableBuildOptions {
    revision: u16,
    table_size: u32,
    packet_blocks: u16,
    partition_start: u32,
}

impl Default for SparableBuildOptions {
    fn default() -> Self {
        Self {
            revision: 0x0260,
            table_size: BLOCK as u32,
            packet_blocks: SPARABLE_PACKET_BLOCKS,
            partition_start: SPARABLE_PARTITION_START,
        }
    }
}

fn sparable_partition_map(options: SparableBuildOptions) -> [u8; 64] {
    sparable_partition_map_with(
        options.revision,
        options.packet_blocks,
        options.table_size,
        &SPARABLE_TABLE_LOCATIONS,
    )
}

fn sparable_partition_map_with(
    revision: u16,
    packet_blocks: u16,
    table_size: u32,
    table_locations: &[u32],
) -> [u8; 64] {
    assert!((1..=4).contains(&table_locations.len()));
    let mut map = [0_u8; 64];
    map[0] = 2;
    map[1] = 64;
    entity_id(&mut map[4..36], b"*UDF Sparable Partition");
    map[28..30].copy_from_slice(&revision.to_le_bytes());
    map[36..38].copy_from_slice(&1_u16.to_le_bytes());
    map[38..40].copy_from_slice(&0_u16.to_le_bytes());
    map[40..42].copy_from_slice(&packet_blocks.to_le_bytes());
    map[42] = table_locations.len() as u8;
    map[44..48].copy_from_slice(&table_size.to_le_bytes());
    for (index, location) in table_locations.iter().enumerate() {
        let offset = 48 + index * 4;
        map[offset..offset + 4].copy_from_slice(&location.to_le_bytes());
    }
    map
}

fn sparing_table(
    revision: u16,
    location: u32,
    sequence: u32,
    table_size: u32,
    originals: [u32; 2],
    packets: [u32; 4],
) -> Vec<u8> {
    let mut table = vec![0_u8; table_size as usize];
    entity_id(&mut table[16..48], b"*UDF Sparing Table");
    table[40..42].copy_from_slice(&revision.to_le_bytes());
    table[48..50].copy_from_slice(&4_u16.to_le_bytes());
    table[52..56].copy_from_slice(&sequence.to_le_bytes());
    for (index, (original, mapped)) in [
        (originals[0], packets[0]),
        (originals[1], packets[1]),
        (0xffff_fff0, packets[2]),
        (u32::MAX, packets[3]),
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 56 + index * 8;
        table[offset..offset + 4].copy_from_slice(&original.to_le_bytes());
        table[offset + 4..offset + 8].copy_from_slice(&mapped.to_le_bytes());
    }
    finish_tag(&mut table, 0, location, 88);
    table
}

fn available_sparing_table(
    revision: u16,
    location: u32,
    sequence: u32,
    table_size: usize,
    entry_count: u16,
    packet_blocks: u16,
    mapped_start: u32,
) -> Vec<u8> {
    let used = 56 + usize::from(entry_count) * 8;
    assert!(used <= table_size);
    let mut table = vec![0_u8; table_size];
    entity_id(&mut table[16..48], b"*UDF Sparing Table");
    table[40..42].copy_from_slice(&revision.to_le_bytes());
    table[48..50].copy_from_slice(&entry_count.to_le_bytes());
    table[52..56].copy_from_slice(&sequence.to_le_bytes());
    for index in 0..u32::from(entry_count) {
        let offset = 56 + index as usize * 8;
        let mapped = mapped_start
            .checked_add(index.checked_mul(u32::from(packet_blocks)).unwrap())
            .unwrap();
        table[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        table[offset + 4..offset + 8].copy_from_slice(&mapped.to_le_bytes());
    }
    finish_tag(&mut table, 0, location, used);
    table
}

fn udf_available_sparable_image(
    packet_blocks: u16,
    table_locations: &[u32],
    entry_count: u16,
) -> (Vec<u8>, u64, usize) {
    const MAPPED_START: u32 = 1024;

    assert!(matches!(packet_blocks, 16 | 32));
    let revision = 0x0260;
    let partition_start = if packet_blocks == 32 {
        320
    } else {
        SPARABLE_PARTITION_START
    };
    let used = 56 + usize::from(entry_count) * 8;
    let table_size = used.div_ceil(BLOCK) * BLOCK;
    let mut image = udf_image(BuildOptions {
        revision,
        ..BuildOptions::default()
    });
    relocate_sparable_partition(&mut image, partition_start);
    for start in [MAIN_VDS, RESERVE_VDS] {
        install_sparable_volume_descriptors_with(
            &mut image,
            start,
            revision,
            packet_blocks,
            table_size as u32,
            table_locations,
            partition_start,
        );
    }

    for &location in table_locations {
        write_block(
            &mut image,
            location,
            &available_sparing_table(
                revision,
                location,
                1,
                table_size,
                entry_count,
                packet_blocks,
                MAPPED_START,
            ),
        );
    }
    let mapped_end = u64::from(MAPPED_START)
        + u64::from(entry_count) * u64::from(packet_blocks)
        + u64::from(packet_blocks);
    let image_blocks = mapped_end.max(BLOCKS as u64);
    (image, image_blocks * BLOCK as u64, used)
}

fn install_sparable_volume_descriptors(
    image: &mut [u8],
    start: u32,
    options: SparableBuildOptions,
) {
    install_sparable_volume_descriptors_with(
        image,
        start,
        options.revision,
        options.packet_blocks,
        options.table_size,
        &SPARABLE_TABLE_LOCATIONS,
        options.partition_start,
    );
}

fn install_sparable_volume_descriptors_with(
    image: &mut [u8],
    start: u32,
    revision: u16,
    packet_blocks: u16,
    table_size: u32,
    table_locations: &[u32],
    partition_start: u32,
) {
    let partition_offset = (start + 1) as usize * BLOCK;
    let partition = &mut image[partition_offset..partition_offset + BLOCK];
    partition[184..188].copy_from_slice(&3_u32.to_le_bytes());
    partition[188..192].copy_from_slice(&partition_start.to_le_bytes());
    partition[192..196].copy_from_slice(&SPARABLE_PARTITION_BLOCKS.to_le_bytes());
    finish_tag(partition, 5, start + 1, 512);

    let logical_offset = (start + 2) as usize * BLOCK;
    let logical = &mut image[logical_offset..logical_offset + BLOCK];
    logical[264..268].copy_from_slice(&64_u32.to_le_bytes());
    logical[268..272].copy_from_slice(&1_u32.to_le_bytes());
    logical[440..504].fill(0);
    logical[440..504].copy_from_slice(&sparable_partition_map_with(
        revision,
        packet_blocks,
        table_size,
        table_locations,
    ));
    finish_tag(logical, 6, start + 2, 504);
}

fn relocate_sparable_partition(image: &mut [u8], destination_block: u32) {
    let source = PARTITION_START as usize * BLOCK;
    let destination = destination_block as usize * BLOCK;
    let length = SPARABLE_PARTITION_BLOCKS as usize * BLOCK;
    assert!(destination >= source);
    image.copy_within(source..source + length, destination);
    image[source..destination].fill(0);
}

fn copy_sparable_packet(
    image: &mut [u8],
    partition_start: u32,
    packet_blocks: u16,
    original: u32,
    destination: u32,
) {
    let packet_bytes = usize::from(packet_blocks) * BLOCK;
    let source = (partition_start + original) as usize * BLOCK;
    let copied = image[source..source + packet_bytes].to_vec();
    let target = destination as usize * BLOCK;
    image[target..target + packet_bytes].copy_from_slice(&copied);
}

fn sparable_replacement_packets(packet_blocks: u16) -> ([u32; 4], [u32; 4]) {
    assert!(matches!(packet_blocks, 16 | 32));
    if packet_blocks == 16 {
        (SPARABLE_STALE_PACKETS, SPARABLE_LATEST_PACKETS)
    } else {
        ([128, 160, 608, 640], [192, 224, 544, 576])
    }
}

fn udf_sparable_image(options: SparableBuildOptions) -> Vec<u8> {
    assert!(options.table_size as usize >= 88);
    assert!(matches!(options.packet_blocks, 16 | 32));
    assert!(
        options
            .partition_start
            .is_multiple_of(u32::from(options.packet_blocks))
    );
    let (stale_packets, latest_packets) = sparable_replacement_packets(options.packet_blocks);
    let mut image = udf_image(BuildOptions {
        revision: options.revision,
        ..BuildOptions::default()
    });
    relocate_sparable_partition(&mut image, options.partition_start);
    install_sparable_volume_descriptors(&mut image, MAIN_VDS, options);
    install_sparable_volume_descriptors(&mut image, RESERVE_VDS, options);

    for (original, stale, latest) in [
        (0, stale_packets[0], latest_packets[0]),
        (
            u32::from(options.packet_blocks),
            stale_packets[1],
            latest_packets[1],
        ),
    ] {
        copy_sparable_packet(
            &mut image,
            options.partition_start,
            options.packet_blocks,
            original,
            stale,
        );
        copy_sparable_packet(
            &mut image,
            options.partition_start,
            options.packet_blocks,
            original,
            latest,
        );
    }
    write_block(
        &mut image,
        latest_packets[0] + 3,
        &file_entry_with_extended_attributes(3, b"spared", &extended_attributes(3), 3),
    );
    let original = options.partition_start as usize * BLOCK;
    let length = usize::from(options.packet_blocks) * 2 * BLOCK;
    image[original..original + length].fill(0);

    write_block(
        &mut image,
        SPARABLE_TABLE_LOCATIONS[0],
        &sparing_table(
            options.revision,
            SPARABLE_TABLE_LOCATIONS[0],
            1,
            options.table_size,
            [0, u32::from(options.packet_blocks)],
            stale_packets,
        ),
    );
    write_block(
        &mut image,
        SPARABLE_TABLE_LOCATIONS[1],
        &sparing_table(
            options.revision,
            SPARABLE_TABLE_LOCATIONS[1],
            2,
            options.table_size,
            [0, u32::from(options.packet_blocks)],
            latest_packets,
        ),
    );
    image
}

fn udf_metadata_over_sparable_image(revision: u16) -> Vec<u8> {
    let metadata_options = MetadataBuildOptions {
        revision,
        mirror: MetadataMirror::None,
        ..MetadataBuildOptions::default()
    };
    let sparable_options = SparableBuildOptions {
        revision,
        ..SparableBuildOptions::default()
    };
    let mut image = udf_metadata_image(metadata_options);
    relocate_sparable_partition(&mut image, SPARABLE_PARTITION_START);
    for start in [MAIN_VDS, RESERVE_VDS] {
        let partition_offset = (start + 1) as usize * BLOCK;
        let partition = &mut image[partition_offset..partition_offset + BLOCK];
        partition[184..188].copy_from_slice(&3_u32.to_le_bytes());
        partition[188..192].copy_from_slice(&SPARABLE_PARTITION_START.to_le_bytes());
        partition[192..196].copy_from_slice(&SPARABLE_PARTITION_BLOCKS.to_le_bytes());
        finish_tag(partition, 5, start + 1, 512);

        let logical_offset = (start + 2) as usize * BLOCK;
        let logical = &mut image[logical_offset..logical_offset + BLOCK];
        let metadata_map = logical[446..510].to_vec();
        logical[264..268].copy_from_slice(&128_u32.to_le_bytes());
        logical[268..272].copy_from_slice(&2_u32.to_le_bytes());
        logical[440..568].fill(0);
        logical[440..504].copy_from_slice(&sparable_partition_map(sparable_options));
        logical[504..568].copy_from_slice(&metadata_map);
        finish_tag(logical, 6, start + 2, 568);
    }

    for (original, stale, latest) in [
        (0, SPARABLE_STALE_PACKETS[0], SPARABLE_LATEST_PACKETS[0]),
        (32, SPARABLE_STALE_PACKETS[1], SPARABLE_LATEST_PACKETS[1]),
    ] {
        copy_sparable_packet(
            &mut image,
            SPARABLE_PARTITION_START,
            SPARABLE_PACKET_BLOCKS,
            original,
            stale,
        );
        copy_sparable_packet(
            &mut image,
            SPARABLE_PARTITION_START,
            SPARABLE_PACKET_BLOCKS,
            original,
            latest,
        );
    }
    write_block(
        &mut image,
        SPARABLE_LATEST_PACKETS[1] + 3,
        &file_entry(3, 5, 3, 15, b"spared-metadata", 3, 1),
    );
    for original in [0_u32, 32] {
        let start = (SPARABLE_PARTITION_START + original) as usize * BLOCK;
        let length = usize::from(SPARABLE_PACKET_BLOCKS) * BLOCK;
        image[start..start + length].fill(0);
    }
    write_block(
        &mut image,
        SPARABLE_TABLE_LOCATIONS[0],
        &sparing_table(
            revision,
            SPARABLE_TABLE_LOCATIONS[0],
            1,
            BLOCK as u32,
            [0, 32],
            SPARABLE_STALE_PACKETS,
        ),
    );
    write_block(
        &mut image,
        SPARABLE_TABLE_LOCATIONS[1],
        &sparing_table(
            revision,
            SPARABLE_TABLE_LOCATIONS[1],
            2,
            BLOCK as u32,
            [0, 32],
            SPARABLE_LATEST_PACKETS,
        ),
    );
    image
}

fn mutate_sparable_maps(image: &mut [u8], mut update: impl FnMut(&mut [u8])) {
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical_offset = (start + 2) as usize * BLOCK;
        let logical = &mut image[logical_offset..logical_offset + BLOCK];
        update(&mut logical[440..504]);
        finish_tag(logical, 6, start + 2, 504);
    }
}

fn mutate_sparing_table(image: &mut [u8], location: u32, mut update: impl FnMut(&mut [u8])) {
    let start = location as usize * BLOCK;
    let table = &mut image[start..start + BLOCK];
    update(table);
    let entries = usize::from(u16::from_le_bytes(table[48..50].try_into().unwrap()));
    finish_tag(table, 0, location, 56 + entries * 8);
}

fn metadata_physical_block(_options: MetadataBuildOptions, mirror: bool, logical: u32) -> u32 {
    let extent_start = if mirror {
        if logical < 32 { 64 } else { 128 }
    } else if logical < 32 {
        32
    } else {
        96
    };
    PARTITION_START + extent_start + logical % 32
}

fn udf_image_with_external_attributes(attributes: &[u8]) -> Vec<u8> {
    let mut image = udf_image(BuildOptions::default());
    let external_icb_lbn = 18_u32;
    let attributes_lbn = 19_u32;
    write_block(&mut image, PARTITION_START + attributes_lbn, attributes);
    write_block(
        &mut image,
        PARTITION_START + external_icb_lbn,
        &file_entry(
            external_icb_lbn,
            8,
            0,
            attributes.len() as u64,
            &short_ad(attributes.len() as u32, 0, attributes_lbn),
            u64::from(external_icb_lbn),
            0,
        ),
    );
    let inline = (PARTITION_START as usize + 3) * BLOCK;
    long_ad(
        &mut image[inline..inline + BLOCK],
        112,
        BLOCK as u32,
        external_icb_lbn,
        0,
    );
    finish_tag(&mut image[inline..inline + BLOCK], 261, 3, 258);
    image
}

fn udf_image_with_streams() -> Vec<u8> {
    let mut image = udf_image(BuildOptions::default());

    let named_directory_lbn = 18_u32;
    let named_stream_lbn = 19_u32;
    let main_entry = (PARTITION_START + 7) as usize * BLOCK;
    long_ad(
        &mut image[main_entry..main_entry + BLOCK],
        152,
        BLOCK as u32,
        named_directory_lbn,
        0,
    );
    image[main_entry + 48..main_entry + 50].copy_from_slice(&2_u16.to_le_bytes());
    finish_tag(
        &mut image[main_entry..main_entry + BLOCK],
        266,
        7,
        216 + "深い内容".len(),
    );

    let named_directory = named_stream_directory();
    write_block(
        &mut image,
        PARTITION_START + named_directory_lbn,
        &stream_extended_file_entry(named_directory_lbn, 13, &named_directory, 7),
    );
    let mut named_stream = stream_extended_file_entry(named_stream_lbn, 5, b"named-index", 7);
    named_stream[36..40].copy_from_slice(&9999_u32.to_le_bytes());
    named_stream[40..44].copy_from_slice(&999_u32.to_le_bytes());
    named_stream[44..48].copy_from_slice(&0_u32.to_le_bytes());
    named_stream[100] = 55;
    finish_tag(
        &mut named_stream,
        266,
        named_stream_lbn,
        216 + b"named-index".len(),
    );
    write_block(
        &mut image,
        PARTITION_START + named_stream_lbn,
        &named_stream,
    );
    for (_, lbn, payload) in UDF_NON_SYSTEM_STREAMS {
        write_block(
            &mut image,
            PARTITION_START + lbn,
            &stream_extended_file_entry(lbn, 5, payload, 7),
        );
    }
    let named_stream_bytes = UDF_NON_SYSTEM_STREAMS
        .iter()
        .try_fold(b"named-index".len() as u64, |total, (_, _, payload)| {
            total.checked_add(payload.len() as u64)
        })
        .unwrap();
    image[main_entry + 64..main_entry + 72]
        .copy_from_slice(&("深い内容".len() as u64 + named_stream_bytes).to_le_bytes());
    finish_tag(
        &mut image[main_entry..main_entry + BLOCK],
        266,
        7,
        216 + "深い内容".len(),
    );

    let system_directory_lbn = 20_u32;
    let system_stream_lbn = 21_u32;
    let file_set = PARTITION_START as usize * BLOCK;
    long_ad(
        &mut image[file_set..file_set + BLOCK],
        464,
        BLOCK as u32,
        system_directory_lbn,
        0,
    );
    finish_tag(&mut image[file_set..file_set + BLOCK], 256, 0, 512);

    let mut system_directory = parent_fid(system_directory_lbn, system_directory_lbn, 0);
    system_directory.extend_from_slice(&stream_fid(
        "*UDF Backup",
        true,
        system_directory_lbn,
        system_stream_lbn,
        0,
    ));
    write_block(
        &mut image,
        PARTITION_START + system_directory_lbn,
        &stream_extended_file_entry(system_directory_lbn, 13, &system_directory, 0),
    );
    write_block(
        &mut image,
        PARTITION_START + system_stream_lbn,
        &stream_extended_file_entry(system_stream_lbn, 5, &timestamp(), 0),
    );
    image
}

fn udf_image_with_continued_file_set(revision: u16) -> Vec<u8> {
    let mut image = udf_image(BuildOptions {
        revision,
        ..BuildOptions::default()
    });
    let file_set_offset = PARTITION_START as usize * BLOCK;
    let mut prevailing = image[file_set_offset..file_set_offset + BLOCK].to_vec();
    prevailing[44..48].copy_from_slice(&1_u32.to_le_bytes());
    prevailing[448..464].fill(0);
    finish_tag(&mut prevailing, 256, 18, 512);
    write_block(&mut image, PARTITION_START + 18, &prevailing);

    long_ad(
        &mut image[file_set_offset..file_set_offset + BLOCK],
        400,
        BLOCK as u32,
        4,
        0,
    );
    long_ad(
        &mut image[file_set_offset..file_set_offset + BLOCK],
        448,
        BLOCK as u32,
        18,
        0,
    );
    finish_tag(
        &mut image[file_set_offset..file_set_offset + BLOCK],
        256,
        0,
        512,
    );
    image
}

fn udf_image_with_multiple_file_sets() -> Vec<u8> {
    let mut image = udf_image_with_continued_file_set(0x0201);
    let second_offset = (PARTITION_START as usize + 18) * BLOCK;
    let mut alternate = image[second_offset..second_offset + BLOCK].to_vec();
    alternate[40..44].copy_from_slice(&1_u32.to_le_bytes());
    alternate[44..48].copy_from_slice(&2_u32.to_le_bytes());
    alternate[304..336].fill(0);
    dstring(&mut alternate[304..336], "ALTERNATE");
    long_ad(&mut alternate, 400, BLOCK as u32, 34, 0);
    alternate[448..464].fill(0);
    finish_tag(&mut alternate, 256, 28, 512);
    write_block(&mut image, PARTITION_START + 28, &alternate);

    long_ad(
        &mut image[second_offset..second_offset + BLOCK],
        448,
        BLOCK as u32,
        28,
        0,
    );
    finish_tag(
        &mut image[second_offset..second_offset + BLOCK],
        256,
        18,
        512,
    );

    let mut alternate_directory = parent_fid(35, 34, 0);
    alternate_directory.extend_from_slice(&fid("other.txt", false, 35, 3));
    write_block(
        &mut image,
        PARTITION_START + 34,
        &file_entry(
            34,
            4,
            0,
            alternate_directory.len() as u64,
            &short_ad(alternate_directory.len() as u32, 0, 35),
            0,
            1,
        ),
    );
    write_block(&mut image, PARTITION_START + 35, &alternate_directory);
    image
}

fn udf_stream_fuzz_image() -> Vec<u8> {
    let mut image = udf_image_with_streams();
    let file_set_offset = PARTITION_START as usize * BLOCK;
    let mut prevailing = image[file_set_offset..file_set_offset + BLOCK].to_vec();
    prevailing[44..48].copy_from_slice(&1_u32.to_le_bytes());
    prevailing[448..464].fill(0);
    finish_tag(&mut prevailing, 256, 22, 512);
    write_block(&mut image, PARTITION_START + 22, &prevailing);
    long_ad(
        &mut image[file_set_offset..file_set_offset + BLOCK],
        448,
        BLOCK as u32,
        22,
        0,
    );
    finish_tag(
        &mut image[file_set_offset..file_set_offset + BLOCK],
        256,
        0,
        512,
    );
    image
}

fn repair_tag_checksum(descriptor: &mut [u8]) {
    descriptor[4] = 0;
    descriptor[4] = descriptor[..16]
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .fold(0_u8, |sum, (_, byte)| sum.wrapping_add(*byte));
}

#[derive(Debug)]
struct ReadEntry {
    path: String,
    kind: EntryKind,
    data: Vec<u8>,
    target: Option<String>,
    uid: Option<u64>,
    gid: Option<u64>,
    mode: Option<u32>,
    inode: Option<u64>,
    links: Option<u64>,
    modified: Option<libarchive_oxide_core::Timestamp>,
    raw_extended_attributes: Option<Vec<u8>>,
    external_raw_extended_attributes: Option<Vec<u8>>,
    udf_stream_kind: Option<Vec<u8>>,
    udf_stream_owner: Option<Vec<u8>>,
    udf_stream_metadata: Option<bool>,
}

fn collect(bytes: Vec<u8>) -> (FormatId, Vec<ReadEntry>) {
    collect_source(Cursor::new(bytes))
}

fn collect_source<R: Read + Seek>(source: R) -> (FormatId, Vec<ReadEntry>) {
    let mut reader = SeekArchiveReader::new(source).unwrap();
    let format = reader.format();
    let mut entries: Vec<ReadEntry> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => {
                let udf_extension = |key: &[u8]| {
                    metadata
                        .extensions()
                        .iter()
                        .find(|extension| {
                            extension.namespace() == "udf-stream" && extension.key() == key
                        })
                        .map(|extension| extension.value().to_vec())
                };
                let udf_stream_metadata = udf_extension(b"metadata")
                    .and_then(|value| value.first().copied())
                    .map(|value| value != 0);
                entries.push(ReadEntry {
                    path: metadata.path().display_lossy(),
                    kind: metadata.kind(),
                    data: Vec::new(),
                    target: metadata
                        .link_target()
                        .map(libarchive_oxide_core::ArchivePath::display_lossy),
                    uid: metadata.owner().uid,
                    gid: metadata.owner().gid,
                    mode: metadata.mode(),
                    inode: metadata.inode(),
                    links: metadata.links(),
                    modified: metadata.times().modified,
                    raw_extended_attributes: metadata
                        .extensions()
                        .iter()
                        .find(|extension| {
                            extension.namespace() == "udf-extended-attributes"
                                && extension.key() == b"raw"
                        })
                        .map(|extension| extension.value().to_vec()),
                    external_raw_extended_attributes: metadata
                        .extensions()
                        .iter()
                        .find(|extension| {
                            extension.namespace() == "udf-extended-attributes"
                                && extension.key() == b"external-raw"
                        })
                        .map(|extension| extension.value().to_vec()),
                    udf_stream_kind: udf_extension(b"kind"),
                    udf_stream_owner: udf_extension(b"owner"),
                    udf_stream_metadata,
                });
            },
            ReaderEvent::Data(bytes) => entries.last_mut().unwrap().data.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    (format, entries)
}

fn assert_reader_error(image: Vec<u8>, expected: ErrorKind) {
    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), expected);
}

fn assert_reader_error_context(image: Vec<u8>, expected: ErrorKind, context: &str) {
    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    let error = error.archive_error().unwrap();
    assert_eq!(error.kind(), expected);
    assert!(
        error.to_string().contains(context),
        "expected error context {context:?}, got {error}"
    );
}

fn minimum_udf_metadata_budget_with<R>(mut source: impl FnMut() -> R) -> usize
where
    R: Read + Seek,
{
    let mut lower = 0_usize;
    let mut upper = Limits::safe()
        .metadata_bytes()
        .expect("safe limits have a metadata budget");
    SeekArchiveReader::with_limits(source(), Limits::safe().with_metadata_bytes(Some(upper)))
        .expect("the safe metadata budget accepts the fixture");
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match SeekArchiveReader::with_limits(
            source(),
            Limits::safe().with_metadata_bytes(Some(middle)),
        ) {
            Ok(_) => upper = middle,
            Err(error) => {
                assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
                lower = middle + 1;
            },
        }
    }
    upper
}

fn minimum_udf_metadata_budget(image: &[u8]) -> usize {
    minimum_udf_metadata_budget_with(|| Cursor::new(image))
}

fn minimum_padded_udf_metadata_budget(image: &[u8], length: u64) -> usize {
    minimum_udf_metadata_budget_with(|| ZeroPaddedImage::new(image.to_vec(), length))
}

#[test]
fn udf_phase1_reads_fe_efe_inline_nested_unicode_sparse_links_and_metadata() {
    let (format, entries) = collect(udf_image(BuildOptions::default()));
    assert_eq!(format, FormatId::Udf);
    let inline = entries
        .iter()
        .find(|entry| entry.path == "inline.txt")
        .unwrap();
    assert_eq!(inline.data, b"inline");
    assert_eq!((inline.uid, inline.gid), (Some(1000), Some(100)));
    assert_eq!((inline.mode, inline.inode), (Some(0o777), Some(3)));
    assert_eq!(
        inline.modified,
        Some(
            libarchive_oxide_core::Timestamp::new(1_785_242_096, 123_456_000)
                .expect("valid timestamp"),
        )
    );
    assert_eq!(
        inline.raw_extended_attributes.as_deref(),
        Some(extended_attributes(3).as_slice())
    );

    let extent = entries
        .iter()
        .find(|entry| entry.path == "extent.bin")
        .unwrap();
    assert_eq!(extent.data, b"extent payload");
    assert_eq!(extent.links, Some(2));

    let unicode = entries
        .iter()
        .find(|entry| entry.path == "nested/日本.txt")
        .unwrap();
    assert_eq!(unicode.data, "深い内容".as_bytes());

    let sparse = entries
        .iter()
        .find(|entry| entry.path == "multi.bin")
        .unwrap();
    assert_eq!(sparse.data.len(), BLOCK * 2 + 5);
    assert!(sparse.data[..BLOCK].iter().all(|byte| *byte == b'a'));
    assert!(sparse.data[BLOCK..BLOCK * 2].iter().all(|byte| *byte == 0));
    assert_eq!(&sparse.data[BLOCK * 2..], b"world");

    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "long.bin")
            .unwrap()
            .data,
        b"long-ad"
    );
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "chain.bin")
            .unwrap()
            .data,
        b"chain"
    );

    let symlink = entries.iter().find(|entry| entry.path == "link").unwrap();
    assert_eq!(symlink.kind, EntryKind::Symlink);
    assert_eq!(symlink.target.as_deref(), Some("extent.bin"));

    let hardlink = entries
        .iter()
        .find(|entry| entry.path == "hard.bin")
        .unwrap();
    assert_eq!(hardlink.kind, EntryKind::Hardlink);
    assert_eq!(hardlink.target.as_deref(), Some("extent.bin"));
    assert!(
        entries
            .iter()
            .any(|entry| { entry.path == "nested/" && entry.kind == EntryKind::Dir })
    );
}

#[test]
fn udf_reads_continued_file_sets_system_streams_and_named_streams() {
    for revision in [0x0102, 0x0150, 0x0200, 0x0201] {
        let (format, entries) = collect(udf_image_with_continued_file_set(revision));
        assert_eq!(format, FormatId::Udf);
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == "inline.txt" && entry.data == b"inline")
        );
    }
    let (_, entries) = collect(udf_image_with_multiple_file_sets());
    assert!(
        entries
            .iter()
            .any(|entry| entry.path == "inline.txt" && entry.data == b"inline")
    );
    assert!(
        entries.iter().all(|entry| entry.path != "other.txt"),
        "the implicit selection must use prevailing file set zero"
    );

    let (format, entries) = collect(udf_image_with_streams());
    assert_eq!(format, FormatId::Udf);
    let named = entries
        .iter()
        .find(|entry| entry.udf_stream_kind.as_deref() == Some(b"named"))
        .unwrap();
    assert_eq!(named.data, b"named-index");
    assert_eq!(
        named.udf_stream_owner.as_deref(),
        Some("nested/日本.txt".as_bytes())
    );
    assert_eq!(named.udf_stream_metadata, Some(false));
    assert_eq!(
        (named.uid, named.gid, named.mode),
        (Some(2000), Some(200), Some(0o777))
    );
    let owner = entries
        .iter()
        .find(|entry| entry.path == "nested/日本.txt")
        .unwrap();
    assert_ne!(named.modified, owner.modified);
    assert!(
        named
            .path
            .starts_with(".libarchive-oxide-udf-streams/named/o-path-")
    );
    assert!(named.path.ends_with("/s-search%3Aindex"));

    let system = entries
        .iter()
        .find(|entry| entry.udf_stream_kind.as_deref() == Some(b"system"))
        .unwrap();
    assert_eq!(system.data, timestamp());
    assert_eq!(system.udf_stream_owner.as_deref(), Some(b"/".as_slice()));
    assert_eq!(system.udf_stream_metadata, Some(true));
    assert_eq!(
        system.path,
        ".libarchive-oxide-udf-streams/system/s-%2AUDF%20Backup"
    );
    for (_, _, payload) in UDF_NON_SYSTEM_STREAMS {
        let stream = entries
            .iter()
            .find(|entry| {
                entry.udf_stream_kind.as_deref() == Some(b"named") && entry.data == payload
            })
            .unwrap();
        assert!(stream.path.contains("%2AUDF"));
        assert_eq!(stream.data, payload);
        assert_eq!(stream.udf_stream_metadata, Some(false));
    }
}

#[test]
fn udf_rejects_broken_file_set_continuations_and_stream_graphs() {
    let second_file_set = (PARTITION_START as usize + 18) * BLOCK;
    let mut bad_crc = udf_image_with_continued_file_set(0x0201);
    bad_crc[second_file_set + 304] ^= 1;
    assert_reader_error(bad_crc, ErrorKind::Integrity);

    let mut bad_checksum = udf_image_with_continued_file_set(0x0201);
    bad_checksum[second_file_set + 4] ^= 1;
    assert_reader_error(bad_checksum, ErrorKind::Integrity);

    let mut bad_location = udf_image_with_continued_file_set(0x0201);
    finish_tag(
        &mut bad_location[second_file_set..second_file_set + BLOCK],
        256,
        19,
        512,
    );
    assert_reader_error(bad_location, ErrorKind::Integrity);

    let mut conflicting_descriptor_number = udf_image_with_continued_file_set(0x0201);
    conflicting_descriptor_number[second_file_set + 40..second_file_set + 44]
        .copy_from_slice(&1_u32.to_le_bytes());
    conflicting_descriptor_number[second_file_set + 44..second_file_set + 48]
        .copy_from_slice(&0_u32.to_le_bytes());
    finish_tag(
        &mut conflicting_descriptor_number[second_file_set..second_file_set + BLOCK],
        256,
        18,
        512,
    );
    assert_reader_error(conflicting_descriptor_number, ErrorKind::Malformed);

    let file_set = PARTITION_START as usize * BLOCK;
    let mut missing_file_set_zero = udf_image_with_continued_file_set(0x0201);
    missing_file_set_zero[file_set + 40..file_set + 44].copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(
        &mut missing_file_set_zero[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    missing_file_set_zero[second_file_set + 40..second_file_set + 44]
        .copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(
        &mut missing_file_set_zero[second_file_set..second_file_set + BLOCK],
        256,
        18,
        512,
    );
    assert_reader_error(missing_file_set_zero, ErrorKind::Malformed);

    let mut cycle = udf_image_with_continued_file_set(0x0201);
    long_ad(
        &mut cycle[second_file_set..second_file_set + BLOCK],
        448,
        BLOCK as u32,
        0,
        0,
    );
    finish_tag(
        &mut cycle[second_file_set..second_file_set + BLOCK],
        256,
        18,
        512,
    );
    assert_reader_error(cycle, ErrorKind::Malformed);

    let mut out_of_range = udf_image_with_continued_file_set(0x0201);
    long_ad(
        &mut out_of_range[file_set..file_set + BLOCK],
        448,
        BLOCK as u32,
        300,
        0,
    );
    finish_tag(&mut out_of_range[file_set..file_set + BLOCK], 256, 0, 512);
    assert_reader_error(out_of_range, ErrorKind::Malformed);

    let error = SeekArchiveReader::with_limits(
        Cursor::new(udf_image_with_continued_file_set(0x0201)),
        Limits::safe().with_nesting(Some(0)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let system_directory = (PARTITION_START as usize + 20) * BLOCK;
    let mut broken_stream_crc = udf_image_with_streams();
    broken_stream_crc[system_directory + 216] ^= 1;
    assert_reader_error(broken_stream_crc, ErrorKind::Integrity);

    let mut stream_out_of_range = udf_image_with_streams();
    long_ad(
        &mut stream_out_of_range[file_set..file_set + BLOCK],
        464,
        BLOCK as u32,
        300,
        0,
    );
    finish_tag(
        &mut stream_out_of_range[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(stream_out_of_range, ErrorKind::Malformed);

    let mut pre_2_stream = udf_image(BuildOptions {
        revision: 0x0150,
        ..BuildOptions::default()
    });
    long_ad(
        &mut pre_2_stream[file_set..file_set + BLOCK],
        464,
        BLOCK as u32,
        20,
        0,
    );
    finish_tag(&mut pre_2_stream[file_set..file_set + BLOCK], 256, 0, 512);
    assert_reader_error(pre_2_stream, ErrorKind::Malformed);

    let named_stream = (PARTITION_START as usize + 19) * BLOCK;
    let mut wrong_unique_id = udf_image_with_streams();
    wrong_unique_id[named_stream + 200..named_stream + 208].copy_from_slice(&8_u64.to_le_bytes());
    finish_tag(
        &mut wrong_unique_id[named_stream..named_stream + BLOCK],
        266,
        19,
        216 + b"named-index".len(),
    );
    assert_reader_error(wrong_unique_id, ErrorKind::Malformed);

    let named_directory = (PARTITION_START as usize + 18) * BLOCK;
    let mut wrong_directory_unique_id = udf_image_with_streams();
    wrong_directory_unique_id[named_directory + 200..named_directory + 208]
        .copy_from_slice(&8_u64.to_le_bytes());
    let named_directory_length = named_stream_directory().len();
    finish_tag(
        &mut wrong_directory_unique_id[named_directory..named_directory + BLOCK],
        266,
        18,
        216 + named_directory_length,
    );
    assert_reader_error(wrong_directory_unique_id, ErrorKind::Malformed);

    let main_entry = (PARTITION_START as usize + 7) * BLOCK;
    let mut missing_stream_parent_link = udf_image_with_streams();
    missing_stream_parent_link[main_entry + 48..main_entry + 50]
        .copy_from_slice(&1_u16.to_le_bytes());
    finish_tag(
        &mut missing_stream_parent_link[main_entry..main_entry + BLOCK],
        266,
        7,
        216 + "深い内容".len(),
    );
    assert_reader_error(missing_stream_parent_link, ErrorKind::Malformed);

    let system_stream = (PARTITION_START as usize + 21) * BLOCK;
    let mut wrong_system_unique_id = udf_image_with_streams();
    wrong_system_unique_id[system_stream + 200..system_stream + 208]
        .copy_from_slice(&1_u64.to_le_bytes());
    finish_tag(
        &mut wrong_system_unique_id[system_stream..system_stream + BLOCK],
        266,
        21,
        216 + timestamp().len(),
    );
    assert_reader_error(wrong_system_unique_id, ErrorKind::Malformed);

    let mut multiple_stream_links = udf_image_with_streams();
    multiple_stream_links[named_stream + 48..named_stream + 50]
        .copy_from_slice(&2_u16.to_le_bytes());
    finish_tag(
        &mut multiple_stream_links[named_stream..named_stream + BLOCK],
        266,
        19,
        216 + b"named-index".len(),
    );
    assert_reader_error(multiple_stream_links, ErrorKind::Malformed);

    let mut missing_stream_flag = udf_image_with_streams();
    missing_stream_flag[named_stream + 34..named_stream + 36].copy_from_slice(&3_u16.to_le_bytes());
    finish_tag(
        &mut missing_stream_flag[named_stream..named_stream + BLOCK],
        266,
        19,
        216 + b"named-index".len(),
    );
    assert_reader_error(missing_stream_flag, ErrorKind::Malformed);

    let mut stream_cycle = udf_image_with_streams();
    let mut self_referencing_directory = parent_fid(20, 20, 0);
    self_referencing_directory.extend_from_slice(&stream_fid("*UDF Backup", true, 20, 20, 0));
    write_block(
        &mut stream_cycle,
        PARTITION_START + 20,
        &stream_extended_file_entry(20, 13, &self_referencing_directory, 0),
    );
    assert_reader_error(stream_cycle, ErrorKind::Malformed);

    let base_entries = collect(udf_image(BuildOptions::default())).1.len() as u64;
    let error = SeekArchiveReader::with_limits(
        Cursor::new(udf_image_with_streams()),
        Limits::safe().with_entries(Some(base_entries)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let error = SeekArchiveReader::with_limits(
        Cursor::new(udf_image_with_streams()),
        Limits::safe().with_path_bytes(Some(32)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_validates_stream_fid_identity_order_roles_and_object_sizes() {
    let parent = parent_fid(18, 7, 7);
    let named_fid = stream_fid("search:index", false, 18, 19, 7);
    let directory = named_stream_directory();
    let directory_entry = (PARTITION_START as usize + 18) * BLOCK;

    let mut reordered_stream_parent = udf_image_with_streams();
    let mut reordered = Vec::with_capacity(directory.len());
    reordered.extend_from_slice(&directory[parent.len()..parent.len() + named_fid.len()]);
    reordered.extend_from_slice(&directory[..parent.len()]);
    reordered.extend_from_slice(&directory[parent.len() + named_fid.len()..]);
    reordered_stream_parent[directory_entry + 216..directory_entry + 216 + directory.len()]
        .copy_from_slice(&reordered);
    finish_tag(
        &mut reordered_stream_parent[directory_entry..directory_entry + BLOCK],
        266,
        18,
        216 + directory.len(),
    );
    assert_reader_error(reordered_stream_parent, ErrorKind::Malformed);

    let mut reordered_normal_parent = udf_image(BuildOptions::default());
    let root_data = (PARTITION_START as usize + 2) * BLOCK;
    let root_parent = parent_fid(2, 1, 0);
    let first = fid("chain.bin", false, 2, 15);
    let mut reordered = Vec::with_capacity(root_parent.len() + first.len());
    reordered.extend_from_slice(&first);
    reordered.extend_from_slice(&root_parent);
    reordered_normal_parent[root_data..root_data + reordered.len()].copy_from_slice(&reordered);
    assert_reader_error(reordered_normal_parent, ErrorKind::Malformed);

    let mut wrong_parent_extent = udf_image_with_streams();
    wrong_parent_extent[directory_entry + 216 + 20..directory_entry + 216 + 24]
        .copy_from_slice(&1024_u32.to_le_bytes());
    refinish_inline_fid(
        &mut wrong_parent_extent,
        18,
        directory.len(),
        0,
        parent.len(),
    );
    assert_reader_error(wrong_parent_extent, ErrorKind::Malformed);

    let mut wrong_parent_unique_id = udf_image_with_streams();
    wrong_parent_unique_id[directory_entry + 216 + 32..directory_entry + 216 + 36]
        .copy_from_slice(&8_u32.to_le_bytes());
    refinish_inline_fid(
        &mut wrong_parent_unique_id,
        18,
        directory.len(),
        0,
        parent.len(),
    );
    assert_reader_error(wrong_parent_unique_id, ErrorKind::Malformed);

    let stream_offset = parent.len();
    let mut wrong_file_version = udf_image_with_streams();
    wrong_file_version
        [directory_entry + 216 + stream_offset + 16..directory_entry + 216 + stream_offset + 18]
        .copy_from_slice(&2_u16.to_le_bytes());
    refinish_inline_fid(
        &mut wrong_file_version,
        18,
        directory.len(),
        stream_offset,
        named_fid.len(),
    );
    assert_reader_error(wrong_file_version, ErrorKind::Malformed);

    for flags in [1_u16, 2_u16] {
        let mut bad_ad_flags = udf_image_with_streams();
        bad_ad_flags[directory_entry + 216 + stream_offset + 30
            ..directory_entry + 216 + stream_offset + 32]
            .copy_from_slice(&flags.to_le_bytes());
        refinish_inline_fid(
            &mut bad_ad_flags,
            18,
            directory.len(),
            stream_offset,
            named_fid.len(),
        );
        assert_reader_error(bad_ad_flags, ErrorKind::Malformed);
    }

    let mut wrong_stream_fid_unique_id = udf_image_with_streams();
    wrong_stream_fid_unique_id
        [directory_entry + 216 + stream_offset + 32..directory_entry + 216 + stream_offset + 36]
        .copy_from_slice(&8_u32.to_le_bytes());
    refinish_inline_fid(
        &mut wrong_stream_fid_unique_id,
        18,
        directory.len(),
        stream_offset,
        named_fid.len(),
    );
    assert_reader_error(wrong_stream_fid_unique_id, ErrorKind::Malformed);

    let mut wrong_first_fid_unique_id = udf_image(BuildOptions::default());
    let first_start = root_data + root_parent.len();
    wrong_first_fid_unique_id[first_start + 32..first_start + 36]
        .copy_from_slice(&99_u32.to_le_bytes());
    finish_tag(
        &mut wrong_first_fid_unique_id[first_start..first_start + first.len()],
        257,
        2,
        first.len(),
    );
    assert_reader_error(wrong_first_fid_unique_id, ErrorKind::Malformed);

    let first_udf_stream = stream_fid(
        UDF_NON_SYSTEM_STREAMS[0].0,
        false,
        18,
        UDF_NON_SYSTEM_STREAMS[0].1,
        7,
    );
    let first_udf_offset = stream_offset + named_fid.len();
    let mut wrong_udf_metadata_bit = udf_image_with_streams();
    wrong_udf_metadata_bit[directory_entry + 216 + first_udf_offset + 18] = 0x10;
    refinish_inline_fid(
        &mut wrong_udf_metadata_bit,
        18,
        directory.len(),
        first_udf_offset,
        first_udf_stream.len(),
    );
    assert_reader_error(wrong_udf_metadata_bit, ErrorKind::Malformed);

    let system_directory = (PARTITION_START as usize + 20) * BLOCK;
    let system_parent = parent_fid(20, 20, 0);
    let system_fid = stream_fid("*UDF Backup", true, 20, 21, 0);
    let system_directory_length = system_parent.len() + system_fid.len();
    let mut wrong_system_fid_unique_id = udf_image_with_streams();
    wrong_system_fid_unique_id[system_directory + 216 + system_parent.len() + 32
        ..system_directory + 216 + system_parent.len() + 36]
        .copy_from_slice(&1_u32.to_le_bytes());
    refinish_inline_fid(
        &mut wrong_system_fid_unique_id,
        20,
        system_directory_length,
        system_parent.len(),
        system_fid.len(),
    );
    assert_reader_error(wrong_system_fid_unique_id, ErrorKind::Malformed);

    let mut wrong_system_directory_unique_id = udf_image_with_streams();
    wrong_system_directory_unique_id[system_directory + 200..system_directory + 208]
        .copy_from_slice(&1_u64.to_le_bytes());
    finish_tag(
        &mut wrong_system_directory_unique_id[system_directory..system_directory + BLOCK],
        266,
        20,
        216 + system_directory_length,
    );
    assert_reader_error(wrong_system_directory_unique_id, ErrorKind::Malformed);

    let mut flagged_stream_directory = udf_image_with_streams();
    flagged_stream_directory[directory_entry + 34..directory_entry + 36]
        .copy_from_slice(&(3_u16 | (1 << 13)).to_le_bytes());
    finish_tag(
        &mut flagged_stream_directory[directory_entry..directory_entry + BLOCK],
        266,
        18,
        216 + directory.len(),
    );
    assert_reader_error(flagged_stream_directory, ErrorKind::Malformed);

    let main_entry = (PARTITION_START as usize + 7) * BLOCK;
    let mut wrong_aggregate_object_size = udf_image_with_streams();
    wrong_aggregate_object_size[main_entry + 64..main_entry + 72]
        .copy_from_slice(&("深い内容".len() as u64).to_le_bytes());
    finish_tag(
        &mut wrong_aggregate_object_size[main_entry..main_entry + BLOCK],
        266,
        7,
        216 + "深い内容".len(),
    );
    assert_reader_error(wrong_aggregate_object_size, ErrorKind::Malformed);

    let mut wrong_directory_object_size = udf_image_with_streams();
    wrong_directory_object_size[directory_entry + 64..directory_entry + 72]
        .copy_from_slice(&(directory.len() as u64 + 1).to_le_bytes());
    finish_tag(
        &mut wrong_directory_object_size[directory_entry..directory_entry + BLOCK],
        266,
        18,
        216 + directory.len(),
    );
    assert_reader_error(wrong_directory_object_size, ErrorKind::Malformed);

    let named_stream_entry = (PARTITION_START as usize + 19) * BLOCK;
    let mut wrong_named_stream_object_size = udf_image_with_streams();
    wrong_named_stream_object_size[named_stream_entry + 64..named_stream_entry + 72]
        .copy_from_slice(&(b"named-index".len() as u64 + 1).to_le_bytes());
    finish_tag(
        &mut wrong_named_stream_object_size[named_stream_entry..named_stream_entry + BLOCK],
        266,
        19,
        216 + b"named-index".len(),
    );
    assert_reader_error(wrong_named_stream_object_size, ErrorKind::Malformed);
}

#[test]
fn udf_streams_bound_metadata_and_fid_buffers() {
    let baseline = udf_image(BuildOptions::default());
    let streamed = udf_image_with_streams();
    let combined = udf_stream_fuzz_image();
    let baseline_budget = minimum_udf_metadata_budget(&baseline);
    let streamed_budget = minimum_udf_metadata_budget(&streamed);
    let combined_budget = minimum_udf_metadata_budget(&combined);
    assert!(
        combined_budget.saturating_sub(streamed_budget) >= 512,
        "the additional retained FSD allocation must be additive to entry metadata: \
         streamed={streamed_budget}, combined={combined_budget}"
    );
    assert!(
        combined_budget > baseline_budget,
        "continued FSD and stream metadata must be included in the budget"
    );
    let error = SeekArchiveReader::with_limits(
        Cursor::new(&combined),
        Limits::safe().with_metadata_bytes(Some(combined_budget - 1)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let mut maximum_fid = udf_image_with_streams();
    let fid = stream_fid_with_implementation_use("*UDF Backup", 23, 21, 0, 1996);
    assert_eq!(fid.len(), BLOCK);
    replace_system_stream_directory_payload(&mut maximum_fid, &fid);
    SeekArchiveReader::new(Cursor::new(&maximum_fid))
        .expect("a one-logical-block FID is valid with the default budget");
    let error = SeekArchiveReader::with_limits(
        Cursor::new(&maximum_fid),
        Limits::safe().with_in_flight_bytes(Some(BLOCK)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let mut oversized_fid = udf_image_with_streams();
    let fid = stream_fid_with_implementation_use("*UDF Backup", 23, 21, 0, 2000);
    assert!(fid.len() > BLOCK);
    replace_system_stream_directory_payload(&mut oversized_fid, &fid);
    assert_reader_error(oversized_fid, ErrorKind::Malformed);
}

#[test]
fn udf_walks_noncontiguous_multi_extent_directories() {
    let mut image = udf_image(BuildOptions::default());
    let first_lbn = 18_u32;
    let second_lbn = 20_u32;
    let first = (PARTITION_START + first_lbn) as usize * BLOCK;
    let second = (PARTITION_START + second_lbn) as usize * BLOCK;
    image[first..first + BLOCK].fill(0);
    image[second..second + BLOCK].fill(0);
    let parent = parent_fid(first_lbn, 1, 0);
    let entry = fid("inline.txt", false, second_lbn, 3);
    image[first..first + parent.len()].copy_from_slice(&parent);
    image[second..second + entry.len()].copy_from_slice(&entry);

    let mut allocation = Vec::new();
    allocation.extend_from_slice(&short_ad(BLOCK as u32, 0, first_lbn));
    allocation.extend_from_slice(&short_ad(entry.len() as u32, 0, second_lbn));
    write_block(
        &mut image,
        PARTITION_START + 1,
        &file_entry(
            1,
            4,
            0,
            BLOCK as u64 + entry.len() as u64,
            &allocation,
            0,
            1,
        ),
    );

    let (_, entries) = collect(image);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "inline.txt");
    assert_eq!(entries[0].data, b"inline");
}

#[test]
fn udf_preserves_special_modes_and_rejects_unsupported_icb_flags() {
    let inline = (PARTITION_START as usize + 3) * BLOCK;
    let unicode = (PARTITION_START as usize + 7) * BLOCK;
    let mut special = udf_image(BuildOptions::default());
    for (offset, tag, location, used) in [
        (inline, 261, 3, 258),
        (unicode, 266, 7, 216 + "深い内容".len()),
    ] {
        let flags = u16::from_le_bytes([special[offset + 34], special[offset + 35]]);
        special[offset + 34..offset + 36].copy_from_slice(&(flags | 0x01c0).to_le_bytes());
        finish_tag(&mut special[offset..offset + BLOCK], tag, location, used);
    }
    let (_, entries) = collect(special);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .mode,
        Some(0o7777)
    );
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "nested/日本.txt")
            .unwrap()
            .mode,
        Some(0o7777)
    );

    let root = (PARTITION_START as usize + 1) * BLOCK;
    for flag in [0x0800_u16, 0x1000, 0x2000] {
        let mut image = udf_image(BuildOptions::default());
        image[root + 34..root + 36].copy_from_slice(&flag.to_le_bytes());
        finish_tag(&mut image[root..root + BLOCK], 261, 1, 184);
        assert_reader_error(image, ErrorKind::Unsupported);
    }
    let mut reserved = udf_image(BuildOptions::default());
    reserved[root + 34..root + 36].copy_from_slice(&0x4000_u16.to_le_bytes());
    finish_tag(&mut reserved[root..root + BLOCK], 261, 1, 184);
    assert_reader_error(reserved, ErrorKind::Malformed);
}

#[test]
fn udf_accepts_each_phase1_revision_and_prefers_udf_in_an_iso_bridge() {
    for revision in [0x0102, 0x0150, 0x0200, 0x0201] {
        let image = udf_image(BuildOptions {
            revision,
            ..BuildOptions::default()
        });
        assert!(matches!(
            FormatId::probe(&image[..17 * BLOCK + 6]),
            ProbeResult::Match(FormatId::Udf)
        ));
        assert_eq!(collect(image).0, FormatId::Udf);
    }
    let bridge = udf_image(BuildOptions {
        bridge: true,
        ..BuildOptions::default()
    });
    assert!(matches!(
        FormatId::probe(&bridge[..18 * BLOCK + 6]),
        ProbeResult::Match(FormatId::Iso9660)
    ));
    assert_eq!(collect(bridge).0, FormatId::Udf);
}

#[test]
fn udf_builtin_provider_reports_read_only_seek_capability() {
    let ProviderCapability::Available(capabilities) =
        ProviderSet::builtins().format_capability(FormatId::Udf)
    else {
        panic!("the built-in UDF provider must be available");
    };
    assert!(capabilities.can_decode());
    assert!(!capabilities.can_encode());
    assert!(capabilities.requires_seek(libarchive_oxide_core::Direction::Read));
}

#[test]
fn udf_250_and_260_metadata_partitions_read_through_public_providers() {
    for (revision, bitmap) in [(0x0250, false), (0x0260, true)] {
        let options = MetadataBuildOptions {
            revision,
            bitmap,
            ..MetadataBuildOptions::default()
        };
        let image = udf_metadata_image(options);
        let (format, entries) = collect(image.clone());
        assert_eq!(format, FormatId::Udf);
        let entry = entries
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap();
        assert_eq!(entry.data, b"metadata");

        let mut session = ArchiveEngine::new()
            .prepare(Cursor::new(image.clone()))
            .unwrap();
        assert_eq!(session.format(), Some(FormatId::Udf));
        assert!(
            session
                .inspect()
                .unwrap()
                .entries()
                .iter()
                .any(|entry| { entry.metadata().path().as_bytes() == b"metadata.txt" })
        );

        let mut range = RangeArchiveReader::new(MemoryRange::new(image)).unwrap();
        assert_eq!(range.format(), FormatId::Udf);
        while !matches!(range.next_event().unwrap(), ReaderEvent::Done) {}
    }

    let shared = udf_metadata_image(MetadataBuildOptions {
        mirror: MetadataMirror::Shared,
        ..MetadataBuildOptions::default()
    });
    assert_eq!(
        collect(shared)
            .1
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );
}

#[test]
fn udf_metadata_partition_maps_across_allocation_boundaries() {
    let options = MetadataBuildOptions {
        logical_base: 32,
        split: true,
        ..MetadataBuildOptions::default()
    };
    let (_, entries) = collect(udf_metadata_image(options));
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );

    let no_mirror = MetadataBuildOptions {
        mirror: MetadataMirror::None,
        ..options
    };
    let mut continued = udf_metadata_image(no_mirror);
    let mut allocations = Vec::new();
    allocations.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 32));
    allocations.extend_from_slice(&short_ad(BLOCK as u32, 3, 7));
    write_block(
        &mut continued,
        PARTITION_START + 4,
        &metadata_file_entry(4, 250, 64, &allocations),
    );
    let mut allocation_extent = tagged_block(258, 7, 32);
    allocation_extent[20..24].copy_from_slice(&8_u32.to_le_bytes());
    allocation_extent[24..32].copy_from_slice(&short_ad((32 * BLOCK) as u32, 0, 96));
    finish_tag(&mut allocation_extent, 258, 7, 32);
    write_block(&mut continued, PARTITION_START + 7, &allocation_extent);
    assert_eq!(
        collect(continued)
            .1
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );

    let mut sparse = udf_metadata_image(no_mirror);
    let mut sparse_allocations = Vec::new();
    sparse_allocations.extend_from_slice(&short_ad((32 * BLOCK) as u32, 2, 0));
    sparse_allocations.extend_from_slice(&short_ad((32 * BLOCK) as u32, 0, 96));
    let mut sparse_entry = metadata_file_entry(4, 250, 64, &sparse_allocations);
    sparse_entry[64..72].copy_from_slice(&32_u64.to_le_bytes());
    finish_tag(&mut sparse_entry, 261, 4, 192);
    write_block(&mut sparse, PARTITION_START + 4, &sparse_entry);
    assert_eq!(
        collect(sparse)
            .1
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );
}

#[test]
fn udf_metadata_partition_uses_duplicate_mirror_only_after_primary_integrity_failure() {
    let options = MetadataBuildOptions::default();
    let mut recoverable = udf_metadata_image(options);
    let primary_fsd =
        metadata_physical_block(options, false, options.logical_base) as usize * BLOCK;
    recoverable[primary_fsd + 4] ^= 1;
    assert_eq!(
        collect(recoverable)
            .1
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );

    let no_mirror = MetadataBuildOptions {
        mirror: MetadataMirror::None,
        ..options
    };
    let mut broken = udf_metadata_image(no_mirror);
    let primary_fsd =
        metadata_physical_block(no_mirror, false, no_mirror.logical_base) as usize * BLOCK;
    broken[primary_fsd + 4] ^= 1;
    assert_reader_error(broken, ErrorKind::Integrity);

    let mut unsupported = udf_metadata_image(options);
    let main_icb = (PARTITION_START + 4) as usize * BLOCK;
    unsupported[main_icb + 20..main_icb + 22].copy_from_slice(&5_u16.to_le_bytes());
    finish_tag(&mut unsupported[main_icb..main_icb + BLOCK], 261, 4, 184);
    assert_reader_error(unsupported, ErrorKind::Unsupported);
}

#[test]
fn udf_metadata_partition_rejects_missing_and_wrong_auxiliary_file_types() {
    let no_mirror = MetadataBuildOptions {
        mirror: MetadataMirror::None,
        ..MetadataBuildOptions::default()
    };
    let mut missing = udf_metadata_image(no_mirror);
    mutate_metadata_maps(&mut missing, |map| {
        map[40..44].copy_from_slice(&200_u32.to_le_bytes());
    });
    assert_reader_error(missing, ErrorKind::Malformed);

    let mut wrong_type = udf_metadata_image(no_mirror);
    let entry = (PARTITION_START + 4) as usize * BLOCK;
    wrong_type[entry + 27] = 5;
    finish_tag(&mut wrong_type[entry..entry + BLOCK], 261, 4, 184);
    assert_reader_error(wrong_type, ErrorKind::Malformed);

    let with_bitmap = MetadataBuildOptions {
        bitmap: true,
        ..MetadataBuildOptions::default()
    };
    let mut wrong_bitmap = udf_metadata_image(with_bitmap);
    let bitmap = (PARTITION_START + 6) as usize * BLOCK;
    wrong_bitmap[bitmap + 27] = 5;
    finish_tag(&mut wrong_bitmap[bitmap..bitmap + BLOCK], 261, 6, 176 + 28);
    assert_reader_error(wrong_bitmap, ErrorKind::Malformed);
}

#[test]
fn udf_metadata_partition_rejects_cycles_overlaps_and_map_constraints() {
    let split = MetadataBuildOptions {
        mirror: MetadataMirror::None,
        logical_base: 32,
        split: true,
        ..MetadataBuildOptions::default()
    };
    let mut overlap = udf_metadata_image(split);
    let entry = (PARTITION_START + 4) as usize * BLOCK;
    overlap[entry + 188..entry + 192].copy_from_slice(&32_u32.to_le_bytes());
    finish_tag(&mut overlap[entry..entry + BLOCK], 261, 4, 192);
    assert_reader_error(overlap, ErrorKind::Malformed);

    let no_mirror = MetadataBuildOptions {
        mirror: MetadataMirror::None,
        ..MetadataBuildOptions::default()
    };
    let mut cycle = udf_metadata_image(no_mirror);
    write_block(
        &mut cycle,
        PARTITION_START + 4,
        &metadata_file_entry(4, 250, 32, &short_ad(BLOCK as u32, 3, 7)),
    );
    let mut allocation_extent = tagged_block(258, 7, 32);
    allocation_extent[20..24].copy_from_slice(&8_u32.to_le_bytes());
    allocation_extent[24..32].copy_from_slice(&short_ad(BLOCK as u32, 3, 7));
    finish_tag(&mut allocation_extent, 258, 7, 32);
    write_block(&mut cycle, PARTITION_START + 7, &allocation_extent);
    assert_reader_error(cycle, ErrorKind::Malformed);

    for update in [(52_usize, 31_u32), (56_usize, 0_u32)] {
        let mut invalid = udf_metadata_image(no_mirror);
        mutate_metadata_maps(&mut invalid, |map| {
            if update.0 == 52 {
                map[52..56].copy_from_slice(&update.1.to_le_bytes());
            } else {
                map[56..58].copy_from_slice(&(update.1 as u16).to_le_bytes());
            }
        });
        assert_reader_error(invalid, ErrorKind::Malformed);
    }

    for offset in [2_usize, 4, 28, 59] {
        let mut invalid = udf_metadata_image(no_mirror);
        mutate_metadata_maps(&mut invalid, |map| {
            map[offset] ^= 1;
        });
        assert_reader_error(invalid, ErrorKind::Malformed);
    }

    let mut ignored_flag_bits = udf_metadata_image(no_mirror);
    mutate_metadata_maps(&mut ignored_flag_bits, |map| {
        map[58] |= 0xfe;
    });
    assert_eq!(collect(ignored_flag_bits).0, FormatId::Udf);
}

#[test]
fn udf_metadata_partition_revision_and_resource_limits_are_typed() {
    let unsupported = MetadataBuildOptions {
        revision: 0x0201,
        mirror: MetadataMirror::None,
        ..MetadataBuildOptions::default()
    };
    assert_reader_error(udf_metadata_image(unsupported), ErrorKind::Unsupported);

    let image = udf_metadata_image(MetadataBuildOptions {
        logical_base: 32,
        split: true,
        ..MetadataBuildOptions::default()
    });
    let minimum = minimum_udf_metadata_budget(&image);
    let error = SeekArchiveReader::with_limits(
        Cursor::new(image),
        Limits::safe().with_metadata_bytes(Some(minimum - 1)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_sparable_partition_revisions_read_highest_sequence_through_public_paths() {
    for revision in [0x0150, 0x0200, 0x0201, 0x0250, 0x0260] {
        let image = udf_sparable_image(SparableBuildOptions {
            revision,
            ..SparableBuildOptions::default()
        });
        let (format, entries) = collect(image.clone());
        assert_eq!(format, FormatId::Udf);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.path == "inline.txt")
                .unwrap()
                .data,
            b"spared"
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.path == "chain.bin")
                .unwrap()
                .data,
            b"chain"
        );

        let mut session = ArchiveEngine::new()
            .prepare(Cursor::new(image.clone()))
            .unwrap();
        assert_eq!(session.format(), Some(FormatId::Udf));
        assert!(
            session
                .inspect()
                .unwrap()
                .entries()
                .iter()
                .any(|entry| entry.metadata().path().as_bytes() == b"inline.txt")
        );

        let mut range = RangeArchiveReader::new(MemoryRange::new(image)).unwrap();
        assert_eq!(range.format(), FormatId::Udf);
        while !matches!(range.next_event().unwrap(), ReaderEvent::Done) {}
    }
}

#[test]
fn udf_sparable_partition_accepts_the_normative_32_block_packet_length() {
    let image = udf_sparable_image(SparableBuildOptions {
        packet_blocks: 32,
        partition_start: 320,
        ..SparableBuildOptions::default()
    });
    let (format, entries) = collect(image);
    assert_eq!(format, FormatId::Udf);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .data,
        b"spared"
    );
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "chain.bin")
            .unwrap()
            .data,
        b"chain"
    );
}

#[test]
fn udf_reads_independent_mkudffs_sparable_fixture() {
    let image = MKUDFFS_SPARABLE_201.to_vec();
    let (format, entries) = collect(image.clone());
    assert_eq!(format, FormatId::Udf);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].path,
        ".libarchive-oxide-udf-streams/system/s-%2AUDF%20Non-Allocatable%20Space"
    );
    assert_eq!(entries[0].kind, EntryKind::File);
    assert!(entries[0].data.is_empty());

    let mut range = RangeArchiveReader::new(MemoryRange::new(image)).unwrap();
    assert_eq!(range.format(), FormatId::Udf);
    while !matches!(range.next_event().unwrap(), ReaderEvent::Done) {}
}

#[test]
fn udf_metadata_partition_layers_over_sparable_packet_translation() {
    for revision in [0x0250, 0x0260] {
        let image = udf_metadata_over_sparable_image(revision);
        let (format, entries) = collect(image.clone());
        assert_eq!(format, FormatId::Udf);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.path == "metadata.txt")
                .unwrap()
                .data,
            b"spared-metadata"
        );

        let mut session = ArchiveEngine::new()
            .prepare(Cursor::new(image.clone()))
            .unwrap();
        assert_eq!(session.format(), Some(FormatId::Udf));
        assert!(
            session
                .inspect()
                .unwrap()
                .entries()
                .iter()
                .any(|entry| entry.metadata().path().as_bytes() == b"metadata.txt")
        );

        let mut range = RangeArchiveReader::new(MemoryRange::new(image)).unwrap();
        assert_eq!(range.format(), FormatId::Udf);
        while !matches!(range.next_event().unwrap(), ReaderEvent::Done) {}
    }

    let mut stale_fallback = udf_metadata_over_sparable_image(0x0260);
    stale_fallback[SPARABLE_TABLE_LOCATIONS[1] as usize * BLOCK + 4] ^= 0x20;
    assert_eq!(
        collect(stale_fallback)
            .1
            .iter()
            .find(|entry| entry.path == "metadata.txt")
            .unwrap()
            .data,
        b"metadata"
    );
}

#[test]
fn udf_sparable_partition_uses_redundancy_and_rejects_equal_sequence_conflicts() {
    let mut single_copy = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut single_copy, |map| {
        map[42] = 1;
        map[52..64].fill(0);
    });
    assert_eq!(
        collect(single_copy)
            .1
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .data,
        b"inline"
    );

    let mut corrupt_stale = udf_sparable_image(SparableBuildOptions::default());
    corrupt_stale[SPARABLE_TABLE_LOCATIONS[0] as usize * BLOCK + 4] ^= 0x80;
    assert_eq!(
        collect(corrupt_stale)
            .1
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .data,
        b"spared"
    );

    let mut corrupt_latest = udf_sparable_image(SparableBuildOptions::default());
    corrupt_latest[SPARABLE_TABLE_LOCATIONS[1] as usize * BLOCK + 4] ^= 0x80;
    assert_eq!(
        collect(corrupt_latest)
            .1
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .data,
        b"inline"
    );

    let mut conflict = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparing_table(&mut conflict, SPARABLE_TABLE_LOCATIONS[0], |table| {
        table[52..56].copy_from_slice(&2_u32.to_le_bytes());
    });
    assert_reader_error_context(conflict, ErrorKind::Integrity, "same sequence number");

    let mut no_valid_copy = udf_sparable_image(SparableBuildOptions::default());
    for location in SPARABLE_TABLE_LOCATIONS {
        no_valid_copy[location as usize * BLOCK + 4] ^= 0x40;
    }
    assert_reader_error(no_valid_copy, ErrorKind::Integrity);
}

#[test]
fn udf_sparable_partition_map_invariants_are_enforced() {
    assert_reader_error(
        udf_sparable_image(SparableBuildOptions {
            revision: 0x0102,
            ..SparableBuildOptions::default()
        }),
        ErrorKind::Unsupported,
    );

    for update in [(2_usize, 1_u8), (42, 0), (43, 1), (56, 1)] {
        let mut image = udf_sparable_image(SparableBuildOptions::default());
        mutate_sparable_maps(&mut image, |map| map[update.0] = update.1);
        assert_reader_error(image, ErrorKind::Malformed);
    }

    let mut wrong_length = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut wrong_length, |map| map[1] = 63);
    assert_reader_error(wrong_length, ErrorKind::Malformed);

    let mut wrong_identifier = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut wrong_identifier, |map| map[27] ^= 1);
    assert_reader_error_context(
        wrong_identifier,
        ErrorKind::Unsupported,
        "Type 2 partition maps",
    );

    for mutation in [
        |map: &mut [u8]| map[4] = 1,
        |map: &mut [u8]| map[28..30].copy_from_slice(&0x0201_u16.to_le_bytes()),
    ] {
        let mut image = udf_sparable_image(SparableBuildOptions::default());
        mutate_sparable_maps(&mut image, mutation);
        assert_reader_error(image, ErrorKind::Malformed);
    }

    let mut non_power_of_two = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut non_power_of_two, |map| {
        map[40..42].copy_from_slice(&3_u16.to_le_bytes());
    });
    assert_reader_error(non_power_of_two, ErrorKind::Malformed);

    let (mut non_profile_packet, length, _) =
        udf_available_sparable_image(16, &[SPARABLE_TABLE_LOCATIONS[0]], 4);
    mutate_sparable_maps(&mut non_profile_packet, |map| {
        map[40..42].copy_from_slice(&8_u16.to_le_bytes());
    });
    let error =
        SeekArchiveReader::new(ZeroPaddedImage::new(non_profile_packet, length)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut short_table = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut short_table, |map| {
        map[44..48].copy_from_slice(&55_u32.to_le_bytes());
    });
    assert_reader_error(short_table, ErrorKind::Malformed);

    let mut duplicate_table = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut duplicate_table, |map| {
        map[52..56].copy_from_slice(&SPARABLE_TABLE_LOCATIONS[0].to_le_bytes());
    });
    assert_reader_error(duplicate_table, ErrorKind::Malformed);

    let mut outside_table = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut outside_table, |map| {
        map[52..56].copy_from_slice(&(BLOCKS as u32).to_le_bytes());
    });
    assert_reader_error(outside_table, ErrorKind::Malformed);

    let mut overlapping_tables = udf_sparable_image(SparableBuildOptions {
        table_size: (2 * BLOCK) as u32,
        ..SparableBuildOptions::default()
    });
    mutate_sparable_maps(&mut overlapping_tables, |map| {
        map[52..56].copy_from_slice(&(SPARABLE_TABLE_LOCATIONS[0] + 1).to_le_bytes());
    });
    assert_reader_error(overlapping_tables, ErrorKind::Malformed);

    let mut same_packet_tables = udf_sparable_image(SparableBuildOptions::default());
    let second = same_packet_tables[SPARABLE_TABLE_LOCATIONS[1] as usize * BLOCK
        ..(SPARABLE_TABLE_LOCATIONS[1] as usize + 1) * BLOCK]
        .to_vec();
    write_block(
        &mut same_packet_tables,
        SPARABLE_TABLE_LOCATIONS[0] + 1,
        &second,
    );
    mutate_sparing_table(
        &mut same_packet_tables,
        SPARABLE_TABLE_LOCATIONS[0] + 1,
        |_| {},
    );
    mutate_sparable_maps(&mut same_packet_tables, |map| {
        map[52..56].copy_from_slice(&(SPARABLE_TABLE_LOCATIONS[0] + 1).to_le_bytes());
    });
    assert_reader_error_context(
        same_packet_tables,
        ErrorKind::Malformed,
        "same sparing packet",
    );

    let mut different_volume = udf_sparable_image(SparableBuildOptions::default());
    mutate_sparable_maps(&mut different_volume, |map| {
        map[36..38].copy_from_slice(&2_u16.to_le_bytes());
    });
    assert_reader_error(different_volume, ErrorKind::Malformed);

    let mut unaligned_start = udf_sparable_image(SparableBuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let offset = (start + 1) as usize * BLOCK;
        let partition = &mut unaligned_start[offset..offset + BLOCK];
        partition[188..192].copy_from_slice(&(SPARABLE_PARTITION_START + 1).to_le_bytes());
        finish_tag(partition, 5, start + 1, 512);
    }
    assert_reader_error(unaligned_start, ErrorKind::Malformed);

    for (access_type, blocks) in [(1_u32, 288_u32), (3, 287)] {
        let mut image = udf_sparable_image(SparableBuildOptions::default());
        for start in [MAIN_VDS, RESERVE_VDS] {
            let offset = (start + 1) as usize * BLOCK;
            let partition = &mut image[offset..offset + BLOCK];
            partition[184..188].copy_from_slice(&access_type.to_le_bytes());
            partition[192..196].copy_from_slice(&blocks.to_le_bytes());
            finish_tag(partition, 5, start + 1, 512);
        }
        assert_reader_error(image, ErrorKind::Malformed);
    }
}

#[test]
fn udf_sparing_table_rejects_bad_packets_ranges_and_reserved_fields() {
    let mutations: [fn(&mut [u8]); 7] = [
        |table| table[50] = 1,
        |table| table[56..60].copy_from_slice(&1_u32.to_le_bytes()),
        |table| table[56..60].copy_from_slice(&288_u32.to_le_bytes()),
        |table| table[56..60].copy_from_slice(&0xffff_fff1_u32.to_le_bytes()),
        |table| table[60..64].copy_from_slice(&695_u32.to_le_bytes()),
        |table| {
            let first = table[60..64].to_vec();
            table[68..72].copy_from_slice(&first);
        },
        |table| table[60..64].copy_from_slice(&SPARABLE_TABLE_LOCATIONS[0].to_le_bytes()),
    ];
    for mutation in mutations {
        let mut image = udf_sparable_image(SparableBuildOptions::default());
        for location in SPARABLE_TABLE_LOCATIONS {
            mutate_sparing_table(&mut image, location, mutation);
        }
        assert_reader_error(image, ErrorKind::Malformed);
    }

    let mut wrong_tag = udf_sparable_image(SparableBuildOptions::default());
    for location in SPARABLE_TABLE_LOCATIONS {
        let start = location as usize * BLOCK;
        wrong_tag[start..start + 2].copy_from_slice(&1_u16.to_le_bytes());
        repair_tag_checksum(&mut wrong_tag[start..start + BLOCK]);
    }
    assert_reader_error(wrong_tag, ErrorKind::Malformed);

    let mut wrong_entity = udf_sparable_image(SparableBuildOptions::default());
    for location in SPARABLE_TABLE_LOCATIONS {
        mutate_sparing_table(&mut wrong_entity, location, |table| table[16] = 1);
    }
    assert_reader_error(wrong_entity, ErrorKind::Malformed);

    let mut bad_body_crc = udf_sparable_image(SparableBuildOptions::default());
    for location in SPARABLE_TABLE_LOCATIONS {
        bad_body_crc[location as usize * BLOCK + 52] ^= 1;
    }
    assert_reader_error(bad_body_crc, ErrorKind::Integrity);
}

#[test]
fn udf_sparing_table_buffer_is_bounded_by_resource_limits() {
    let image = udf_sparable_image(SparableBuildOptions {
        table_size: (2 * BLOCK) as u32,
        ..SparableBuildOptions::default()
    });
    assert_eq!(
        collect(image.clone())
            .1
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .data,
        b"spared"
    );
    let error = SeekArchiveReader::with_limits(
        Cursor::new(image),
        Limits::safe().with_in_flight_bytes(Some(BLOCK)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_sparing_table_accepts_capped_large_descriptor_crc_and_rejects_short_caps() {
    const ENTRY_COUNT: u16 = 8192;
    let (image, length, used) =
        udf_available_sparable_image(16, &[SPARABLE_TABLE_LOCATIONS[0]], ENTRY_COUNT);
    assert!(used - 16 > usize::from(u16::MAX));
    let (format, entries) = collect_source(ZeroPaddedImage::new(image.clone(), length));
    assert_eq!(format, FormatId::Udf);
    assert!(entries.iter().any(|entry| entry.path == "inline.txt"));

    let mut short_crc = image;
    let start = SPARABLE_TABLE_LOCATIONS[0] as usize * BLOCK;
    let crc_length = usize::from(u16::MAX - 1);
    let crc = crc16(&short_crc[start + 16..start + 16 + crc_length]);
    short_crc[start + 8..start + 10].copy_from_slice(&crc.to_le_bytes());
    short_crc[start + 10..start + 12].copy_from_slice(&(crc_length as u16).to_le_bytes());
    repair_tag_checksum(&mut short_crc[start..start + BLOCK]);
    let error = SeekArchiveReader::new(ZeroPaddedImage::new(short_crc, length)).unwrap_err();
    let error = error.archive_error().unwrap();
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[test]
fn udf_sparing_table_copy_metadata_is_charged_cumulatively() {
    const ENTRY_COUNT: u16 = 2041;
    let (single, single_length, _) =
        udf_available_sparable_image(16, &[SPARABLE_TABLE_LOCATIONS[0]], ENTRY_COUNT);
    let single_minimum = minimum_padded_udf_metadata_budget(&single, single_length);
    assert!(single_minimum > 0);
    let mut reader = SeekArchiveReader::with_limits(
        ZeroPaddedImage::new(single.clone(), single_length),
        Limits::safe().with_metadata_bytes(Some(single_minimum)),
    )
    .unwrap();
    while !matches!(reader.next_event().unwrap(), ReaderEvent::Done) {}
    let error = SeekArchiveReader::with_limits(
        ZeroPaddedImage::new(single, single_length),
        Limits::safe().with_metadata_bytes(Some(single_minimum - 1)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let (redundant, redundant_length, _) =
        udf_available_sparable_image(16, &SPARABLE_TABLE_LOCATIONS, ENTRY_COUNT);
    let error = SeekArchiveReader::with_limits(
        ZeroPaddedImage::new(redundant.clone(), redundant_length),
        Limits::safe().with_metadata_bytes(Some(single_minimum)),
    )
    .unwrap_err();
    let error = error.archive_error().unwrap();
    assert_eq!(error.kind(), ErrorKind::Limit);
    assert!(error.to_string().contains("sparing-table copies"));

    let redundant_minimum = minimum_padded_udf_metadata_budget(&redundant, redundant_length);
    assert!(redundant_minimum > single_minimum);
    let mut reader = SeekArchiveReader::with_limits(
        ZeroPaddedImage::new(redundant.clone(), redundant_length),
        Limits::safe().with_metadata_bytes(Some(redundant_minimum)),
    )
    .unwrap();
    while !matches!(reader.next_event().unwrap(), ReaderEvent::Done) {}
    let error = SeekArchiveReader::with_limits(
        ZeroPaddedImage::new(redundant, redundant_length),
        Limits::safe().with_metadata_bytes(Some(redundant_minimum - 1)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_virtual_partition_vat_revisions_read_through_public_seek_engine_and_range_paths() {
    for revision in [0x0150, 0x0200, 0x0201, 0x0250, 0x0260] {
        let image = udf_virtual_image(VirtualBuildOptions {
            revision,
            ..VirtualBuildOptions::default()
        });
        let (format, entries) = collect(image.clone());
        assert_eq!(format, FormatId::Udf);
        let entry = entries
            .iter()
            .find(|entry| entry.path == "virtual.txt")
            .unwrap();
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.data, b"virtual-vat");

        let mut session = ArchiveEngine::new()
            .prepare(Cursor::new(image.clone()))
            .unwrap();
        assert_eq!(session.format(), Some(FormatId::Udf));
        assert!(
            session
                .inspect()
                .unwrap()
                .entries()
                .iter()
                .any(|entry| entry.metadata().path().as_bytes() == b"virtual.txt")
        );

        let mut range = RangeArchiveReader::new(MemoryRange::new(image)).unwrap();
        assert_eq!(range.format(), FormatId::Udf);
        while !matches!(range.next_event().unwrap(), ReaderEvent::Done) {}
    }
}

#[test]
fn udf_virtual_partition_reads_direct_and_continued_vat_allocations_and_bounded_history() {
    for options in [
        VirtualBuildOptions {
            storage: VatStorage::External(VatAllocation::Short),
            ..VirtualBuildOptions::default()
        },
        VirtualBuildOptions {
            storage: VatStorage::External(VatAllocation::Long),
            ..VirtualBuildOptions::default()
        },
        VirtualBuildOptions {
            storage: VatStorage::External(VatAllocation::Continuation),
            ..VirtualBuildOptions::default()
        },
        VirtualBuildOptions {
            storage: VatStorage::External(VatAllocation::ChainedContinuation),
            ..VirtualBuildOptions::default()
        },
        VirtualBuildOptions {
            history: VatHistory::Previous,
            ..VirtualBuildOptions::default()
        },
    ] {
        let (_, entries) = collect(udf_virtual_image(options));
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.path == "virtual.txt")
                .unwrap()
                .data,
            b"virtual-vat"
        );
    }
}

#[test]
fn udf_virtual_partition_rejects_missing_truncated_cyclic_and_overlapping_vats() {
    let mut missing = udf_virtual_image(VirtualBuildOptions::default());
    let latest = (PARTITION_START + VAT_LATEST_ICB) as usize * BLOCK;
    missing[latest..latest + BLOCK].fill(0);
    assert_reader_error(missing, ErrorKind::Malformed);

    let mut wrong_type = udf_virtual_image(VirtualBuildOptions::default());
    wrong_type[latest + 27] = 5;
    finish_tag(
        &mut wrong_type[latest..latest + BLOCK],
        261,
        VAT_LATEST_ICB,
        176 + vat_body(0x0260, &vat_entries(VatStorage::Inline), None).len(),
    );
    assert_reader_error(wrong_type, ErrorKind::Malformed);

    let mut truncated = udf_virtual_image(VirtualBuildOptions::default());
    write_block(
        &mut truncated,
        PARTITION_START + VAT_LATEST_ICB,
        &file_entry(VAT_LATEST_ICB, 248, 3, 100, &[0_u8; 100], 0, 0),
    );
    assert_reader_error(truncated, ErrorKind::Malformed);

    let mut malformed_150 = udf_virtual_image(VirtualBuildOptions {
        revision: 0x0150,
        ..VirtualBuildOptions::default()
    });
    mutate_inline_vat(&mut malformed_150, |body| body[12] = 1);
    assert_reader_error(malformed_150, ErrorKind::Malformed);

    let mut malformed_200 = udf_virtual_image(VirtualBuildOptions {
        revision: 0x0200,
        ..VirtualBuildOptions::default()
    });
    mutate_inline_vat(&mut malformed_200, |body| body[150] = 1);
    assert_reader_error(malformed_200, ErrorKind::Malformed);

    let mut cycle = udf_virtual_image(VirtualBuildOptions::default());
    mutate_inline_vat(&mut cycle, |body| {
        body[132..136].copy_from_slice(&VAT_LATEST_ICB.to_le_bytes());
    });
    assert_reader_error_context(cycle, ErrorKind::Malformed, "cycle in UDF VAT history");

    let mut duplicate_mapping = udf_virtual_image(VirtualBuildOptions::default());
    mutate_inline_vat(&mut duplicate_mapping, |body| {
        body[156..160].copy_from_slice(&VIRTUAL_FILE_SET_PHYSICAL.to_le_bytes());
    });
    assert_reader_error(duplicate_mapping, ErrorKind::Malformed);

    let mut vat_overlap = udf_virtual_image(VirtualBuildOptions::default());
    mutate_inline_vat(&mut vat_overlap, |body| {
        body[152..156].copy_from_slice(&VAT_LATEST_ICB.to_le_bytes());
    });
    assert_reader_error(vat_overlap, ErrorKind::Malformed);

    let mut outside_physical = udf_virtual_image(VirtualBuildOptions::default());
    mutate_inline_vat(&mut outside_physical, |body| {
        body[152..156].copy_from_slice(&300_u32.to_le_bytes());
    });
    assert_reader_error(outside_physical, ErrorKind::Malformed);

    let mut unallocated_file_set = udf_virtual_image(VirtualBuildOptions::default());
    mutate_inline_vat(&mut unallocated_file_set, |body| {
        body[152..156].copy_from_slice(&u32::MAX.to_le_bytes());
    });
    assert_reader_error(unallocated_file_set, ErrorKind::Malformed);

    let mut allocation_overlap = udf_virtual_image(VirtualBuildOptions {
        storage: VatStorage::External(VatAllocation::Short),
        ..VirtualBuildOptions::default()
    });
    allocation_overlap[latest + 188..latest + 192]
        .copy_from_slice(&VAT_FIRST_EXTENT_PHYSICAL.to_le_bytes());
    finish_tag(
        &mut allocation_overlap[latest..latest + BLOCK],
        261,
        VAT_LATEST_ICB,
        192,
    );
    assert_reader_error(allocation_overlap, ErrorKind::Malformed);

    let mut truncated_allocations = udf_virtual_image(VirtualBuildOptions {
        storage: VatStorage::External(VatAllocation::Short),
        ..VirtualBuildOptions::default()
    });
    truncated_allocations[latest + 172..latest + 176].copy_from_slice(&12_u32.to_le_bytes());
    finish_tag(
        &mut truncated_allocations[latest..latest + BLOCK],
        261,
        VAT_LATEST_ICB,
        188,
    );
    assert_reader_error(truncated_allocations, ErrorKind::Malformed);

    let mut allocation_cycle = udf_virtual_image(VirtualBuildOptions {
        storage: VatStorage::External(VatAllocation::Continuation),
        ..VirtualBuildOptions::default()
    });
    let allocation_extent = (PARTITION_START + VAT_ALLOCATION_EXTENT_PHYSICAL) as usize * BLOCK;
    allocation_cycle[allocation_extent + 20..allocation_extent + 24]
        .copy_from_slice(&8_u32.to_le_bytes());
    allocation_cycle[allocation_extent + 24..allocation_extent + 32].copy_from_slice(&short_ad(
        40,
        3,
        VAT_ALLOCATION_EXTENT_PHYSICAL,
    ));
    allocation_cycle[allocation_extent + 32..allocation_extent + 40].fill(0);
    finish_tag(
        &mut allocation_cycle[allocation_extent..allocation_extent + BLOCK],
        258,
        VAT_ALLOCATION_EXTENT_PHYSICAL,
        32,
    );
    assert_reader_error_context(
        allocation_cycle,
        ErrorKind::Malformed,
        "cycle in UDF VAT allocations",
    );

    let mut wrong_back_pointer = udf_virtual_image(VirtualBuildOptions {
        storage: VatStorage::External(VatAllocation::Continuation),
        ..VirtualBuildOptions::default()
    });
    wrong_back_pointer[allocation_extent + 16..allocation_extent + 20]
        .copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(
        &mut wrong_back_pointer[allocation_extent..allocation_extent + BLOCK],
        258,
        VAT_ALLOCATION_EXTENT_PHYSICAL,
        40,
    );
    assert_reader_error_context(wrong_back_pointer, ErrorKind::Malformed, "back pointer");
}

#[test]
fn udf_virtual_partition_rejects_invalid_maps_and_nonphysical_file_allocations() {
    let mut reserved = udf_virtual_image(VirtualBuildOptions::default());
    mutate_virtual_maps(&mut reserved, |map| map[40] = 1);
    assert_reader_error(reserved, ErrorKind::Malformed);

    let mut wrong_sequence = udf_virtual_image(VirtualBuildOptions::default());
    mutate_virtual_maps(&mut wrong_sequence, |map| {
        map[36..38].copy_from_slice(&2_u16.to_le_bytes());
    });
    assert_reader_error(wrong_sequence, ErrorKind::Malformed);

    let mut missing_physical = udf_virtual_image(VirtualBuildOptions::default());
    mutate_virtual_maps(&mut missing_physical, |map| {
        map[38..40].copy_from_slice(&1_u16.to_le_bytes());
    });
    assert_reader_error(missing_physical, ErrorKind::Malformed);

    let mut duplicate_map = udf_virtual_image(VirtualBuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical_offset = (start + 2) as usize * BLOCK;
        let logical = &mut duplicate_map[logical_offset..logical_offset + BLOCK];
        let map = logical[446..510].to_vec();
        logical[510..574].copy_from_slice(&map);
        logical[264..268].copy_from_slice(&134_u32.to_le_bytes());
        logical[268..272].copy_from_slice(&3_u32.to_le_bytes());
        finish_tag(logical, 6, start + 2, 574);
    }
    assert_reader_error(duplicate_map, ErrorKind::Malformed);

    let mut wrong_access = udf_virtual_image(VirtualBuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let partition = (start + 1) as usize * BLOCK;
        wrong_access[partition + 184..partition + 188].copy_from_slice(&1_u32.to_le_bytes());
        finish_tag(
            &mut wrong_access[partition..partition + BLOCK],
            5,
            start + 1,
            512,
        );
    }
    assert_reader_error(wrong_access, ErrorKind::Malformed);

    assert_reader_error(
        udf_virtual_image(VirtualBuildOptions {
            revision: 0x0102,
            ..VirtualBuildOptions::default()
        }),
        ErrorKind::Unsupported,
    );

    let mut virtual_data_reference = udf_virtual_image(VirtualBuildOptions::default());
    let root = (PARTITION_START + VIRTUAL_ROOT_PHYSICAL) as usize * BLOCK;
    virtual_data_reference[root + 184..root + 186].copy_from_slice(&1_u16.to_le_bytes());
    finish_tag(&mut virtual_data_reference[root..root + BLOCK], 261, 1, 192);
    assert_reader_error(virtual_data_reference, ErrorKind::Malformed);

    let mut short_data_reference = udf_virtual_image(VirtualBuildOptions::default());
    short_data_reference[root + 34..root + 36].copy_from_slice(&0_u16.to_le_bytes());
    short_data_reference[root + 172..root + 176].copy_from_slice(&8_u32.to_le_bytes());
    short_data_reference[root + 176..root + 184].copy_from_slice(&short_ad(
        BLOCK as u32,
        0,
        VIRTUAL_DIRECTORY_PHYSICAL,
    ));
    finish_tag(&mut short_data_reference[root..root + BLOCK], 261, 1, 184);
    assert_reader_error_context(
        short_data_reference,
        ErrorKind::Malformed,
        "must use long or immediate allocation descriptors",
    );
}

#[test]
fn udf_virtual_partition_vat_metadata_budget_is_enforced() {
    let image = udf_virtual_image(VirtualBuildOptions {
        storage: VatStorage::External(VatAllocation::Short),
        history: VatHistory::Previous,
        ..VirtualBuildOptions::default()
    });
    let depth_error = SeekArchiveReader::with_limits(
        Cursor::new(image.clone()),
        Limits::safe().with_nesting(Some(0)),
    )
    .unwrap_err();
    let depth_error = depth_error.archive_error().unwrap();
    assert_eq!(depth_error.kind(), ErrorKind::Limit);
    assert!(depth_error.to_string().contains("UDF VAT history depth"));

    let allocation_depth_error = SeekArchiveReader::with_limits(
        Cursor::new(udf_virtual_image(VirtualBuildOptions {
            storage: VatStorage::External(VatAllocation::Continuation),
            ..VirtualBuildOptions::default()
        })),
        Limits::safe().with_nesting(Some(0)),
    )
    .unwrap_err();
    let allocation_depth_error = allocation_depth_error.archive_error().unwrap();
    assert_eq!(allocation_depth_error.kind(), ErrorKind::Limit);
    assert!(
        allocation_depth_error
            .to_string()
            .contains("UDF VAT allocation depth")
    );

    let minimum = minimum_udf_metadata_budget(&image);
    let error = SeekArchiveReader::with_limits(
        Cursor::new(image),
        Limits::safe().with_metadata_bytes(Some(minimum - 1)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_uses_backup_anchor_and_reserve_vds_but_never_falls_back_to_iso() {
    assert_eq!(
        collect(udf_image(BuildOptions {
            corrupt_first_anchor: true,
            ..BuildOptions::default()
        }))
        .0,
        FormatId::Udf
    );
    assert_eq!(
        collect(udf_image(BuildOptions {
            corrupt_main: true,
            ..BuildOptions::default()
        }))
        .0,
        FormatId::Udf
    );

    let mut broken = udf_image(BuildOptions {
        bridge: true,
        ..BuildOptions::default()
    });
    broken[(PARTITION_START as usize + 1) * BLOCK + 4] ^= 1;
    let error = SeekArchiveReader::new(Cursor::new(broken)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[test]
fn udf_limits_and_write_refusal_are_typed() {
    let image = udf_image(BuildOptions::default());
    let error = SeekArchiveReader::with_limits(
        Cursor::new(image.clone()),
        Limits::safe().with_entries(Some(2)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let error = SeekArchiveReader::with_limits(
        Cursor::new(image.clone()),
        Limits::safe().with_decoded_total(Some(3)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let mut reader = SeekArchiveReader::with_limits(
        Cursor::new(image),
        Limits::safe().with_decoded_total(Some(538)),
    )
    .unwrap();
    let error = loop {
        if let Err(error) = reader.next_event() {
            break error;
        }
    };
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let error =
        SeekArchiveWriter::with_format(Cursor::new(Vec::new()), FormatId::Udf, Limits::safe())
            .unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );
    let error = ArchiveWriter::with_format(Vec::new(), FormatId::Udf).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    let options = CreateOptions::new().with_format(FormatId::Udf);
    let error = ArchiveEngine::new()
        .create(Vec::new(), options)
        .unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );
    let error = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    for limits in [
        Limits::safe().with_path_bytes(Some(3)),
        Limits::safe().with_nesting(Some(0)),
        Limits::safe().with_metadata_bytes(Some(16)),
        Limits::safe().with_entry_bytes(Some(5)),
        Limits::safe().with_in_flight_bytes(Some(1024)),
    ] {
        let error =
            SeekArchiveReader::with_limits(Cursor::new(udf_image(BuildOptions::default())), limits)
                .unwrap_err();
        assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    }
}

#[test]
fn udf_validates_media_anchors_vds_icbs_dstrings_and_character_sets() {
    let mut reserve_is_broken = udf_image(BuildOptions::default());
    reserve_is_broken[RESERVE_VDS as usize * BLOCK + 4] ^= 1;
    assert_eq!(collect(reserve_is_broken).0, FormatId::Udf);

    let mut final_anchor_only = udf_image(BuildOptions::default());
    for block in [256, BLOCKS as u32 - 1 - 256] {
        final_anchor_only[block as usize * BLOCK + 4] ^= 1;
    }
    assert_eq!(collect(final_anchor_only).0, FormatId::Udf);

    let mut odd_sized = udf_image(BuildOptions::default());
    odd_sized.push(0);
    assert_reader_error(odd_sized, ErrorKind::Unsupported);

    let logical_volume = (MAIN_VDS as usize + 2) * BLOCK;
    let mut wrong_block_size = udf_image(BuildOptions::default());
    wrong_block_size[logical_volume + 212..logical_volume + 216]
        .copy_from_slice(&4096_u32.to_le_bytes());
    finish_tag(
        &mut wrong_block_size[logical_volume..logical_volume + BLOCK],
        6,
        MAIN_VDS + 2,
        446,
    );
    assert_reader_error(wrong_block_size, ErrorKind::Unsupported);

    let mut non_aligned_vds = udf_image(BuildOptions::default());
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        let anchor_offset = block as usize * BLOCK;
        non_aligned_vds[anchor_offset + 16..anchor_offset + 20]
            .copy_from_slice(&(4_u32 * BLOCK as u32 - 1).to_le_bytes());
        non_aligned_vds[anchor_offset + 24..anchor_offset + 28]
            .copy_from_slice(&(4_u32 * BLOCK as u32 - 1).to_le_bytes());
        finish_tag(
            &mut non_aligned_vds[anchor_offset..anchor_offset + BLOCK],
            2,
            block,
            512,
        );
    }
    assert_reader_error(non_aligned_vds, ErrorKind::Malformed);

    let file_set = PARTITION_START as usize * BLOCK;
    let mut short_icb = udf_image(BuildOptions::default());
    short_icb[file_set + 400..file_set + 404].copy_from_slice(&16_u32.to_le_bytes());
    finish_tag(&mut short_icb[file_set..file_set + BLOCK], 256, 0, 512);
    assert_reader_error(short_icb, ErrorKind::Malformed);

    let mut invalid_dstring = udf_image(BuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical = (start as usize + 2) * BLOCK;
        invalid_dstring[logical + 211] = u8::MAX;
        finish_tag(
            &mut invalid_dstring[logical..logical + BLOCK],
            6,
            start + 2,
            446,
        );
    }
    assert_reader_error(invalid_dstring, ErrorKind::Malformed);

    let mut unsupported_charspec = udf_image(BuildOptions::default());
    unsupported_charspec[logical_volume + 20] = 1;
    finish_tag(
        &mut unsupported_charspec[logical_volume..logical_volume + BLOCK],
        6,
        MAIN_VDS + 2,
        446,
    );
    assert_reader_error(unsupported_charspec, ErrorKind::Unsupported);

    let mut revision_mismatch = udf_image(BuildOptions::default());
    revision_mismatch[file_set + 440..file_set + 442].copy_from_slice(&0x0102_u16.to_le_bytes());
    finish_tag(
        &mut revision_mismatch[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(revision_mismatch, ErrorKind::Malformed);

    let phrase_end = file_set + 48 + 1 + b"OSTA Compressed Unicode".len();
    let mut nonzero_charspec_padding = udf_image(BuildOptions::default());
    nonzero_charspec_padding[phrase_end] = 1;
    finish_tag(
        &mut nonzero_charspec_padding[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(nonzero_charspec_padding, ErrorKind::Malformed);

    let mut nonzero_dstring_padding = udf_image(BuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let logical = (start as usize + 2) * BLOCK;
        nonzero_dstring_padding[logical + 84 + 7] = 1;
        finish_tag(
            &mut nonzero_dstring_padding[logical..logical + BLOCK],
            6,
            start + 2,
            446,
        );
    }
    assert_reader_error(nonzero_dstring_padding, ErrorKind::Malformed);

    let domain_padding = file_set + 416 + 1 + b"*OSTA UDF Compliant".len();
    let mut nonzero_domain_padding = udf_image(BuildOptions::default());
    nonzero_domain_padding[domain_padding] = 1;
    finish_tag(
        &mut nonzero_domain_padding[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(nonzero_domain_padding, ErrorKind::Malformed);

    let mut nonzero_nsr_padding = udf_image(BuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let partition = (start as usize + 1) * BLOCK;
        nonzero_nsr_padding[partition + 25 + 6] = 1;
        finish_tag(
            &mut nonzero_nsr_padding[partition..partition + BLOCK],
            5,
            start + 1,
            512,
        );
    }
    assert_reader_error(nonzero_nsr_padding, ErrorKind::Malformed);

    let mut short_anchor_crc = udf_image(BuildOptions::default());
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        let offset = block as usize * BLOCK;
        finish_tag(&mut short_anchor_crc[offset..offset + BLOCK], 2, block, 24);
    }
    assert_reader_error(short_anchor_crc, ErrorKind::Malformed);

    let mut short_file_set_crc = udf_image(BuildOptions::default());
    finish_tag(
        &mut short_file_set_crc[file_set..file_set + BLOCK],
        256,
        0,
        416,
    );
    assert_reader_error(short_file_set_crc, ErrorKind::Malformed);

    let mut absent_optional_ads = udf_image(BuildOptions::default());
    absent_optional_ads[file_set + 458..file_set + 464].fill(0xa5);
    absent_optional_ads[file_set + 474..file_set + 480].fill(0x5a);
    finish_tag(
        &mut absent_optional_ads[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_eq!(collect(absent_optional_ads).0, FormatId::Udf);

    let mut invalid_empty_ad_location = udf_image(BuildOptions::default());
    invalid_empty_ad_location[file_set + 452..file_set + 456].copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(
        &mut invalid_empty_ad_location[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(invalid_empty_ad_location, ErrorKind::Malformed);

    let mut invalid_empty_ad_type = udf_image(BuildOptions::default());
    invalid_empty_ad_type[file_set + 448..file_set + 452]
        .copy_from_slice(&0x4000_0000_u32.to_le_bytes());
    finish_tag(
        &mut invalid_empty_ad_type[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(invalid_empty_ad_type, ErrorKind::Malformed);
}

#[test]
fn udf_validates_parent_fids_sparse_ranges_extended_attributes_and_symlinks() {
    let directory = (PARTITION_START as usize + 2) * BLOCK;
    let mut missing_parent = udf_image(BuildOptions::default());
    missing_parent[directory + 18] |= 0x04;
    finish_tag(&mut missing_parent[directory..directory + 40], 257, 2, 40);
    assert_reader_error(missing_parent, ErrorKind::Malformed);

    let mut wrong_parent = udf_image(BuildOptions::default());
    long_ad(
        &mut wrong_parent[directory..directory + 40],
        20,
        BLOCK as u32,
        4,
        0,
    );
    finish_tag(&mut wrong_parent[directory..directory + 40], 257, 2, 40);
    assert_reader_error(wrong_parent, ErrorKind::Malformed);

    let multi = (PARTITION_START as usize + 9) * BLOCK;
    let mut unrecorded_outside = udf_image(BuildOptions::default());
    unrecorded_outside[multi + 184..multi + 192].copy_from_slice(&short_ad(4, 1, 999));
    finish_tag(&mut unrecorded_outside[multi..multi + BLOCK], 261, 9, 200);
    assert_reader_error(unrecorded_outside, ErrorKind::Malformed);

    let mut unallocated_with_location = udf_image(BuildOptions::default());
    unallocated_with_location[multi + 184..multi + 192].copy_from_slice(&short_ad(4, 2, 1));
    finish_tag(
        &mut unallocated_with_location[multi..multi + BLOCK],
        261,
        9,
        200,
    );
    assert_reader_error(unallocated_with_location, ErrorKind::Malformed);

    let mut unaligned_nonfinal_extent = udf_image(BuildOptions::default());
    unaligned_nonfinal_extent[multi + 176..multi + 184].copy_from_slice(&short_ad(5, 0, 11));
    unaligned_nonfinal_extent[multi + 184..multi + 192].copy_from_slice(&short_ad(
        BLOCK as u32,
        2,
        0,
    ));
    unaligned_nonfinal_extent[multi + 192..multi + 200].copy_from_slice(&short_ad(
        BLOCK as u32,
        0,
        12,
    ));
    finish_tag(
        &mut unaligned_nonfinal_extent[multi..multi + BLOCK],
        261,
        9,
        200,
    );
    assert_reader_error(unaligned_nonfinal_extent, ErrorKind::Malformed);

    let inline = (PARTITION_START as usize + 3) * BLOCK;
    let mut inner_ea_checksum = udf_image(BuildOptions::default());
    inner_ea_checksum[inline + 176 + 4] ^= 1;
    finish_tag(&mut inner_ea_checksum[inline..inline + BLOCK], 261, 3, 258);
    assert_reader_error(inner_ea_checksum, ErrorKind::Integrity);

    let external_attributes = extended_attributes(19);
    let (_, external_entries) = collect(udf_image_with_external_attributes(&external_attributes));
    let external_inline = external_entries
        .iter()
        .find(|entry| entry.path == "inline.txt")
        .unwrap();
    assert_eq!(
        external_inline.external_raw_extended_attributes.as_deref(),
        Some(external_attributes.as_slice())
    );

    let extended_file = (PARTITION_START as usize + 7) * BLOCK;
    let mut absent_optional_icbs = udf_image(BuildOptions::default());
    absent_optional_icbs[inline + 122..inline + 128].fill(0xa5);
    absent_optional_icbs[extended_file + 146..extended_file + 152].fill(0x5a);
    absent_optional_icbs[extended_file + 162..extended_file + 168].fill(0x3c);
    finish_tag(
        &mut absent_optional_icbs[inline..inline + BLOCK],
        261,
        3,
        258,
    );
    finish_tag(
        &mut absent_optional_icbs[extended_file..extended_file + BLOCK],
        266,
        7,
        216 + "深い内容".len(),
    );
    assert_eq!(collect(absent_optional_icbs).0, FormatId::Udf);

    let mut invalid_empty_external_location = udf_image(BuildOptions::default());
    invalid_empty_external_location[inline + 116..inline + 120]
        .copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(
        &mut invalid_empty_external_location[inline..inline + BLOCK],
        261,
        3,
        258,
    );
    assert_reader_error(invalid_empty_external_location, ErrorKind::Malformed);

    let mut unaligned_ea = udf_image(BuildOptions::default());
    write_block(
        &mut unaligned_ea,
        PARTITION_START + 3,
        &file_entry_with_extended_attributes(3, b"inline", &unaligned_extended_attributes(3), 3),
    );
    assert_reader_error(unaligned_ea, ErrorKind::Malformed);

    let mut invalid_timestamp = udf_image(BuildOptions::default());
    invalid_timestamp[inline + 93] = u8::MAX;
    finish_tag(&mut invalid_timestamp[inline..inline + BLOCK], 261, 3, 258);
    let (_, entries) = collect(invalid_timestamp);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .modified,
        None
    );

    let mut absolute_symlink = udf_image(BuildOptions::default());
    let mut target = vec![1, 0, 0, 0, 5, 11, 0, 0, 8];
    target.extend_from_slice(b"extent.bin");
    write_block(
        &mut absolute_symlink,
        PARTITION_START + 8,
        &file_entry(8, 12, 3, target.len() as u64, &target, 8, 1),
    );
    let (_, entries) = collect(absolute_symlink);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "link")
            .unwrap()
            .target
            .as_deref(),
        Some("/extent.bin")
    );

    let mut empty_symlink = udf_image(BuildOptions::default());
    write_block(
        &mut empty_symlink,
        PARTITION_START + 8,
        &file_entry(8, 12, 3, 0, &[], 8, 1),
    );
    assert_reader_error(empty_symlink, ErrorKind::Malformed);

    let named_root_component = [1, 1, 0, 0, 8];
    let mut named_root = udf_image(BuildOptions::default());
    write_block(
        &mut named_root,
        PARTITION_START + 8,
        &file_entry(
            8,
            12,
            3,
            named_root_component.len() as u64,
            &named_root_component,
            8,
            1,
        ),
    );
    assert_reader_error(named_root, ErrorKind::Unsupported);

    let mut leap_second = udf_image(BuildOptions::default());
    leap_second[inline + 84..inline + 86].copy_from_slice(&0x2000_u16.to_le_bytes());
    leap_second[inline + 92] = 60;
    finish_tag(&mut leap_second[inline..inline + BLOCK], 261, 3, 258);
    let (_, entries) = collect(leap_second);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "inline.txt")
            .unwrap()
            .modified,
        Some(
            libarchive_oxide_core::Timestamp::new(1_785_242_100, 123_456_000)
                .expect("valid timestamp"),
        )
    );
}

#[test]
fn udf_external_extended_attribute_icbs_validate_role_integrity_and_limits() {
    let attributes = extended_attributes(19);
    let external_icb = (PARTITION_START as usize + 18) * BLOCK;
    let attribute_data = (PARTITION_START as usize + 19) * BLOCK;

    let mut wrong_type = udf_image_with_external_attributes(&attributes);
    wrong_type[external_icb + 27] = 5;
    finish_tag(
        &mut wrong_type[external_icb..external_icb + BLOCK],
        261,
        18,
        184,
    );
    assert_reader_error(wrong_type, ErrorKind::Malformed);

    let mut linked = udf_image_with_external_attributes(&attributes);
    linked[external_icb + 48..external_icb + 50].copy_from_slice(&1_u16.to_le_bytes());
    finish_tag(
        &mut linked[external_icb..external_icb + BLOCK],
        261,
        18,
        184,
    );
    assert_reader_error(linked, ErrorKind::Malformed);

    let mut recursive = udf_image_with_external_attributes(&attributes);
    long_ad(
        &mut recursive[external_icb..external_icb + BLOCK],
        112,
        BLOCK as u32,
        18,
        0,
    );
    finish_tag(
        &mut recursive[external_icb..external_icb + BLOCK],
        261,
        18,
        184,
    );
    assert_reader_error(recursive, ErrorKind::Malformed);

    let mut corrupt = udf_image_with_external_attributes(&attributes);
    corrupt[attribute_data + 16] ^= 1;
    assert_reader_error(corrupt, ErrorKind::Integrity);

    let mut malformed_attributes = attributes.clone();
    malformed_attributes[16..20].copy_from_slice(&1_u32.to_le_bytes());
    finish_tag(&mut malformed_attributes, 262, 19, 24);
    assert_reader_error(
        udf_image_with_external_attributes(&malformed_attributes),
        ErrorKind::Malformed,
    );

    let mut large_attributes = vec![0_u8; BLOCK * 2];
    large_attributes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    large_attributes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    finish_tag(&mut large_attributes, 262, 19, 24);
    let error = SeekArchiveReader::with_limits(
        Cursor::new(udf_image_with_external_attributes(&large_attributes)),
        Limits::safe().with_in_flight_bytes(Some(BLOCK)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn udf_validates_zero_length_ads_and_selects_prevailing_vds_descriptors() {
    let root = (PARTITION_START as usize + 1) * BLOCK;
    for descriptor in [short_ad(0, 1, 0), short_ad(0, 0, 1)] {
        let mut image = udf_image(BuildOptions::default());
        image[root + 176..root + 184].copy_from_slice(&descriptor);
        finish_tag(&mut image[root..root + BLOCK], 261, 1, 184);
        assert_reader_error(image, ErrorKind::Malformed);
    }

    let long_file = (PARTITION_START as usize + 13) * BLOCK;
    let mut nonzero_partition = udf_image(BuildOptions::default());
    nonzero_partition[long_file + 176..long_file + 192]
        .copy_from_slice(&long_allocation_ad(0, 0, 0, 1));
    finish_tag(
        &mut nonzero_partition[long_file..long_file + BLOCK],
        261,
        13,
        192,
    );
    assert_reader_error(nonzero_partition, ErrorKind::Malformed);

    let mut prevailing = udf_image(BuildOptions::default());
    let logical = (MAIN_VDS as usize + 2) * BLOCK;
    prevailing[logical + 16..logical + 20].copy_from_slice(&10_u32.to_le_bytes());
    finish_tag(
        &mut prevailing[logical..logical + BLOCK],
        6,
        MAIN_VDS + 2,
        446,
    );
    let mut obsolete = prevailing[logical..logical + BLOCK].to_vec();
    obsolete[16..20].copy_from_slice(&5_u32.to_le_bytes());
    obsolete[240..242].copy_from_slice(&0x0260_u16.to_le_bytes());
    finish_tag(&mut obsolete, 6, MAIN_VDS + 3, 446);
    write_block(&mut prevailing, MAIN_VDS + 3, &obsolete);
    write_block(
        &mut prevailing,
        MAIN_VDS + 4,
        &tagged_block(8, MAIN_VDS + 4, 16),
    );
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        let offset = block as usize * BLOCK;
        prevailing[offset + 16..offset + 20].copy_from_slice(&(5_u32 * BLOCK as u32).to_le_bytes());
        finish_tag(&mut prevailing[offset..offset + BLOCK], 2, block, 512);
    }
    assert_eq!(collect(prevailing.clone()).0, FormatId::Udf);

    let mut conflicting = prevailing;
    let obsolete = (MAIN_VDS as usize + 3) * BLOCK;
    conflicting[obsolete + 16..obsolete + 20].copy_from_slice(&10_u32.to_le_bytes());
    finish_tag(
        &mut conflicting[obsolete..obsolete + BLOCK],
        6,
        MAIN_VDS + 3,
        446,
    );
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        let offset = block as usize * BLOCK;
        conflicting[offset + 24..offset + 28]
            .copy_from_slice(&(5_u32 * BLOCK as u32).to_le_bytes());
        conflicting[offset + 28..offset + 32].copy_from_slice(&MAIN_VDS.to_le_bytes());
        finish_tag(&mut conflicting[offset..offset + BLOCK], 2, block, 512);
    }
    assert_reader_error(conflicting, ErrorKind::Malformed);

    let mut cross_type_collision = udf_image(BuildOptions::default());
    for start in [MAIN_VDS, RESERVE_VDS] {
        let partition = (start as usize + 1) * BLOCK;
        cross_type_collision[partition + 16..partition + 20].copy_from_slice(&1_u32.to_le_bytes());
        finish_tag(
            &mut cross_type_collision[partition..partition + BLOCK],
            5,
            start + 1,
            512,
        );
    }
    assert_reader_error(cross_type_collision, ErrorKind::Malformed);

    let mut continued = udf_image(BuildOptions::default());
    let mut pointer = tagged_block(3, MAIN_VDS + 3, 512);
    pointer[16..20].copy_from_slice(&4_u32.to_le_bytes());
    pointer[20..24].copy_from_slice(&(BLOCK as u32).to_le_bytes());
    pointer[24..28].copy_from_slice(&(MAIN_VDS + 4).to_le_bytes());
    finish_tag(&mut pointer, 3, MAIN_VDS + 3, 512);
    write_block(&mut continued, MAIN_VDS + 3, &pointer);
    write_block(
        &mut continued,
        MAIN_VDS + 4,
        &tagged_block(8, MAIN_VDS + 4, 16),
    );
    assert_eq!(collect(continued).0, FormatId::Udf);

    let mut pointer_cycle = udf_image(BuildOptions::default());
    let mut pointer = tagged_block(3, MAIN_VDS + 3, 512);
    pointer[16..20].copy_from_slice(&4_u32.to_le_bytes());
    pointer[20..24].copy_from_slice(&(4_u32 * BLOCK as u32).to_le_bytes());
    pointer[24..28].copy_from_slice(&MAIN_VDS.to_le_bytes());
    finish_tag(&mut pointer, 3, MAIN_VDS + 3, 512);
    write_block(&mut pointer_cycle, MAIN_VDS + 3, &pointer);
    for block in [256, BLOCKS as u32 - 1 - 256, BLOCKS as u32 - 1] {
        let offset = block as usize * BLOCK;
        pointer_cycle[offset + 24..offset + 28]
            .copy_from_slice(&(4_u32 * BLOCK as u32).to_le_bytes());
        pointer_cycle[offset + 28..offset + 32].copy_from_slice(&MAIN_VDS.to_le_bytes());
        finish_tag(&mut pointer_cycle[offset..offset + BLOCK], 2, block, 512);
    }
    assert_reader_error(pointer_cycle, ErrorKind::Malformed);
}

#[test]
fn udf_validates_file_body_tail_and_allocation_termination() {
    let payload = b"extent payload";
    let mut valid_tail = udf_image(BuildOptions::default());
    let mut allocation = Vec::new();
    allocation.extend_from_slice(&short_ad(payload.len() as u32, 0, 10));
    allocation.extend_from_slice(&short_ad(BLOCK as u32, 1, 18));
    write_block(
        &mut valid_tail,
        PARTITION_START + 4,
        &file_entry(4, 5, 0, payload.len() as u64, &allocation, 4, 2),
    );
    assert_eq!(
        collect(valid_tail)
            .1
            .into_iter()
            .find(|entry| entry.path == "extent.bin")
            .unwrap()
            .data,
        payload
    );

    let mut oversized_body = udf_image(BuildOptions::default());
    write_block(
        &mut oversized_body,
        PARTITION_START + 4,
        &file_entry(
            4,
            5,
            0,
            payload.len() as u64,
            &short_ad(BLOCK as u32, 0, 10),
            4,
            2,
        ),
    );
    assert_reader_error(oversized_body, ErrorKind::Malformed);

    for tail in [short_ad(5, 1, 18), short_ad(BLOCK as u32, 0, 18)] {
        let mut image = udf_image(BuildOptions::default());
        let mut allocation = Vec::new();
        allocation.extend_from_slice(&short_ad(payload.len() as u32, 0, 10));
        allocation.extend_from_slice(&tail);
        write_block(
            &mut image,
            PARTITION_START + 4,
            &file_entry(4, 5, 0, payload.len() as u64, &allocation, 4, 2),
        );
        assert_reader_error(image, ErrorKind::Malformed);
    }

    let mut after_terminator = udf_image(BuildOptions::default());
    let mut allocation = Vec::new();
    allocation.extend_from_slice(&short_ad(0, 0, 0));
    allocation.extend_from_slice(&short_ad(payload.len() as u32, 0, 10));
    write_block(
        &mut after_terminator,
        PARTITION_START + 4,
        &file_entry(4, 5, 0, payload.len() as u64, &allocation, 4, 2),
    );
    assert_reader_error(after_terminator, ErrorKind::Malformed);

    let mut after_continuation = udf_image(BuildOptions::default());
    let mut allocation = Vec::new();
    allocation.extend_from_slice(&short_ad(BLOCK as u32, 3, 16));
    allocation.extend_from_slice(&short_ad(5, 0, 17));
    write_block(
        &mut after_continuation,
        PARTITION_START + 15,
        &file_entry(15, 5, 0, 5, &allocation, 15, 1),
    );
    assert_reader_error(after_continuation, ErrorKind::Malformed);
}

#[test]
fn archive_engine_routes_udf_through_the_seek_reader() {
    let mut session = ArchiveEngine::new()
        .prepare(Cursor::new(udf_image(BuildOptions::default())))
        .unwrap();
    assert_eq!(session.format(), Some(FormatId::Udf));
    let inspection = session.inspect().unwrap();
    assert!(inspection.entries().iter().any(|entry| {
        entry.metadata().path().as_bytes() == b"nested/\xe6\x97\xa5\xe6\x9c\xac.txt"
    }));
}

#[test]
fn range_source_routes_udf_through_the_shared_seek_reader() {
    let mut reader =
        RangeArchiveReader::new(MemoryRange::new(udf_image(BuildOptions::default()))).unwrap();
    assert_eq!(reader.format(), FormatId::Udf);
    let mut saw_payload = false;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) if bytes == b"inline" => saw_payload = true,
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert!(saw_payload);
}

#[cfg(feature = "async")]
#[test]
fn futures_seek_and_async_range_route_udf_through_the_same_parser() {
    futures_lite::future::block_on(async {
        let image = udf_image(BuildOptions::default());
        let mut seek = libarchive_oxide::AsyncSeekArchiveReader::new(
            futures_lite::io::Cursor::new(image.clone()),
        )
        .await
        .unwrap();
        assert_eq!(seek.format(), FormatId::Udf);
        while !matches!(seek.next_event().await.unwrap(), ReaderEvent::Done) {}

        let mut range = AsyncRangeArchiveReader::new(MemoryRange::new(image))
            .await
            .unwrap();
        assert_eq!(range.format(), FormatId::Udf);
        while !matches!(range.next_event().await.unwrap(), ReaderEvent::Done) {}
    });
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn tokio_seek_routes_udf_through_the_same_parser() {
    let mut reader = libarchive_oxide::TokioSeekArchiveReader::new(Cursor::new(udf_image(
        BuildOptions::default(),
    )))
    .await
    .unwrap();
    assert_eq!(reader.format(), FormatId::Udf);
    while !matches!(reader.next_event().await.unwrap(), ReaderEvent::Done) {}
}

#[test]
fn udf_descriptor_integrity_location_and_extent_ranges_are_validated() {
    let root = (PARTITION_START as usize + 1) * BLOCK;

    let mut checksum = udf_image(BuildOptions::default());
    checksum[root + 4] ^= 1;
    let error = SeekArchiveReader::new(Cursor::new(checksum)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let mut crc = udf_image(BuildOptions::default());
    crc[root + 8] ^= 1;
    repair_tag_checksum(&mut crc[root..root + BLOCK]);
    let error = SeekArchiveReader::new(Cursor::new(crc)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let mut location = udf_image(BuildOptions::default());
    location[root + 12..root + 16].copy_from_slice(&2_u32.to_le_bytes());
    repair_tag_checksum(&mut location[root..root + BLOCK]);
    let error = SeekArchiveReader::new(Cursor::new(location)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);

    let mut outside = udf_image(BuildOptions::default());
    outside[root + 180..root + 184].copy_from_slice(&999_u32.to_le_bytes());
    finish_tag(&mut outside[root..root + BLOCK], 261, 1, 184);
    let error = SeekArchiveReader::new(Cursor::new(outside)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut nonzero_root_unique_id = udf_image(BuildOptions::default());
    nonzero_root_unique_id[root + 160..root + 168].copy_from_slice(&1_u64.to_le_bytes());
    finish_tag(&mut nonzero_root_unique_id[root..root + BLOCK], 261, 1, 184);
    assert_reader_error(nonzero_root_unique_id, ErrorKind::Malformed);

    let inline = (PARTITION_START as usize + 3) * BLOCK;
    let mut embedded_blocks_recorded = udf_image(BuildOptions::default());
    embedded_blocks_recorded[inline + 64..inline + 72].copy_from_slice(&1_u64.to_le_bytes());
    finish_tag(
        &mut embedded_blocks_recorded[inline..inline + BLOCK],
        261,
        3,
        258,
    );
    assert_reader_error(embedded_blocks_recorded, ErrorKind::Malformed);

    let extent = (PARTITION_START as usize + 4) * BLOCK;
    let mut missing_recorded_block = udf_image(BuildOptions::default());
    missing_recorded_block[extent + 64..extent + 72].copy_from_slice(&0_u64.to_le_bytes());
    finish_tag(
        &mut missing_recorded_block[extent..extent + BLOCK],
        261,
        4,
        184,
    );
    assert_reader_error(missing_recorded_block, ErrorKind::Malformed);
}

#[test]
fn udf_rejects_cycles_duplicate_paths_truncated_fids_and_invalid_unicode() {
    let allocation_extent = (PARTITION_START as usize + 16) * BLOCK;
    let mut cycle = udf_image(BuildOptions::default());
    cycle[allocation_extent + 24..allocation_extent + 32].copy_from_slice(&short_ad(
        BLOCK as u32,
        3,
        16,
    ));
    finish_tag(
        &mut cycle[allocation_extent..allocation_extent + BLOCK],
        258,
        16,
        32,
    );
    let error = SeekArchiveReader::new(Cursor::new(cycle)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let directory = (PARTITION_START as usize + 2) * BLOCK;
    let mut duplicate = udf_image(BuildOptions::default());
    let first = duplicate[directory + 140 + 38..directory + 140 + 47].to_vec();
    duplicate[directory + 284 + 38..directory + 284 + 47].copy_from_slice(&first);
    finish_tag(&mut duplicate[directory + 284..directory + 332], 257, 2, 48);
    let error = SeekArchiveReader::new(Cursor::new(duplicate)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let root = (PARTITION_START as usize + 1) * BLOCK;
    let mut truncated = udf_image(BuildOptions::default());
    let declared = u64::from_le_bytes(truncated[root + 56..root + 64].try_into().unwrap());
    truncated[root + 56..root + 64].copy_from_slice(&(declared - 1).to_le_bytes());
    finish_tag(&mut truncated[root..root + BLOCK], 261, 1, 184);
    let error = SeekArchiveReader::new(Cursor::new(truncated)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut unicode = udf_image(BuildOptions::default());
    unicode[directory + 40 + 38] = 7;
    finish_tag(&mut unicode[directory + 40..directory + 88], 257, 2, 48);
    let error = SeekArchiveReader::new(Cursor::new(unicode)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut unaligned_implementation_use = udf_image(BuildOptions::default());
    unaligned_implementation_use[directory + 40 + 36..directory + 40 + 38]
        .copy_from_slice(&2_u16.to_le_bytes());
    assert_reader_error(unaligned_implementation_use, ErrorKind::Malformed);

    let mut short_implementation_use = udf_image(BuildOptions::default());
    short_implementation_use[directory + 40 + 36..directory + 40 + 38]
        .copy_from_slice(&4_u16.to_le_bytes());
    assert_reader_error(short_implementation_use, ErrorKind::Malformed);

    let extent_fid = directory + 88;
    let mut nonzero_padding = udf_image(BuildOptions::default());
    nonzero_padding[extent_fid + 49] = 1;
    finish_tag(
        &mut nonzero_padding[extent_fid..extent_fid + 52],
        257,
        2,
        52,
    );
    assert_reader_error(nonzero_padding, ErrorKind::Malformed);

    let mut deleted_padding = udf_image(BuildOptions::default());
    deleted_padding[extent_fid + 18] |= 0x04;
    deleted_padding[extent_fid + 49] = 1;
    finish_tag(
        &mut deleted_padding[extent_fid..extent_fid + 52],
        257,
        2,
        52,
    );
    assert_reader_error(deleted_padding, ErrorKind::Malformed);
}

#[test]
fn udf_unsupported_revision_maps_and_strategy_are_typed() {
    for revision in [0x0202, 0x0300] {
        assert_reader_error(
            udf_image(BuildOptions {
                revision,
                ..BuildOptions::default()
            }),
            ErrorKind::Unsupported,
        );
    }

    let logical_volume = (MAIN_VDS as usize + 2) * BLOCK;
    let mut type_two_map = udf_image(BuildOptions::default());
    type_two_map[logical_volume + 440] = 2;
    finish_tag(
        &mut type_two_map[logical_volume..logical_volume + BLOCK],
        6,
        MAIN_VDS + 2,
        446,
    );
    let error = SeekArchiveReader::new(Cursor::new(type_two_map)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut metadata_map = udf_image(BuildOptions::default());
    metadata_map[logical_volume + 264..logical_volume + 268].copy_from_slice(&64_u32.to_le_bytes());
    metadata_map[logical_volume + 440..logical_volume + 504].fill(0);
    metadata_map[logical_volume + 440] = 2;
    metadata_map[logical_volume + 441] = 64;
    entity_id(
        &mut metadata_map[logical_volume + 444..logical_volume + 476],
        b"*UDF Metadata Partition",
    );
    finish_tag(
        &mut metadata_map[logical_volume..logical_volume + BLOCK],
        6,
        MAIN_VDS + 2,
        504,
    );
    assert_reader_error(metadata_map, ErrorKind::Unsupported);

    let root = (PARTITION_START as usize + 1) * BLOCK;
    let mut strategy = udf_image(BuildOptions::default());
    strategy[root + 20..root + 22].copy_from_slice(&5_u16.to_le_bytes());
    finish_tag(&mut strategy[root..root + BLOCK], 261, 1, 184);
    let error = SeekArchiveReader::new(Cursor::new(strategy)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn udf_reads_extended_allocation_descriptors_including_sparse_and_continuation_extents() {
    let mut image = udf_image(BuildOptions::default());

    let extent_data = b"extent payload";
    let extent_ad = extended_allocation_ad(
        extent_data.len() as u32,
        0,
        extent_data.len() as u32,
        extent_data.len() as u32,
        10,
        0,
    );
    write_block(
        &mut image,
        PARTITION_START + 4,
        &file_entry(4, 5, 2, extent_data.len() as u64, &extent_ad, 4, 2),
    );

    let mut multi_ads = Vec::new();
    multi_ads.extend_from_slice(&extended_allocation_ad(
        BLOCK as u32,
        0,
        BLOCK as u32,
        BLOCK as u32,
        11,
        0,
    ));
    multi_ads.extend_from_slice(&extended_allocation_ad(
        BLOCK as u32,
        2,
        0,
        BLOCK as u32,
        0,
        0,
    ));
    multi_ads.extend_from_slice(&extended_allocation_ad(5, 0, 5, 5, 12, 0));
    let mut multi_entry = file_entry(9, 5, 2, (BLOCK as u64 * 2) + 5, &multi_ads, 9, 1);
    multi_entry[64..72].copy_from_slice(&2_u64.to_le_bytes());
    finish_tag(&mut multi_entry, 261, 9, 176 + multi_ads.len());
    write_block(&mut image, PARTITION_START + 9, &multi_entry);

    let continuation = extended_allocation_ad(BLOCK as u32, 3, BLOCK as u32, BLOCK as u32, 16, 0);
    write_block(
        &mut image,
        PARTITION_START + 15,
        &file_entry(15, 5, 2, 5, &continuation, 15, 1),
    );
    let chained = extended_allocation_ad(5, 0, 5, 5, 17, 0);
    let mut allocation_extent = tagged_block(258, 16, 24 + chained.len());
    allocation_extent[20..24].copy_from_slice(&(chained.len() as u32).to_le_bytes());
    allocation_extent[24..24 + chained.len()].copy_from_slice(&chained);
    finish_tag(&mut allocation_extent, 258, 16, 24 + chained.len());
    write_block(&mut image, PARTITION_START + 16, &allocation_extent);

    let (_, entries) = collect(image);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "extent.bin")
            .unwrap()
            .data,
        extent_data
    );
    let multi = entries
        .iter()
        .find(|entry| entry.path == "multi.bin")
        .unwrap();
    assert_eq!(multi.data.len(), BLOCK * 2 + 5);
    assert!(multi.data[BLOCK..BLOCK * 2].iter().all(|byte| *byte == 0));
    assert_eq!(&multi.data[BLOCK * 2..], b"world");
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "chain.bin")
            .unwrap()
            .data,
        b"chain"
    );
}

#[test]
fn udf_rejects_malformed_or_transformed_extended_allocation_descriptors() {
    let cases = [
        (
            extended_allocation_ad(7, 0, 0x4000_0007, 7, 10, 0),
            ErrorKind::Malformed,
        ),
        (
            extended_allocation_ad(6, 0, 7, 7, 10, 0),
            ErrorKind::Malformed,
        ),
        (
            extended_allocation_ad(7, 0, 5, 7, 10, 0),
            ErrorKind::Unsupported,
        ),
        (
            extended_allocation_ad(7, 1, 1, 7, 10, 0),
            ErrorKind::Malformed,
        ),
        (
            extended_allocation_ad(0, 0, 0, 1, 0, 0),
            ErrorKind::Malformed,
        ),
    ];
    for (allocation, expected) in cases {
        let mut image = udf_image(BuildOptions::default());
        write_block(
            &mut image,
            PARTITION_START + 4,
            &file_entry(4, 5, 2, 7, &allocation, 4, 2),
        );
        assert_reader_error(image, expected);
    }

    let mut truncated = udf_image(BuildOptions::default());
    write_block(
        &mut truncated,
        PARTITION_START + 4,
        &file_entry(
            4,
            5,
            2,
            7,
            &extended_allocation_ad(7, 0, 7, 7, 10, 0)[..19],
            4,
            2,
        ),
    );
    assert_reader_error(truncated, ErrorKind::Malformed);
}

/// Explicit fixture generator used to refresh `fuzz/corpus/read_udf/seed.udf`.
///
/// It is ignored in normal test runs and only writes when the destination is
/// supplied by the maintainer.
#[test]
#[ignore = "explicit deterministic fuzz-corpus generator"]
fn generate_udf_fuzz_seed() {
    let destination =
        std::env::var_os("LIBARCHIVE_OXIDE_UDF_SEED").expect("seed destination is required");
    std::fs::write(destination, udf_stream_fuzz_image()).unwrap();
}

/// Explicit fixture generator for the UDF 2.60 Metadata Partition fuzz seed.
#[test]
#[ignore = "explicit deterministic metadata-partition fuzz-corpus generator"]
fn generate_udf_metadata_fuzz_seed() {
    let destination = std::env::var_os("LIBARCHIVE_OXIDE_UDF_METADATA_SEED")
        .expect("metadata seed destination is required");
    std::fs::write(
        destination,
        udf_metadata_image(MetadataBuildOptions {
            revision: 0x0260,
            bitmap: true,
            logical_base: 32,
            split: true,
            ..MetadataBuildOptions::default()
        }),
    )
    .unwrap();
}

/// Explicit fixture generator for the UDF 2.60 Virtual Partition/VAT fuzz seed.
#[test]
#[ignore = "explicit deterministic virtual-partition fuzz-corpus generator"]
fn generate_udf_virtual_vat_fuzz_seed() {
    let destination = std::env::var_os("LIBARCHIVE_OXIDE_UDF_VIRTUAL_VAT_SEED")
        .expect("virtual VAT seed destination is required");
    std::fs::write(
        destination,
        udf_virtual_image(VirtualBuildOptions {
            revision: 0x0260,
            storage: VatStorage::External(VatAllocation::ChainedContinuation),
            history: VatHistory::Previous,
        }),
    )
    .unwrap();
}

/// Explicit fixture generator for the UDF 2.60 Sparable Partition fuzz seed.
#[test]
#[ignore = "explicit deterministic sparable-partition fuzz-corpus generator"]
fn generate_udf_sparable_fuzz_seed() {
    let destination = std::env::var_os("LIBARCHIVE_OXIDE_UDF_SPARABLE_SEED")
        .expect("Sparable seed destination is required");
    std::fs::write(
        destination,
        udf_sparable_image(SparableBuildOptions {
            revision: 0x0260,
            ..SparableBuildOptions::default()
        }),
    )
    .unwrap();
}
