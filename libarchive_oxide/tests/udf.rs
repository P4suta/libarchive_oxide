// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic UDF Phase 1 images and public-path contract tests.

#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::range_plus_one,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{self, Cursor};

use libarchive_oxide::libarchive_oxide_core::{
    EntryKind, ErrorKind, FormatId, Limits, ProbeResult,
};
use libarchive_oxide::{
    ArchiveEngine, ArchiveWriter, CreateOptions, ProviderCapability, ProviderSet,
    RangeArchiveReader, RangeSource, ReaderEvent, SeekArchiveReader, SeekArchiveWriter,
    SourceIdentity,
};

#[derive(Debug)]
struct MemoryRange {
    bytes: Vec<u8>,
    identity: SourceIdentity,
}

impl MemoryRange {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            identity: SourceIdentity::new(b"udf-test-image".to_vec()),
        }
    }
}

impl RangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
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
impl libarchive_oxide::AsyncRangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    async fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        RangeSource::read_range(self, offset, output)
    }
}

const BLOCK: usize = 2048;
const BLOCKS: usize = 700;
const PARTITION_START: u32 = 300;
const MAIN_VDS: u32 = 257;
const RESERVE_VDS: u32 = 620;

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
    let crc_length = used.saturating_sub(16);
    let crc = crc16(&descriptor[16..used]);
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
    long_ad(&mut descriptor, 20, BLOCK as u32, icb_lbn, 0);
    descriptor[36..38].copy_from_slice(&0_u16.to_le_bytes());
    descriptor[38..38 + name.len()].copy_from_slice(&name);
    finish_tag(&mut descriptor, 257, location, length);
    descriptor
}

fn parent_fid(location: u32, parent_icb_lbn: u32) -> Vec<u8> {
    let mut descriptor = vec![0_u8; 40];
    descriptor[16..18].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[18] = 0x0a;
    descriptor[19] = 0;
    long_ad(&mut descriptor, 20, BLOCK as u32, parent_icb_lbn, 0);
    descriptor[36..38].copy_from_slice(&0_u16.to_le_bytes());
    finish_tag(&mut descriptor, 257, location, 40);
    descriptor
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

    let mut root_directory = parent_fid(2, 1);
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
    let mut nested_directory = parent_fid(6, 1);
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
    modified: Option<libarchive_oxide::libarchive_oxide_core::Timestamp>,
    raw_extended_attributes: Option<Vec<u8>>,
}

fn collect(bytes: Vec<u8>) -> (FormatId, Vec<ReadEntry>) {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let format = reader.format();
    let mut entries: Vec<ReadEntry> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => entries.push(ReadEntry {
                path: metadata.path().display_lossy(),
                kind: metadata.kind(),
                data: Vec::new(),
                target: metadata
                    .link_target()
                    .map(libarchive_oxide::libarchive_oxide_core::ArchivePath::display_lossy),
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
            }),
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
        Some(libarchive_oxide::libarchive_oxide_core::Timestamp {
            secs: 1_785_242_096,
            nanos: 123_456_000,
        })
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
fn udf_walks_noncontiguous_multi_extent_directories() {
    let mut image = udf_image(BuildOptions::default());
    let first_lbn = 18_u32;
    let second_lbn = 20_u32;
    let first = (PARTITION_START + first_lbn) as usize * BLOCK;
    let second = (PARTITION_START + second_lbn) as usize * BLOCK;
    image[first..first + BLOCK].fill(0);
    image[second..second + BLOCK].fill(0);
    let parent = parent_fid(first_lbn, 1);
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
    for revision in [0x0102, 0x0150, 0x0201] {
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
    assert!(capabilities.requires_seek());
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

    let mut continued_file_set = udf_image(BuildOptions::default());
    long_ad(
        &mut continued_file_set[file_set..file_set + BLOCK],
        448,
        BLOCK as u32,
        18,
        0,
    );
    finish_tag(
        &mut continued_file_set[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(continued_file_set, ErrorKind::Unsupported);

    let mut system_stream_directory = udf_image(BuildOptions::default());
    long_ad(
        &mut system_stream_directory[file_set..file_set + BLOCK],
        464,
        BLOCK as u32,
        18,
        0,
    );
    finish_tag(
        &mut system_stream_directory[file_set..file_set + BLOCK],
        256,
        0,
        512,
    );
    assert_reader_error(system_stream_directory, ErrorKind::Unsupported);

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

    let mut external_ea = udf_image(BuildOptions::default());
    long_ad(
        &mut external_ea[inline..inline + BLOCK],
        112,
        BLOCK as u32,
        18,
        0,
    );
    finish_tag(&mut external_ea[inline..inline + BLOCK], 261, 3, 258);
    assert_reader_error(external_ea, ErrorKind::Unsupported);

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
        Some(libarchive_oxide::libarchive_oxide_core::Timestamp {
            secs: 1_785_242_100,
            nanos: 123_456_000,
        })
    );
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
        .open(Cursor::new(udf_image(BuildOptions::default())))
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

        let mut range = libarchive_oxide::AsyncRangeArchiveReader::new(MemoryRange::new(image))
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
fn udf_unsupported_revision_maps_strategy_extended_ads_and_streams_are_typed() {
    for revision in [0x0250, 0x0260] {
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

    for identifier in [
        b"*UDF Metadata Partition".as_slice(),
        b"*UDF Sparable Partition".as_slice(),
        b"*UDF Virtual Partition".as_slice(),
    ] {
        let mut image = udf_image(BuildOptions::default());
        image[logical_volume + 264..logical_volume + 268].copy_from_slice(&64_u32.to_le_bytes());
        image[logical_volume + 440..logical_volume + 504].fill(0);
        image[logical_volume + 440] = 2;
        image[logical_volume + 441] = 64;
        entity_id(
            &mut image[logical_volume + 444..logical_volume + 476],
            identifier,
        );
        finish_tag(
            &mut image[logical_volume..logical_volume + BLOCK],
            6,
            MAIN_VDS + 2,
            504,
        );
        assert_reader_error(image, ErrorKind::Unsupported);
    }

    let root = (PARTITION_START as usize + 1) * BLOCK;
    let mut strategy = udf_image(BuildOptions::default());
    strategy[root + 20..root + 22].copy_from_slice(&5_u16.to_le_bytes());
    finish_tag(&mut strategy[root..root + BLOCK], 261, 1, 184);
    let error = SeekArchiveReader::new(Cursor::new(strategy)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut extended_ad = udf_image(BuildOptions::default());
    extended_ad[root + 34..root + 36].copy_from_slice(&2_u16.to_le_bytes());
    finish_tag(&mut extended_ad[root..root + BLOCK], 261, 1, 184);
    let error = SeekArchiveReader::new(Cursor::new(extended_ad)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let extended_file = (PARTITION_START as usize + 7) * BLOCK;
    let mut named_stream = udf_image(BuildOptions::default());
    named_stream[extended_file + 152] = 1;
    let used = 16
        + usize::from(u16::from_le_bytes(
            named_stream[extended_file + 10..extended_file + 12]
                .try_into()
                .unwrap(),
        ));
    finish_tag(
        &mut named_stream[extended_file..extended_file + BLOCK],
        266,
        7,
        used,
    );
    let error = SeekArchiveReader::new(Cursor::new(named_stream)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );
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
    std::fs::write(destination, udf_image(BuildOptions::default())).unwrap();
}
