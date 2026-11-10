// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seek-capable ZIP streaming contracts.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

use libarchive_oxide::{
    ArchiveReader, ArchiveWriter, ReaderEvent, SeekArchiveReader, SeekArchiveWriter, ZipMethod,
};
use libarchive_oxide_core::{
    ArchiveMetadata, ArchivePath, Device, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Extension, FormatId, Limits, Owner, Timestamp,
};

fn zip_fixture(method: ZipMethod) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), method, Limits::default());
    let body = vec![b'a'; 200_000];
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("large.txt"))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).unwrap();
    for chunk in body.chunks(997) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

#[test]
fn zip_seek_reader_exposes_nonstructural_dos_attributes_as_file_flags() {
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
    let attributes = FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_DIRECTORY
        | FILE_ATTRIBUTE_ARCHIVE;
    let mut archive = zip_fixture(ZipMethod::Store);
    let central = archive
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .expect("ZIP central directory");
    let mut external = u32::from_le_bytes(archive[central + 38..central + 42].try_into().unwrap());
    external |= attributes;
    archive[central + 38..central + 42].copy_from_slice(&external.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("reader");
    assert!(matches!(
        reader.next_event().expect("archive metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().expect("entry") else {
        panic!("expected ZIP entry");
    };
    assert_eq!(
        metadata.file_flags(),
        u64::from(attributes & !FILE_ATTRIBUTE_DIRECTORY)
    );
}

#[test]
fn zip_archive_comment_roundtrips() {
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
    writer
        .set_archive_metadata(&ArchiveMetadata::new().with_comment(b"archive comment".to_vec()))
        .unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert_eq!(metadata.comment(), Some(b"archive comment".as_slice()));
        },
        other => panic!("expected ZIP archive metadata, got {other:?}"),
    }
}

#[test]
fn zip_writer_rejects_empty_typed_comments_before_entry_output() {
    let mut writer =
        SeekArchiveWriter::with_format(Cursor::new(Vec::new()), FormatId::Zip, Limits::default())
            .unwrap();
    let error = writer
        .set_archive_metadata(&ArchiveMetadata::new().with_comment(Vec::new()))
        .expect_err("ZIP cannot distinguish an empty archive comment from no comment");
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("empty.txt"))
        .size(Some(0))
        .comment(Some(Vec::new()))
        .build();
    let mut writer =
        SeekArchiveWriter::with_format(Cursor::new(Vec::new()), FormatId::Zip, Limits::default())
            .unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("ZIP cannot distinguish an empty file comment from no comment");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn iso_volume_metadata_roundtrips() {
    let volume_name = vec![b'V'; 32];
    let metadata = ArchiveMetadata::new()
        .with_volume_name(ArchivePath::from_bytes(volume_name.clone()))
        .with_extension(Extension::new(
            "iso9660-volume",
            b"system-id".to_vec(),
            b"ARCA".to_vec(),
        ))
        .with_extension(Extension::new(
            "iso9660-volume",
            b"application-id".to_vec(),
            b"LIBARCHIVE_OXIDE_TEST".to_vec(),
        ));
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
    .unwrap();
    writer.set_archive_metadata(&metadata).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert_eq!(
                metadata.volume_name().map(ArchivePath::as_bytes),
                Some(volume_name.as_slice())
            );
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "iso9660-volume"
                    && extension.key() == b"system-id"
                    && extension.value() == b"ARCA"
            }));
        },
        other => panic!("expected ISO archive metadata, got {other:?}"),
    }
}

#[test]
fn iso_archive_metadata_rejects_unrepresentable_volume_properties() {
    let cases = [
        ArchiveMetadata::new().with_volume_name(ArchivePath::from_utf8("lowercase")),
        ArchiveMetadata::new().with_volume_name(ArchivePath::from_bytes(vec![b'V'; 33])),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"unknown".to_vec(),
            b"opaque".to_vec(),
        )),
        ArchiveMetadata::new()
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                b"FIRST".to_vec(),
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                b"SECOND".to_vec(),
            )),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"system-id".to_vec(),
            vec![b'S'; 33],
        )),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"application-id".to_vec(),
            vec![b'A'; 129],
        )),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"system-id".to_vec(),
            Vec::new(),
        )),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"system-id".to_vec(),
            b"TRAILING\0".to_vec(),
        )),
        ArchiveMetadata::new().with_extension(Extension::new(
            "iso9660-volume",
            b"application-id".to_vec(),
            b"TRAILING ".to_vec(),
        )),
    ];

    for metadata in cases {
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::Iso9660,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .set_archive_metadata(&metadata)
            .expect_err("unrepresentable ISO volume metadata must fail closed");
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error:?}");
    }
}

fn minimum_seek_archive_metadata_budget(format: FormatId, metadata: &ArchiveMetadata) -> usize {
    let (mut low, mut high) = (0_usize, 4_096_usize);
    while low < high {
        let middle = low + (high - low) / 2;
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            format,
            Limits::default().with_metadata_bytes(Some(middle)),
        )
        .unwrap();
        match writer.set_archive_metadata(metadata) {
            Ok(()) => high = middle,
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::Limit, "{format:?}: {error:?}");
                low = middle + 1;
            },
        }
    }
    low
}

#[test]
fn iso_archive_metadata_replacement_uses_only_the_current_budget() {
    let first = ArchiveMetadata::new().with_extension(Extension::new(
        "iso9660-volume",
        b"application-id".to_vec(),
        b"FIRST_APPLICATION".to_vec(),
    ));
    let second = ArchiveMetadata::new().with_extension(Extension::new(
        "iso9660-volume",
        b"application-id".to_vec(),
        b"FINAL_APPLICATION".to_vec(),
    ));
    let budget = minimum_seek_archive_metadata_budget(FormatId::Iso9660, &first);
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default().with_metadata_bytes(Some(budget)),
    )
    .unwrap();
    writer.set_archive_metadata(&first).unwrap();
    writer
        .set_archive_metadata(&second)
        .expect("replacing equal-cost metadata must not double-count its budget");
    drop(writer);

    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
    .unwrap();
    writer.set_archive_metadata(&first).unwrap();
    writer.set_archive_metadata(&second).unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert!(metadata.extensions().iter().any(|extension| {
                extension.key() == b"application-id" && extension.value() == b"FINAL_APPLICATION"
            }));
        },
        event => panic!("expected ISO archive metadata, got {event:?}"),
    }
}

#[test]
fn iso_rejects_unrepresentable_entry_extensions() {
    let cases = [
        Extension::new("foreign", b"ZZ".to_vec(), vec![b'Z', b'Z', 4, 1]),
        Extension::new("iso-system-use", b"ZZ".to_vec(), vec![1, 2, 3]),
        Extension::new("iso-system-use", b"PX".to_vec(), vec![b'P', b'X', 4, 1]),
    ];

    for extension in cases {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .extension(extension)
            .build();
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::Iso9660,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("unrepresentable ISO entry extension must fail closed");
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error:?}");
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_archive_metadata_replacement_uses_only_the_current_budget() {
    let first = ArchiveMetadata::new().with_extension(Extension::new(
        "7z-archive-property",
        vec![0x7f],
        b"FIRST".to_vec(),
    ));
    let second = ArchiveMetadata::new().with_extension(Extension::new(
        "7z-archive-property",
        vec![0x7f],
        b"FINAL".to_vec(),
    ));
    let budget = minimum_seek_archive_metadata_budget(FormatId::SevenZip, &first);
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default().with_metadata_bytes(Some(budget)),
    )
    .unwrap();
    writer.set_archive_metadata(&first).unwrap();
    writer
        .set_archive_metadata(&second)
        .expect("replacing equal-cost metadata must not double-count its budget");
    let archive = writer.finish().unwrap().into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert!(
                metadata
                    .extensions()
                    .iter()
                    .any(|extension| extension.key() == [0x7f] && extension.value() == b"FINAL")
            );
        },
        event => panic!("expected 7z archive metadata, got {event:?}"),
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_unknown_archive_property_roundtrips() {
    let metadata = ArchiveMetadata::new().with_extension(Extension::new(
        "7z-archive-property",
        vec![0x7f],
        b"opaque".to_vec(),
    ));
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    writer.set_archive_metadata(&metadata).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "7z-archive-property"
                    && extension.key() == [0x7f]
                    && extension.value() == b"opaque"
            }));
        },
        other => panic!("expected 7z archive metadata, got {other:?}"),
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_unknown_files_property_roundtrips() {
    let property = 0x7e_u64.to_le_bytes().to_vec();
    let metadata = ArchiveMetadata::new().with_extension(Extension::new(
        "7z-files-property",
        property.clone(),
        b"opaque files property".to_vec(),
    ));
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    writer.set_archive_metadata(&metadata).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "7z-files-property"
                    && extension.key() == property
                    && extension.value() == b"opaque files property"
            }));
        },
        other => panic!("expected 7z archive metadata, got {other:?}"),
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_writer_rejects_reserved_raw_properties_before_entry_output() {
    let archive_end = ArchiveMetadata::new().with_extension(Extension::new(
        "7z-archive-property",
        vec![0x00],
        b"cannot follow an end marker".to_vec(),
    ));
    let reserved_file_properties = [
        0x00_u64, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x18,
    ];
    let cases = std::iter::once(archive_end).chain(reserved_file_properties.map(|property| {
        ArchiveMetadata::new().with_extension(Extension::new(
            "7z-files-property",
            property.to_le_bytes().to_vec(),
            b"container-owned".to_vec(),
        ))
    }));
    for metadata in cases {
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::SevenZip,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .set_archive_metadata(&metadata)
            .expect_err("7z writer must reject raw properties it cannot reproduce");
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error:?}");
    }
}

fn collect(bytes: Vec<u8>) -> Vec<u8> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.format(), FormatId::Zip);
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.path().as_bytes(), b"large.txt");
                assert_eq!(metadata.size(), Some(200_000));
            },
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::EndEntry | ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Done => return body,
            _ => panic!("unknown seek event"),
        }
    }
}

fn streaming_zip_fixture(method: ZipMethod) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), method, Limits::default());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("large.txt"))
        .size(None)
        .build();
    writer.start_entry(&metadata).unwrap();
    let body = vec![b'b'; 200_000];
    for chunk in body.chunks(997) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn iso_fixture() -> Vec<u8> {
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default(),
    )
    .unwrap();
    for (kind, path, body) in [
        (EntryKind::File, &b"HELLO.TXT"[..], &b"hello"[..]),
        (EntryKind::Dir, &b"SUB/"[..], &b""[..]),
        (
            EntryKind::File,
            &b"SUB/DATA.BIN"[..],
            &b"streamed ISO extent"[..],
        ),
    ] {
        let metadata = EntryMetadata::builder(kind, ArchivePath::from_bytes(path.to_vec()))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(body).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn iso_both_u16(value: u16) -> [u8; 4] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [little[0], little[1], big[0], big[1]]
}

fn iso_both_u32(value: u32) -> [u8; 8] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [
        little[0], little[1], little[2], little[3], big[0], big[1], big[2], big[3],
    ]
}

fn iso_record(identifier: &[u8], lba: u32, size: u32, flags: u8, susp: &[u8]) -> Vec<u8> {
    let padding = usize::from(identifier.len().is_multiple_of(2));
    let length = 33 + identifier.len() + padding + susp.len();
    let mut record = vec![0; length];
    record[0] = u8::try_from(length).unwrap();
    record[2..10].copy_from_slice(&iso_both_u32(lba));
    record[10..18].copy_from_slice(&iso_both_u32(size));
    record[18..25].copy_from_slice(&[126, 7, 19, 12, 0, 0, 0]);
    record[25] = flags;
    record[28..32].copy_from_slice(&iso_both_u16(1));
    record[32] = u8::try_from(identifier.len()).unwrap();
    record[33..33 + identifier.len()].copy_from_slice(identifier);
    record[33 + identifier.len() + padding..].copy_from_slice(susp);
    record
}

fn rr_field(signature: [u8; 2], value: &[u8]) -> Vec<u8> {
    let mut field = Vec::with_capacity(4 + value.len());
    field.extend_from_slice(&signature);
    field.push(u8::try_from(4 + value.len()).unwrap());
    field.push(1);
    field.extend_from_slice(value);
    field
}

fn rr_px(mode: u32, links: u32, uid: u32, gid: u32, inode: u32) -> Vec<u8> {
    let mut value = Vec::new();
    for number in [mode, links, uid, gid, inode] {
        value.extend_from_slice(&iso_both_u32(number));
    }
    rr_field(*b"PX", &value)
}

fn rock_ridge_iso_fixture() -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut image = vec![0; 22 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[40..47].copy_from_slice(b"RR_TEST");
    pvd[80..88].copy_from_slice(&iso_both_u32(22));
    pvd[120..124].copy_from_slice(&iso_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_both_u16(2048));
    let root = iso_record(&[0], 20, 2048, 0x02, &[]);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    let mut root_susp = rr_field(*b"SP", &[0xbe, 0xef, 0]);
    root_susp.extend_from_slice(&rr_field(*b"RR", &[0xff]));
    records.extend_from_slice(&iso_record(&[0], 20, 2048, 0x02, &root_susp));
    records.extend_from_slice(&iso_record(&[1], 20, 2048, 0x02, &[]));

    let mut file_susp = rr_field(*b"NM", &[&[0_u8][..], b"pretty.txt"].concat());
    file_susp.extend_from_slice(&rr_px(0o100_640, 1, 1000, 1001, 42));
    let mut tf = vec![0x02];
    tf.extend_from_slice(&[126, 7, 19, 12, 34, 56, 0]);
    file_susp.extend_from_slice(&rr_field(*b"TF", &tf));
    records.extend_from_slice(&iso_record(b"FILE.TXT;1", 21, 7, 0, &file_susp));

    let mut link_susp = rr_field(*b"NM", &[&[0_u8][..], b"link"].concat());
    link_susp.extend_from_slice(&rr_px(0o120_777, 1, 1000, 1001, 43));
    let mut sl = vec![0];
    sl.extend_from_slice(&[0, 10]);
    sl.extend_from_slice(b"pretty.txt");
    link_susp.extend_from_slice(&rr_field(*b"SL", &sl));
    records.extend_from_slice(&iso_record(b"LINK.;1", 21, 0, 0, &link_susp));

    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[21 * SECTOR..21 * SECTOR + 7].copy_from_slice(b"payload");
    image
}

fn multi_extent_iso_fixture() -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut image = vec![0; 24 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_both_u32(24));
    pvd[120..124].copy_from_slice(&iso_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_both_u16(2048));
    let root = iso_record(&[0], 20, 2048, 0x02, &[]);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    records.extend_from_slice(&iso_record(&[0], 20, 2048, 0x02, &[]));
    records.extend_from_slice(&iso_record(&[1], 20, 2048, 0x02, &[]));
    records.extend_from_slice(&iso_record(b"SPLIT.BIN;1", 21, 5, 0x80, &[]));
    records.extend_from_slice(&iso_record(b"SPLIT.BIN;1", 23, 6, 0, &[]));
    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[21 * SECTOR..21 * SECTOR + 5].copy_from_slice(b"first");
    image[22 * SECTOR..23 * SECTOR].fill(0xa5);
    image[23 * SECTOR..23 * SECTOR + 6].copy_from_slice(b"second");
    image
}

fn multi_extent_record_starts(image: &[u8]) -> Vec<usize> {
    image
        .windows(b"SPLIT.BIN;1".len())
        .enumerate()
        .filter_map(|(position, bytes)| {
            if bytes == b"SPLIT.BIN;1" {
                Some(position.checked_sub(33).unwrap())
            } else {
                None
            }
        })
        .collect()
}

fn multi_extent_extended_attribute_iso_fixture() -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut image = multi_extent_iso_fixture();
    image.resize(25 * SECTOR, 0);
    image[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(25));
    let records = multi_extent_record_starts(&image);
    for record in &records {
        image[*record + 1] = 1;
        image[*record + 25] |= 0x10;
    }

    let mut first_attributes = [0_u8; SECTOR];
    first_attributes[0..4].copy_from_slice(&iso_both_u16(110));
    first_attributes[4..8].copy_from_slice(&iso_both_u16(111));
    first_attributes[8..10].copy_from_slice(&0xffaa_u16.to_be_bytes());
    first_attributes[180] = 1;
    first_attributes[246..250].copy_from_slice(&iso_both_u16(0));
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&first_attributes);
    image[22 * SECTOR..22 * SECTOR + 5].copy_from_slice(b"first");

    let mut final_attributes = [0_u8; SECTOR];
    final_attributes[0..4].copy_from_slice(&iso_both_u16(120));
    final_attributes[4..8].copy_from_slice(&iso_both_u16(121));
    final_attributes[8..10].copy_from_slice(&0xfeaa_u16.to_be_bytes());
    final_attributes[180] = 1;
    final_attributes[246..250].copy_from_slice(&iso_both_u16(0));
    image[23 * SECTOR..24 * SECTOR].copy_from_slice(&final_attributes);
    image[24 * SECTOR..24 * SECTOR + 6].copy_from_slice(b"second");
    image
}

fn interleaved_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let payload = (0_u8..=250).cycle().take(5000).collect::<Vec<_>>();
    let mut image = vec![0; 27 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_both_u32(27));
    pvd[120..124].copy_from_slice(&iso_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_both_u16(2048));
    let root = iso_record(&[0], 20, 2048, 0x02, &[]);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    records.extend_from_slice(&iso_record(&[0], 20, 2048, 0x02, &[]));
    records.extend_from_slice(&iso_record(&[1], 20, 2048, 0x02, &[]));
    let mut file = iso_record(b"STRIPED.BIN;1", 21, 5000, 0, &[]);
    file[26] = 1;
    file[27] = 1;
    records.extend_from_slice(&file);
    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&payload[..SECTOR]);
    image[22 * SECTOR..23 * SECTOR].fill(0xa5);
    image[23 * SECTOR..24 * SECTOR].copy_from_slice(&payload[SECTOR..2 * SECTOR]);
    image[24 * SECTOR..25 * SECTOR].fill(0x5a);
    image[25 * SECTOR..25 * SECTOR + payload.len() - 2 * SECTOR]
        .copy_from_slice(&payload[2 * SECTOR..]);
    (image, payload)
}

fn interleaved_record_start(image: &[u8]) -> usize {
    image
        .windows(b"STRIPED.BIN;1".len())
        .position(|bytes| bytes == b"STRIPED.BIN;1")
        .unwrap()
        .checked_sub(33)
        .unwrap()
}

fn extended_attribute_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let (mut image, payload) = interleaved_iso_fixture();
    let record = interleaved_record_start(&image);
    image[record + 1] = 1;
    image[record + 25] |= 0x10;
    image[record + 26] = 0;
    image[record + 27] = 0;

    let mut attributes = [0_u8; SECTOR];
    attributes[0..4].copy_from_slice(&iso_both_u16(1000));
    attributes[4..8].copy_from_slice(&iso_both_u16(1001));
    attributes[8..10].copy_from_slice(&0xfeaa_u16.to_be_bytes());
    attributes[10..27].copy_from_slice(b"2026081501020300\0");
    attributes[27..44].copy_from_slice(b"2026081602030400\x04");
    attributes[84..116].fill(b' ');
    attributes[180] = 1;
    attributes[181] = 3;
    attributes[246..250].copy_from_slice(&iso_both_u16(4));
    attributes[250..254].copy_from_slice(b"meta");
    attributes[254..257].copy_from_slice(b"esc");
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&attributes);
    image[22 * SECTOR..22 * SECTOR + payload.len()].copy_from_slice(&payload);
    (image, payload)
}

fn root_extended_attribute_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let (mut image, payload) = interleaved_iso_fixture();
    let file_record = interleaved_record_start(&image) - 20 * SECTOR;
    let mut directory = [0_u8; SECTOR];
    directory.copy_from_slice(&image[20 * SECTOR..21 * SECTOR]);
    directory[1] = 1;
    let dotdot = usize::from(directory[0]);
    directory[dotdot + 1] = 1;
    directory[file_record + 2..file_record + 10].copy_from_slice(&iso_both_u32(22));
    directory[file_record + 26] = 0;
    directory[file_record + 27] = 0;

    let mut attributes = [0_u8; SECTOR];
    attributes[8..10].copy_from_slice(&0xaaaa_u16.to_be_bytes());
    attributes[180] = 1;
    attributes[246..250].copy_from_slice(&iso_both_u16(0));
    image[16 * SECTOR + 157] = 1;
    image[20 * SECTOR..21 * SECTOR].copy_from_slice(&attributes);
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&directory);
    image[22 * SECTOR..22 * SECTOR + payload.len()].copy_from_slice(&payload);
    (image, payload)
}

fn directory_extended_attribute_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    const SECTOR: usize = 2048;
    let payload = b"nested extended-attribute payload".to_vec();
    let mut image = vec![0; 24 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_both_u32(24));
    pvd[120..124].copy_from_slice(&iso_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_both_u16(2048));
    let root = iso_record(&[0], 20, 2048, 0x02, &[]);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut root_records = Vec::new();
    root_records.extend_from_slice(&iso_record(&[0], 20, 2048, 0x02, &[]));
    root_records.extend_from_slice(&iso_record(&[1], 20, 2048, 0x02, &[]));
    let mut directory = iso_record(b"SUB", 21, 2048, 0x12, &[]);
    directory[1] = 1;
    root_records.extend_from_slice(&directory);
    image[20 * SECTOR..20 * SECTOR + root_records.len()].copy_from_slice(&root_records);

    let mut attributes = [0_u8; SECTOR];
    attributes[0..4].copy_from_slice(&iso_both_u16(2000));
    attributes[4..8].copy_from_slice(&iso_both_u16(2001));
    attributes[8..10].copy_from_slice(&0xffaa_u16.to_be_bytes());
    attributes[180] = 1;
    attributes[246..250].copy_from_slice(&iso_both_u16(0));
    image[21 * SECTOR..22 * SECTOR].copy_from_slice(&attributes);

    let mut child_records = Vec::new();
    let mut dot = iso_record(&[0], 21, 2048, 0x12, &[]);
    dot[1] = 1;
    child_records.extend_from_slice(&dot);
    child_records.extend_from_slice(&iso_record(&[1], 20, 2048, 0x02, &[]));
    child_records.extend_from_slice(&iso_record(
        b"FILE.TXT;1",
        23,
        u32::try_from(payload.len()).unwrap(),
        0,
        &[],
    ));
    image[22 * SECTOR..22 * SECTOR + child_records.len()].copy_from_slice(&child_records);
    image[23 * SECTOR..23 * SECTOR + payload.len()].copy_from_slice(&payload);
    (image, payload)
}

#[cfg(feature = "sevenz")]
fn sevenz_fixture() -> Vec<u8> {
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    for (path, body) in [
        (&b"one.txt"[..], b"first payload".repeat(4096)),
        (&b"two.bin"[..], vec![0x5a; 180_000]),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).unwrap();
        for chunk in body.chunks(997) {
            writer.write_data(chunk).unwrap();
        }
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap().into_inner()
}

struct OneByteSeek {
    inner: Cursor<Vec<u8>>,
}

impl Read for OneByteSeek {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let maximum = output.len().min(1);
        self.inner.read(&mut output[..maximum])
    }
}

impl Seek for OneByteSeek {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[derive(Debug)]
struct ObservedCursor {
    inner: Cursor<Vec<u8>>,
    maximum_written_position: Rc<Cell<u64>>,
}

impl ObservedCursor {
    fn new(maximum_written_position: Rc<Cell<u64>>) -> Self {
        Self {
            inner: Cursor::new(Vec::new()),
            maximum_written_position,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.inner.into_inner()
    }
}

impl std::io::Write for ObservedCursor {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.maximum_written_position.set(
            self.maximum_written_position
                .get()
                .max(self.inner.position()),
        );
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for ObservedCursor {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[test]
fn zip_store_and_deflate_payloads_stream_without_whole_entry_vecs() {
    assert_eq!(collect(zip_fixture(ZipMethod::Store)), vec![b'a'; 200_000]);
    assert_eq!(
        collect(zip_fixture(ZipMethod::Deflate)),
        vec![b'a'; 200_000]
    );
    #[cfg(feature = "bzip2")]
    assert_eq!(collect(zip_fixture(ZipMethod::Bzip2)), vec![b'a'; 200_000]);
    #[cfg(feature = "zstd")]
    assert_eq!(collect(zip_fixture(ZipMethod::Zstd)), vec![b'a'; 200_000]);
    // LZMA read+write both use lzma-rust2 (both profiles).
    #[cfg(feature = "xz")]
    assert_eq!(collect(zip_fixture(ZipMethod::Lzma)), vec![b'a'; 200_000]);
    #[cfg(feature = "xz")]
    assert_eq!(collect(zip_fixture(ZipMethod::Xz)), vec![b'a'; 200_000]);
    #[cfg(feature = "ppmd")]
    assert_eq!(collect(zip_fixture(ZipMethod::Ppmd8)), vec![b'a'; 200_000]);
}

#[test]
fn common_writer_streams_unknown_size_zip_with_data_descriptors() {
    let methods = {
        #[allow(unused_mut)]
        let mut v = vec![ZipMethod::Store, ZipMethod::Deflate];
        #[cfg(feature = "bzip2")]
        v.push(ZipMethod::Bzip2);
        #[cfg(feature = "zstd")]
        v.push(ZipMethod::Zstd);
        #[cfg(feature = "xz")]
        v.push(ZipMethod::Lzma);
        #[cfg(feature = "xz")]
        v.push(ZipMethod::Xz);
        #[cfg(feature = "ppmd")]
        v.push(ZipMethod::Ppmd8);
        v
    };
    for method in methods {
        let archive = streaming_zip_fixture(method);
        assert_ne!(archive[6] & 0x08, 0);
        assert!(archive.windows(4).any(|window| window == b"PK\x07\x08"));
        assert_eq!(collect(archive), vec![b'b'; 200_000]);
    }
}

#[test]
fn sequential_zip_reads_supported_methods() {
    let mut reader = ArchiveReader::new(Cursor::new(zip_fixture(ZipMethod::Store)));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
}

#[test]
fn unsupported_coder_metadata_can_be_listed_and_skipped() {
    let mut bytes = zip_fixture(ZipMethod::Store);
    let central = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[8..10].copy_from_slice(&12_u16.to_le_bytes());
    bytes[central + 10..central + 12].copy_from_slice(&12_u16.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn unknown_zip_extra_is_preserved_by_streaming_roundtrip() {
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("extra.txt"))
        .size(Some(0))
        .extension(Extension::new(
            "zip-extra",
            0xcafe_u16.to_le_bytes().to_vec(),
            vec![1, 2, 3, 4],
        ))
        .build();
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let mut reader = SeekArchiveReader::new(Cursor::new(writer.finish().unwrap())).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("entry metadata expected");
    };
    assert!(metadata.extensions().iter().any(|extension| {
        extension.namespace() == "zip-extra"
            && extension.key() == 0xcafe_u16.to_le_bytes()
            && extension.value() == [1, 2, 3, 4]
    }));
}

fn zip_unicode_extra(id: u16, original: &[u8], utf8: &[u8]) -> Extension {
    let mut value = vec![1];
    value.extend_from_slice(&libarchive_oxide::filter::crc32(original).to_le_bytes());
    value.extend_from_slice(utf8);
    Extension::new("zip-extra", id.to_le_bytes().to_vec(), value)
}

fn replace_u16_all(bytes: &mut [u8], from: u16, to: u16) -> usize {
    let from = from.to_le_bytes();
    let to = to.to_le_bytes();
    let mut replacements = 0;
    for index in 0..bytes.len().saturating_sub(1) {
        if bytes[index..index + 2] == from {
            bytes[index..index + 2].copy_from_slice(&to);
            replacements += 1;
        }
    }
    replacements
}

fn filetime(seconds: i64) -> u64 {
    u64::try_from(i128::from(seconds) + 11_644_473_600).unwrap() * 10_000_000
}

#[test]
fn zip_unicode_and_timestamp_extras_are_typed_and_preserved() {
    let raw_name = b"legacy.txt";
    let raw_comment = b"legacy comment";
    let mut extended_times = vec![0x07];
    for seconds in [11_i32, 22, 33] {
        extended_times.extend_from_slice(&seconds.to_le_bytes());
    }
    let mut ntfs = vec![0; 4];
    ntfs.extend_from_slice(&1_u16.to_le_bytes());
    ntfs.extend_from_slice(&24_u16.to_le_bytes());
    for seconds in [1_700_000_001_i64, 1_700_000_002, 1_700_000_003] {
        ntfs.extend_from_slice(&filetime(seconds).to_le_bytes());
    }
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(raw_name.to_vec()))
            .size(None)
            .comment(Some(raw_comment.to_vec()))
            .times(EntryTimes {
                modified: Some(Timestamp::from_seconds(1_700_000_001)),
                accessed: Some(Timestamp::from_seconds(1_700_000_002)),
                changed: Some(Timestamp::from_seconds(33)),
                created: Some(Timestamp::from_seconds(1_700_000_003)),
            })
            // Write inert private IDs first, then patch the completed raw fixture below.
            // The public writer now correctly refuses metadata whose applicable Unicode extra would override its typed path/comment.
            .extension(zip_unicode_extra(0xcafe, raw_name, "正確.txt".as_bytes()))
            .extension(zip_unicode_extra(
                0xcaff,
                raw_comment,
                "正確なコメント".as_bytes(),
            ))
            .extension(Extension::new(
                "zip-extra",
                0x5455_u16.to_le_bytes().to_vec(),
                extended_times,
            ))
            .extension(Extension::new(
                "zip-extra",
                0x000a_u16.to_le_bytes().to_vec(),
                ntfs,
            ))
            .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"body").unwrap();
    writer.end_entry().unwrap();
    let mut archive = writer.finish().unwrap();
    assert_eq!(replace_u16_all(&mut archive, 0xcafe, 0x7075), 2);
    assert_eq!(replace_u16_all(&mut archive, 0xcaff, 0x6375), 2);
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("ZIP entry expected");
    };
    assert_eq!(metadata.path().as_bytes(), "正確.txt".as_bytes());
    assert_eq!(metadata.comment(), Some("正確なコメント".as_bytes()));
    assert_eq!(
        metadata.times().modified.map(Timestamp::seconds),
        Some(1_700_000_001)
    );
    assert_eq!(
        metadata.times().accessed.map(Timestamp::seconds),
        Some(1_700_000_002)
    );
    assert_eq!(
        metadata.times().created.map(Timestamp::seconds),
        Some(1_700_000_003)
    );
    assert_eq!(metadata.times().changed.map(Timestamp::seconds), Some(33));
    for id in [0x7075_u16, 0x6375, 0x5455, 0x000a] {
        assert!(
            metadata
                .extensions()
                .iter()
                .any(|extension| extension.key() == id.to_le_bytes())
        );
    }
}

fn read_single_entry(archive: Vec<u8>) -> EntryMetadata {
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("ZIP entry expected");
    };
    metadata
}

#[test]
fn zip_infozip_unix_extras_are_typed_as_owner() {
    // Info-ZIP New Unix (0x7855): uid(2), gid(2).
    let mut new_unix = Vec::new();
    new_unix.extend_from_slice(&1000_u16.to_le_bytes());
    new_unix.extend_from_slice(&1001_u16.to_le_bytes());
    // Info-ZIP Unix (0x5855): AcTime(4), ModTime(4), UID(2), GID(2).
    let mut old_unix = Vec::new();
    old_unix.extend_from_slice(&77_i32.to_le_bytes());
    old_unix.extend_from_slice(&88_i32.to_le_bytes());
    old_unix.extend_from_slice(&2000_u16.to_le_bytes());
    old_unix.extend_from_slice(&2001_u16.to_le_bytes());

    let new_meta = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("new.txt"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(1000),
            gid: Some(1001),
            ..Owner::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x7855_u16.to_le_bytes().to_vec(),
            new_unix,
        ))
        .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&new_meta).unwrap();
    writer.end_entry().unwrap();
    let read = read_single_entry(writer.finish().unwrap());
    assert_eq!(read.owner().uid, Some(1000));
    assert_eq!(read.owner().gid, Some(1001));

    let old_meta = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("old.txt"))
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(88)),
            accessed: Some(Timestamp::from_seconds(77)),
            ..EntryTimes::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x5855_u16.to_le_bytes().to_vec(),
            old_unix,
        ))
        .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&old_meta).unwrap();
    writer.end_entry().unwrap();
    let read = read_single_entry(writer.finish().unwrap());
    // The Info-ZIP UX (0x5855) central form is access/modification time only; the
    // uid/gid trailing this 12-byte body belong to the local-header layout and are
    // deliberately NOT read from the central directory (avoids a positional guess).
    assert_eq!(read.owner().uid, None);
    assert_eq!(read.owner().gid, None);
    assert_eq!(read.times().accessed.map(Timestamp::seconds), Some(77));
    assert_eq!(read.times().modified.map(Timestamp::seconds), Some(88));
}

#[test]
fn zip_preserved_time_extras_do_not_synthesize_a_second_timestamp() {
    // A raw field that already carries access/modification times (Info-ZIP UX
    // 0x5855, or NTFS 0x000a) must suppress the writer's synthesized Extended
    // Timestamp (0x5455) even when typed times are also present, so a round trip
    // never duplicates the timestamp payload across two extra fields.
    for id in [0x5855_u16, 0x000a] {
        let raw = if id == 0x5855 {
            let mut ux = Vec::new();
            ux.extend_from_slice(&55_i32.to_le_bytes());
            ux.extend_from_slice(&66_i32.to_le_bytes());
            ux
        } else {
            let mut ntfs = vec![0; 4];
            ntfs.extend_from_slice(&1_u16.to_le_bytes());
            ntfs.extend_from_slice(&24_u16.to_le_bytes());
            for seconds in [66_i64, 55, 44] {
                ntfs.extend_from_slice(&filetime(seconds).to_le_bytes());
            }
            ntfs
        };
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("t.txt"))
            .size(Some(0))
            .times(EntryTimes {
                modified: Some(Timestamp::from_seconds(66)),
                accessed: Some(Timestamp::from_seconds(55)),
                created: (id == 0x000a).then_some(Timestamp::from_seconds(44)),
                ..EntryTimes::default()
            })
            .extension(Extension::new("zip-extra", id.to_le_bytes().to_vec(), raw))
            .build();
        let mut writer =
            ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        let read = read_single_entry(writer.finish().unwrap());
        assert!(
            read.extensions()
                .iter()
                .any(|extension| extension.key() == id.to_le_bytes()),
            "raw time-bearing extra {id:#06x} should be preserved"
        );
        assert!(
            !read
                .extensions()
                .iter()
                .any(|extension| extension.key() == 0x5455_u16.to_le_bytes()),
            "no derived Extended Timestamp should be synthesized when {id:#06x} times exist"
        );
        assert_eq!(read.times().modified.map(Timestamp::seconds), Some(66));
    }
}

#[test]
fn zip_owner_and_timestamps_round_trip_as_derived_extras() {
    // Typed metadata carries no raw extras; the writer must synthesize the
    // Extended Timestamp (0x5455) and Info-ZIP New Unix (0x7855) fields, and the
    // reader must surface them again.
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("typed.txt"))
        .size(Some(4))
        .owner(Owner {
            uid: Some(4242),
            gid: Some(2424),
            ..Owner::default()
        })
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(1_700_000_100)),
            accessed: Some(Timestamp::from_seconds(1_700_000_200)),
            ..EntryTimes::default()
        })
        .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"body").unwrap();
    writer.end_entry().unwrap();
    let read = read_single_entry(writer.finish().unwrap());

    assert_eq!(read.owner().uid, Some(4242));
    assert_eq!(read.owner().gid, Some(2424));
    assert_eq!(
        read.times().modified.map(Timestamp::seconds),
        Some(1_700_000_100)
    );
    assert_eq!(
        read.times().accessed.map(Timestamp::seconds),
        Some(1_700_000_200)
    );
    for id in [0x5455_u16, 0x7855] {
        assert!(
            read.extensions()
                .iter()
                .any(|extension| extension.key() == id.to_le_bytes()),
            "derived extra {id:#06x} missing from round trip"
        );
    }
}

#[test]
fn zip_preserved_extended_timestamp_is_not_duplicated() {
    // An entry that already carries a raw Extended Timestamp must not gain a
    // second, writer-synthesized copy when its typed projection is coherent.
    let mut raw_timestamp = vec![0x01_u8];
    raw_timestamp.extend_from_slice(&123_i32.to_le_bytes());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("dup.txt"))
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(123)),
            ..EntryTimes::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x5455_u16.to_le_bytes().to_vec(),
            raw_timestamp,
        ))
        .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let read = read_single_entry(writer.finish().unwrap());
    let count = read
        .extensions()
        .iter()
        .filter(|extension| extension.key() == 0x5455_u16.to_le_bytes())
        .count();
    assert_eq!(count, 1, "Extended Timestamp extra was duplicated");
    assert_eq!(read.times().modified.map(Timestamp::seconds), Some(123));
}

#[test]
fn zip_short_infozip_unix_extra_is_not_misread() {
    // A truncated New Unix field (2 bytes, below the 4-byte uid+gid form) must be
    // ignored rather than silently misinterpreted into a bogus owner.
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("short.txt"))
        .size(Some(0))
        .extension(Extension::new(
            "zip-extra",
            0x7855_u16.to_le_bytes().to_vec(),
            vec![0x2a, 0x00],
        ))
        .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let read = read_single_entry(writer.finish().unwrap());
    assert_eq!(read.owner().uid, None);
    assert_eq!(read.owner().gid, None);
    // The unrecognized short field is still preserved verbatim.
    assert!(
        read.extensions()
            .iter()
            .any(|extension| extension.key() == 0x7855_u16.to_le_bytes())
    );
}

#[test]
fn zip_symlink_payload_is_exposed_as_a_typed_link_target() {
    let target = b"target/file.txt";
    let metadata =
        EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link-to-file"))
            .size(Some(target.len() as u64))
            .mode(Some(0o777))
            .link_target(Some(ArchivePath::from_utf8("target/file.txt")))
            .build();
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();

    let mut reader = SeekArchiveReader::new(Cursor::new(writer.finish().unwrap())).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("ZIP symbolic link expected");
    };
    assert_eq!(metadata.kind(), EntryKind::Symlink);
    assert_eq!(
        metadata.link_target().map(ArchivePath::as_bytes),
        Some(target.as_slice())
    );
}

#[test]
fn iso_index_and_file_extents_stream_through_the_seek_api() {
    let archive = iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive.clone())).unwrap();
    assert_eq!(reader.format(), FormatId::Iso9660);
    let mut entries = Vec::new();
    let mut current_path = Vec::new();
    let mut current_body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current_path = metadata.path().as_bytes().to_vec();
                assert!(metadata.size().is_some());
            },
            ReaderEvent::Data(bytes) => current_body.extend_from_slice(bytes),
            ReaderEvent::EndEntry => {
                entries.push((current_path.clone(), std::mem::take(&mut current_body)));
            },
            ReaderEvent::Done => break,
            _ => panic!("unknown seek event"),
        }
    }
    assert!(entries.contains(&(b"HELLO.TXT".to_vec(), b"hello".to_vec())));
    assert!(entries.contains(&(b"SUB/".to_vec(), Vec::new())));
    assert!(entries.contains(&(b"SUB/DATA.BIN".to_vec(), b"streamed ISO extent".to_vec())));

    let mut sequential = ArchiveReader::new(Cursor::new(archive));
    let error = sequential.next_event().unwrap_err();
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Capability)
    );
}

#[test]
fn iso_multi_extent_file_streams_noncontiguous_sections_in_record_order() {
    let mut reader = SeekArchiveReader::new(Cursor::new(multi_extent_iso_fixture()))
        .expect("open multi-extent ISO image");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("multi-extent file metadata expected");
    };
    assert_eq!(metadata.path().as_bytes(), b"SPLIT.BIN");
    assert_eq!(metadata.size(), Some(11));

    let mut payload = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected multi-extent event: {event:?}"),
        }
    }
    assert_eq!(payload, b"firstsecond");
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));

    let mut mixed = multi_extent_iso_fixture();
    let records = multi_extent_record_starts(&mixed);
    mixed[records[0] + 26] = 1;
    let mut reader = SeekArchiveReader::new(Cursor::new(mixed)).unwrap();
    let mut payload = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"firstsecond");
}

#[test]
fn iso_multi_extent_file_uses_final_extended_attributes_and_retains_each_record() {
    let mut reader =
        SeekArchiveReader::new(Cursor::new(multi_extent_extended_attribute_iso_fixture())).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("multi-extent EA metadata expected");
    };
    assert_eq!(metadata.mode(), Some(0o540));
    assert_eq!(metadata.owner().uid, Some(120));
    assert_eq!(metadata.owner().gid, Some(121));
    assert_eq!(
        metadata
            .extensions()
            .iter()
            .filter(|extension| extension.namespace() == "iso-extended-attribute")
            .count(),
        2
    );
    let mut payload = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"firstsecond");
}

#[test]
fn iso_multi_extent_file_requires_a_matching_final_record() {
    let mut unterminated = multi_extent_iso_fixture();
    let records = multi_extent_record_starts(&unterminated);
    assert_eq!(records.len(), 2);
    unterminated[records[1] + 25] |= 0x80;
    let error = SeekArchiveReader::new(Cursor::new(unterminated)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut mismatched = multi_extent_iso_fixture();
    let records = multi_extent_record_starts(&mismatched);
    mismatched[records[1] + 33] = b'X';
    let error = SeekArchiveReader::new(Cursor::new(mismatched)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_directory_identifier_padding_must_be_zero() {
    let mut archive = rock_ridge_iso_fixture();
    let identifier = b"FILE.TXT;1";
    let position = archive
        .windows(identifier.len())
        .position(|bytes| bytes == identifier)
        .unwrap();
    archive[position + identifier.len()] = 1;
    let error = SeekArchiveReader::new(Cursor::new(archive)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_directory_records_must_not_cross_a_logical_block() {
    const SECTOR: usize = 2048;
    let mut image = vec![0; 25 * SECTOR];
    let mut pvd = [0_u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&iso_both_u32(25));
    pvd[120..124].copy_from_slice(&iso_both_u16(1));
    pvd[124..128].copy_from_slice(&iso_both_u16(1));
    pvd[128..132].copy_from_slice(&iso_both_u16(2048));
    let root = iso_record(&[0], 20, 4096, 0x02, &[]);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    image[16 * SECTOR..17 * SECTOR].copy_from_slice(&pvd);
    image[17 * SECTOR] = 255;
    image[17 * SECTOR + 1..17 * SECTOR + 6].copy_from_slice(b"CD001");
    image[17 * SECTOR + 6] = 1;

    let mut records = Vec::new();
    records.extend_from_slice(&iso_record(&[0], 20, 4096, 0x02, &[]));
    records.extend_from_slice(&iso_record(&[1], 20, 4096, 0x02, &[]));
    for index in 0..7 {
        let identifier = format!("F{index}");
        let mut system_use = vec![0; 214];
        system_use[..4].copy_from_slice(&[b'Z', b'Z', 214, 1]);
        let filler = iso_record(identifier.as_bytes(), 24, 0, 0, &system_use);
        assert_eq!(filler.len(), 250);
        records.extend_from_slice(&filler);
    }
    let mut system_use = vec![0; 184];
    system_use[..4].copy_from_slice(&[b'Z', b'Z', 184, 1]);
    let filler = iso_record(b"F7", 24, 0, 0, &system_use);
    assert_eq!(filler.len(), 220);
    records.extend_from_slice(&filler);
    assert_eq!(records.len(), 2038);
    records.extend_from_slice(&iso_record(b"FILE.TXT;1", 24, 7, 0, &[]));
    image[20 * SECTOR..20 * SECTOR + records.len()].copy_from_slice(&records);
    image[24 * SECTOR..24 * SECTOR + 7].copy_from_slice(b"payload");

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_directory_block_padding_must_be_zero() {
    let (mut image, _) = interleaved_iso_fixture();
    let record = interleaved_record_start(&image);
    let padding_start = record + usize::from(image[record]);
    assert_eq!(image[padding_start], 0);
    image[padding_start + 17] = 0x7f;
    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_extents_stay_within_the_declared_volume_space() {
    const SECTOR: usize = 2048;

    let mut trailing_extent = multi_extent_iso_fixture();
    trailing_extent[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(23));
    let error = SeekArchiveReader::new(Cursor::new(trailing_extent)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut truncated_volume = multi_extent_iso_fixture();
    truncated_volume[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(25));
    let error = SeekArchiveReader::new(Cursor::new(truncated_volume)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut root_outside = multi_extent_iso_fixture();
    root_outside[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(20));
    let error = SeekArchiveReader::new(Cursor::new(root_outside)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut empty_volume = multi_extent_iso_fixture();
    empty_volume[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(0));
    let error = SeekArchiveReader::new(Cursor::new(empty_volume)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut inconsistent_endian = multi_extent_iso_fixture();
    inconsistent_endian[16 * SECTOR + 80..16 * SECTOR + 84].copy_from_slice(&24_u32.to_le_bytes());
    inconsistent_endian[16 * SECTOR + 84..16 * SECTOR + 88].copy_from_slice(&25_u32.to_be_bytes());
    let error = SeekArchiveReader::new(Cursor::new(inconsistent_endian)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut trailing_bytes = multi_extent_iso_fixture();
    trailing_bytes.extend_from_slice(&[0xa5; SECTOR]);
    SeekArchiveReader::new(Cursor::new(trailing_bytes)).unwrap();

    let (mut interleaved, _) = interleaved_iso_fixture();
    interleaved[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(25));
    let error = SeekArchiveReader::new(Cursor::new(interleaved)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_volume_descriptor_set_stays_within_the_declared_volume_space() {
    const SECTOR: usize = 2048;
    let mut image = multi_extent_iso_fixture();
    image[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(17));
    image[16 * SECTOR + 158..16 * SECTOR + 166].copy_from_slice(&iso_both_u32(1));

    let mut root = Vec::new();
    root.extend_from_slice(&iso_record(&[0], 1, 2048, 0x02, &[]));
    root.extend_from_slice(&iso_record(&[1], 1, 2048, 0x02, &[]));
    image[SECTOR..SECTOR + root.len()].copy_from_slice(&root);

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_root_directory_extent_stays_within_the_declared_volume_space() {
    const SECTOR: usize = 2048;
    let mut image = multi_extent_iso_fixture();
    image[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(21));
    image[16 * SECTOR + 166..16 * SECTOR + 174].copy_from_slice(&iso_both_u32(4096));
    image[20 * SECTOR..22 * SECTOR].fill(0);

    let mut root = Vec::new();
    root.extend_from_slice(&iso_record(&[0], 20, 4096, 0x02, &[]));
    root.extend_from_slice(&iso_record(&[1], 20, 4096, 0x02, &[]));
    image[20 * SECTOR..20 * SECTOR + root.len()].copy_from_slice(&root);

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_joliet_tree_uses_its_own_declared_volume_space() {
    const SECTOR: usize = 2048;
    let mut image = iso_fixture();
    assert_eq!(image[17 * SECTOR], 2);
    let primary_root_lba = u32::from_le_bytes(
        image[16 * SECTOR + 158..16 * SECTOR + 162]
            .try_into()
            .unwrap(),
    );
    image[usize::try_from(primary_root_lba).unwrap() * SECTOR] = 34;
    image[17 * SECTOR + 80..17 * SECTOR + 88].copy_from_slice(&iso_both_u32(19));

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_joliet_logical_block_size_is_validated() {
    const SECTOR: usize = 2048;
    let mut image = iso_fixture();
    assert_eq!(image[17 * SECTOR], 2);
    let primary_root_lba = u32::from_le_bytes(
        image[16 * SECTOR + 158..16 * SECTOR + 162]
            .try_into()
            .unwrap(),
    );
    image[usize::try_from(primary_root_lba).unwrap() * SECTOR] = 34;
    image[17 * SECTOR + 128..17 * SECTOR + 132].copy_from_slice(&iso_both_u16(4096));

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut inconsistent_endian = iso_fixture();
    inconsistent_endian[17 * SECTOR + 130..17 * SECTOR + 132]
        .copy_from_slice(&4096_u16.to_be_bytes());
    let error = SeekArchiveReader::new(Cursor::new(inconsistent_endian)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_descriptor_root_record_geometry_is_validated() {
    const SECTOR: usize = 2048;

    let mut zero_length = multi_extent_iso_fixture();
    zero_length[16 * SECTOR + 156] = 0;
    let error = SeekArchiveReader::new(Cursor::new(zero_length)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut invalid_identifier = multi_extent_iso_fixture();
    invalid_identifier[16 * SECTOR + 188] = 0;
    let error = SeekArchiveReader::new(Cursor::new(invalid_identifier)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut not_a_directory = multi_extent_iso_fixture();
    not_a_directory[16 * SECTOR + 181] = 0;
    let error = SeekArchiveReader::new(Cursor::new(not_a_directory)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut interleaved = multi_extent_iso_fixture();
    interleaved[16 * SECTOR + 182] = 1;
    let error = SeekArchiveReader::new(Cursor::new(interleaved)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_entry_on_another_volume_is_not_read_from_the_local_offset() {
    const SECTOR: usize = 2048;
    let mut image = multi_extent_iso_fixture();
    image[16 * SECTOR + 120..16 * SECTOR + 124].copy_from_slice(&iso_both_u16(2));
    let records = multi_extent_record_starts(&image);
    image[records[0] + 28..records[0] + 32].copy_from_slice(&iso_both_u16(2));

    let error = SeekArchiveReader::new(Cursor::new(image)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut later_section = multi_extent_iso_fixture();
    later_section[16 * SECTOR + 120..16 * SECTOR + 124].copy_from_slice(&iso_both_u16(2));
    let records = multi_extent_record_starts(&later_section);
    later_section[records[1] + 28..records[1] + 32].copy_from_slice(&iso_both_u16(2));
    let error = SeekArchiveReader::new(Cursor::new(later_section)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut local_member = multi_extent_iso_fixture();
    local_member[16 * SECTOR + 120..16 * SECTOR + 124].copy_from_slice(&iso_both_u16(2));
    SeekArchiveReader::new(Cursor::new(local_member)).unwrap();
}

#[test]
fn iso_volume_set_identifiers_are_structurally_valid() {
    const SECTOR: usize = 2048;

    let mut empty_set = multi_extent_iso_fixture();
    empty_set[16 * SECTOR + 120..16 * SECTOR + 124].copy_from_slice(&iso_both_u16(0));
    let error = SeekArchiveReader::new(Cursor::new(empty_set)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut sequence_outside_set = multi_extent_iso_fixture();
    sequence_outside_set[16 * SECTOR + 124..16 * SECTOR + 128].copy_from_slice(&iso_both_u16(2));
    let error = SeekArchiveReader::new(Cursor::new(sequence_outside_set)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut inconsistent_endian = multi_extent_iso_fixture();
    inconsistent_endian[16 * SECTOR + 120..16 * SECTOR + 122].copy_from_slice(&2_u16.to_le_bytes());
    let error = SeekArchiveReader::new(Cursor::new(inconsistent_endian)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut root_mismatch = multi_extent_iso_fixture();
    root_mismatch[16 * SECTOR + 184..16 * SECTOR + 188].copy_from_slice(&iso_both_u16(2));
    let error = SeekArchiveReader::new(Cursor::new(root_mismatch)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut record_endian = multi_extent_iso_fixture();
    let record = multi_extent_record_starts(&record_endian)[0];
    record_endian[record + 30..record + 32].copy_from_slice(&2_u16.to_be_bytes());
    let error = SeekArchiveReader::new(Cursor::new(record_endian)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn iso_multi_extent_file_checks_each_extent_and_aggregate_limits() {
    let mut outside = multi_extent_iso_fixture();
    let records = multi_extent_record_starts(&outside);
    outside[records[1] + 2..records[1] + 10].copy_from_slice(&iso_both_u32(24));
    let error = SeekArchiveReader::new(Cursor::new(outside)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let limits = Limits::default().with_entry_bytes(Some(10));
    let error = SeekArchiveReader::with_limits(Cursor::new(multi_extent_iso_fixture()), limits)
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let limits = Limits::default().with_decoded_total(Some(10));
    let mut reader =
        SeekArchiveReader::with_limits(Cursor::new(multi_extent_iso_fixture()), limits).unwrap();
    let error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("decoded-total limit unexpectedly accepted 11 bytes"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn iso_multi_extent_file_can_be_skipped_without_reading_section_gaps() {
    let mut reader = SeekArchiveReader::new(Cursor::new(multi_extent_iso_fixture())).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn iso_interleaved_file_streams_units_without_physical_gaps() {
    let (image, expected) = interleaved_iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(image)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("interleaved ISO file metadata expected");
    };
    assert_eq!(metadata.path().as_bytes(), b"STRIPED.BIN");
    assert_eq!(metadata.size(), Some(expected.len() as u64));
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected interleaved ISO event: {event:?}"),
        }
    }
    assert_eq!(decoded, expected);
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn iso_extended_attribute_record_shifts_payload_and_types_metadata() {
    let (image, expected) = extended_attribute_iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(image)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().unwrap() else {
        panic!("ISO extended-attribute file metadata expected");
    };
    assert_eq!(metadata.path().as_bytes(), b"STRIPED.BIN");
    assert_eq!(metadata.size(), Some(expected.len() as u64));
    assert_eq!(metadata.mode(), Some(0o540));
    assert_eq!(metadata.owner().uid, Some(1000));
    assert_eq!(metadata.owner().gid, Some(1001));
    assert_eq!(
        metadata.times().created,
        Some(Timestamp::from_seconds(1_786_755_723))
    );
    assert_eq!(
        metadata.times().modified,
        Some(Timestamp::from_seconds(1_786_842_184))
    );
    let extended = metadata
        .extensions()
        .iter()
        .find(|extension| {
            extension.namespace() == "iso-extended-attribute" && extension.key() == b"record"
        })
        .expect("raw ISO extended-attribute record");
    assert_eq!(extended.value().len(), 257);
    assert_eq!(&extended.value()[250..254], b"meta");
    assert_eq!(&extended.value()[254..], b"esc");

    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected extended-attribute ISO event: {event:?}"),
        }
    }
    assert_eq!(decoded, expected);
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn iso_root_extended_attribute_allocation_shifts_the_directory() {
    let (image, expected) = root_extended_attribute_iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(image)).unwrap();
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, expected);
}

#[test]
fn iso_directory_extended_attribute_shifts_children_and_types_metadata() {
    let (image, expected) = directory_extended_attribute_iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(image)).unwrap();
    let mut decoded = Vec::new();
    let mut saw_directory = false;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"SUB/" => {
                saw_directory = true;
                assert_eq!(metadata.kind(), EntryKind::Dir);
                assert_eq!(metadata.mode(), Some(0o500));
                assert_eq!(metadata.owner().uid, Some(2000));
                assert_eq!(metadata.owner().gid, Some(2001));
            },
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert!(saw_directory);
    assert_eq!(decoded, expected);
}

#[test]
fn iso_extended_attribute_record_validates_structure_and_limits() {
    const SECTOR: usize = 2048;

    let (mut unknown_version, _) = extended_attribute_iso_fixture();
    unknown_version[21 * SECTOR + 180] = 2;
    let error = SeekArchiveReader::new(Cursor::new(unknown_version)).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let (mut oversized_fields, _) = extended_attribute_iso_fixture();
    oversized_fields[21 * SECTOR + 246..21 * SECTOR + 250].copy_from_slice(&iso_both_u16(1800));
    let error = SeekArchiveReader::new(Cursor::new(oversized_fields)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut invalid_permissions, _) = extended_attribute_iso_fixture();
    let permissions = 0xfeaa_u16 & !0x0002;
    invalid_permissions[21 * SECTOR + 8..21 * SECTOR + 10]
        .copy_from_slice(&permissions.to_be_bytes());
    let error = SeekArchiveReader::new(Cursor::new(invalid_permissions)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut missing_record, _) = extended_attribute_iso_fixture();
    let record = interleaved_record_start(&missing_record);
    missing_record[record + 1] = 0;
    let error = SeekArchiveReader::new(Cursor::new(missing_record)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut unprotected_owner, _) = extended_attribute_iso_fixture();
    let record = interleaved_record_start(&unprotected_owner);
    unprotected_owner[record + 25] &= !0x10;
    let error = SeekArchiveReader::new(Cursor::new(unprotected_owner)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut record_mismatch, _) = extended_attribute_iso_fixture();
    record_mismatch[21 * SECTOR + 78] = 1;
    let error = SeekArchiveReader::new(Cursor::new(record_mismatch)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut invalid_date, _) = extended_attribute_iso_fixture();
    invalid_date[21 * SECTOR + 10..21 * SECTOR + 27].copy_from_slice(b"2026131501020300\0");
    let error = SeekArchiveReader::new(Cursor::new(invalid_date)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut outside_volume, _) = extended_attribute_iso_fixture();
    outside_volume[16 * SECTOR + 80..16 * SECTOR + 88].copy_from_slice(&iso_both_u32(21));
    let error = SeekArchiveReader::new(Cursor::new(outside_volume)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (plain, _) = interleaved_iso_fixture();
    let (extended, _) = extended_attribute_iso_fixture();
    let minimum_metadata_budget = |image: &[u8]| {
        let (mut low, mut high) = (0_usize, 4096_usize);
        while low < high {
            let middle = low + (high - low) / 2;
            match SeekArchiveReader::with_limits(
                Cursor::new(image.to_vec()),
                Limits::default().with_metadata_bytes(Some(middle)),
            ) {
                Ok(_) => high = middle,
                Err(error) => {
                    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
                    low = middle + 1;
                },
            }
        }
        low
    };
    let plain_budget = minimum_metadata_budget(&plain);
    let extended_budget = minimum_metadata_budget(&extended);
    assert_eq!(extended_budget - plain_budget, 257);
    SeekArchiveReader::with_limits(
        Cursor::new(plain),
        Limits::default().with_metadata_bytes(Some(plain_budget)),
    )
    .expect("the same entry without EA fits its exact metadata budget");
    let error = SeekArchiveReader::with_limits(
        Cursor::new(extended),
        Limits::default().with_metadata_bytes(Some(plain_budget)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let (mut bounded, payload) = extended_attribute_iso_fixture();
    let record = interleaved_record_start(&bounded);
    bounded[record + 1] = 2;
    bounded[21 * SECTOR + 246..21 * SECTOR + 250].copy_from_slice(&iso_both_u16(3000));
    bounded[23 * SECTOR..23 * SECTOR + payload.len()].copy_from_slice(&payload);
    let limits = Limits::default().with_in_flight_bytes(Some(SECTOR));
    let error = SeekArchiveReader::with_limits(Cursor::new(bounded), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn iso_interleaved_file_validates_layout_and_resource_limits() {
    let (mut missing_unit, _) = interleaved_iso_fixture();
    let record = interleaved_record_start(&missing_unit);
    missing_unit[record + 26] = 0;
    let error = SeekArchiveReader::new(Cursor::new(missing_unit)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut outside, _) = interleaved_iso_fixture();
    let record = interleaved_record_start(&outside);
    outside[record + 2..record + 10].copy_from_slice(&iso_both_u32(23));
    let error = SeekArchiveReader::new(Cursor::new(outside)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (mut dot_interleaved, _) = interleaved_iso_fixture();
    dot_interleaved[20 * 2048 + 26] = 1;
    let error = SeekArchiveReader::new(Cursor::new(dot_interleaved)).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let (image, _) = interleaved_iso_fixture();
    let limits = Limits::default().with_entry_bytes(Some(4999));
    let error = SeekArchiveReader::with_limits(Cursor::new(image), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let (image, _) = interleaved_iso_fixture();
    let limits = Limits::default().with_decoded_total(Some(4999));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(image), limits).unwrap();
    let error = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("decoded-total limit accepted interleaved payload"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn iso_interleaved_file_skip_uses_its_physical_end() {
    let (image, _) = interleaved_iso_fixture();
    let mut reader = SeekArchiveReader::new(Cursor::new(image)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn seek_format_detection_tolerates_short_reads() {
    for archive in [zip_fixture(ZipMethod::Store), iso_fixture()] {
        let mut reader = SeekArchiveReader::new(OneByteSeek {
            inner: Cursor::new(archive),
        })
        .unwrap();
        assert!(matches!(
            reader.next_event().unwrap(),
            ReaderEvent::ArchiveMetadata(_)
        ));
    }
}

#[test]
fn rock_ridge_metadata_is_typed_and_raw_fields_are_preserved() {
    let mut reader =
        SeekArchiveReader::new(Cursor::new(rock_ridge_iso_fixture())).expect("open RR image");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(file) = reader.next_event().unwrap() else {
        panic!("file metadata expected");
    };
    assert_eq!(file.path().as_bytes(), b"pretty.txt");
    assert_eq!(file.mode(), Some(0o640));
    assert_eq!(file.owner().uid, Some(1000));
    assert_eq!(file.owner().gid, Some(1001));
    assert_eq!(file.inode(), Some(42));
    assert!(file.times().modified.is_some());
    assert!(
        file.extensions()
            .iter()
            .any(|extension| extension.namespace() == "iso-system-use" && extension.key() == b"PX")
    );
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Data(b"payload")
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    let ReaderEvent::Entry(link) = reader.next_event().unwrap() else {
        panic!("link metadata expected");
    };
    assert_eq!(link.kind(), EntryKind::Symlink);
    assert_eq!(link.path().as_bytes(), b"link");
    assert_eq!(
        link.link_target().map(ArchivePath::as_bytes),
        Some(&b"pretty.txt"[..])
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn common_iso_writer_streams_payload_and_roundtrips_rock_ridge_metadata() {
    let maximum_written_position = Rc::new(Cell::new(0));
    let output = ObservedCursor::new(Rc::clone(&maximum_written_position));
    let mut writer =
        SeekArchiveWriter::with_format(output, FormatId::Iso9660, Limits::default()).unwrap();
    let timestamp = Timestamp::new(1_721_390_096, 120_000_000).expect("valid timestamp");
    let file = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sub/pretty.txt"))
        .size(None)
        .mode(Some(0o640))
        .owner(Owner {
            uid: Some(1000),
            gid: Some(1001),
            ..Owner::default()
        })
        .times(EntryTimes {
            modified: Some(timestamp),
            accessed: Some(timestamp),
            ..EntryTimes::default()
        })
        .inode_and_links(Some(42), Some(1))
        .extension(Extension::new(
            "iso-system-use",
            b"ZZ".to_vec(),
            vec![b'Z', b'Z', 7, 1, 1, 2, 3],
        ))
        .build();
    writer.start_entry(&file).unwrap();
    for _ in 0..256 {
        writer.write_data(b"streaming payload").unwrap();
    }
    assert!(
        maximum_written_position.get() > 19 * 2048,
        "file bytes must reach the ISO destination before finish"
    );
    writer.end_entry().unwrap();

    let directory = EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_utf8("sub/")).build();
    writer.start_entry(&directory).unwrap();
    writer.end_entry().unwrap();
    let symlink = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("sub/latest"))
        .link_target(Some(ArchivePath::from_utf8("pretty.txt")))
        .mode(Some(0o777))
        .build();
    writer.start_entry(&symlink).unwrap();
    writer.end_entry().unwrap();
    let device = EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("sub/console"))
        .devices(None, Some(Device { major: 5, minor: 1 }))
        .build();
    writer.start_entry(&device).unwrap();
    writer.end_entry().unwrap();
    let output = writer.finish().unwrap().into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).unwrap();
    assert_eq!(reader.format(), FormatId::Iso9660);
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let mut seen_file = false;
    let mut seen_link = false;
    let mut seen_device = false;
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"sub/pretty.txt" => {
                seen_file = true;
                assert_eq!(metadata.kind(), EntryKind::File);
                assert_eq!(metadata.mode(), Some(0o640));
                assert_eq!(metadata.owner().uid, Some(1000));
                assert_eq!(metadata.owner().gid, Some(1001));
                assert_eq!(metadata.inode(), Some(42));
                assert_eq!(metadata.times().modified, Some(timestamp));
                assert_eq!(metadata.times().accessed, Some(timestamp));
                assert!(metadata.extensions().iter().any(|extension| {
                    extension.key() == b"ZZ" && extension.value() == [b'Z', b'Z', 7, 1, 1, 2, 3]
                }));
            },
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"sub/latest" => {
                seen_link = true;
                assert_eq!(metadata.kind(), EntryKind::Symlink);
                assert_eq!(
                    metadata.link_target().map(ArchivePath::as_bytes),
                    Some(&b"pretty.txt"[..])
                );
            },
            ReaderEvent::Entry(metadata) if metadata.path().as_bytes() == b"sub/console" => {
                seen_device = true;
                assert_eq!(metadata.kind(), EntryKind::Char);
                assert_eq!(
                    metadata.referenced_device(),
                    Some(Device { major: 5, minor: 1 })
                );
            },
            ReaderEvent::Entry(_) | ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => panic!("unknown ISO event"),
        }
    }
    assert!(seen_file && seen_link && seen_device);
    assert_eq!(body, b"streaming payload".repeat(256));
}

#[test]
fn iso_writer_rejects_unrepresentable_timestamp_range_and_precision() {
    for timestamp in [
        Timestamp::from_seconds(253_402_300_800),
        Timestamp::new(1_700_000_000, 1).unwrap(),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("invalid-time.bin"))
                .size(Some(0))
                .times(EntryTimes {
                    modified: Some(timestamp),
                    ..EntryTimes::default()
                })
                .build();
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::Iso9660,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("ISO writer must reject a timestamp it cannot encode exactly");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }
}

#[test]
fn iso_timestamp_year_boundaries_roundtrip() {
    for (index, timestamp) in [
        Timestamp::from_seconds(-62_167_219_200),
        Timestamp::new(253_402_300_799, 990_000_000).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_utf8(format!("boundary-{index}.bin")),
        )
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(timestamp),
            ..EntryTimes::default()
        })
        .build();
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::Iso9660,
            Limits::default(),
        )
        .unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
        assert!(matches!(
            reader.next_event().unwrap(),
            ReaderEvent::ArchiveMetadata(_)
        ));
        let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
            panic!("ISO boundary entry missing");
        };
        assert_eq!(decoded.times().modified, Some(timestamp));
    }
}

#[test]
fn iso_writer_rejects_unrepresentable_typed_fields_before_entry_output() {
    let base =
        |kind| EntryMetadata::builder(kind, ArchivePath::from_utf8("entry.bin")).size(Some(0));
    let cases = vec![
        base(EntryKind::Hardlink)
            .link_target(Some(ArchivePath::from_utf8("target.bin")))
            .build(),
        base(EntryKind::File)
            .owner(Owner {
                user: Some(b"alice".to_vec()),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File)
            .owner(Owner {
                uid: Some(u64::from(u32::MAX) + 1),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File).mode(Some(0o10_000)).build(),
        base(EntryKind::File)
            .inode_and_links(Some(u64::from(u32::MAX) + 1), Some(1))
            .build(),
        base(EntryKind::File)
            .inode_and_links(Some(1), Some(u64::from(u32::MAX) + 1))
            .build(),
        base(EntryKind::File)
            .devices(Some(Device { major: 1, minor: 2 }), None)
            .build(),
        base(EntryKind::Char)
            .devices(
                None,
                Some(Device {
                    major: u64::from(u32::MAX) + 1,
                    minor: 0,
                }),
            )
            .build(),
        base(EntryKind::File).file_flags(1).build(),
        base(EntryKind::File)
            .comment(Some(b"comment".to_vec()))
            .build(),
    ];
    for metadata in cases {
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::Iso9660,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("ISO direct writer must fail closed on lossy typed metadata");
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error:?}");
    }
}

#[test]
fn iso_writer_rejects_oversized_declared_file_before_entry_output() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("large.bin"))
        .size(Some(u64::from(u32::MAX) + 1))
        .build();
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::Iso9660,
        Limits::default().with_entry_bytes(None),
    )
    .unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("ISO declared file size must fit its u32 directory record");
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_writer_rejects_unrepresentable_timestamp_range_and_precision() {
    for timestamp in [
        Timestamp::from_seconds(-11_644_473_601),
        Timestamp::from_seconds(i64::MAX),
        Timestamp::new(1_700_000_000, 1).unwrap(),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("invalid-time.bin"))
                .size(Some(0))
                .times(EntryTimes {
                    modified: Some(timestamp),
                    ..EntryTimes::default()
                })
                .build();
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::SevenZip,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("7z writer must reject a timestamp it cannot encode exactly");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_filetime_boundaries_roundtrip() {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;
    let maximum = Timestamp::new(
        i64::try_from(u64::MAX / TICKS_PER_SECOND).unwrap() - FILETIME_EPOCH_DIFF,
        u32::try_from(u64::MAX % TICKS_PER_SECOND).unwrap() * 100,
    )
    .unwrap();
    for (index, timestamp) in [Timestamp::from_seconds(-FILETIME_EPOCH_DIFF), maximum]
        .into_iter()
        .enumerate()
    {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_utf8(format!("filetime-{index}.bin")),
        )
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(timestamp),
            ..EntryTimes::default()
        })
        .build();
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::SevenZip,
            Limits::default(),
        )
        .unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
        assert!(matches!(
            reader.next_event().unwrap(),
            ReaderEvent::ArchiveMetadata(_)
        ));
        let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
            panic!("7z FILETIME boundary entry missing");
        };
        assert_eq!(decoded.times().modified, Some(timestamp));
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_windows_file_attributes_roundtrip_as_typed_file_flags() {
    const FILE_ATTRIBUTE_READONLY: u64 = 0x0000_0001;
    const FILE_ATTRIBUTE_HIDDEN: u64 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u64 = 0x0000_0004;
    const FILE_ATTRIBUTE_ARCHIVE: u64 = 0x0000_0020;
    let file_flags = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_ARCHIVE;
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("attributes.bin"))
            .size(Some(0))
            .mode(Some(0o640))
            .file_flags(file_flags)
            .build();
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .expect("writer");
    writer.start_entry(&metadata).expect("start entry");
    writer.end_entry().expect("end entry");
    let archive = writer.finish().expect("finish").into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("reader");
    assert!(matches!(
        reader.next_event().expect("archive metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().expect("entry") else {
        panic!("7z file-attribute entry missing");
    };
    assert_eq!(decoded.mode(), Some(0o640));
    assert_eq!(decoded.file_flags(), file_flags);
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_writer_rejects_unrepresentable_typed_entry_metadata() {
    let base =
        |kind| EntryMetadata::builder(kind, ArchivePath::from_utf8("entry.bin")).size(Some(0));
    let cases = vec![
        base(EntryKind::Char).build(),
        base(EntryKind::File)
            .owner(Owner {
                uid: Some(1),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File).mode(Some(0)).build(),
        base(EntryKind::File)
            .inode_and_links(Some(1), Some(1))
            .build(),
        base(EntryKind::File)
            .devices(Some(Device { major: 1, minor: 2 }), None)
            .build(),
        base(EntryKind::File)
            .xattr(b"user.test".to_vec(), b"value".to_vec())
            .build(),
        base(EntryKind::File).acl(b"acl".to_vec()).build(),
        base(EntryKind::File).file_flags(1_u64 << 32).build(),
        base(EntryKind::File).file_flags(0x0000_0010).build(),
        base(EntryKind::File).file_flags(0x0000_8000).build(),
        base(EntryKind::File).encrypted(true).build(),
        base(EntryKind::File)
            .comment(Some(b"comment".to_vec()))
            .build(),
        base(EntryKind::File)
            .extension(Extension::new(
                "7z-entry-property",
                b"key".to_vec(),
                b"value".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(vec![0xff, b'.', b'b', b'i', b'n']),
        )
        .size(Some(0))
        .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("nul\0name"))
            .size(Some(0))
            .build(),
        EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_utf8("dir"))
            .size(Some(1))
            .build(),
    ];
    for metadata in cases {
        let mut writer = SeekArchiveWriter::with_format(
            Cursor::new(Vec::new()),
            FormatId::SevenZip,
            Limits::default(),
        )
        .unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("7z direct writer must fail closed on lossy typed metadata");
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error:?}");
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_solid_folder_streams_across_file_boundaries() {
    let mut reader = SeekArchiveReader::new(Cursor::new(sevenz_fixture())).unwrap();
    assert_eq!(reader.format(), FormatId::SevenZip);
    let mut paths = Vec::new();
    let mut bodies = Vec::new();
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => paths.push(metadata.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::EndEntry => bodies.push(std::mem::take(&mut body)),
            ReaderEvent::Done => break,
            _ => panic!("unknown 7z event"),
        }
    }
    assert_eq!(paths, [b"one.txt".to_vec(), b"two.bin".to_vec()]);
    assert_eq!(bodies[0], b"first payload".repeat(4096));
    assert_eq!(bodies[1], vec![0x5a; 180_000]);
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_unsupported_coder_still_allows_metadata_listing() {
    let mut archive = sevenz_fixture();
    let header_offset =
        32 + usize::try_from(u64::from_le_bytes(archive[12..20].try_into().unwrap())).unwrap();
    let header_size =
        usize::try_from(u64::from_le_bytes(archive[20..28].try_into().unwrap())).unwrap();
    let header_end = header_offset + header_size;
    let coder = archive[header_offset..header_end]
        .windows(4)
        .position(|window| window == [0x01, 0x21, 0x21, 0x01])
        .unwrap()
        + header_offset
        + 2;
    archive[coder] = 0x22;
    let header_crc = libarchive_oxide::filter::crc32(&archive[header_offset..header_end]);
    archive[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let start_crc = libarchive_oxide::filter::crc32(&archive[12..32]);
    archive[8..12].copy_from_slice(&start_crc.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
}

#[cfg(feature = "sevenz")]
#[test]
fn common_sevenz_writer_streams_payload_and_roundtrips() {
    let maximum_written_position = Rc::new(Cell::new(0));
    let output = ObservedCursor::new(Rc::clone(&maximum_written_position));
    let mut writer =
        SeekArchiveWriter::with_format(output, FormatId::SevenZip, Limits::default()).unwrap();
    let first = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("one.bin"))
        .size(None)
        .build();
    writer.start_entry(&first).unwrap();
    let chunk = vec![0x5a; 64 * 1024];
    for _ in 0..48 {
        writer.write_data(&chunk).unwrap();
    }
    assert!(
        maximum_written_position.get() > 32,
        "compressed bytes must reach the destination before finish"
    );
    writer.end_entry().unwrap();
    let directory = EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_utf8("empty/"))
        .size(Some(0))
        .build();
    writer.start_entry(&directory).unwrap();
    writer.end_entry().unwrap();
    let output = writer.finish().unwrap();

    let mut reader = SeekArchiveReader::new(Cursor::new(output.into_inner())).unwrap();
    let mut entries = Vec::new();
    let mut current = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                entries.push((
                    metadata.path().as_bytes().to_vec(),
                    metadata.kind(),
                    Vec::new(),
                ));
            },
            ReaderEvent::Data(bytes) => current.extend_from_slice(bytes),
            ReaderEvent::EndEntry => {
                entries.last_mut().unwrap().2 = std::mem::take(&mut current);
            },
            ReaderEvent::Done => break,
            _ => panic!("unknown 7z event"),
        }
    }
    assert_eq!(entries[0].0, b"one.bin");
    assert_eq!(entries[0].1, EntryKind::File);
    assert_eq!(entries[0].2, chunk.repeat(48));
    assert_eq!(entries[1], (b"empty".to_vec(), EntryKind::Dir, Vec::new()));
}

#[cfg(feature = "sevenz")]
#[test]
fn common_sevenz_writer_rejects_declared_size_mismatch() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("bad.bin"))
        .size(Some(4))
        .build();
    let mut writer = SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        Limits::default(),
    )
    .unwrap();
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"three").unwrap();
    let error = writer.end_entry().unwrap_err();
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Protocol)
    );
}

// ---------------------------------------------------------------------------
// ZIP BZip2 (method 12) adversarial contracts.
// ---------------------------------------------------------------------------

#[cfg(feature = "bzip2")]
fn raw_bzip2_zip(content: &[u8], body_override: Option<Vec<u8>>) -> Vec<u8> {
    use std::io::Write;

    let full = {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(content).unwrap();
        e.finish().unwrap()
    };
    let body = body_override.unwrap_or(full);
    let crc = {
        let mut c = flate2::Crc::new();
        c.update(content);
        c.sum()
    };
    let name = b"member.bin";
    let mut out = Vec::new();
    let put16 = |o: &mut Vec<u8>, v: u16| o.extend_from_slice(&v.to_le_bytes());
    let put32 = |o: &mut Vec<u8>, v: u32| o.extend_from_slice(&v.to_le_bytes());
    let local_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x03\x04");
    put16(&mut out, 46);
    put16(&mut out, 0);
    put16(&mut out, 12);
    put16(&mut out, 0);
    put16(&mut out, 0x21);
    put32(&mut out, crc);
    put32(&mut out, body.len() as u32);
    put32(&mut out, content.len() as u32);
    put16(&mut out, name.len() as u16);
    put16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&body);
    let central_offset = out.len() as u32;
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    put16(&mut central, 0x031e);
    put16(&mut central, 46);
    put16(&mut central, 0);
    put16(&mut central, 12);
    put16(&mut central, 0);
    put16(&mut central, 0x21);
    put32(&mut central, crc);
    put32(&mut central, body.len() as u32);
    put32(&mut central, content.len() as u32);
    put16(&mut central, name.len() as u16);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put32(&mut central, 0);
    put32(&mut central, local_offset);
    central.extend_from_slice(name);
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, 1);
    put16(&mut out, 1);
    put32(&mut out, central_size);
    put32(&mut out, central_offset);
    put16(&mut out, 0);
    out
}

#[cfg(feature = "bzip2")]
#[test]
fn zip_bzip2_roundtrips_through_seek_reader() {
    let content = b"bzip2 payload for the seek reader\n".repeat(50);
    let bytes = raw_bzip2_zip(&content, None);
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(body, content);
}

#[cfg(feature = "bzip2")]
#[test]
fn zip_bzip2_truncated_payload_is_structured_error() {
    let content = b"bzip2 payload that will be truncated\n".repeat(50);
    let full = {
        use std::io::Write;
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(&content).unwrap();
        e.finish().unwrap()
    };
    // Drop the trailing footer/CRC so the declared compressed_size matches the
    // truncated body and the decoder runs out of input before StreamEnd.
    let truncated = full[..full.len() - 4].to_vec();
    let bytes = raw_bzip2_zip(&content, Some(truncated));
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("truncated bzip2 stream must fail");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

#[cfg(feature = "bzip2")]
#[test]
fn zip_bzip2_bomb_is_bounded_by_limits() {
    let content = vec![0_u8; 1 << 20];
    let bytes = raw_bzip2_zip(&content, None);
    let limits = Limits::default().with_decoded_total(Some(4096));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("bzip2 bomb must be bounded by limits");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

#[cfg(not(feature = "bzip2"))]
#[test]
fn zip_method_12_is_unsupported_without_bzip2_feature() {
    let mut bytes = zip_fixture(ZipMethod::Store);
    let central = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[8..10].copy_from_slice(&12_u16.to_le_bytes());
    bytes[central + 10..central + 12].copy_from_slice(&12_u16.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
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
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

// ---------------------------------------------------------------------------
// ZIP Zstandard (method 93) contracts.
//
// READ is exercised on BOTH profiles via a first-party raw-ZIP builder whose
// body is a raw zstd frame from the independent-C `zstd` crate (dev-dep
// `zstd-codec`). WRITE-without-encoder (portable) and feature-off degradation
// are asserted to produce structured errors, never panics.
// ---------------------------------------------------------------------------

#[cfg(feature = "zstd")]
fn raw_zstd_zip(content: &[u8], body_override: Option<Vec<u8>>) -> Vec<u8> {
    let full = zstd_codec::stream::encode_all(Cursor::new(content), 3).unwrap();
    let body = body_override.unwrap_or(full);
    let crc = {
        let mut c = flate2::Crc::new();
        c.update(content);
        c.sum()
    };
    let name = b"member.bin";
    let mut out = Vec::new();
    let put16 = |o: &mut Vec<u8>, v: u16| o.extend_from_slice(&v.to_le_bytes());
    let put32 = |o: &mut Vec<u8>, v: u32| o.extend_from_slice(&v.to_le_bytes());
    let local_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x03\x04");
    put16(&mut out, 63);
    put16(&mut out, 0);
    put16(&mut out, 93);
    put16(&mut out, 0);
    put16(&mut out, 0x21);
    put32(&mut out, crc);
    put32(&mut out, body.len() as u32);
    put32(&mut out, content.len() as u32);
    put16(&mut out, name.len() as u16);
    put16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&body);
    let central_offset = out.len() as u32;
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    put16(&mut central, 0x031e);
    put16(&mut central, 63);
    put16(&mut central, 0);
    put16(&mut central, 93);
    put16(&mut central, 0);
    put16(&mut central, 0x21);
    put32(&mut central, crc);
    put32(&mut central, body.len() as u32);
    put32(&mut central, content.len() as u32);
    put16(&mut central, name.len() as u16);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put32(&mut central, 0);
    put32(&mut central, local_offset);
    central.extend_from_slice(name);
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, 1);
    put16(&mut out, 1);
    put32(&mut out, central_size);
    put32(&mut out, central_offset);
    put16(&mut out, 0);
    out
}

#[cfg(feature = "zstd")]
#[test]
fn zip_zstd_roundtrips_through_seek_reader() {
    let content = b"zstd payload for the seek reader\n".repeat(50);
    let bytes = raw_zstd_zip(&content, None);
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(body, content);
}

#[cfg(feature = "zstd")]
#[test]
fn zip_zstd_truncated_payload_is_structured_error() {
    let content = b"zstd payload that will be truncated\n".repeat(50);
    let full = zstd_codec::stream::encode_all(Cursor::new(&content), 3).unwrap();
    // Cut the frame in half so the declared compressed_size matches the
    // truncated body and the decoder runs out of input before its terminal block.
    let truncated = full[..full.len() / 2].to_vec();
    let bytes = raw_zstd_zip(&content, Some(truncated));
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("truncated zstd stream must fail");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

#[cfg(feature = "zstd")]
#[test]
fn zip_zstd_bomb_is_bounded_by_limits() {
    let content = vec![0_u8; 1 << 20];
    let bytes = raw_zstd_zip(&content, None);
    let limits = Limits::default().with_decoded_total(Some(4096));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("zstd bomb must be bounded by limits");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

// Portable method-93 production is a real streaming writer, not a deferred
// Unsupported selection.
#[cfg(all(feature = "zstd", not(feature = "native-codecs")))]
#[test]
fn portable_zip_zstd_write_roundtrips() {
    assert_eq!(collect(zip_fixture(ZipMethod::Zstd)), vec![b'a'; 200_000]);
}

// Feature-off: method 93 falls through to the structured Unsupported error and
// still enumerates via end_offset (identical to the bzip2-off behavior).
#[cfg(not(feature = "zstd"))]
#[test]
fn zip_method_93_is_unsupported_without_zstd_feature() {
    let mut bytes = zip_fixture(ZipMethod::Store);
    let central = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[8..10].copy_from_slice(&93_u16.to_le_bytes());
    bytes[central + 10..central + 12].copy_from_slice(&93_u16.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
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
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}

// ---------------------------------------------------------------------------
// ZIP LZMA (method 14) adversarial contracts.
//
// READ is exercised via a first-party raw-ZIP builder whose body is a raw
// LZMA1 stream (9-byte ZIP-LZMA header + EOS marker) from `lzma-rust2`.
// Truncation and decompression-bomb inputs must surface structured errors;
// feature-off degradation is asserted separately.
// ---------------------------------------------------------------------------

#[cfg(feature = "xz")]
fn raw_lzma_zip(content: &[u8], body_override: Option<Vec<u8>>) -> Vec<u8> {
    use std::io::Write;

    let full = {
        let options = lzma_rust2::LzmaOptions::with_preset(6);
        let mut sink = Vec::new();
        sink.extend_from_slice(&[9, 20]);
        sink.extend_from_slice(&5_u16.to_le_bytes());
        sink.push(options.get_props());
        sink.extend_from_slice(&options.dict_size.to_le_bytes());
        let mut writer = lzma_rust2::LzmaWriter::new_no_header(sink, &options, true).unwrap();
        writer.write_all(content).unwrap();
        writer.finish().unwrap()
    };
    let body = body_override.unwrap_or(full);
    let crc = {
        let mut c = flate2::Crc::new();
        c.update(content);
        c.sum()
    };
    let name = b"member.bin";
    let mut out = Vec::new();
    let put16 = |o: &mut Vec<u8>, v: u16| o.extend_from_slice(&v.to_le_bytes());
    let put32 = |o: &mut Vec<u8>, v: u32| o.extend_from_slice(&v.to_le_bytes());
    let local_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x03\x04");
    put16(&mut out, 63);
    put16(&mut out, 0x0002);
    put16(&mut out, 14);
    put16(&mut out, 0);
    put16(&mut out, 0x21);
    put32(&mut out, crc);
    put32(&mut out, body.len() as u32);
    put32(&mut out, content.len() as u32);
    put16(&mut out, name.len() as u16);
    put16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&body);
    let central_offset = out.len() as u32;
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    put16(&mut central, 0x031e);
    put16(&mut central, 63);
    put16(&mut central, 0x0002);
    put16(&mut central, 14);
    put16(&mut central, 0);
    put16(&mut central, 0x21);
    put32(&mut central, crc);
    put32(&mut central, body.len() as u32);
    put32(&mut central, content.len() as u32);
    put16(&mut central, name.len() as u16);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put16(&mut central, 0);
    put32(&mut central, 0);
    put32(&mut central, local_offset);
    central.extend_from_slice(name);
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, 1);
    put16(&mut out, 1);
    put32(&mut out, central_size);
    put32(&mut out, central_offset);
    put16(&mut out, 0);
    out
}

#[cfg(feature = "xz")]
#[test]
fn zip_lzma_roundtrips_through_seek_reader() {
    let content = b"lzma payload for the seek reader\n".repeat(50);
    let bytes = raw_lzma_zip(&content, None);
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(body, content);
}

#[cfg(feature = "xz")]
#[test]
fn zip_lzma_empty_member_roundtrips_through_seek_reader() {
    // EOS-only stream (zero-length LZMA read edge; mirrors the fixture's
    // sub/empty.txt member).
    let bytes = raw_lzma_zip(b"", None);
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(body.len(), 0);
}

#[cfg(feature = "xz")]
#[test]
fn zip_lzma_truncated_payload_is_structured_error() {
    let content = b"lzma payload that will be truncated\n".repeat(50);
    let full = {
        use std::io::Write;
        let options = lzma_rust2::LzmaOptions::with_preset(6);
        let mut sink = Vec::new();
        sink.extend_from_slice(&[9, 20]);
        sink.extend_from_slice(&5_u16.to_le_bytes());
        sink.push(options.get_props());
        sink.extend_from_slice(&options.dict_size.to_le_bytes());
        let mut writer = lzma_rust2::LzmaWriter::new_no_header(sink, &options, true).unwrap();
        writer.write_all(&content).unwrap();
        writer.finish().unwrap()
    };
    // Cut the raw stream short so the known uncompressed size is never reached
    // and no end marker arrives: the decoder must surface a structured error.
    let truncated = full[..full.len() / 2].to_vec();
    let bytes = raw_lzma_zip(&content, Some(truncated));
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("truncated lzma stream must fail");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

#[cfg(feature = "xz")]
#[test]
fn zip_lzma_bad_property_size_is_structured_error() {
    // A ZIP-LZMA header whose prop_size != 5 must be rejected as Malformed.
    let content = b"lzma payload with a corrupt header\n".repeat(10);
    let mut bytes = raw_lzma_zip(&content, None);
    // The first member body starts at local_offset(0) + 30 + name_len(10).
    // Bytes [2..4] of the 9-byte header are prop_size; corrupt them to 4.
    let header_prop_size = 30 + 10 + 2;
    bytes[header_prop_size..header_prop_size + 2].copy_from_slice(&4_u16.to_le_bytes());
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("bad LZMA property size must fail");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Malformed)
    );
}

#[cfg(feature = "xz")]
#[test]
fn zip_lzma_bomb_is_bounded_by_limits() {
    let content = vec![0_u8; 1 << 20];
    let bytes = raw_lzma_zip(&content, None);
    let limits = Limits::default().with_decoded_total(Some(4096));
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits).unwrap();
    let mut error = None;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => break,
            Ok(_) => {},
            Err(e) => {
                error = Some(e);
                break;
            },
        }
    }
    let error = error.expect("lzma bomb must be bounded by limits");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

// Feature-off: method 14 falls through to the structured Unsupported error and
// still enumerates via end_offset (identical to the bzip2/zstd-off behavior).
#[cfg(not(feature = "xz"))]
#[test]
fn zip_method_14_is_unsupported_without_xz_feature() {
    let mut bytes = zip_fixture(ZipMethod::Store);
    let central = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[8..10].copy_from_slice(&14_u16.to_le_bytes());
    bytes[central + 10..central + 12].copy_from_slice(&14_u16.to_le_bytes());

    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).unwrap();
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
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
}
