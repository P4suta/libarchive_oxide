// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seek-capable ZIP streaming contracts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

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
fn iso_volume_metadata_roundtrips() {
    let metadata = ArchiveMetadata::new()
        .with_volume_name(ArchivePath::from_utf8("MY_VOLUME"))
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
                Some(b"MY_VOLUME".as_slice())
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
}

#[test]
fn common_writer_streams_unknown_size_zip_with_data_descriptors() {
    for method in [ZipMethod::Store, ZipMethod::Deflate] {
        let archive = streaming_zip_fixture(method);
        assert_ne!(archive[6] & 0x08, 0);
        assert!(archive.windows(4).any(|window| window == b"PK\x07\x08"));
        assert_eq!(collect(archive), vec![b'b'; 200_000]);
    }
}

#[test]
fn sequential_zip_reports_seek_required() {
    let mut reader = ArchiveReader::new(Cursor::new(zip_fixture(ZipMethod::Store)));
    let error = reader.next_event().unwrap_err();
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Capability)
    );
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
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(raw_name.to_vec()))
            .size(None)
            .comment(Some(raw_comment.to_vec()))
            .extension(zip_unicode_extra(0x7075, raw_name, "正確.txt".as_bytes()))
            .extension(zip_unicode_extra(
                0x6375,
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
    let mut reader = SeekArchiveReader::new(Cursor::new(writer.finish().unwrap())).unwrap();
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
        metadata.times().modified.map(|value| value.secs),
        Some(1_700_000_001)
    );
    assert_eq!(
        metadata.times().accessed.map(|value| value.secs),
        Some(1_700_000_002)
    );
    assert_eq!(
        metadata.times().created.map(|value| value.secs),
        Some(1_700_000_003)
    );
    assert_eq!(metadata.times().changed.map(|value| value.secs), Some(33));
    for id in [0x7075_u16, 0x6375, 0x5455, 0x000a] {
        assert!(
            metadata
                .extensions()
                .iter()
                .any(|extension| extension.key() == id.to_le_bytes())
        );
    }
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
    writer.write_data(target).unwrap();
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
    let timestamp = Timestamp {
        secs: 1_721_390_096,
        nanos: 120_000_000,
    };
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
            vec![1, 2, 3],
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
                assert!(
                    metadata
                        .extensions()
                        .iter()
                        .any(|extension| extension.key() == b"ZZ")
                );
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
