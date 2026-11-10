// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end v0.2 synchronous streaming contracts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};

use libarchive_oxide::advanced::{Pipeline, PipelineEvent};
use libarchive_oxide::filter::gzip::GzipEncoder;
use libarchive_oxide::{ArchiveReader, ArchiveWriter, ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveMetadata, ArchivePath, Codec, CodecStatus, Device, EndOfInput, EntryKind, EntryMetadata,
    EntryTimes, Extension, FormatId, Limits, Owner, SparseExtent, Timestamp,
};

type EntryBodies = Vec<(Vec<u8>, Vec<u8>)>;

fn tar_bytes() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (name, body) in [
        (&b"a.txt"[..], &b"alpha"[..]),
        (&b"dir/b.txt"[..], &b"bravo"[..]),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(body).unwrap();
        writer.end_entry().unwrap();
    }
    writer.finish().unwrap()
}

fn write_empty_tar_entry(metadata: &EntryMetadata) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(metadata).unwrap();
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn first_entry_metadata(archive: Vec<u8>) -> EntryMetadata {
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(metadata) => return metadata,
            ReaderEvent::Done => panic!("tar entry missing"),
            _ => {},
        }
    }
}

#[test]
fn tar_reencoding_preserves_pax_extension_multiplicity() {
    let original = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("pax.txt"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(42),
            gid: Some(84),
            user: Some(b"alice".to_vec()),
            group: Some(b"staff".to_vec()),
        })
        .times(EntryTimes {
            modified: Some(Timestamp::new(10, 500_000_000).unwrap()),
            accessed: Some(Timestamp::from_seconds(11)),
            changed: Some(Timestamp::from_seconds(12)),
            created: Some(Timestamp::from_seconds(13)),
        })
        .xattr(b"user.demo".to_vec(), b"value".to_vec())
        .acl(b"user::rw-".to_vec())
        .extension(Extension::new(
            "pax",
            b"vendor.unknown".to_vec(),
            b"preserve-me".to_vec(),
        ))
        .build();
    let first = first_entry_metadata(write_empty_tar_entry(&original));
    let second = first_entry_metadata(write_empty_tar_entry(&first));
    assert_eq!(second.extensions(), first.extensions());
    assert_eq!(second.owner(), first.owner());
    assert_eq!(second.times(), first.times());
    assert_eq!(second.xattrs(), first.xattrs());
    assert_eq!(second.acl(), first.acl());
}

#[test]
fn tar_reencoding_preserves_coherent_raw_sparse_pax() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse.bin"))
        .size(Some(12))
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(0)),
            ..EntryTimes::default()
        })
        .sparse_extent(SparseExtent::new(2, 3).unwrap())
        .sparse_extent(SparseExtent::new(8, 2).unwrap())
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.map".to_vec(),
            b"2, 3,8,2".to_vec(),
        ))
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.size".to_vec(),
            b"12".to_vec(),
        ))
        .build();
    let logical = b"\0\0abc\0\0\0de\0\0";
    let encode = |metadata: &EntryMetadata| {
        let mut writer = ArchiveWriter::new(Vec::new());
        writer.start_entry(metadata).unwrap();
        writer.write_data(logical).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };

    let first = first_entry_metadata(encode(&metadata));
    assert!(first.extensions().iter().any(|extension| {
        extension.key() == b"GNU.sparse.map" && extension.value() == b"2, 3,8,2"
    }));
    assert!(
        first.extensions().iter().any(|extension| {
            extension.key() == b"GNU.sparse.size" && extension.value() == b"12"
        })
    );
    assert!(
        !first
            .extensions()
            .iter()
            .any(|extension| extension.key() == b"GNU.sparse.realsize")
    );

    let second = first_entry_metadata(encode(&first));
    assert_eq!(second.extensions(), first.extensions());
    assert_eq!(second.sparse_extents(), first.sparse_extents());
}

#[test]
fn tar_reencoding_preserves_coherent_raw_sparse_pairs() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("pairs.bin"))
        .size(Some(6))
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(0)),
            ..EntryTimes::default()
        })
        .sparse_extent(SparseExtent::new(2, 2).unwrap())
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.offset".to_vec(),
            b"2".to_vec(),
        ))
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.numbytes".to_vec(),
            b"2".to_vec(),
        ))
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.realsize".to_vec(),
            b"6".to_vec(),
        ))
        .build();
    let logical = b"\0\0ab\0\0";
    let encode = |metadata: &EntryMetadata| {
        let mut writer = ArchiveWriter::new(Vec::new());
        writer.start_entry(metadata).unwrap();
        writer.write_data(logical).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };

    let first = first_entry_metadata(encode(&metadata));
    assert!(
        !first
            .extensions()
            .iter()
            .any(|extension| extension.key() == b"GNU.sparse.map")
    );
    let second = first_entry_metadata(encode(&first));
    assert_eq!(second.extensions(), first.extensions());
    assert_eq!(second.sparse_extents(), first.sparse_extents());
}

#[test]
fn tar_rejects_malformed_raw_sparse_pax_before_header_output() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("bad-map.bin"))
        .size(Some(2))
        .sparse_extent(SparseExtent::new(0, 1).unwrap())
        .extension(Extension::new(
            "pax",
            b"GNU.sparse.map".to_vec(),
            b"0".to_vec(),
        ))
        .build();
    let mut writer = ArchiveWriter::new(Vec::new());
    let error = writer
        .start_entry(&metadata)
        .expect_err("malformed raw GNU sparse map must fail before output");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Malformed);
    assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
}

#[test]
fn tar_rejects_mismatched_device_metadata_before_header_output() {
    let maximum = (1_u64 << 56) - 1;
    let cases = [
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("file-device"))
            .size(Some(0))
            .devices(None, Some(Device { major: 1, minor: 2 }))
            .build(),
        EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("missing-device"))
            .size(Some(0))
            .build(),
        EntryMetadata::builder(EntryKind::Block, ArchivePath::from_utf8("large-device"))
            .size(Some(0))
            .devices(
                None,
                Some(Device {
                    major: maximum + 1,
                    minor: 0,
                }),
            )
            .build(),
    ];
    for metadata in cases {
        let mut writer = ArchiveWriter::new(Vec::new());
        let error = writer
            .start_entry(&metadata)
            .expect_err("Tar device metadata must be kind- and field-representable");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{error:?}"
        );
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[test]
fn tar_device_base256_maximum_roundtrips() {
    let maximum = (1_u64 << 56) - 1;
    let metadata = EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("device"))
        .size(Some(0))
        .devices(
            None,
            Some(Device {
                major: maximum,
                minor: maximum,
            }),
        )
        .build();
    let decoded = first_entry_metadata(write_empty_tar_entry(&metadata));
    assert_eq!(decoded.kind(), EntryKind::Char);
    assert_eq!(decoded.referenced_device(), metadata.referenced_device());
}

#[test]
fn tar_typed_entry_comment_roundtrips() {
    let original = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("comment.txt"))
        .size(Some(0))
        .comment(Some(b"entry comment".to_vec()))
        .build();
    let decoded = first_entry_metadata(write_empty_tar_entry(&original));
    assert_eq!(decoded.comment(), original.comment());
}

#[test]
fn tar_rejects_conflicting_typed_and_raw_pax_metadata() {
    let cases = [
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("user.txt"))
            .size(Some(0))
            .owner(Owner {
                user: Some(b"typed".to_vec()),
                ..Owner::default()
            })
            .extension(Extension::new("pax", b"uname".to_vec(), b"raw".to_vec()))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("time.txt"))
            .size(Some(0))
            .times(EntryTimes {
                modified: Some(Timestamp::from_seconds(1)),
                ..EntryTimes::default()
            })
            .extension(Extension::new("pax", b"mtime".to_vec(), b"2".to_vec()))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("xattr.txt"))
            .size(Some(0))
            .xattr(b"user.demo".to_vec(), b"typed".to_vec())
            .extension(Extension::new(
                "pax",
                b"SCHILY.xattr.user.demo".to_vec(),
                b"raw".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("comment.txt"))
            .size(Some(0))
            .comment(Some(b"typed".to_vec()))
            .extension(Extension::new(
                "pax",
                b"LIBARCHIVE.comment".to_vec(),
                b"raw".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse-map.bin"))
            .size(Some(12))
            .sparse_extent(SparseExtent::new(2, 3).unwrap())
            .sparse_extent(SparseExtent::new(8, 2).unwrap())
            .extension(Extension::new(
                "pax",
                b"GNU.sparse.map".to_vec(),
                b"1,5".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse-size.bin"))
            .size(Some(12))
            .sparse_extent(SparseExtent::new(2, 3).unwrap())
            .sparse_extent(SparseExtent::new(8, 2).unwrap())
            .extension(Extension::new(
                "pax",
                b"GNU.sparse.realsize".to_vec(),
                b"13".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("raw-sparse.bin"))
            .size(Some(12))
            .extension(Extension::new(
                "pax",
                b"GNU.sparse.realsize".to_vec(),
                b"12".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse-v1.bin"))
            .size(Some(2))
            .sparse_extent(SparseExtent::new(0, 1).unwrap())
            .extension(Extension::new(
                "pax",
                b"GNU.sparse.major".to_vec(),
                b"1".to_vec(),
            ))
            .build(),
    ];
    for metadata in cases {
        let mut writer = ArchiveWriter::new(Vec::new());
        let error = writer
            .start_entry(&metadata)
            .expect_err("conflicting typed and raw PAX metadata must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{error:?}"
        );
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[test]
fn tar_rejects_conflicting_structural_pax_metadata() {
    let cases = [
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("typed.txt"))
            .size(Some(0))
            .extension(Extension::new("pax", b"path".to_vec(), b"raw.txt".to_vec()))
            .build(),
        EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
            .size(Some(0))
            .link_target(Some(ArchivePath::from_utf8("typed-target")))
            .extension(Extension::new(
                "pax",
                b"linkpath".to_vec(),
                b"raw-target".to_vec(),
            ))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("size.txt"))
            .size(Some(0))
            .extension(Extension::new("pax", b"size".to_vec(), b"1".to_vec()))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("owner.txt"))
            .size(Some(0))
            .owner(Owner {
                uid: Some(1),
                gid: Some(2),
                ..Owner::default()
            })
            .extension(Extension::new("pax", b"uid".to_vec(), b"3".to_vec()))
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("group.txt"))
            .size(Some(0))
            .owner(Owner {
                uid: Some(1),
                gid: Some(2),
                ..Owner::default()
            })
            .extension(Extension::new("pax", b"gid".to_vec(), b"3".to_vec()))
            .build(),
    ];
    for metadata in cases {
        let mut writer = ArchiveWriter::new(Vec::new());
        let error = writer
            .start_entry(&metadata)
            .expect_err("conflicting structural PAX metadata must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{error:?}"
        );
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[cfg(not(feature = "bzip2"))]
#[test]
fn failed_filter_initialization_returns_an_error_instead_of_panicking_on_recovery() {
    let mut reader = ArchiveReader::open(Cursor::new(b"BZh-disabled-filter".to_vec()));
    assert!(reader.next_event().is_err());

    let error = reader
        .into_inner()
        .expect_err("the constructor consumed the source before reporting the disabled codec");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Protocol);
}

#[test]
fn entry_read_and_write_adapters_form_the_high_level_streaming_path() {
    let body: Vec<u8> = (0_u8..=251).cycle().take(200_000).collect();
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("body.bin"))
        .size(Some(body.len() as u64))
        .build();
    let mut writer = ArchiveWriter::create(Vec::new());
    {
        let mut entry = writer.start_entry_writer(&metadata).unwrap();
        for chunk in body.chunks(997) {
            entry.write_all(chunk).unwrap();
        }
        entry.finish().unwrap();
    }
    let encoded = writer.finish().unwrap();

    let mut reader = ArchiveReader::open(Cursor::new(encoded.clone()));
    let mut entry = reader.next_entry().unwrap().expect("one entry");
    assert_eq!(entry.metadata().path().as_bytes(), b"body.bin");
    let mut decoded = Vec::new();
    let mut small = [0_u8; 113];
    loop {
        let read = entry.read(&mut small).unwrap();
        if read == 0 {
            break;
        }
        decoded.extend_from_slice(&small[..read]);
    }
    assert_eq!(decoded, body);
    drop(entry);
    assert!(reader.next_entry().unwrap().is_none());

    let mut reader = ArchiveReader::open(Cursor::new(encoded));
    let mut entry = reader.next_entry().unwrap().expect("one entry");
    let mut one = [0_u8; 1];
    entry.read_exact(&mut one).unwrap();
    drop(entry);
    assert_eq!(
        reader
            .next_entry()
            .unwrap_err()
            .archive_error()
            .expect("protocol error")
            .kind(),
        libarchive_oxide_core::ErrorKind::Protocol
    );
}

#[test]
fn writer_rejects_invalid_metadata_before_producing_output() {
    let invalid = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
        .size(Some(0))
        .build();
    let mut writer = ArchiveWriter::new(Vec::new());
    let error = writer
        .start_entry(&invalid)
        .expect_err("missing link target must be rejected");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Malformed);
    assert!(
        writer.abort().expect("abort writer").is_empty(),
        "validation must happen before the first output byte"
    );
}

#[derive(Debug)]
struct RejectWrites;

impl Write for RejectWrites {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected writer failure"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn unified_error_preserves_io_kind_and_source() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("file"))
        .size(Some(0))
        .try_build()
        .expect("valid metadata");
    let mut writer = ArchiveWriter::new(RejectWrites);
    let error = writer
        .start_entry(&metadata)
        .expect_err("injected output error");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Io);
    assert!(error.io_error().is_some());
    assert!(std::error::Error::source(&error).is_some());
}

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    let mut encoder = GzipEncoder::new(Limits::default());
    let mut out = Vec::new();
    let mut input = plain;
    let mut buf = [0_u8; 31];
    loop {
        let step = encoder.process(input, &mut buf, EndOfInput::End).unwrap();
        input = &input[step.consumed..];
        out.extend_from_slice(&buf[..step.produced]);
        if step.status == CodecStatus::Done {
            break;
        }
    }
    out
}

fn filter_bytes(plain: &[u8], filter: FilterId) -> Vec<u8> {
    match filter {
        FilterId::Gzip => gzip_bytes(plain),
        FilterId::Bzip2 => {
            #[cfg(feature = "bzip2")]
            {
                let mut writer =
                    bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                writer.write_all(plain).unwrap();
                writer.finish().unwrap()
            }
            #[cfg(not(feature = "bzip2"))]
            {
                panic!("bzip2 test fixture requested without the bzip2 feature")
            }
        },
        FilterId::Zstd => zstd_codec::stream::encode_all(Cursor::new(plain), 3).unwrap(),
        FilterId::Xz => {
            let mut writer =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
                    .unwrap();
            writer.write_all(plain).unwrap();
            writer.finish().unwrap()
        },
        FilterId::Lz4 => {
            let mut writer = lz4_flex::frame::FrameEncoder::new(Vec::new());
            writer.write_all(plain).unwrap();
            writer.finish().unwrap()
        },
        _ => panic!("unknown test filter"),
    }
}

/// Outer filters available in the current additive feature set.
fn enabled_outer_filters() -> Vec<FilterId> {
    [FilterId::Gzip, FilterId::Zstd, FilterId::Xz, FilterId::Lz4]
        .into_iter()
        .chain(cfg!(feature = "bzip2").then_some(FilterId::Bzip2))
        .collect()
}

fn collect(input: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    collect_with_limits(input, Limits::default())
}

fn collect_with_limits(input: Vec<u8>, limits: Limits) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut reader = ArchiveReader::with_limits(Cursor::new(input), limits);
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => {
                current = Some((meta.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current.as_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::EndEntry => entries.push(current.take().unwrap()),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) => {},
            _ => panic!("unknown event"),
        }
    }
    entries
}

fn collect_pipeline(
    input: &[u8],
    limits: Limits,
) -> Result<EntryBodies, libarchive_oxide_core::ArchiveError> {
    let mut pipeline = Pipeline::new(limits);
    let mut position = 0;
    let mut finished = false;
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match pipeline.poll_event()? {
            PipelineEvent::NeedInput => {
                if position == input.len() {
                    if !finished {
                        pipeline.finish_input()?;
                        finished = true;
                    }
                } else {
                    let count = pipeline.feed(&input[position..=position])?;
                    assert_eq!(count, 1);
                    position += count;
                }
            },
            PipelineEvent::ArchiveMetadata(_) => {},
            PipelineEvent::Entry(metadata) => {
                current = Some((metadata.path().as_bytes().to_vec(), Vec::new()));
            },
            PipelineEvent::Data(bytes) => {
                current.as_mut().unwrap().1.extend_from_slice(bytes);
            },
            PipelineEvent::EndEntry => entries.push(current.take().unwrap()),
            PipelineEvent::Done => return Ok(entries),
            _ => panic!("unknown pipeline event"),
        }
    }
}

#[test]
fn plain_and_gzip_streams_are_identical() {
    let tar = tar_bytes();
    let expected = vec![
        (b"a.txt".to_vec(), b"alpha".to_vec()),
        (b"dir/b.txt".to_vec(), b"bravo".to_vec()),
    ];
    assert_eq!(collect(tar.clone()), expected);
    assert_eq!(collect(gzip_bytes(&tar)), expected);
}

#[test]
fn tar_global_pax_metadata_roundtrips_before_entries() {
    let metadata = ArchiveMetadata::new()
        .with_comment(b"archive comment".to_vec())
        .with_extension(Extension::new(
            "pax",
            b"example.vendor".to_vec(),
            b"preserved".to_vec(),
        ));
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.set_archive_metadata(&metadata).unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    let first = match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert_eq!(metadata.comment(), Some(b"archive comment".as_slice()));
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "pax"
                    && extension.key() == b"example.vendor"
                    && extension.value() == b"preserved"
            }));
            metadata
        },
        other => panic!("expected archive metadata, got {other:?}"),
    };

    let mut writer = ArchiveWriter::new(Vec::new());
    writer.set_archive_metadata(&first).unwrap();
    let mut reader = ArchiveReader::new(Cursor::new(writer.finish().unwrap()));
    let second = match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => metadata,
        other => panic!("expected archive metadata, got {other:?}"),
    };
    assert_eq!(second.comment(), first.comment());
    assert_eq!(second.extensions(), first.extensions());
}

#[test]
fn tar_global_pax_comment_multiplicity_uses_the_last_typed_value() {
    let metadata = ArchiveMetadata::new()
        .with_comment(b"current".to_vec())
        .with_extension(Extension::new(
            "pax",
            b"LIBARCHIVE.comment".to_vec(),
            b"legacy".to_vec(),
        ))
        .with_extension(Extension::new(
            "pax",
            b"LIBARCHIVE.comment".to_vec(),
            b"current".to_vec(),
        ));
    let mut writer = ArchiveWriter::new(Vec::new());
    writer
        .set_archive_metadata(&metadata)
        .expect("last global PAX comment agrees with typed metadata");
    let mut reader = ArchiveReader::new(Cursor::new(writer.finish().unwrap()));
    let ReaderEvent::ArchiveMetadata(decoded) = reader.next_event().unwrap() else {
        panic!("global PAX metadata missing");
    };
    assert_eq!(decoded.comment(), metadata.comment());
    assert_eq!(decoded.extensions(), metadata.extensions());
}

#[test]
fn tar_and_zip_reject_unrepresentable_archive_metadata() {
    let cases = [
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_volume_name(ArchivePath::from_utf8("TAR_VOLUME")),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "unknown",
                b"key".to_vec(),
                b"value".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new()
                .with_comment(b"typed".to_vec())
                .with_extension(Extension::new(
                    "pax",
                    b"LIBARCHIVE.comment".to_vec(),
                    b"conflicting".to_vec(),
                )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"GNU.sparse.realsize".to_vec(),
                b"12".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"path".to_vec(),
                b"overrides-every-entry".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"size".to_vec(),
                b"1".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"SCHILY.xattr.user.demo".to_vec(),
                b"value".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"SCHILY.acl.access".to_vec(),
                b"user::rw-".to_vec(),
            )),
        ),
        (
            FormatId::Tar,
            ArchiveMetadata::new().with_extension(Extension::new(
                "pax",
                b"LIBARCHIVE.comment".to_vec(),
                b"raw-only".to_vec(),
            )),
        ),
        (
            FormatId::Zip,
            ArchiveMetadata::new().with_volume_name(ArchivePath::from_utf8("ZIP_VOLUME")),
        ),
        (
            FormatId::Zip,
            ArchiveMetadata::new().with_extension(Extension::new(
                "zip-archive-extra",
                b"key".to_vec(),
                b"value".to_vec(),
            )),
        ),
    ];

    for (format, metadata) in cases {
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        let error = writer
            .set_archive_metadata(&metadata)
            .expect_err("unrepresentable archive metadata must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{format:?}: {error:?}"
        );
    }
}

#[test]
fn zip_rejects_unrepresentable_entry_extensions() {
    let cases = [
        Extension::new("foreign", 0xcafe_u16.to_le_bytes().to_vec(), vec![1]),
        Extension::new("zip-extra", vec![0xca], vec![1]),
        Extension::new("zip-extra", 0x0001_u16.to_le_bytes().to_vec(), vec![1]),
        Extension::new("zip-extra", 0x9901_u16.to_le_bytes().to_vec(), vec![1]),
    ];

    for extension in cases {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .extension(extension)
            .build();
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("unrepresentable ZIP entry extension must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{error:?}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn zip_windows_file_attributes_roundtrip_through_the_central_directory() {
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
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).expect("writer");
    writer.start_entry(&metadata).expect("start entry");
    writer.end_entry().expect("end entry");
    let archive = writer.finish().expect("finish");

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("reader");
    assert!(matches!(
        reader.next_event().expect("archive metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().expect("entry") else {
        panic!("ZIP file-attribute entry missing");
    };
    assert_eq!(decoded.mode(), Some(0o640));
    assert_eq!(decoded.file_flags(), file_flags);
}

#[test]
#[allow(clippy::too_many_lines)]
fn zip_rejects_unrepresentable_typed_entry_fields() {
    let base =
        |kind| EntryMetadata::builder(kind, ArchivePath::from_utf8("entry.bin")).size(Some(0));
    let cases = vec![
        base(EntryKind::File)
            .owner(Owner {
                user: Some(b"user".to_vec()),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File)
            .owner(Owner {
                uid: Some(1),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File)
            .owner(Owner {
                uid: Some(65_536),
                gid: Some(1),
                ..Owner::default()
            })
            .build(),
        base(EntryKind::File)
            .times(EntryTimes {
                created: Some(Timestamp::from_seconds(1)),
                ..EntryTimes::default()
            })
            .build(),
        base(EntryKind::File)
            .times(EntryTimes {
                modified: Some(Timestamp::new(1, 1).unwrap()),
                ..EntryTimes::default()
            })
            .build(),
        base(EntryKind::File)
            .times(EntryTimes {
                accessed: Some(Timestamp::from_seconds(i64::from(i32::MAX) + 1)),
                ..EntryTimes::default()
            })
            .build(),
        base(EntryKind::File)
            .inode_and_links(Some(1), Some(1))
            .build(),
        base(EntryKind::File)
            .devices(Some(Device { major: 1, minor: 2 }), None)
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(2))
            .sparse_extent(SparseExtent::new(1, 1).unwrap())
            .build(),
        base(EntryKind::File)
            .xattr(b"user.key".to_vec(), b"value".to_vec())
            .build(),
        base(EntryKind::File).acl(b"user::rw-".to_vec()).build(),
        base(EntryKind::File).file_flags(0x0000_0010).build(),
        base(EntryKind::File).file_flags(0x0000_0100).build(),
        base(EntryKind::File).encrypted(true).build(),
        base(EntryKind::Hardlink)
            .link_target(Some(ArchivePath::from_utf8("target")))
            .build(),
        base(EntryKind::Char).build(),
        base(EntryKind::Block).build(),
        base(EntryKind::Fifo).build(),
        base(EntryKind::Socket).build(),
    ];
    for metadata in cases {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("unrepresentable ZIP typed metadata must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{error:?}"
        );
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[test]
fn zip_symlink_target_is_metadata_owned_and_roundtrips() {
    let target = ArchivePath::from_utf8("../target.txt");
    let metadata = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
        .size(Some(target.as_bytes().len() as u64))
        .link_target(Some(target.clone()))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("ZIP symlink entry missing");
    };
    assert_eq!(decoded.kind(), EntryKind::Symlink);
    assert_eq!(decoded.link_target(), Some(&target));

    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
    writer.start_entry(&metadata).unwrap();
    let error = writer
        .write_data(target.as_bytes())
        .expect_err("callers must not duplicate metadata-owned ZIP symlink payload");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Protocol);

    let mismatched = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("bad-link"))
        .size(Some(0))
        .link_target(Some(ArchivePath::from_utf8("target")))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
    let error = writer
        .start_entry(&mismatched)
        .expect_err("ZIP symlink size must equal its metadata-owned target length");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Unsupported);
    assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);

    let limits = Limits::default()
        .with_path_bytes(None)
        .with_in_flight_bytes(Some(4));
    let bounded =
        EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("bounded-link"))
            .size(Some(5))
            .link_target(Some(ArchivePath::from_utf8("12345")))
            .build();
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Zip, limits).unwrap();
    let error = writer
        .start_entry(&bounded)
        .expect_err("ZIP symlink target must obey the in-flight memory limit");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Limit);
}

#[test]
fn zip_rejects_conflicting_typed_and_raw_structured_extras() {
    let mut timestamp_body = vec![0x01];
    timestamp_body.extend_from_slice(&2_i32.to_le_bytes());
    let timestamp = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("time.bin"))
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(1)),
            ..EntryTimes::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x5455_u16.to_le_bytes().to_vec(),
            timestamp_body,
        ))
        .build();
    let owner = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("owner.bin"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(1),
            gid: Some(2),
            ..Owner::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x7855_u16.to_le_bytes().to_vec(),
            [3_u16.to_le_bytes(), 4_u16.to_le_bytes()].concat(),
        ))
        .build();
    for metadata in [timestamp, owner] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("conflicting typed and raw ZIP metadata must fail closed");
        assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Unsupported);
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[test]
fn zip_structured_extras_synthesize_only_missing_typed_fields() {
    let mut timestamp_body = vec![0x01];
    timestamp_body.extend_from_slice(&2_i32.to_le_bytes());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("mixed.bin"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(1),
            gid: Some(2),
            ..Owner::default()
        })
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(2)),
            accessed: Some(Timestamp::from_seconds(3)),
            ..EntryTimes::default()
        })
        .extension(Extension::new(
            "zip-extra",
            0x5455_u16.to_le_bytes().to_vec(),
            timestamp_body,
        ))
        .build();
    let archive = {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("ZIP entry missing");
    };
    assert_eq!(decoded.owner(), metadata.owner());
    assert_eq!(decoded.times(), metadata.times());

    let reencoded = {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        writer.start_entry(&decoded).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };
    let mut reader = SeekArchiveReader::new(Cursor::new(reencoded)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(roundtripped) = reader.next_event().unwrap() else {
        panic!("re-encoded ZIP entry missing");
    };
    assert_eq!(roundtripped.owner(), decoded.owner());
    assert_eq!(roundtripped.times(), decoded.times());
    assert_eq!(roundtripped.extensions(), decoded.extensions());
}

#[test]
fn zip_coherent_ntfs_times_preserve_creation_and_100ns_precision() {
    const FILETIME_EPOCH: u64 = 11_644_473_600;
    let timestamp = Timestamp::new(1_700_000_000, 100).unwrap();
    let ticks = (u64::try_from(timestamp.seconds()).unwrap() + FILETIME_EPOCH) * 10_000_000
        + u64::from(timestamp.nanoseconds() / 100);
    let mut ntfs = vec![0_u8; 4];
    ntfs.extend_from_slice(&1_u16.to_le_bytes());
    ntfs.extend_from_slice(&24_u16.to_le_bytes());
    for _ in 0..3 {
        ntfs.extend_from_slice(&ticks.to_le_bytes());
    }
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("ntfs.bin"))
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(timestamp),
            accessed: Some(timestamp),
            changed: None,
            created: Some(timestamp),
        })
        .extension(Extension::new(
            "zip-extra",
            0x000a_u16.to_le_bytes().to_vec(),
            ntfs,
        ))
        .build();
    let archive = {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("ZIP entry missing");
    };
    assert_eq!(decoded.times(), metadata.times());
}

#[test]
fn zip_rejects_malformed_structured_extra_bodies() {
    let malformed = [(0x5455_u16, vec![0x01]), (0x000a_u16, vec![0, 0, 0, 0, 1])];
    for (id, value) in malformed {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("malformed.bin"))
                .size(Some(0))
                .extension(Extension::new(
                    "zip-extra",
                    id.to_le_bytes().to_vec(),
                    value,
                ))
                .build();
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("truncated structured ZIP metadata must fail closed");
        assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Malformed);
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

fn zip_unicode_extra(id: u16, original: &[u8], unicode: &[u8]) -> Extension {
    let mut value = vec![1];
    value.extend_from_slice(&libarchive_oxide::filter::crc32(original).to_le_bytes());
    value.extend_from_slice(unicode);
    Extension::new("zip-extra", id.to_le_bytes().to_vec(), value)
}

#[test]
fn zip_rejects_applicable_unicode_extras_that_override_typed_metadata() {
    let path = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("legacy.txt"))
        .size(Some(0))
        .extension(zip_unicode_extra(
            0x7075,
            b"legacy.txt",
            "正確.txt".as_bytes(),
        ))
        .build();
    let comment = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("comment.txt"))
        .size(Some(0))
        .comment(Some(b"legacy comment".to_vec()))
        .extension(zip_unicode_extra(
            0x6375,
            b"legacy comment",
            "正確なコメント".as_bytes(),
        ))
        .build();
    let directory = EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_utf8("directory"))
        .size(Some(0))
        .extension(zip_unicode_extra(
            0x7075,
            b"directory/",
            "overridden/".as_bytes(),
        ))
        .build();
    for metadata in [path, comment, directory] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("applicable Unicode extra must not override typed metadata");
        assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Unsupported);
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

#[test]
fn zip_rejects_applicable_non_utf8_unicode_extra() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("legacy.txt"))
        .size(Some(0))
        .extension(zip_unicode_extra(0x7075, b"legacy.txt", &[0xff]))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("applicable Unicode extra must contain UTF-8");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Malformed);
    assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
}

#[test]
fn zip_preserves_inert_unicode_extras_during_exact_reencoding() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("正確.txt"))
        .size(Some(0))
        .comment(Some("正確なコメント".as_bytes().to_vec()))
        .extension(zip_unicode_extra(
            0x7075,
            b"legacy.txt",
            "正確.txt".as_bytes(),
        ))
        .extension(zip_unicode_extra(
            0x6375,
            b"legacy comment",
            "正確なコメント".as_bytes(),
        ))
        .build();
    let archive = {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("ZIP entry missing");
    };
    assert_eq!(decoded.path(), metadata.path());
    assert_eq!(decoded.comment(), metadata.comment());
    assert_eq!(decoded.extensions(), metadata.extensions());
}

#[test]
fn zip_directory_suffix_obeys_serialized_path_bounds() {
    let metadata = EntryMetadata::builder(
        EntryKind::Dir,
        ArchivePath::from_utf8("d".repeat(usize::from(u16::MAX))),
    )
    .size(Some(0))
    .build();
    let mut writer = ArchiveWriter::with_format_and_limits(
        Vec::new(),
        FormatId::Zip,
        Limits::default().with_path_bytes(None),
    )
    .unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("serialized directory slash must fit the ZIP pathname field");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Limit);
    assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
}

#[test]
fn tar_cpio_and_ar_reject_unrepresentable_entry_extensions() {
    let cases = [
        (
            FormatId::Tar,
            Extension::new("foreign", b"key".to_vec(), b"value".to_vec()),
        ),
        (
            FormatId::Cpio,
            Extension::new("pax", b"key".to_vec(), b"value".to_vec()),
        ),
        (
            FormatId::Ar,
            Extension::new("pax", b"key".to_vec(), b"value".to_vec()),
        ),
    ];

    for (format, extension) in cases {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .extension(extension)
            .build();
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("unrepresentable entry extension must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{format:?}: {error:?}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn tar_cpio_and_ar_reject_unrepresentable_entry_fields() {
    let base =
        |kind| EntryMetadata::builder(kind, ArchivePath::from_utf8("entry.bin")).size(Some(0));
    let accessed = EntryTimes {
        accessed: Some(Timestamp::new(1, 0).unwrap()),
        ..EntryTimes::default()
    };
    let named_owner = Owner {
        user: Some(b"user".to_vec()),
        ..Owner::default()
    };
    let cases = vec![
        (FormatId::Tar, base(EntryKind::File).file_flags(1).build()),
        (FormatId::Tar, base(EntryKind::File).encrypted(true).build()),
        (
            FormatId::Tar,
            base(EntryKind::File)
                .inode_and_links(Some(7), Some(1))
                .build(),
        ),
        (
            FormatId::Tar,
            base(EntryKind::File)
                .devices(Some(Device { major: 1, minor: 2 }), None)
                .build(),
        ),
        (
            FormatId::Cpio,
            base(EntryKind::File).owner(named_owner.clone()).build(),
        ),
        (
            FormatId::Cpio,
            base(EntryKind::File).times(accessed).build(),
        ),
        (
            FormatId::Cpio,
            base(EntryKind::File)
                .xattr(b"user.key".to_vec(), b"value".to_vec())
                .build(),
        ),
        (
            FormatId::Cpio,
            base(EntryKind::File).acl(b"user::rw-".to_vec()).build(),
        ),
        (FormatId::Cpio, base(EntryKind::File).file_flags(1).build()),
        (
            FormatId::Cpio,
            base(EntryKind::File).encrypted(true).build(),
        ),
        (
            FormatId::Cpio,
            base(EntryKind::File)
                .comment(Some(b"comment".to_vec()))
                .build(),
        ),
        (FormatId::Ar, base(EntryKind::Dir).build()),
        (
            FormatId::Ar,
            base(EntryKind::File).owner(named_owner).build(),
        ),
        (FormatId::Ar, base(EntryKind::File).times(accessed).build()),
        (
            FormatId::Ar,
            base(EntryKind::File)
                .inode_and_links(Some(7), Some(1))
                .build(),
        ),
        (
            FormatId::Ar,
            base(EntryKind::File)
                .devices(None, Some(Device { major: 1, minor: 2 }))
                .build(),
        ),
        (
            FormatId::Ar,
            base(EntryKind::File)
                .xattr(b"user.key".to_vec(), b"value".to_vec())
                .build(),
        ),
        (
            FormatId::Ar,
            base(EntryKind::File).acl(b"user::rw-".to_vec()).build(),
        ),
        (FormatId::Ar, base(EntryKind::File).file_flags(1).build()),
        (FormatId::Ar, base(EntryKind::File).encrypted(true).build()),
        (
            FormatId::Ar,
            base(EntryKind::File)
                .comment(Some(b"comment".to_vec()))
                .build(),
        ),
    ];

    for (format, metadata) in cases {
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("unrepresentable entry field must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{format:?}: {error:?}"
        );
    }
}

#[test]
fn cpio_and_ar_reject_lossy_numeric_metadata() {
    for format in [FormatId::Cpio, FormatId::Ar] {
        for modified in [
            Timestamp::from_seconds(-1),
            Timestamp::new(1, 1).expect("valid timestamp"),
        ] {
            let metadata =
                EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
                    .size(Some(0))
                    .times(EntryTimes {
                        modified: Some(modified),
                        ..EntryTimes::default()
                    })
                    .build();
            let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
            let error = writer
                .start_entry(&metadata)
                .expect_err("lossy timestamp conversion must fail closed");
            assert_eq!(
                error.kind(),
                libarchive_oxide_core::ErrorKind::Unsupported,
                "{format:?}: {error:?}"
            );
        }
    }

    for metadata in [
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .owner(Owner {
                uid: Some(1_000_000),
                ..Owner::default()
            })
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .owner(Owner {
                gid: Some(1_000_000),
                ..Owner::default()
            })
            .build(),
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .times(EntryTimes {
                modified: Some(Timestamp::from_seconds(1_000_000_000_000)),
                ..EntryTimes::default()
            })
            .build(),
    ] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Ar).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("ar fixed-width numeric overflow must fail closed");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Limit,
            "{error:?}"
        );
    }

    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
        .size(Some(10_000_000_000))
        .build();
    let limits = Limits::default().with_entry_bytes(None);
    let mut writer =
        ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Ar, limits).unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("ar fixed-width size overflow must fail closed");
    assert_eq!(
        error.kind(),
        libarchive_oxide_core::ErrorKind::Limit,
        "{error:?}"
    );
}

#[test]
fn ar_reserved_short_names_roundtrip_through_bsd_inline_encoding() {
    for name in [b"/".as_slice(), b"/SYM64", b"/123", b"#1/7"] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .size(Some(0))
                .build();
        let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Ar).unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.end_entry().unwrap();
        let decoded = first_entry_metadata(writer.finish().unwrap());
        assert_eq!(decoded.path().as_bytes(), name, "{name:?}");
    }
}

#[test]
fn cpio_rejects_the_reserved_trailer_path_before_output() {
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"TRAILER!!!".to_vec()),
    )
    .size(Some(0))
    .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Cpio).unwrap();
    let error = writer
        .start_entry(&metadata)
        .expect_err("cpio trailer sentinel cannot be an archive entry");
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Unsupported);
    assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
}

#[test]
fn permission_only_writers_reject_mode_type_bits() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
        .size(Some(0))
        .mode(Some(0o100_640))
        .build();

    for format in [FormatId::Tar, FormatId::Cpio, FormatId::Ar, FormatId::Zip] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        let error = writer
            .start_entry(&metadata)
            .expect_err("writer must not silently strip mode type bits");
        assert_eq!(
            error.kind(),
            libarchive_oxide_core::ErrorKind::Unsupported,
            "{format:?}: {error:?}"
        );
        assert!(
            writer.abort().expect("abort writer").is_empty(),
            "{format:?} emitted output before rejecting mode bits"
        );
    }
}

#[test]
fn ar_maximum_fixed_width_numeric_metadata_roundtrips() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("maximum.bin"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(999_999),
            gid: Some(999_999),
            ..Owner::default()
        })
        .times(EntryTimes {
            modified: Some(Timestamp::from_seconds(999_999_999_999)),
            ..EntryTimes::default()
        })
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Ar).unwrap();
    writer
        .start_entry(&metadata)
        .expect("maximum fixed-width values must fit");
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    let decoded = loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(entry) => break entry,
            ReaderEvent::Done => panic!("ar entry missing"),
            _ => {},
        }
    };
    assert_eq!(decoded.owner().uid, Some(999_999));
    assert_eq!(decoded.owner().gid, Some(999_999));
    assert_eq!(
        decoded.times().modified,
        Some(Timestamp::from_seconds(999_999_999_999))
    );
}

#[test]
fn gzip_trailer_is_authenticated() {
    let tar = tar_bytes();
    let mut gzip = gzip_bytes(&tar);
    let last = gzip.len() - 8;
    gzip[last] ^= 0x80;
    let mut reader = ArchiveReader::new(Cursor::new(gzip));
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("corrupt trailer was accepted"),
            Ok(_) => {},
            Err(error) => {
                assert!(
                    error.archive_error().is_some_and(|archive| {
                        archive.kind() == libarchive_oxide_core::ErrorKind::Malformed
                    }) || error
                        .io_error()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::InvalidData)
                );
                break;
            },
        }
    }
}

#[test]
fn truncated_gzip_trailer_is_rejected() {
    let tar = tar_bytes();
    let mut gzip = gzip_bytes(&tar);
    gzip.truncate(gzip.len() - 3);
    let mut reader = ArchiveReader::new(Cursor::new(gzip));
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("truncated trailer was accepted"),
            Ok(_) => {},
            Err(error) => {
                assert!(
                    error.archive_error().is_some_and(|archive| {
                        archive.kind() == libarchive_oxide_core::ErrorKind::Malformed
                    }) || error
                        .io_error()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::InvalidData)
                );
                break;
            },
        }
    }
}

#[test]
fn nested_filter_depth_is_bounded_and_composes_statically() {
    let expected = vec![
        (b"a.txt".to_vec(), b"alpha".to_vec()),
        (b"dir/b.txt".to_vec(), b"bravo".to_vec()),
    ];
    let mut nested = tar_bytes();
    let filters: Vec<_> = enabled_outer_filters()
        .into_iter()
        .filter(|filter| *filter != FilterId::Lz4)
        .collect();
    for filter in &filters {
        nested = filter_bytes(&nested, *filter);
    }
    assert_eq!(collect(nested.clone()), expected);

    let rejected_depth = filters.len().saturating_sub(1);
    let limits = Limits::default().with_filter_depth(Some(rejected_depth));
    let mut reader = ArchiveReader::with_limits(Cursor::new(nested), limits);
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => {
                panic!("nested filters bypassed the configured depth limit")
            },
            Ok(_) => {},
            Err(error) => {
                assert_eq!(
                    error
                        .archive_error()
                        .map(libarchive_oxide_core::ArchiveError::kind),
                    Some(libarchive_oxide_core::ErrorKind::Limit),
                    "{error:?}"
                );
                break;
            },
        }
    }
}

#[test]
fn caller_driven_pipeline_composes_every_codec_at_one_byte_boundaries() {
    let expected = vec![
        (b"a.txt".to_vec(), b"alpha".to_vec()),
        (b"dir/b.txt".to_vec(), b"bravo".to_vec()),
    ];
    let mut nested = tar_bytes();
    let filters = enabled_outer_filters();
    for filter in &filters {
        nested = filter_bytes(&nested, *filter);
    }
    assert_eq!(
        collect_pipeline(
            &nested,
            Limits::default().with_filter_depth(Some(filters.len()))
        )
        .unwrap(),
        expected
    );

    let error = collect_pipeline(
        &nested,
        Limits::default().with_filter_depth(Some(filters.len().saturating_sub(1))),
    )
    .unwrap_err();
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Limit);
}

#[test]
fn caller_driven_pipeline_validates_concatenated_members_and_trailing_data() {
    let tar = tar_bytes();
    for filter in enabled_outer_filters() {
        let split = tar.len() / 2;
        let mut members = filter_bytes(&tar[..split], filter);
        if filter == FilterId::Xz {
            members.extend_from_slice(&[0; 4]);
        }
        members.extend_from_slice(&filter_bytes(&tar[split..], filter));
        assert_eq!(
            collect_pipeline(&members, Limits::default()).unwrap(),
            vec![
                (b"a.txt".to_vec(), b"alpha".to_vec()),
                (b"dir/b.txt".to_vec(), b"bravo".to_vec()),
            ],
            "{filter:?}"
        );

        let mut trailing = filter_bytes(&tar, filter);
        trailing.push(0x55);
        assert!(
            collect_pipeline(&trailing, Limits::default()).is_err(),
            "{filter:?}"
        );
    }
}

#[test]
#[cfg(feature = "bzip2")]
fn caller_driven_pipeline_rejects_bzip2_crc_failure_and_truncation() {
    let tar = tar_bytes();
    let mut corrupt = filter_bytes(&tar, FilterId::Bzip2);
    *corrupt.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let mut truncated = filter_bytes(&tar, FilterId::Bzip2);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(
        collect_pipeline(&truncated, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn caller_driven_pipeline_rejects_truncated_zstd() {
    let tar = tar_bytes();
    let mut truncated = filter_bytes(&tar, FilterId::Zstd);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(
        collect_pipeline(&truncated, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn caller_driven_pipeline_reports_malformed_zstd_fuzz_regression() {
    const MALFORMED: &[u8] =
        include_bytes!("fixtures/zstd/crash-142bc61adb972f47b2d1ef33ae89832307ea82d5.zst");
    assert_eq!(
        collect_pipeline(MALFORMED, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn caller_driven_pipeline_rejects_truncated_lz4() {
    let tar = tar_bytes();
    let mut truncated = filter_bytes(&tar, FilterId::Lz4);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(
        collect_pipeline(&truncated, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn selected_zstd_writer_is_deterministic_and_independently_decodable() {
    let payload: Vec<u8> = (0_u8..=251).cycle().take(200_000).collect();
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"portable-zstd.bin".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();

    let build = |filter, chunk: usize| {
        let mut writer =
            ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, filter, Limits::default())
                .unwrap();
        writer.start_entry(&metadata).unwrap();
        for bytes in payload.chunks(chunk) {
            writer.write_data(bytes).unwrap();
        }
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };

    let plain = build(None, payload.len());
    let one_write = build(Some(FilterId::Zstd), payload.len());
    let one_byte_writes = build(Some(FilterId::Zstd), 1);
    assert_eq!(one_write, one_byte_writes);
    assert_eq!(
        zstd_codec::stream::decode_all(Cursor::new(one_write.as_slice())).unwrap(),
        plain
    );

    let mut corrupt = one_write;
    *corrupt.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn selected_xz_writer_is_deterministic_and_interoperable() {
    // Keep the interoperability payload above 16 KiB so it crosses parser/output chunks, but use a
    // small independent payload for one-byte writer boundaries. Feeding preset-6 LZMA one byte at a
    // time is intentionally adversarial and otherwise makes debug CI time scale with call count.
    let payload: Vec<u8> = (0_u8..=251).cycle().take(16 * 1024 + 17).collect();
    let boundary_payload: Vec<u8> = (0_u8..=251).cycle().take(257).collect();

    let build = |input: &[u8], filter, chunk: usize| {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"portable-xz.bin".to_vec()),
        )
        .size(Some(input.len() as u64))
        .build();
        let mut writer =
            ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, filter, Limits::default())
                .unwrap();
        writer.start_entry(&metadata).unwrap();
        for bytes in input.chunks(chunk) {
            writer.write_data(bytes).unwrap();
        }
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };

    let plain = build(&payload, None, payload.len());
    let expected = collect(plain.clone());
    let one_write = build(&payload, Some(FilterId::Xz), payload.len());
    let boundary_one_write = build(
        &boundary_payload,
        Some(FilterId::Xz),
        boundary_payload.len(),
    );
    let boundary_one_byte_writes = build(&boundary_payload, Some(FilterId::Xz), 1);
    assert_eq!(boundary_one_write, boundary_one_byte_writes);

    let mut native_decoder = xz_codec::read::XzDecoder::new_multi_decoder(one_write.as_slice());
    let mut native_plain = Vec::new();
    native_decoder.read_to_end(&mut native_plain).unwrap();
    assert_eq!(native_plain, plain);

    let mut native_encoder = xz_codec::write::XzEncoder::new(Vec::new(), 6);
    native_encoder.write_all(&native_plain).unwrap();
    let native_stream = native_encoder.finish().unwrap();
    assert_eq!(
        collect_pipeline(&native_stream, Limits::default()).unwrap(),
        expected
    );

    let mut corrupt_header = native_stream.clone();
    corrupt_header[8] ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt_header, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let footer = native_stream.len() - 12;
    let backward_size =
        u32::from_le_bytes(native_stream[footer + 4..footer + 8].try_into().unwrap());
    let index_size = (backward_size as usize + 1) * 4;
    let mut corrupt_block_checksum = native_stream.clone();
    corrupt_block_checksum[footer - index_size - 1] ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt_block_checksum, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let mut truncated = native_stream.clone();
    truncated.pop();
    assert_eq!(
        collect_pipeline(&truncated, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let mut invalid_padding = native_stream;
    invalid_padding.push(0);
    assert_eq!(
        collect_pipeline(&invalid_padding, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn caller_driven_xz_rejects_unbounded_index_before_allocation() {
    let input =
        include_bytes!("../../fuzz/corpus/codec_xz/b16afad38be9f4c8a35cf2a4dba55890278d5b5f");
    assert_eq!(
        collect_pipeline(input, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Limit
    );
}

#[test]
fn selected_lz4_writer_is_deterministic_and_independently_decodable() {
    let payload: Vec<u8> = (0_u8..=251).cycle().take(20_000).collect();
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"portable-lz4.bin".to_vec()),
    )
    .size(Some(payload.len() as u64))
    .build();

    let build = |filter, chunk: usize| {
        let mut writer =
            ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, filter, Limits::default())
                .unwrap();
        writer.start_entry(&metadata).unwrap();
        for bytes in payload.chunks(chunk) {
            writer.write_data(bytes).unwrap();
        }
        writer.end_entry().unwrap();
        writer.finish().unwrap()
    };

    let plain = build(None, payload.len());
    let one_write = build(Some(FilterId::Lz4), payload.len());
    let one_byte_writes = build(Some(FilterId::Lz4), 1);
    assert_eq!(one_write, one_byte_writes);

    let mut decoder = lz4_codec::Decoder::new(one_write.as_slice()).unwrap();
    let mut native_plain = Vec::new();
    decoder.read_to_end(&mut native_plain).unwrap();
    assert_eq!(native_plain, plain);

    let flg = one_write[4];
    let header_length =
        4 + 2 + if flg & 0x08 != 0 { 8 } else { 0 } + if flg & 0x01 != 0 { 4 } else { 0 } + 1;
    let mut corrupt_header = one_write.clone();
    corrupt_header[header_length - 1] ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt_header, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let mut corrupt_block = one_write.clone();
    let block_length = (u32::from_le_bytes(
        corrupt_block[header_length..header_length + 4]
            .try_into()
            .unwrap(),
    ) & 0x7fff_ffff) as usize;
    corrupt_block[header_length + 4 + block_length] ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt_block, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );

    let mut corrupt_content = one_write;
    *corrupt_content.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        collect_pipeline(&corrupt_content, Limits::default())
            .unwrap_err()
            .kind(),
        libarchive_oxide_core::ErrorKind::Malformed
    );
}

#[test]
fn streaming_writer_round_trips_without_archive_buffering() {
    let mut writer = ArchiveWriter::new(Vec::new());
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"streamed.txt".to_vec()),
    )
    .size(Some(13))
    .mode(Some(0o640))
    .build();
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"streamed ").unwrap();
    writer.write_data(b"body").unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();

    assert_eq!(
        collect(archive),
        vec![(b"streamed.txt".to_vec(), b"streamed body".to_vec())]
    );
}

#[test]
fn empty_tar_is_resolved_at_eof_without_waiting_for_an_iso_descriptor() {
    let archive = ArchiveWriter::new(Vec::new()).finish().unwrap();
    assert_eq!(collect(archive).len(), 0);
}

#[test]
fn runtime_dispatch_is_opaque_and_supports_all_sequential_formats() {
    let expected = vec![(b"sequential.txt".to_vec(), b"body".to_vec())];
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"sequential.txt".to_vec()),
    )
    .size(Some(4))
    .build();

    for format in [FormatId::Cpio, FormatId::Ar] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(b"body").unwrap();
        writer.end_entry().unwrap();
        assert_eq!(collect(writer.finish().unwrap()), expected);
    }
}

#[test]
fn one_command_writer_contract_covers_all_sequential_formats() {
    for format in [FormatId::Tar, FormatId::Cpio, FormatId::Ar] {
        let mut writer = ArchiveWriter::with_format(Vec::new(), format).unwrap();
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"command.txt".to_vec()),
        )
        .size(Some(7))
        .build();
        writer.start_entry(&metadata).unwrap();
        writer.write_data(b"command").unwrap();
        writer.end_entry().unwrap();
        let archive = writer.finish().unwrap();
        assert_eq!(
            collect(archive),
            vec![(b"command.txt".to_vec(), b"command".to_vec())]
        );
    }
}

#[test]
fn tar_gzip_writer_is_streaming_end_to_end() {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Gzip),
        Limits::default(),
    )
    .unwrap();
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"filtered.txt".to_vec()),
    )
    .size(Some(13))
    .build();
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"filtered ").unwrap();
    writer.write_data(b"body").unwrap();
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();
    assert_eq!(
        collect(archive),
        vec![(b"filtered.txt".to_vec(), b"filtered body".to_vec())]
    );
}

#[test]
fn tar_writer_roundtrips_typed_pax_and_sparse_data_without_spooling() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse.bin"))
        .size(Some(12))
        .mode(Some(0o640))
        .owner(Owner {
            uid: Some(42),
            gid: Some(84),
            user: Some(b"alice".to_vec()),
            group: Some(b"staff".to_vec()),
        })
        .times(EntryTimes {
            modified: Some(Timestamp::new(1_700_000_000, 500_000_000).expect("valid timestamp")),
            accessed: Some(Timestamp::new(1_700_000_001, 250_000_000).expect("valid timestamp")),
            changed: Some(Timestamp::new(-2, 500_000_000).expect("valid timestamp")),
            created: None,
        })
        .sparse_extent(SparseExtent::new(2, 3).expect("valid sparse extent"))
        .sparse_extent(SparseExtent::new(8, 2).expect("valid sparse extent"))
        .xattr(b"user.demo".to_vec(), b"value".to_vec())
        .acl(b"user::rw-".to_vec())
        .extension(Extension::new(
            "pax",
            b"vendor.unknown".to_vec(),
            b"preserve-me".to_vec(),
        ))
        .build();
    let logical = b"\0\0abc\0\0\0de\0\0";
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata).unwrap();
    for byte in logical {
        writer.write_data(&[*byte]).unwrap();
    }
    writer.end_entry().unwrap();
    let archive = writer.finish().unwrap();
    assert!(
        archive
            .windows(b"abcde".len())
            .any(|window| window == b"abcde")
    );
    assert!(
        !archive
            .windows(logical.len())
            .any(|window| window == logical)
    );

    let mut reader = ArchiveReader::new(Cursor::new(archive));
    let mut decoded = Vec::new();
    let mut decoded_metadata = None;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(value) => decoded_metadata = Some(value),
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    let decoded_metadata = decoded_metadata.unwrap();
    assert_eq!(decoded, logical);
    assert_eq!(decoded_metadata.sparse_extents(), metadata.sparse_extents());
    assert_eq!(
        decoded_metadata.owner().user.as_deref(),
        Some(b"alice".as_slice())
    );
    assert_eq!(
        decoded_metadata.times().changed,
        Some(Timestamp::new(-2, 500_000_000).expect("valid timestamp"))
    );
    assert!(decoded_metadata.extensions().iter().any(|extension| {
        extension.key() == b"vendor.unknown" && extension.value() == b"preserve-me"
    }));
}
