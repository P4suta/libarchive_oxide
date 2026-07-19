// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end v0.2 synchronous streaming contracts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Write};

use libarchive_oxide::filter::gzip::GzipEncoder;
use libarchive_oxide::{ArchiveReader, ArchiveWriter, Pipeline, PipelineEvent, ReaderEvent};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveMetadata, ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata,
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
            let mut writer =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            writer.write_all(plain).unwrap();
            writer.finish().unwrap()
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
    let metadata = ArchiveMetadata::new().with_extension(Extension::new(
        "pax",
        b"example.vendor".to_vec(),
        b"preserved".to_vec(),
    ));
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.set_archive_metadata(&metadata).unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    match reader.next_event().unwrap() {
        ReaderEvent::ArchiveMetadata(metadata) => {
            assert!(metadata.extensions().iter().any(|extension| {
                extension.namespace() == "pax"
                    && extension.key() == b"example.vendor"
                    && extension.value() == b"preserved"
            }));
        },
        other => panic!("expected archive metadata, got {other:?}"),
    }
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
                assert!(error.to_string().contains("CRC32"));
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
                assert!(error.to_string().contains("truncated trailer"));
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
    for filter in [
        FilterId::Gzip,
        FilterId::Bzip2,
        FilterId::Zstd,
        FilterId::Xz,
    ] {
        nested = filter_bytes(&nested, filter);
    }
    assert_eq!(collect(nested.clone()), expected);

    let limits = Limits::default().with_filter_depth(Some(3));
    let mut reader = ArchiveReader::with_limits(Cursor::new(nested), limits);
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("four filters bypassed a depth-three limit"),
            Ok(_) => {},
            Err(error) => {
                assert_eq!(
                    error
                        .archive_error()
                        .map(libarchive_oxide_core::ArchiveError::kind),
                    Some(libarchive_oxide_core::ErrorKind::Limit)
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
    for filter in [
        FilterId::Gzip,
        FilterId::Bzip2,
        FilterId::Zstd,
        FilterId::Xz,
        FilterId::Lz4,
    ] {
        nested = filter_bytes(&nested, filter);
    }
    assert_eq!(
        collect_pipeline(&nested, Limits::default().with_filter_depth(Some(5))).unwrap(),
        expected
    );

    let error =
        collect_pipeline(&nested, Limits::default().with_filter_depth(Some(4))).unwrap_err();
    assert_eq!(error.kind(), libarchive_oxide_core::ErrorKind::Limit);
}

#[test]
fn caller_driven_pipeline_validates_concatenated_members_and_trailing_data() {
    let tar = tar_bytes();
    for filter in [
        FilterId::Gzip,
        FilterId::Bzip2,
        FilterId::Zstd,
        FilterId::Xz,
        FilterId::Lz4,
    ] {
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
    assert!(collect(archive).is_empty());
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
            modified: Some(Timestamp {
                secs: 1_700_000_000,
                nanos: 500_000_000,
            }),
            accessed: Some(Timestamp {
                secs: 1_700_000_001,
                nanos: 250_000_000,
            }),
            changed: Some(Timestamp {
                secs: -2,
                nanos: 500_000_000,
            }),
            created: None,
        })
        .sparse_extent(SparseExtent {
            offset: 2,
            length: 3,
        })
        .sparse_extent(SparseExtent {
            offset: 8,
            length: 2,
        })
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
        Some(Timestamp {
            secs: -2,
            nanos: 500_000_000,
        })
    );
    assert!(decoded_metadata.extensions().iter().any(|extension| {
        extension.key() == b"vendor.unknown" && extension.value() == b"preserve-me"
    }));
}
