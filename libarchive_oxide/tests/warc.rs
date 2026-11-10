// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public API, specification-fixture, and negative evidence for WARC.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Read};
#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use std::task::{Context, Poll};

#[cfg(feature = "async")]
use futures_io::AsyncRead;
#[cfg(feature = "async")]
use futures_lite::future::block_on;
use libarchive_oxide::Limits;
use libarchive_oxide::advanced::{Pipeline, PipelineEvent};
use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, ErrorKind, Extension,
    FormatId, ReaderEvent,
};
#[cfg(feature = "async")]
use libarchive_oxide::{AsyncArchiveReader, AsyncArchiveWriter};

#[cfg(feature = "async")]
struct AsyncOneByte {
    bytes: Vec<u8>,
    position: usize,
}

#[cfg(feature = "async")]
impl AsyncRead for AsyncOneByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Poll::Ready(Ok(0));
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Poll::Ready(Ok(1))
    }
}

fn fixture() -> Vec<u8> {
    let mut value = Vec::new();
    let mut high = None;
    for byte in include_bytes!("fixtures/warc/iipc-annex-b-metadata.hex") {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => panic!("fixture contains a non-hex byte"),
        };
        if let Some(first) = high.take() {
            value.push((first << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }
    assert!(high.is_none(), "fixture must contain whole bytes");
    value
}

fn extension<'a>(extensions: &'a [Extension], name: &[u8]) -> Option<&'a [u8]> {
    extensions
        .iter()
        .find(|extension| {
            extension.namespace() == "warc" && extension.key().eq_ignore_ascii_case(name)
        })
        .map(Extension::value)
}

fn writable_metadata(size: u64, record_id: &[u8]) -> EntryMetadata {
    EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"logical-record".to_vec()),
    )
    .size(Some(size))
    .mode(Some(0o644))
    .extension(Extension::new(
        "warc",
        b"WARC-Type".to_vec(),
        b"resource".to_vec(),
    ))
    .extension(Extension::new(
        "warc",
        b"WARC-Record-ID".to_vec(),
        record_id.to_vec(),
    ))
    .extension(Extension::new(
        "warc",
        b"WARC-Date".to_vec(),
        b"2026-08-14T00:00:00Z".to_vec(),
    ))
    .build()
}

#[test]
fn iipc_annex_b_fixture_auto_detects_and_preserves_named_fields() {
    let expected = b"via: http://www.archive.org/\r\n\
                     hopsFromSeed: E\r\n\
                     fetchTimeMs: 565\r\n";
    let mut reader = ArchiveReader::open(Cursor::new(fixture()));
    let mut entry = reader.next_entry().unwrap().expect("one WARC record");
    assert_eq!(entry.metadata().size(), Some(65));
    assert_eq!(
        extension(entry.metadata().extensions(), b"WARC-Type"),
        Some(b"metadata".as_slice())
    );
    assert_eq!(
        extension(entry.metadata().extensions(), b"WARC-Target-URI"),
        Some(b"http://www.archive.org/images/logoc.jpg".as_slice())
    );
    assert!(
        entry
            .metadata()
            .path()
            .display_lossy()
            .starts_with("warc/00000000000000000001/")
    );
    let mut body = Vec::new();
    entry.read_to_end(&mut body).unwrap();
    drop(entry);
    assert_eq!(reader.format(), Some(FormatId::Warc));
    assert_eq!(body, expected);
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn caller_driven_pipeline_decodes_the_fixture_at_every_byte_boundary() {
    let bytes = fixture();
    let mut pipeline = Pipeline::new(Limits::safe());
    let mut offset = 0;
    let mut finished = false;
    let mut decoded = Vec::new();
    loop {
        match pipeline.poll_event().unwrap() {
            PipelineEvent::NeedInput if offset < bytes.len() => {
                assert_eq!(pipeline.feed(&bytes[offset..=offset]).unwrap(), 1);
                offset += 1;
            },
            PipelineEvent::NeedInput if !finished => {
                pipeline.finish_input().unwrap();
                finished = true;
            },
            PipelineEvent::NeedInput => panic!("finished WARC pipeline requested input"),
            PipelineEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            PipelineEvent::Done => break,
            PipelineEvent::ArchiveMetadata(_)
            | PipelineEvent::Entry(_)
            | PipelineEvent::EndEntry => {},
            _ => panic!("unknown pipeline event"),
        }
    }
    assert_eq!(pipeline.format(), Some(FormatId::Warc));
    assert_eq!(decoded.len(), 65);
}

#[test]
fn explicit_reader_accepts_case_insensitive_fields_and_path_collisions_are_impossible() {
    let record = |version: &str, body: &str| {
        format!(
            "WARC/{version}\r\n\
             warc-record-id: <urn:uuid:same>\r\n\
             content-length: {}\r\n\
             \r\n\
             {body}\r\n\r\n",
            body.len()
        )
        .into_bytes()
    };
    let mut bytes = record("1.0", "first");
    bytes.extend_from_slice(&record("1.1", "second"));
    let mut reader =
        ArchiveReader::with_format(Cursor::new(bytes), FormatId::Warc).expect("WARC reader");
    let mut first = reader.next_entry().unwrap().unwrap();
    let first_path = first.metadata().path().as_bytes().to_vec();
    first.read_to_end(&mut Vec::new()).unwrap();
    drop(first);
    let second = reader.next_entry().unwrap().unwrap();
    let second_path = second.metadata().path().as_bytes().to_vec();
    assert_ne!(first_path, second_path);
}

#[test]
fn malformed_and_truncated_public_inputs_return_typed_errors() {
    for bytes in [
        b"WARC/1.1\r\nWARC-Type: resource\r\n\r\n".as_slice(),
        b"WARC/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx\r\n\r\n",
        b"WARC/1.1\r\nContent-Length: 4\r\n\r\nabc",
        b"WARC/1.1\r\nContent-Length: 0\r\n\r\n\r\n",
    ] {
        let mut reader = ArchiveReader::open(Cursor::new(bytes));
        loop {
            match reader.next_event() {
                Ok(ReaderEvent::Done) => panic!("malformed WARC unexpectedly completed"),
                Ok(_) => {},
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::Malformed);
                    break;
                },
            }
        }
    }
}

#[test]
fn warc_writer_streams_a_v11_record_and_round_trips_named_fields() {
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"source/path-is-not-serialized".to_vec()),
    )
    .size(Some(4))
    .mode(Some(0o644))
    .extension(Extension::new(
        "warc",
        b"WARC-Type".to_vec(),
        b"resource".to_vec(),
    ))
    .extension(Extension::new(
        "warc",
        b"WARC-Record-ID".to_vec(),
        b"<urn:uuid:writer-roundtrip>".to_vec(),
    ))
    .extension(Extension::new(
        "warc",
        b"WARC-Date".to_vec(),
        b"2026-08-14T00:00:00Z".to_vec(),
    ))
    .extension(Extension::new(
        "warc",
        b"Content-Type".to_vec(),
        b"application/octet-stream".to_vec(),
    ))
    .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    writer.start_entry(&metadata).expect("start WARC record");
    writer
        .write_data(b"body")
        .expect("write WARC content block");
    writer.end_entry().expect("end WARC record");
    let bytes = writer.finish().expect("finish WARC file");

    assert!(bytes.starts_with(b"WARC/1.1\r\n"));
    assert!(
        bytes
            .windows(19)
            .any(|window| window == b"Content-Length: 4\r\n")
    );
    assert!(bytes.ends_with(b"body\r\n\r\n"));

    let mut reader = ArchiveReader::new(Cursor::new(bytes));
    let mut entry = reader.next_entry().expect("read WARC").expect("one record");
    assert_eq!(entry.metadata().size(), Some(4));
    assert_eq!(
        extension(entry.metadata().extensions(), b"WARC-Record-ID"),
        Some(b"<urn:uuid:writer-roundtrip>".as_slice())
    );
    assert_eq!(
        extension(entry.metadata().extensions(), b"Content-Length"),
        Some(b"4".as_slice())
    );
    let mut body = Vec::new();
    entry.read_to_end(&mut body).expect("read content block");
    drop(entry);
    assert_eq!(body, b"body");
    assert!(reader.next_entry().expect("finish WARC").is_none());
}

#[test]
fn warc_writer_rejects_missing_required_fields_and_unrepresentable_metadata() {
    let missing = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"missing".to_vec()),
    )
    .size(Some(0))
    .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    let error = writer
        .start_entry(&missing)
        .expect_err("mandatory WARC fields are required");
    assert_eq!(error.kind(), ErrorKind::Malformed);

    let unsupported =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(b"xattr".to_vec()))
            .size(Some(0))
            .xattr(b"user.test".to_vec(), b"value".to_vec())
            .extension(Extension::new(
                "warc",
                b"WARC-Type".to_vec(),
                b"metadata".to_vec(),
            ))
            .extension(Extension::new(
                "warc",
                b"WARC-Record-ID".to_vec(),
                b"<urn:uuid:unsupported>".to_vec(),
            ))
            .extension(Extension::new(
                "warc",
                b"WARC-Date".to_vec(),
                b"2026-08-14T00:00:00Z".to_vec(),
            ))
            .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    let error = writer
        .start_entry(&unsupported)
        .expect_err("WARC cannot represent xattrs");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn warc_writer_supports_v10_and_validates_named_field_framing() {
    let metadata = writable_metadata(0, b"<urn:uuid:v10>")
        .into_builder()
        .extension(Extension::new("warc", b"version".to_vec(), b"1.0".to_vec()))
        .extension(Extension::new(
            "warc",
            b"Content-Length".to_vec(),
            b"0".to_vec(),
        ))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    writer.start_entry(&metadata).expect("start v1.0 record");
    writer.end_entry().expect("end v1.0 record");
    let bytes = writer.finish().expect("finish WARC");
    assert!(bytes.starts_with(b"WARC/1.0\r\n"));
    assert_eq!(
        bytes
            .windows(b"Content-Length:".len())
            .filter(|window| *window == b"Content-Length:")
            .count(),
        1
    );

    for invalid in [
        writable_metadata(0, b"<urn:uuid:length>")
            .into_builder()
            .extension(Extension::new(
                "warc",
                b"Content-Length".to_vec(),
                b"1".to_vec(),
            ))
            .build(),
        writable_metadata(0, b"<urn:uuid:control>")
            .into_builder()
            .extension(Extension::new(
                "warc",
                b"X-Invalid".to_vec(),
                b"line\nbreak".to_vec(),
            ))
            .build(),
        writable_metadata(0, b"<urn:uuid:duplicate>")
            .into_builder()
            .extension(Extension::new(
                "warc",
                b"warc-type".to_vec(),
                b"metadata".to_vec(),
            ))
            .build(),
    ] {
        let mut writer =
            ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
        let error = writer
            .start_entry(&invalid)
            .expect_err("invalid WARC named fields must fail before data");
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }
}

#[test]
fn warc_writer_preserves_a_wire_field_named_version_after_the_synthetic_version() {
    let bytes = b"WARC/1.1\r\n\
WARC-Type: metadata\r\n\
WARC-Record-ID: <urn:uuid:version-field>\r\n\
WARC-Date: 2026-08-14T00:00:00Z\r\n\
version: wire-value\r\n\
Content-Length: 0\r\n\r\n\r\n\r\n";
    let mut reader = ArchiveReader::new(Cursor::new(bytes));
    let mut entry = reader.next_entry().expect("read WARC").expect("one record");
    let metadata = entry.metadata().clone();
    entry.read_to_end(&mut Vec::new()).expect("read empty body");
    drop(entry);

    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    writer
        .start_entry(&metadata)
        .expect("reader metadata must be writable");
    writer.end_entry().expect("end record");
    let encoded = writer.finish().expect("finish WARC");
    assert!(
        encoded
            .windows(b"version: wire-value\r\n".len())
            .any(|window| window == b"version: wire-value\r\n")
    );
}

#[test]
fn warc_writer_payload_size_and_resource_limits_are_typed() {
    let empty = ArchiveWriter::with_format(Vec::new(), FormatId::Warc)
        .expect("WARC writer")
        .finish()
        .expect_err("an empty WARC file is not a readable archive");
    assert_eq!(empty.kind(), ErrorKind::Protocol);

    let metadata = writable_metadata(2, b"<urn:uuid:size>");
    let mut short = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    short.start_entry(&metadata).expect("start record");
    short.write_data(b"x").expect("write short prefix");
    assert_eq!(
        short.end_entry().expect_err("short content block").kind(),
        ErrorKind::Protocol
    );

    let mut long = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("WARC writer");
    long.start_entry(&metadata).expect("start record");
    assert_eq!(
        long.write_data(b"xyz")
            .expect_err("long content block")
            .kind(),
        ErrorKind::Protocol
    );

    for (limits, expected) in [
        (Limits::safe().with_entries(Some(0)), ErrorKind::Limit),
        (
            Limits::safe().with_metadata_bytes(Some(10)),
            ErrorKind::Limit,
        ),
        (Limits::safe().with_entry_bytes(Some(1)), ErrorKind::Limit),
    ] {
        let mut writer = ArchiveWriter::with_format_and_limits(Vec::new(), FormatId::Warc, limits)
            .expect("bounded WARC writer");
        assert_eq!(
            writer
                .start_entry(&metadata)
                .expect_err("WARC begin limit")
                .kind(),
            expected
        );
    }

    let mut total = ArchiveWriter::with_format_and_limits(
        Vec::new(),
        FormatId::Warc,
        Limits::safe().with_decoded_total(Some(1)),
    )
    .expect("bounded WARC writer");
    total.start_entry(&metadata).expect("start bounded record");
    assert_eq!(
        total
            .write_data(b"xy")
            .expect_err("WARC total limit")
            .kind(),
        ErrorKind::Limit
    );
}

#[cfg(feature = "async")]
#[test]
fn futures_reader_and_writer_share_the_warc_state_machines() {
    block_on(async {
        let metadata = writable_metadata(5, b"<urn:uuid:futures>");
        let mut writer = AsyncArchiveWriter::with_format(Vec::new(), FormatId::Warc)
            .expect("futures WARC writer");
        writer
            .start_entry(&metadata)
            .await
            .expect("start futures record");
        writer
            .write_data(b"async")
            .await
            .expect("write futures record");
        writer.end_entry().await.expect("end futures record");
        let bytes = writer.finish().await.expect("finish futures WARC");

        let mut reader = AsyncArchiveReader::new(AsyncOneByte { bytes, position: 0 });
        let mut body = Vec::new();
        loop {
            match reader.next_event().await.expect("read futures WARC") {
                ReaderEvent::Data(data) => body.extend_from_slice(data),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                _ => panic!("unknown futures WARC event"),
            }
        }
        assert_eq!(body, b"async");
    });
}

#[cfg(all(feature = "async", feature = "tokio"))]
#[tokio::test(flavor = "current_thread")]
async fn tokio_reader_and_writer_share_the_warc_state_machines() {
    use libarchive_oxide::{TokioArchiveReader, TokioArchiveWriter};

    let metadata = writable_metadata(5, b"<urn:uuid:tokio>");
    let mut writer =
        TokioArchiveWriter::with_format(Vec::new(), FormatId::Warc).expect("Tokio WARC writer");
    writer
        .start_entry(&metadata)
        .await
        .expect("start Tokio record");
    writer
        .write_data(b"tokio")
        .await
        .expect("write Tokio record");
    writer.end_entry().await.expect("end Tokio record");
    let bytes = writer.finish().await.expect("finish Tokio WARC");

    let mut reader = TokioArchiveReader::new(bytes.as_slice());
    let mut body = Vec::new();
    loop {
        match reader.next_event().await.expect("read Tokio WARC") {
            ReaderEvent::Data(data) => body.extend_from_slice(data),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown Tokio WARC event"),
        }
    }
    assert_eq!(body, b"tokio");
}
