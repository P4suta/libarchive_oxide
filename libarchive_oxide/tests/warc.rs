// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public API, specification-fixture, and negative evidence for WARC.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Read};

use libarchive_oxide::Limits;
use libarchive_oxide::advanced::{Pipeline, PipelineEvent};
use libarchive_oxide::{ArchiveReader, ArchiveWriter, ErrorKind, Extension, FormatId, ReaderEvent};

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
fn warc_has_no_writer_creation_path() {
    let error = ArchiveWriter::with_format(Vec::new(), FormatId::Warc)
        .expect_err("WARC must remain read-only");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}
