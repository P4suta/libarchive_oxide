// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit raw-format contracts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read};

use libarchive_oxide::{ArchiveEngine, ArchiveReader, FormatId, ReaderEvent};
use libarchive_oxide_core::{ErrorKind, Limits};

#[test]
fn raw_is_never_guessed_but_explicit_selection_streams_one_entry() {
    let body: Vec<u8> = (0_u8..=250).cycle().take(300_000).collect();

    let mut automatic = ArchiveReader::open(Cursor::new(body.clone()));
    let automatic_error = automatic
        .next_event()
        .expect_err("signatureless bytes must not be guessed as raw");
    assert_eq!(
        automatic_error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );

    let mut reader =
        ArchiveReader::with_format(Cursor::new(body.clone()), FormatId::Raw).expect("raw reader");
    let mut entry = reader.next_entry().expect("next entry").expect("raw entry");
    assert_eq!(entry.metadata().path().as_bytes(), b"data");
    assert_eq!(entry.metadata().size(), None);
    let mut decoded = Vec::new();
    entry.read_to_end(&mut decoded).expect("raw body");
    drop(entry);
    assert_eq!(decoded, body);
    assert!(reader.next_entry().expect("raw done").is_none());
    assert_eq!(reader.format(), Some(FormatId::Raw));
}

#[test]
fn explicit_empty_raw_differs_from_the_canonical_empty_archive() {
    let mut raw =
        ArchiveReader::with_format(Cursor::new(Vec::<u8>::new()), FormatId::Raw).expect("raw");
    let mut entry = raw.next_entry().expect("raw entry").expect("one entry");
    let mut decoded = Vec::new();
    entry.read_to_end(&mut decoded).expect("empty raw body");
    assert!(decoded.is_empty());
    drop(entry);
    assert!(raw.next_entry().expect("raw done").is_none());

    let mut automatic = ArchiveReader::open(Cursor::new(Vec::<u8>::new()));
    assert!(automatic.next_entry().expect("empty archive").is_none());
    assert_eq!(automatic.format(), Some(FormatId::Empty));
}

#[test]
fn raw_enforces_the_decoded_total_limit_before_consuming_excess() {
    let limits = Limits::safe()
        .with_filter_depth(Some(0))
        .with_decoded_total(Some(3));
    let mut reader =
        ArchiveReader::with_format_and_limits(Cursor::new(b"abcd".to_vec()), FormatId::Raw, limits)
            .expect("raw reader");
    assert!(matches!(
        reader.next_event().expect("metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().expect("entry"),
        ReaderEvent::Entry(_)
    ));
    assert!(matches!(
        reader.next_event().expect("bounded data"),
        ReaderEvent::Data(b"abc")
    ));
    let error = reader.next_event().expect_err("decoded limit");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Limit)
    );
}

#[test]
fn explicit_streaming_reader_rejects_seek_formats_before_reading() {
    let error = ArchiveReader::with_format(Cursor::new(Vec::<u8>::new()), FormatId::Zip)
        .expect_err("ZIP requires seek");
    assert_eq!(error.kind(), ErrorKind::Capability);
}

#[test]
fn prepared_raw_session_preserves_the_explicit_format_across_rewind() {
    let body = b"prepared raw body".repeat(1_000);
    let mut session = ArchiveEngine::new()
        .prepare_with_format(Cursor::new(body.clone()), FormatId::Raw)
        .expect("prepared raw session");
    let inspection = session.inspect().expect("raw inspection");
    assert_eq!(inspection.format(), FormatId::Raw);
    assert_eq!(inspection.entries().len(), 1);
    assert_eq!(
        inspection.entries()[0].metadata().path().as_bytes(),
        b"data"
    );

    session.rewind().expect("raw rewind");
    let mut decoded = Vec::new();
    loop {
        match session.next_event().expect("raw session event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);
}

#[cfg(feature = "gzip")]
#[test]
fn explicit_raw_selection_is_applied_after_outer_gzip_decoding() {
    use std::io::Write;

    let body = b"raw through an independently produced gzip stream".repeat(10_000);
    let mut gzip_writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip_writer.write_all(&body).expect("gzip input");
    let compressed = gzip_writer.finish().expect("gzip finish");

    let mut reader = ArchiveReader::with_format(Cursor::new(compressed), FormatId::Raw)
        .expect("raw+gzip reader");
    let mut entry = reader.next_entry().expect("next entry").expect("raw entry");
    let mut decoded = Vec::new();
    entry.read_to_end(&mut decoded).expect("decoded raw body");
    assert_eq!(decoded, body);
}

#[cfg(feature = "async")]
#[test]
fn asynchronous_raw_reader_uses_the_same_sans_io_decoder() {
    futures_lite::future::block_on(async {
        let body = b"async raw body".repeat(20_000);
        let input = futures_lite::io::Cursor::new(body.clone());
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_format(input, FormatId::Raw)
            .expect("async raw reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.expect("async raw event") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, body);
    });
}
