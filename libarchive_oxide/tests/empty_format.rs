// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interoperability and failure evidence for the zero-byte archive format.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::Cursor;

use libarchive_oxide::{ArchiveReader, ReaderEvent};
use libarchive_oxide_core::{ErrorKind, FormatId};

fn assert_empty_archive(bytes: Vec<u8>) {
    let mut reader = ArchiveReader::new(Cursor::new(bytes));
    assert!(matches!(
        reader.next_event().expect("archive metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert_eq!(reader.format(), Some(FormatId::Empty));
    assert!(matches!(
        reader.next_event().expect("empty archive completion"),
        ReaderEvent::Done
    ));
}

#[test]
fn zero_byte_input_is_a_first_class_empty_archive() {
    assert_empty_archive(Vec::new());
}

#[test]
fn independently_generated_empty_gzip_member_wraps_an_empty_archive() {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let frame = encoder.finish().expect("independent gzip producer");
    assert_empty_archive(frame);
}

#[test]
fn unknown_nonempty_input_is_not_downgraded_to_empty_or_raw() {
    let mut reader = ArchiveReader::new(Cursor::new(b"not an archive".to_vec()));
    let error = reader
        .next_event()
        .expect_err("unknown bytes must remain unsupported");
    assert_eq!(
        error
            .archive_error()
            .map(libarchive_oxide_core::ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
    assert_eq!(reader.format(), None);
}
