// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit spool bounds.

use std::io::{Read, Seek, SeekFrom, Write};

use libarchive_oxide::{SpoolReader, SpoolWriter};

#[test]
fn spool_moves_across_threshold_and_remains_seekable() {
    let mut writer = SpoolWriter::with_limits(4, 32);
    writer.write_all(b"0123456789").unwrap();
    let mut reader = writer.finish().unwrap();
    assert_eq!(reader.len(), 10);
    reader.seek(SeekFrom::Start(3)).unwrap();
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"3456789");
}

#[test]
fn spool_rejects_bytes_beyond_the_explicit_maximum() {
    let mut writer = SpoolWriter::with_limits(8, 5);
    assert!(writer.write_all(b"123456").is_err());
    assert!(writer.is_empty());

    let result = SpoolReader::from_reader_with_limits(&b"123456"[..], 8, 5);
    assert!(result.is_err());
}
