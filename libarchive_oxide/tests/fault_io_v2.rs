// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! I/O fault propagation and poisoned-writer contracts.

#![allow(clippy::unwrap_used)]

use std::error::Error;
use std::fmt;
use std::io::{self, Cursor, Read, Write};

use libarchive_oxide::{ArchiveReader, ArchiveWriter};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata};

#[derive(Debug)]
struct Injected;

impl fmt::Display for Injected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected I/O failure")
    }
}

impl Error for Injected {}

#[derive(Debug)]
struct FailingWrite {
    bytes: Vec<u8>,
    fail_at: usize,
}

impl Write for FailingWrite {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.bytes.len() == self.fail_at {
            return Err(io::Error::other(Injected));
        }
        let count = input.len().min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&input[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_preserves_injected_error_and_never_synthesizes_a_trailer_after_failure() {
    for fail_at in [0, 1, 511, 512, 700] {
        let output = FailingWrite {
            bytes: Vec::new(),
            fail_at,
        };
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("fault.bin"))
            .size(Some(1024))
            .build();
        let mut writer = ArchiveWriter::new(output);
        let result = writer
            .start_entry(&metadata)
            .and_then(|()| writer.write_data(&[0x5a; 1024]))
            .and_then(|()| writer.end_entry());
        let error = result.unwrap_err();
        assert_eq!(
            error.io_error().map(io::Error::kind),
            Some(io::ErrorKind::Other)
        );
        assert!(
            error
                .io_error()
                .and_then(io::Error::get_ref)
                .and_then(|source| source.downcast_ref::<Injected>())
                .is_some()
        );
        let poisoned = writer.write_data(b"x").unwrap_err();
        assert!(poisoned.archive_error().is_some());
        let partial = writer.abort().unwrap().bytes;
        assert_eq!(partial.len(), fail_at);
        assert!(!partial.ends_with(&[0; 1024]));
    }
}

struct FailingRead {
    input: Cursor<Vec<u8>>,
    remaining: usize,
}

impl Read for FailingRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other(Injected));
        }
        let count = output.len().min(self.remaining);
        let read = self.input.read(&mut output[..count])?;
        self.remaining -= read;
        Ok(read)
    }
}

#[test]
fn reader_preserves_the_original_io_error_source() {
    let mut archive = ArchiveWriter::new(Vec::new());
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("fault.bin"))
        .size(Some(1024))
        .build();
    archive.start_entry(&metadata).unwrap();
    archive.write_data(&[0x5a; 1024]).unwrap();
    archive.end_entry().unwrap();
    let bytes = archive.finish().unwrap();

    let input = FailingRead {
        input: Cursor::new(bytes),
        remaining: 600,
    };
    let mut reader = ArchiveReader::new(input);
    let error = loop {
        match reader.next_event() {
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert!(
        error
            .io_error()
            .and_then(io::Error::get_ref)
            .and_then(|source| source.downcast_ref::<Injected>())
            .is_some()
    );
}
