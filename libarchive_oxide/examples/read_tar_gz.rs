// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Create and read a `.tar.gz` through the common bounded state machine.

use std::io::Cursor;
use std::process::ExitCode;

use libarchive_oxide::{ArchiveReader, ArchiveWriter, ReaderEvent};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("read_tar_gz: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Gzip),
        Limits::default(),
    )
    .map_err(|error| error.to_string())?;
    for (name, body) in [
        (
            b"greeting.txt".as_slice(),
            b"hello from libarchive_oxide\n".as_slice(),
        ),
        (
            b"docs/notes.md".as_slice(),
            b"# notes\n\nbounded streaming archives.\n".as_slice(),
        ),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .size(Some(body.len() as u64))
                .mode(Some(0o644))
                .build();
        writer
            .start_entry(&metadata)
            .map_err(|error| error.to_string())?;
        writer.write_data(body).map_err(|error| error.to_string())?;
        writer.end_entry().map_err(|error| error.to_string())?;
    }
    let archive = writer.finish().map_err(|error| error.to_string())?;

    let mut reader = ArchiveReader::new(Cursor::new(archive));
    loop {
        match reader.next_event().map_err(|error| error.to_string())? {
            ReaderEvent::Entry(metadata) => println!(
                "{:?}\t{:?}\t{}",
                metadata.kind(),
                metadata.size(),
                metadata.path().display_lossy()
            ),
            ReaderEvent::Data(bytes) => {
                print!("{}", String::from_utf8_lossy(bytes));
            },
            ReaderEvent::EndEntry => println!(),
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Done => return Ok(()),
            _ => return Err("unexpected future archive event".into()),
        }
    }
}
