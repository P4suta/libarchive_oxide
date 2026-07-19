// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extract through a directory capability and the safe default policy.

use std::io::Cursor;
use std::process::ExitCode;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{ArchiveReader, ArchiveWriter, Extractor};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("extract_safe: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut writer = ArchiveWriter::new(Vec::new());
    for (name, body) in [
        (b"assets/logo.txt".as_slice(), b"safe content\n".as_slice()),
        (
            b"../escape.txt".as_slice(),
            b"this must never escape\n".as_slice(),
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

    let destination = tempfile::tempdir().map_err(|error| error.to_string())?;
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority())
        .map_err(|error| error.to_string())?;
    let mut reader = ArchiveReader::new(Cursor::new(archive));
    let report = Extractor::new(root)
        .extract(&mut reader)
        .map_err(|error| error.to_string())?;
    println!(
        "{} entry outcomes under {}",
        report.outcomes().len(),
        destination.path().display()
    );
    Ok(())
}
