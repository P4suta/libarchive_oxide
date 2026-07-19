// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Create a ZIP incrementally, without retaining an entry payload.

use std::path::PathBuf;
use std::process::ExitCode;

use libarchive_oxide::{ArchiveWriter, ZipMethod};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("create_zip: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let destination = std::env::args().nth(1).map_or_else(
        || std::env::temp_dir().join("libarchive_oxide-example.zip"),
        PathBuf::from,
    );
    let file = std::fs::File::create(&destination).map_err(|error| error.to_string())?;
    let mut writer = ArchiveWriter::with_zip_method(file, ZipMethod::Deflate, Limits::default());
    for (name, body) in [
        (
            b"README.txt".as_slice(),
            b"Packed by the libarchive_oxide streaming example.\n".as_slice(),
        ),
        (
            b"data/payload.bin".as_slice(),
            b"\x00\x01\x02\x03streamed-streamed-streamed\x04\x05".as_slice(),
        ),
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
                .size(None)
                .mode(Some(0o644))
                .build();
        writer
            .start_entry(&metadata)
            .map_err(|error| error.to_string())?;
        for chunk in body.chunks(7) {
            writer
                .write_data(chunk)
                .map_err(|error| error.to_string())?;
        }
        writer.end_entry().map_err(|error| error.to_string())?;
    }
    let file = writer.finish().map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    println!("wrote {length} bytes to {}", destination.display());
    Ok(())
}
