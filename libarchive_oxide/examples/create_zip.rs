// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Create a `.zip` in memory with the streaming [`ZipWriter`], then write it to disk.
//!
//! Run it with `cargo run --example create_zip` (writes to a temp file), or pass a destination path:
//! `cargo run --example create_zip -- out.zip`. The writer buffers each entry's plaintext, picks
//! DEFLATE (falling back to store when it would not shrink), and emits the central directory and
//! end-of-central-directory record at `finish`.

use std::borrow::Cow;
use std::path::PathBuf;
use std::process::ExitCode;

use libarchive_oxide::libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};
use libarchive_oxide::zip::ZipWriter;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("create_zip: {e}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let bytes = build_zip()?;

    let dest = std::env::args().nth(1).map_or_else(
        || std::env::temp_dir().join("libarchive_oxide-example.zip"),
        PathBuf::from,
    );
    std::fs::write(&dest, &bytes).map_err(|e| e.to_string())?;

    println!("wrote {} bytes to {}", bytes.len(), dest.display());
    println!("verify with:  oxunzip -l {}", dest.display());
    Ok(())
}

/// Builds a two-entry zip in memory. `ZipWriter` accepts any `Sink`; a `Vec<u8>` is the in-memory
/// one, so the whole archive is assembled without touching the filesystem.
fn build_zip() -> Result<Vec<u8>, String> {
    let entries: [(&[u8], &[u8]); 2] = [
        (
            b"README.txt",
            b"Packed by the libarchive_oxide create_zip example.\n",
        ),
        (
            b"data/payload.bin",
            b"\x00\x01\x02\x03compressible-compressible-compressible\x04\x05",
        ),
    ];

    // Default options: DEFLATE, no encryption. `ZipWriter::with_options` takes a `ZipOptions` to
    // switch on `WinZip` AES-256 (a password) or the store-only method.
    let mut writer = ZipWriter::new(Vec::new());
    for (name, content) in entries {
        let mut meta = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        meta.mode = 0o644;
        meta.size = content.len() as u64;
        let mut sink = writer.start_entry(&meta).map_err(|e| e.to_string())?;
        sink.write_chunk(content).map_err(|e| e.to_string())?;
        sink.close().map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(writer.into_inner())
}
