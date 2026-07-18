// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read a `.tar.gz`: auto-detect the gzip filter, then stream the tar entries.
//!
//! Run it with `cargo run --example read_tar_gz`. To keep the example self-contained it first
//! synthesizes a small `.tar.gz` in memory (a `TarWriter` fed into [`libarchive_oxide::compress`]),
//! then reads it back through the very same entry points a consumer would use on a file from disk:
//! [`libarchive_oxide::decompress`] to strip the compression, then [`libarchive_oxide::reader`] to
//! iterate entries — all dispatched over sealed enums with zero type erasure.

use std::borrow::Cow;
use std::process::ExitCode;

use libarchive_oxide::libarchive_oxide_core::filter::FilterId;
use libarchive_oxide::libarchive_oxide_core::format::tar::TarWriter;
use libarchive_oxide::libarchive_oxide_core::{
    Entry, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("read_tar_gz: {e}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    // 1. Build a plain tar in memory, then gzip it — this is exactly the byte stream a `.tar.gz`
    //    file holds.
    let targz = make_sample_targz()?;
    println!("synthesized a {}-byte .tar.gz\n", targz.len());

    // 2. Auto-detect the compression from the leading magic bytes and strip it. `decompress`
    //    borrows the input when there is nothing to strip, so a plain `.tar` costs no copy.
    let plain = libarchive_oxide::decompress(&targz).map_err(|e| e.to_string())?;

    // 3. Detect the archive format and iterate its entries. `reader` returns an `AnyReader` by
    //    value (a sealed enum), never a boxed trait object.
    let mut reader = libarchive_oxide::reader(&plain).map_err(|e| e.to_string())?;
    while let Some(mut entry) = reader.next_entry().map_err(|e| e.to_string())? {
        // Copy the metadata we need before borrowing the payload cursor mutably.
        let name = String::from_utf8_lossy(&entry.meta().path).into_owned();
        let kind = entry.meta().kind;
        let declared = entry.meta().size;

        let body = drain(&mut entry)?;
        println!("{kind:?}\t{declared:>6} bytes\t{name}");
        if kind == EntryKind::File {
            println!("  └─ {:?}", String::from_utf8_lossy(&body));
        }
    }
    Ok(())
}

/// Reads an entry's whole payload into a `Vec` via the chunked [`EntryData`] cursor.
fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = entry
            .data()
            .read_chunk(&mut buf)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(body)
}

/// Produces a small `.tar.gz` entirely in memory using the public write + codec API.
fn make_sample_targz() -> Result<Vec<u8>, String> {
    let files: [(&[u8], &[u8]); 2] = [
        (b"greeting.txt", b"hello from libarchive_oxide\n"),
        (
            b"docs/notes.md",
            b"# notes\n\nunified, pure-Rust archives.\n",
        ),
    ];

    let mut writer = TarWriter::new(Vec::new());
    for (name, content) in files {
        let mut meta = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        meta.mode = 0o644;
        meta.size = content.len() as u64;
        let mut sink = writer.start_entry(&meta).map_err(|e| e.to_string())?;
        sink.write_chunk(content).map_err(|e| e.to_string())?;
        sink.close().map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    let tar = writer.into_inner();

    libarchive_oxide::compress(&tar, FilterId::Gzip).map_err(|e| e.to_string())
}
