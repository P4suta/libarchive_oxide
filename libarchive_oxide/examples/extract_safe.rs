//! Extract an archive with the traversal-safe path API.
//!
//! Run it with `cargo run --example extract_safe`. It synthesizes a tar that includes a *hostile*
//! `../escape.txt` entry, then extracts it through [`libarchive_oxide::extract::extract`], which runs
//! every entry path through [`libarchive_oxide::sanitize`]. The path-traversal (`../`) entry is
//! rejected and counted as skipped rather than written outside the destination; symlinks and devices are
//! skipped by the same conservative default. The returned [`Stats`] reports what was materialized.
//!
//! [`Stats`]: libarchive_oxide::Stats

use std::borrow::Cow;
use std::process::ExitCode;

use libarchive_oxide::libarchive_oxide_core::format::tar::TarWriter;
use libarchive_oxide::libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("extract_safe: {e}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    // First, the path guard in isolation: `sanitize` maps a raw archive path to a safe *relative*
    // path, or `None` when it would escape the destination.
    for raw in [
        b"docs/readme.txt".as_slice(),
        b"../escape.txt".as_slice(),
        b"/etc/passwd".as_slice(),
    ] {
        let shown = String::from_utf8_lossy(raw);
        match libarchive_oxide::sanitize(raw) {
            Some(safe) => println!("sanitize({shown:?}) -> {}", safe.display()),
            None => println!("sanitize({shown:?}) -> rejected (unsafe)"),
        }
    }
    println!();

    // Now the same guard applied end-to-end by `extract`.
    let tar = make_hostile_tar()?;
    let dest = std::env::temp_dir().join("libarchive_oxide-extract-demo");

    let mut reader = libarchive_oxide::reader(&tar).map_err(|e| e.to_string())?;
    let stats =
        libarchive_oxide::extract::extract(&mut reader, &dest).map_err(|e| e.to_string())?;

    println!("extracted into {}", dest.display());
    println!(
        "  files={} dirs={} skipped={} (the ../escape.txt entry is in `skipped`)",
        stats.files, stats.dirs, stats.skipped
    );
    Ok(())
}

/// Builds a tar with two legitimate entries and one path-traversal attack, in memory.
fn make_hostile_tar() -> Result<Vec<u8>, String> {
    let mut writer = TarWriter::new(Vec::new());

    add_dir(&mut writer, b"assets")?;
    add_file(&mut writer, b"assets/logo.txt", b"safe content\n")?;
    // Hostile: a classic directory-traversal path. `extract` must skip it.
    add_file(
        &mut writer,
        b"../escape.txt",
        b"you should never see this on disk\n",
    )?;

    writer.finish().map_err(|e| e.to_string())?;
    Ok(writer.into_inner())
}

fn add_dir(writer: &mut TarWriter<Vec<u8>>, name: &[u8]) -> Result<(), String> {
    let mut meta = EntryMeta::new(EntryKind::Dir, Cow::Borrowed(name));
    meta.mode = 0o755;
    let mut sink = writer.start_entry(&meta).map_err(|e| e.to_string())?;
    sink.close().map_err(|e| e.to_string())?;
    Ok(())
}

fn add_file(writer: &mut TarWriter<Vec<u8>>, name: &[u8], content: &[u8]) -> Result<(), String> {
    let mut meta = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
    meta.mode = 0o644;
    meta.size = content.len() as u64;
    let mut sink = writer.start_entry(&meta).map_err(|e| e.to_string())?;
    sink.write_chunk(content).map_err(|e| e.to_string())?;
    sink.close().map_err(|e| e.to_string())?;
    Ok(())
}
