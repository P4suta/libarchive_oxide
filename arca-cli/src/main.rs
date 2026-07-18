//! `arca` CLI — a bsdtar-style demonstrator over the arca library.
//!
//! Usage:
//!   arca t <archive>            List entries.
//!   arca x <archive> [-C <dir>] Extract entries under <dir> (default: current directory).
//!
//! The archive may be plain or compressed (gzip/zstd/xz/lz4); compression and format are
//! auto-detected. Extraction sanitizes paths and caps the decompressed size.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Cap on decompressed size for untrusted input (defends against decompression bombs).
///
/// Declared as `u64` so the 4 GiB literal does not overflow `usize` on 32-bit targets; it is
/// clamped to `usize::MAX` at the call site.
const MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("arca: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut args = args.into_iter();
    let cmd = args
        .next()
        .ok_or("missing subcommand (expected `t`, `x`, or `c`)")?;

    let mut positional: Vec<String> = Vec::new();
    let mut dest_dir = PathBuf::from(".");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-C" => dest_dir = PathBuf::from(args.next().ok_or("-C requires a directory")?),
            _ => positional.push(arg),
        }
    }

    match cmd.as_str() {
        "t" | "x" => {
            let file = positional.first().ok_or("missing archive path")?;
            let bytes = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let cap = usize::try_from(MAX_DECOMPRESSED).unwrap_or(usize::MAX);
            let plain = arca::decompress_capped(&bytes, cap).map_err(|e| e.to_string())?;
            let mut reader = arca::reader(&plain).map_err(|e| e.to_string())?;
            if cmd == "t" {
                list(reader.as_mut())
            } else {
                extract(reader.as_mut(), &dest_dir)
            }
        }
        "c" => {
            let (archive, inputs) = positional
                .split_first()
                .ok_or("usage: arca c <archive> <path>...")?;
            if inputs.is_empty() {
                return Err("usage: arca c <archive> <path>...".into());
            }
            let bytes = arca::create::build_archive(inputs, archive).map_err(|e| e.to_string())?;
            std::fs::write(archive, &bytes).map_err(|e| format!("cannot write {archive}: {e}"))?;
            eprintln!(
                "created {archive} ({} bytes) from {} path(s)",
                bytes.len(),
                inputs.len()
            );
            Ok(())
        }
        other => Err(format!(
            "unknown subcommand `{other}` (expected `t`, `x`, or `c`)"
        )),
    }
}

fn list(reader: &mut dyn arca_core::EntryReader) -> Result<(), String> {
    while let Some(entry) = reader.next_entry().map_err(|e| e.to_string())? {
        let meta = entry.meta();
        println!(
            "{:<10} {:>12}  {}",
            kind_label(meta.kind),
            meta.size,
            String::from_utf8_lossy(&meta.path),
        );
    }
    Ok(())
}

fn extract(reader: &mut dyn arca_core::EntryReader, dest: &Path) -> Result<(), String> {
    let stats = arca::extract::extract(reader, dest).map_err(|e| e.to_string())?;
    eprintln!(
        "extracted {} files, {} dirs ({} skipped) into {}",
        stats.files,
        stats.dirs,
        stats.skipped,
        dest.display(),
    );
    Ok(())
}

fn kind_label(kind: arca_core::EntryKind) -> &'static str {
    use arca_core::EntryKind::{Block, Char, Dir, Fifo, File, Hardlink, Socket, Symlink};
    match kind {
        File => "file",
        Dir => "dir",
        Symlink => "symlink",
        Hardlink => "hardlink",
        Char => "char",
        Block => "block",
        Fifo => "fifo",
        Socket => "socket",
        _ => "other",
    }
}
