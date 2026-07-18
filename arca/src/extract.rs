//! Archive format auto-detection and safe filesystem extraction (the std entry points).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use arca_core::format::ar::{Ar, ArReader};
use arca_core::format::cpio::{Cpio, CpioReader};
use arca_core::format::tar::{Tar, TarReader};
use arca_core::format::{ArchiveFormat, Detection};
use arca_core::{EntryKind, EntryReader};

use crate::path::sanitize;

/// Detects the archive format from `plain` (already decompressed) and builds a reader.
///
/// Recognizes tar, ar, and cpio. Errors if the bytes match none of them.
pub fn reader(plain: &[u8]) -> io::Result<Box<dyn EntryReader + '_>> {
    if matches!(Tar::sniff(plain), Detection::Match) {
        Ok(Box::new(TarReader::new(plain)))
    } else if matches!(Ar::sniff(plain), Detection::Match) {
        Ok(Box::new(ArReader::new(plain)))
    } else if matches!(Cpio::sniff(plain), Detection::Match) {
        Ok(Box::new(CpioReader::new(plain)))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "arca: unrecognized archive format",
        ))
    }
}

/// Counts of what an extraction materialized.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Regular files written.
    pub files: usize,
    /// Directories created.
    pub dirs: usize,
    /// Entries skipped (unsafe path, or an unsupported kind such as symlink/device).
    pub skipped: usize,
}

/// Extracts every entry of `reader` under `dest`, sanitizing each path against traversal.
///
/// Files and directories are materialized; symlinks, devices, and unsafe paths are counted as
/// skipped (a conservative, portable default). `dest` is created if missing.
pub fn extract(reader: &mut dyn EntryReader, dest: &Path) -> io::Result<Stats> {
    fs::create_dir_all(dest)?;
    let mut stats = Stats::default();

    while let Some(mut entry) = reader.next_entry().map_err(to_io)? {
        let kind = entry.meta().kind;
        let Some(rel) = sanitize(&entry.meta().path) else {
            stats.skipped += 1;
            continue;
        };
        let path = dest.join(&rel);

        match kind {
            EntryKind::Dir => {
                fs::create_dir_all(&path)?;
                stats.dirs += 1;
            }
            EntryKind::File => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut file = fs::File::create(&path)?;
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let n = entry.data().read_chunk(&mut buf).map_err(to_io)?;
                    if n == 0 {
                        break;
                    }
                    file.write_all(&buf[..n])?;
                }
                stats.files += 1;
            }
            _ => stats.skipped += 1,
        }
    }

    Ok(stats)
}

/// Maps a sans-IO core error into a std I/O error for the std surface.
fn to_io(e: arca_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
}
