// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared implementation for `oxtar`, `oxcpio`, `oxcat`, and `oxunzip`.
//!
//! Exit codes are 0 for success, 1 for runtime errors, and 2 for usage errors.
//! Extraction rejects path traversal. Transparent decompression is capped at
//! [`MAX_DECOMPRESSED`].

#![forbid(unsafe_code)]

pub mod cat;
pub mod cpio;
pub mod tar;
pub mod unzip;

use std::path::Path;

use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader};

pub use cat::run_cat;
pub use cpio::run_cpio;
pub use tar::run_tar;
pub use unzip::run_unzip;

/// Maximum decompressed size.
///
/// Stored as `u64` because 4 GiB exceeds `usize` on 32-bit targets.
pub const MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

/// Returns [`MAX_DECOMPRESSED`] as `usize`, clamped on 32-bit targets.
#[must_use]
pub fn decompress_cap() -> usize {
    usize::try_from(MAX_DECOMPRESSED).unwrap_or(usize::MAX)
}

/// A CLI error and process exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// Message written to standard error.
    pub message: String,
    /// Process exit code: 1 for runtime errors, 2 for usage errors.
    pub code: u8,
}

impl CliError {
    /// Creates a usage error with exit code 2.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }

    /// Creates a runtime error with exit code 1.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    /// Creates an unsupported-option error with exit code 2.
    pub fn unsupported(flag: impl std::fmt::Display) -> Self {
        Self::usage(format!("unsupported: {flag}"))
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Convenience alias for CLI entry points.
pub type CliResult = Result<(), CliError>;

/// Reads a file or returns a runtime error.
pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::runtime(format!("cannot read {path}: {e}")))
}

/// Detects an archive and writes its entry list to standard output.
///
/// Verbose output includes mode, owner, size, modification time, and name.
/// Member operands select exact paths or directory prefixes. Unmatched operands
/// return a runtime error.
pub(crate) fn list_bytes(
    bytes: &[u8],
    password: Option<&[u8]>,
    members: &[String],
    verbose: bool,
) -> CliResult {
    let plain = libarchive_oxide::decompress_capped(bytes, decompress_cap())
        .map_err(|e| CliError::runtime(e.to_string()))?;
    let mut reader = libarchive_oxide::reader_with_password(&plain, password)
        .map_err(|e| CliError::runtime(e.to_string()))?;
    let mut filter = MemberFilter::new(members);
    while let Some(entry) = reader
        .next_entry()
        .map_err(|e| CliError::runtime(e.to_string()))?
    {
        let meta = entry.meta();
        if !filter.selects(&meta.path) {
            continue;
        }
        if verbose {
            println!("{}", format_long(meta));
        } else {
            println!("{}", String::from_utf8_lossy(&meta.path));
        }
    }
    filter.ensure_all_matched()
}

/// Extracts an archive under `dest`.
///
/// Paths are sanitized and decompression is limited. Member operands select
/// exact paths or directory prefixes.
pub(crate) fn extract_bytes(
    bytes: &[u8],
    dest: &Path,
    password: Option<&[u8]>,
    verbose: bool,
    members: &[String],
) -> CliResult {
    let plain = libarchive_oxide::decompress_capped(bytes, decompress_cap())
        .map_err(|e| CliError::runtime(e.to_string()))?;
    let mut reader = libarchive_oxide::reader_with_password(&plain, password)
        .map_err(|e| CliError::runtime(e.to_string()))?;
    if !verbose && members.is_empty() {
        return libarchive_oxide::extract::extract(&mut reader, dest)
            .map(|_| ())
            .map_err(|e| CliError::runtime(e.to_string()));
    }
    extract_selected(&mut reader, dest, verbose, members)
}

/// Extracts selected members with optional logging.
fn extract_selected<R: EntryReader>(
    reader: &mut R,
    dest: &Path,
    verbose: bool,
    members: &[String],
) -> CliResult {
    use std::io::Write;

    std::fs::create_dir_all(dest).map_err(|e| CliError::runtime(e.to_string()))?;
    let mut filter = MemberFilter::new(members);
    while let Some(mut entry) = reader
        .next_entry()
        .map_err(|e| CliError::runtime(e.to_string()))?
    {
        let kind = entry.meta().kind;
        if !filter.selects(&entry.meta().path) {
            continue;
        }
        let Some(rel) = libarchive_oxide::sanitize(&entry.meta().path) else {
            continue;
        };
        let path = dest.join(&rel);
        match kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&path).map_err(|e| CliError::runtime(e.to_string()))?;
            },
            EntryKind::File => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| CliError::runtime(e.to_string()))?;
                }
                let mut file =
                    std::fs::File::create(&path).map_err(|e| CliError::runtime(e.to_string()))?;
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let n = entry
                        .data()
                        .read_chunk(&mut buf)
                        .map_err(|e| CliError::runtime(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    file.write_all(&buf[..n])
                        .map_err(|e| CliError::runtime(e.to_string()))?;
                }
                if verbose {
                    eprintln!("x {}", rel.display());
                }
            },
            _ => {},
        }
    }
    filter.ensure_all_matched()
}

/// Selects entries and tracks matched operands.
///
/// Empty operands select all entries. Other operands match exact paths or
/// directory prefixes. Trailing slashes are ignored.
#[derive(Debug)]
struct MemberFilter<'m> {
    members: &'m [String],
    matched: Vec<bool>,
}

impl<'m> MemberFilter<'m> {
    /// Creates a member filter.
    fn new(members: &'m [String]) -> Self {
        Self {
            members,
            matched: vec![false; members.len()],
        }
    }

    /// Returns whether `path` is selected and records matching operands.
    fn selects(&mut self, path: &[u8]) -> bool {
        if self.members.is_empty() {
            return true;
        }
        let entry = trim_trailing_slash(path);
        let mut selected = false;
        for (i, m) in self.members.iter().enumerate() {
            let want = trim_trailing_slash(m.as_bytes());
            if entry == want
                || (entry.len() > want.len()
                    && entry.starts_with(want)
                    && entry[want.len()] == b'/')
            {
                self.matched[i] = true;
                selected = true;
            }
        }
        selected
    }

    /// Fails (exit 1) if any member operand matched no entry, reporting the first such operand as
    /// `<name>: Not found in archive`. A no-op when the operand list was empty or all matched.
    fn ensure_all_matched(&self) -> CliResult {
        match self.matched.iter().position(|&m| !m) {
            Some(i) => Err(CliError::runtime(format!(
                "{}: Not found in archive",
                self.members[i]
            ))),
            None => Ok(()),
        }
    }
}

/// Trims a single trailing `/` for name comparison (`sub/` and `sub` name the same member).
fn trim_trailing_slash(p: &[u8]) -> &[u8] {
    p.strip_suffix(b"/").unwrap_or(p)
}

/// Formats one entry as an `ls -l`-style long listing line for `-tv`, matching `bsdtar -tv`'s
/// mode / owner / size / mtime / name columns (symlinks append ` -> target`).
fn format_long(meta: &EntryMeta<'_>) -> String {
    let mode = mode_string(meta.kind, meta.mode);
    let date = meta.mtime.map_or_else(
        || "1970-01-01 00:00".to_string(),
        |t| format_timestamp(t.secs),
    );
    let name = String::from_utf8_lossy(&meta.path);
    match &meta.link_target {
        Some(target) if matches!(meta.kind, EntryKind::Symlink) => format!(
            "{mode} {}/{} {:>10} {date} {name} -> {}",
            meta.uid,
            meta.gid,
            meta.size,
            String::from_utf8_lossy(target),
        ),
        _ => format!(
            "{mode} {}/{} {:>10} {date} {name}",
            meta.uid, meta.gid, meta.size
        ),
    }
}

/// Builds the 10-char `drwxr-xr-x`-style mode string from an entry kind and permission bits.
fn mode_string(kind: EntryKind, mode: u32) -> String {
    let type_ch = match kind {
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::Char => 'c',
        EntryKind::Block => 'b',
        EntryKind::Fifo => 'p',
        EntryKind::Socket => 's',
        _ => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(type_ch);
    for shift in [6u32, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Formats a UNIX timestamp (seconds since the epoch) as `YYYY-MM-DD HH:MM` (UTC), for `-tv`.
fn format_timestamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {hour:02}:{min:02}")
}

/// Civil date `(year, month, day)` from days since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
