// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared library for the `ox*` CLI tools (`oxtar`/`oxcpio`/`oxcat`/`oxunzip`).
//!
//! Each `[[bin]]` is a thin `main` that forwards to a `run_*` entry point here and maps the
//! returned [`CliError`] onto the unified exit-code contract:
//!
//! - **0** — success.
//! - **1** — runtime failure (I/O error, corrupt archive, decompression-bomb cap hit).
//! - **2** — usage error (bad/unknown/unsupported flag, missing operand).
//!
//! The tools mirror the de-facto `bsdtar`/`bsdcpio`/`bsdcat`/`bsdunzip` interfaces and reuse the
//! flagship library's logic wholesale (auto-detecting [`reader`], [`extract`], the create/build
//! functions, and [`decompress`]). Classic flags the library cannot honor faithfully are **not**
//! silently stubbed: they return a clear `unsupported: <flag>` usage error (exit 2) and are
//! documented in each tool's `--help`.
//!
//! # Safe defaults (an intentional, documented divergence from historical tar)
//!
//! Unlike classic `tar`, these tools keep two safety nets **on by default**, because the library is
//! designed to consume untrusted archives:
//!
//! - **Path-traversal rejection**: entries whose sanitized path escapes the destination (`../`,
//!   absolute paths, Windows drive/UNC prefixes) are refused, via [`libarchive_oxide::sanitize`].
//! - **Decompression-bomb cap**: transparent decompression is capped at [`MAX_DECOMPRESSED`] bytes.
//!
//! [`reader`]: libarchive_oxide::reader
//! [`extract`]: libarchive_oxide::extract::extract
//! [`decompress`]: libarchive_oxide::decompress

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

/// Cap on decompressed size for untrusted input (defends against decompression bombs).
///
/// Declared as `u64` so the 4 GiB literal does not overflow `usize` on 32-bit targets; it is
/// clamped to `usize::MAX` at the call site.
pub const MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

/// The decompression-bomb cap as a `usize` (clamped on 32-bit targets).
#[must_use]
pub fn decompress_cap() -> usize {
    usize::try_from(MAX_DECOMPRESSED).unwrap_or(usize::MAX)
}

/// A CLI failure carrying the exit code it maps to.
///
/// The two kinds encode the unified exit-code contract: [`CliError::usage`] → exit 2 (the user
/// invoked the tool wrong, e.g. an unknown or unsupported flag), [`CliError::runtime`] → exit 1
/// (the invocation was valid but the work failed). Success is the `Ok` arm, never a `CliError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// Human-readable message, printed to stderr as `"<tool>: <message>"`.
    pub message: String,
    /// The process exit code this error maps to (1 = runtime, 2 = usage).
    pub code: u8,
}

impl CliError {
    /// A usage error (exit 2): bad, unknown, or unsupported flags; missing operands.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }

    /// A runtime error (exit 1): a valid invocation whose work failed.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    /// An "unsupported flag" usage error (exit 2) with a consistent, greppable prefix.
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

/// Reads a file into memory, mapping I/O failure onto a runtime error (exit 1).
pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::runtime(format!("cannot read {path}: {e}")))
}

/// Reads an archive's bytes, auto-detecting compression + format, and lists its entries to stdout.
///
/// The output mirrors the de-facto tools: **without** `verbose` one bare pathname per line (what
/// `bsdtar -t` / GNU `tar -t` emit, so `tar -tf x | while read name` works); **with** `verbose` an
/// `ls -l`-style long listing (mode, owner, size, mtime, name), matching `bsdtar -tv`.
///
/// When `members` is non-empty, only entries whose name matches one of them are listed (the faithful
/// `tar -t member...` / `cpio -it pattern` selection); an empty slice lists everything. A member
/// operand that matches no entry is an error (exit 1), never a silent success — see [`MemberFilter`].
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

/// Reads an archive's bytes and extracts its entries under `dest` (paths sanitized, size capped).
///
/// `verbose` echoes each materialized entry's name to stderr, mirroring `bsdtar -v`. When `members`
/// is non-empty, only matching entries are extracted (faithful `tar -x member...` selection); an
/// empty slice with `verbose == false` takes the library's tested batch-extract fast path.
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

/// Extraction with member selection and/or verbose logging. Reuses the same sanitize + kind
/// dispatch as [`libarchive_oxide::extract::extract`]; only the member filter and the `-v` echo
/// differ, so the safe-path guarantees (traversal rejection, symlink/device skip) are identical.
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

/// Selects entries by member operand while tracking which operands actually matched.
///
/// An empty operand list selects every entry. Otherwise an operand matches an entry when it equals
/// the entry name, or the entry lies under a member directory (`member/...`); comparison is on raw
/// bytes with a trailing `/` normalized away. Crucially, [`selects`](Self::selects) records each
/// operand it satisfies so that [`ensure_all_matched`](Self::ensure_all_matched) can fail on an
/// operand that named nothing — mirroring the non-zero exit and `<name>: Not found in archive`
/// diagnostic that GNU `tar` and `bsdtar`/`bsdcpio` give, rather than the silent exit-0 that a bare
/// `continue` would produce for a user's typo or wrong member name.
#[derive(Debug)]
struct MemberFilter<'m> {
    members: &'m [String],
    matched: Vec<bool>,
}

impl<'m> MemberFilter<'m> {
    /// Builds a filter over `members`, with every operand initially unmatched.
    fn new(members: &'m [String]) -> Self {
        Self {
            members,
            matched: vec![false; members.len()],
        }
    }

    /// Whether `path` is selected, recording **every** operand it satisfies. An empty operand list
    /// selects everything (and leaves nothing to check afterwards).
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
