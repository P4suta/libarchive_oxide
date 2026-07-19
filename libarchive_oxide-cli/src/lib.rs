// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared implementation for `oxarchive`, `oxtar`, `oxcpio`, `oxcat`, and
//! `oxunzip`.
//!
//! Exit codes are 0 for success, 1 for runtime errors, and 2 for usage errors.
//! Extraction rejects path traversal. Transparent decompression is capped at
//! [`MAX_DECOMPRESSED`].

#![forbid(unsafe_code)]

pub mod cat;
pub mod cpio;
pub mod oxarchive;
pub mod tar;
pub mod unzip;

use std::io::{Read, Seek};
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::{
    ArchiveReader, EntryOutcomeKind, ExtractionPolicy, Extractor, FilterReader, ReaderEvent,
    SecretBytes, SeekArchiveReader,
};
use libarchive_oxide_core::{EntryKind, EntryMetadata};

pub use cat::run_cat;
pub use cpio::run_cpio;
pub use oxarchive::run_oxarchive;
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

/// Lists a sequential archive without retaining the compressed or plain input.
pub(crate) fn list_stream<R: Read>(input: R, members: &[String], verbose: bool) -> CliResult {
    let input = FilterReader::new(input).map_err(|error| CliError::runtime(error.to_string()))?;
    let mut reader = ArchiveReader::new(input);
    let mut filter = MemberFilter::new(members);
    loop {
        match reader
            .next_event()
            .map_err(|error| CliError::runtime(error.to_string()))?
        {
            ReaderEvent::Entry(metadata) => {
                if !filter.selects(metadata.path().as_bytes()) {
                    continue;
                }
                if verbose {
                    println!("{}", format_long_v2(&metadata));
                } else {
                    println!("{}", metadata.path().display_lossy());
                }
            },
            ReaderEvent::Done => return filter.ensure_all_matched(),
            _ => {},
        }
    }
}

/// Extracts a sequential archive through the capability-based safe extractor.
pub(crate) fn extract_stream<R: Read>(
    input: R,
    dest: &Path,
    verbose: bool,
    members: &[String],
) -> CliResult {
    std::fs::create_dir_all(dest).map_err(|error| CliError::runtime(error.to_string()))?;
    let root = Dir::open_ambient_dir(dest, ambient_authority())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let input = FilterReader::new(input).map_err(|error| CliError::runtime(error.to_string()))?;
    let mut reader = ArchiveReader::new(input);
    let mut extractor = Extractor::new(root);
    let mut filter = MemberFilter::new(members);
    let report = extractor
        .extract_matching(&mut reader, |metadata| {
            filter.selects(metadata.path().as_bytes())
        })
        .map_err(|error| CliError::runtime(error.to_string()))?;
    filter.ensure_all_matched()?;
    for outcome in report.outcomes() {
        match outcome.outcome() {
            EntryOutcomeKind::File | EntryOutcomeKind::Directory if verbose => {
                eprintln!("x {}", outcome.path().display_lossy());
            },
            EntryOutcomeKind::Rejected(reason) => {
                eprintln!(
                    "oxtar: refused {}: {reason:?}",
                    outcome.path().display_lossy()
                );
            },
            _ => {},
        }
    }
    if report.has_rejections() {
        return Err(CliError::runtime(
            "one or more archive entries were refused by the safe extraction policy",
        ));
    }
    Ok(())
}

/// Lists a seek-required archive while retaining only its bounded index.
pub(crate) fn list_seek<R: Read + Seek>(
    input: R,
    password: Option<&[u8]>,
    members: &[String],
    verbose: bool,
) -> CliResult {
    let mut reader = match password {
        Some(password) => SeekArchiveReader::with_password(input, SecretBytes::from(password)),
        None => SeekArchiveReader::new(input),
    }
    .map_err(|error| CliError::runtime(error.to_string()))?;
    let mut filter = MemberFilter::new(members);
    loop {
        match reader
            .next_event()
            .map_err(|error| CliError::runtime(error.to_string()))?
        {
            ReaderEvent::Entry(metadata) => {
                if filter.selects(metadata.path().as_bytes()) {
                    if verbose {
                        println!("{}", format_long_v2(&metadata));
                    } else {
                        println!("{}", metadata.path().display_lossy());
                    }
                }
                reader
                    .skip_entry()
                    .map_err(|error| CliError::runtime(error.to_string()))?;
            },
            ReaderEvent::Done => return filter.ensure_all_matched(),
            _ => {},
        }
    }
}

/// Extracts a seek-required archive with capability-based safe filesystem I/O.
pub(crate) fn extract_seek<R: Read + Seek>(
    input: R,
    password: Option<&[u8]>,
    dest: &Path,
    verbose: bool,
    members: &[String],
    overwrite: bool,
) -> CliResult {
    std::fs::create_dir_all(dest).map_err(|error| CliError::runtime(error.to_string()))?;
    let root = Dir::open_ambient_dir(dest, ambient_authority())
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let mut reader = match password {
        Some(password) => SeekArchiveReader::with_password(input, SecretBytes::from(password)),
        None => SeekArchiveReader::new(input),
    }
    .map_err(|error| CliError::runtime(error.to_string()))?;
    let policy = ExtractionPolicy::safe().allow_overwrite(overwrite);
    let mut extractor = Extractor::with_policy(root, policy);
    let mut filter = MemberFilter::new(members);
    let report = extractor
        .extract_seek_matching(&mut reader, |metadata| {
            filter.selects(metadata.path().as_bytes())
        })
        .map_err(|error| CliError::runtime(error.to_string()))?;
    filter.ensure_all_matched()?;
    for outcome in report.outcomes() {
        match outcome.outcome() {
            EntryOutcomeKind::File | EntryOutcomeKind::Directory if verbose => {
                eprintln!("x {}", outcome.path().display_lossy());
            },
            EntryOutcomeKind::Rejected(reason) => {
                eprintln!(
                    "oxunzip: refused {}: {reason:?}",
                    outcome.path().display_lossy()
                );
            },
            _ => {},
        }
    }
    if report.has_rejections() {
        return Err(CliError::runtime(
            "one or more archive entries were refused by the safe extraction policy",
        ));
    }
    Ok(())
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

fn format_long_v2(meta: &EntryMetadata) -> String {
    let mode = mode_string(meta.kind(), meta.mode().unwrap_or(0));
    let date = meta.times().modified.map_or_else(
        || "1970-01-01 00:00".to_string(),
        |timestamp| format_timestamp(timestamp.secs),
    );
    let name = meta.path().display_lossy();
    let owner = meta.owner();
    let uid = owner.uid.unwrap_or(0);
    let gid = owner.gid.unwrap_or(0);
    match meta.link_target() {
        Some(target) if matches!(meta.kind(), EntryKind::Symlink) => format!(
            "{mode} {uid}/{gid} {:>10} {date} {name} -> {}",
            meta.size().unwrap_or(0),
            target.display_lossy(),
        ),
        _ => format!(
            "{mode} {uid}/{gid} {:>10} {date} {name}",
            meta.size().unwrap_or(0)
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
