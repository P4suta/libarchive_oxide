// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small metadata value types shared by the richer v0.2 metadata model.

use crate::{ArchiveError, ErrorKind};

/// Entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// Character device.
    Char,
    /// Block device.
    Block,
    /// Named pipe (FIFO).
    Fifo,
    /// UNIX domain socket.
    Socket,
}

/// Sensible portable permissions for formats whose mode field is mandatory.
pub(crate) const fn default_mode(kind: EntryKind) -> u32 {
    match kind {
        EntryKind::Dir => 0o755,
        EntryKind::Symlink => 0o777,
        EntryKind::File | EntryKind::Hardlink => 0o644,
        EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket => 0o600,
    }
}

/// A timestamp in seconds and nanoseconds, independent of `std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    secs: i64,
    nanos: u32,
}

impl Timestamp {
    /// Creates a timestamp, rejecting a fractional second outside the valid
    /// nanosecond range.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Malformed`] when `nanos` is one billion or greater.
    pub fn new(secs: i64, nanos: u32) -> Result<Self, ArchiveError> {
        if nanos >= 1_000_000_000 {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_context("timestamp nanoseconds must be less than 1,000,000,000"));
        }
        Ok(Self { secs, nanos })
    }

    /// Creates a whole-second timestamp.
    #[must_use]
    pub const fn from_seconds(secs: i64) -> Self {
        Self { secs, nanos: 0 }
    }

    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.secs
    }

    /// Nanoseconds within the second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanos
    }
}
