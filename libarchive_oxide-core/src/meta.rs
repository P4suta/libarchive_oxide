// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small metadata value types shared by the richer v0.2 metadata model.

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
    /// Seconds since the UNIX epoch.
    pub secs: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nanos: u32,
}
