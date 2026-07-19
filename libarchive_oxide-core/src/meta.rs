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

/// A timestamp in seconds and nanoseconds, independent of `std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// Seconds since the UNIX epoch.
    pub secs: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nanos: u32,
}
