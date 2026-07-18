// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal byte-sink abstraction for the write path (sans-IO, `no_std`).
//!
//! The read path borrows an input `&[u8]`; its dual, the write path, pushes bytes into a [`Sink`].
//! The core provides an in-memory [`Vec`] sink (which never fails); the std layer writes the
//! finished buffer to a file at its boundary, keeping I/O errors out of the pure core.

use alloc::vec::Vec;

use crate::Result;

/// A byte sink that format writers push encoded bytes into.
pub trait Sink {
    /// Appends all of `data` to the sink.
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        (**self).write_all(data)
    }
}
