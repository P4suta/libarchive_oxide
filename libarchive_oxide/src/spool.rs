// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit, bounded memory-to-temp-file spooling.

use std::io::{self, Read, Seek, SeekFrom, Write};

use tempfile::{SpooledTempFile, spooled_tempfile};

use crate::StreamError;

/// Safe-profile in-memory threshold: 8 MiB.
pub const DEFAULT_MEMORY_THRESHOLD: usize = 8 * 1024 * 1024;
/// Safe-profile total spool limit: 4 GiB.
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Explicit bounded spool destination.
///
/// Data remains in memory through the configured threshold and then moves to
/// an automatically deleted temporary file.
#[derive(Debug)]
pub struct SpoolWriter {
    inner: SpooledTempFile,
    maximum: u64,
    written: u64,
}

impl SpoolWriter {
    /// Creates the safe 8 MiB / 4 GiB spool profile.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MEMORY_THRESHOLD, DEFAULT_MAX_BYTES)
    }

    /// Creates an explicitly sized spool profile.
    #[must_use]
    pub fn with_limits(memory_threshold: usize, maximum: u64) -> Self {
        Self {
            inner: spooled_tempfile(memory_threshold),
            maximum,
            written: 0,
        }
    }

    /// Finishes writing and returns a seekable reader positioned at byte zero.
    pub fn finish(mut self) -> Result<SpoolReader, StreamError> {
        self.inner.flush().map_err(StreamError::io)?;
        self.inner
            .seek(SeekFrom::Start(0))
            .map_err(StreamError::io)?;
        Ok(SpoolReader {
            inner: self.inner,
            length: self.written,
        })
    }

    /// Bytes accepted so far.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.written
    }

    /// Whether no bytes have been accepted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.written == 0
    }

    /// Drops the spool without preserving incomplete output.
    pub fn abort(self) {
        drop(self);
    }
}

impl Default for SpoolWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for SpoolWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum.saturating_sub(self.written);
        if input.len() as u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "spool exceeds configured maximum",
            ));
        }
        let written = self.inner.write(input)?;
        self.written = self
            .written
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "spool length overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Seekable completed spool.
#[derive(Debug)]
pub struct SpoolReader {
    inner: SpooledTempFile,
    length: u64,
}

impl SpoolReader {
    /// Explicitly spools an input using the safe profile.
    pub fn from_reader(mut input: impl Read) -> Result<Self, StreamError> {
        Self::from_reader_with_limits(&mut input, DEFAULT_MEMORY_THRESHOLD, DEFAULT_MAX_BYTES)
    }

    /// Explicitly spools an input with caller-selected bounds.
    pub fn from_reader_with_limits(
        mut input: impl Read,
        memory_threshold: usize,
        maximum: u64,
    ) -> Result<Self, StreamError> {
        let mut writer = SpoolWriter::with_limits(memory_threshold, maximum);
        io::copy(&mut input, &mut writer).map_err(StreamError::io)?;
        writer.finish()
    }

    /// Total spool length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Whether the spool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Read for SpoolReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}

impl Seek for SpoolReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
