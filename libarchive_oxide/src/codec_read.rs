// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic bounded `Read` adapter over any sans-I/O [`Codec`].
//!
//! [`CodecReader`] drives a caller-supplied [`Codec`] against an inner byte
//! source, retaining neither the compressed input nor the decoded output beyond
//! one fixed-size staging buffer. It is the shared engine behind the outer
//! filter readers (zstd, LZ4, …) and any future coder that speaks the sans-I/O
//! [`Codec`] protocol.

use std::io::{self, Read};

use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, EndOfInput, ErrorKind};

/// Staging-buffer size for the compressed side of a [`CodecReader`].
pub(crate) const BUFFER: usize = 64 * 1024;

/// A bounded streaming reader that decodes `input` through the sans-I/O `decoder`.
///
/// Generic over the inner reader `Inner` and the codec `C`, so a single
/// implementation serves every codec that implements [`Codec`]. `name` labels
/// the codec in error messages.
pub(crate) struct CodecReader<Inner: Read, C: Codec> {
    input: Inner,
    decoder: C,
    name: &'static str,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    done: bool,
    failed: bool,
}

impl<Inner: Read, C: Codec> CodecReader<Inner, C> {
    /// Wraps `input`, decoding it through `decoder`. `name` labels the codec in errors.
    pub(crate) fn new(input: Inner, decoder: C, name: &'static str) -> Self {
        Self {
            input,
            decoder,
            name,
            buffer: vec![0; BUFFER],
            start: 0,
            end: 0,
            eof: false,
            done: false,
            failed: false,
        }
    }

    /// Reclaims the inner reader at its current physical position.
    pub(crate) fn into_inner(self) -> Inner {
        self.input
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start != 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() || self.eof {
            return Ok(());
        }
        let read = self.input.read(&mut self.buffer[self.end..])?;
        if read == 0 {
            self.eof = true;
        } else {
            self.end += read;
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.failed = true;
        Err(error)
    }
}

impl<Inner: Read, C: Codec> Read for CodecReader<Inner, C> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.done {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} reader is in a failed state", self.name),
            ));
        }
        loop {
            if self.start == self.end && !self.eof {
                self.fill()?;
            }
            let input_length = self.end - self.start;
            let end = if self.eof {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = match self
                .decoder
                .process(&self.buffer[self.start..self.end], output, end)
                .and_then(|step| step.validate(input_length, output.len()))
            {
                Ok(step) => step,
                Err(error) => return self.fail(codec_archive_io(error)),
            };
            self.start += step.consumed;
            if step.produced != 0 {
                return Ok(step.produced);
            }
            match step.status {
                CodecStatus::Done => {
                    self.done = true;
                    return Ok(0);
                },
                CodecStatus::NeedInput if self.start == self.end && !self.eof => {
                    self.fill()?;
                },
                CodecStatus::NeedOutput if step.consumed != 0 => {},
                CodecStatus::NeedInput if self.eof => {
                    return self.fail(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} decoder requested input after the source ended",
                            self.name
                        ),
                    ));
                },
                _ => {
                    return self.fail(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} reader made no progress", self.name),
                    ));
                },
            }
        }
    }
}

/// Maps a codec [`ArchiveError`] onto an [`io::Error`], preserving the failure class.
pub(crate) fn codec_archive_io(error: ArchiveError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Limit => io::ErrorKind::OutOfMemory,
        ErrorKind::Unsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}
