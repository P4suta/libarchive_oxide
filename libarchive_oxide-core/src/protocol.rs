// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified sans-I/O codec and archive protocols.

use core::fmt;

use crate::metadata::{ArchiveMetadata, EntryMetadata};
use crate::{ArchiveError, ErrorKind};

/// Whether the supplied input is the final input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfInput {
    /// Additional input may arrive.
    More,
    /// No additional input will arrive.
    End,
}

/// Three-way incremental detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeResult<T> {
    /// A format/filter matched.
    Match(T),
    /// At least `minimum` prefix bytes are required.
    NeedMore {
        /// Minimum prefix size needed for the next decision.
        minimum: usize,
    },
    /// The candidate did not match.
    NoMatch,
}

/// What a byte codec needs after one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecStatus {
    /// Supply additional input.
    NeedInput,
    /// Supply additional output capacity.
    NeedOutput,
    /// One complete codec stream ended.
    Done,
}

/// Progress made by a byte codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecStep {
    /// Input bytes consumed.
    pub consumed: usize,
    /// Output bytes produced.
    pub produced: usize,
    /// Required next action.
    pub status: CodecStatus,
}

impl CodecStep {
    /// Validates counts and progress against the provided buffers.
    pub fn validate(self, input_len: usize, output_len: usize) -> Result<Self, ArchiveError> {
        if self.consumed > input_len || self.produced > output_len {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("codec reported out-of-range progress"));
        }
        if self.consumed == 0 && self.produced == 0 {
            let valid_wait = matches!(self.status, CodecStatus::NeedInput) && input_len == 0;
            let valid_backpressure =
                matches!(self.status, CodecStatus::NeedOutput) && output_len == 0;
            if !valid_wait && !valid_backpressure && !matches!(self.status, CodecStatus::Done) {
                return Err(
                    ArchiveError::new(ErrorKind::Protocol).with_context("codec made no progress")
                );
            }
        }
        Ok(self)
    }
}

/// Incremental byte-to-byte codec.
pub trait Codec {
    /// Processes input, including finalization when `end` is [`EndOfInput::End`].
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError>;
}

/// A borrowed entry-data window.
#[derive(Clone, Copy)]
pub struct Chunk<'a> {
    bytes: &'a [u8],
}

impl<'a> Chunk<'a> {
    /// Wraps a borrowed data window.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Window bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

impl fmt::Debug for Chunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Structural event produced by an archive decoder.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum DecodeEvent<'a> {
    /// Supply more archive bytes.
    NeedInput,
    /// Supply a non-empty scratch/output buffer.
    NeedOutput,
    /// Archive-level metadata was discovered or updated.
    ArchiveMetadata(ArchiveMetadata),
    /// A new entry begins.
    Entry(EntryMetadata),
    /// Entry body bytes.
    Data(Chunk<'a>),
    /// Current entry body ended.
    EndEntry,
    /// Archive ended.
    Done,
}

/// Progress and event from one archive decoder call.
#[derive(Debug)]
pub struct DecodeStep<'a> {
    /// Input bytes consumed.
    pub consumed: usize,
    /// Scratch-buffer bytes produced.
    pub produced: usize,
    /// Structural event.
    pub event: DecodeEvent<'a>,
}

impl DecodeStep<'_> {
    /// Validates progress against the supplied buffers.
    pub fn validate(self, input_len: usize, output_len: usize) -> Result<Self, ArchiveError> {
        if self.consumed > input_len || self.produced > output_len {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("archive decoder reported out-of-range progress"));
        }
        if self.consumed == 0 && self.produced == 0 {
            let semantic_progress = match &self.event {
                DecodeEvent::NeedInput
                | DecodeEvent::NeedOutput
                | DecodeEvent::ArchiveMetadata(_)
                | DecodeEvent::Entry(_)
                | DecodeEvent::EndEntry
                | DecodeEvent::Done => true,
                DecodeEvent::Data(chunk) => !chunk.bytes.is_empty(),
            };
            if !semantic_progress {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive decoder made no progress"));
            }
        }
        Ok(self)
    }
}

/// Incremental archive decoder.
pub trait ArchiveDecoder {
    /// Consumes archive bytes and produces at most one structural event.
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError>;
}

/// Input command for an archive encoder.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodeCommand<'a> {
    /// Begins an entry.
    BeginEntry(&'a EntryMetadata),
    /// Supplies entry body bytes.
    Data(&'a [u8]),
    /// Ends the current entry.
    EndEntry,
    /// Finalizes the archive.
    Finish,
}

/// Encoder state after one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeStatus {
    /// The caller may submit another command.
    NeedCommand,
    /// The caller must provide more output capacity while retaining the command.
    NeedOutput,
    /// The archive is finalized.
    Done,
}

/// Progress from one archive encoder call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeStep {
    /// Data-command bytes consumed. Non-data commands use 0 or 1.
    pub consumed: usize,
    /// Output bytes produced.
    pub produced: usize,
    /// Encoder state.
    pub status: EncodeStatus,
}

impl EncodeStep {
    /// Validates encoder progress for one command.
    pub fn validate(
        self,
        data_input_len: Option<usize>,
        output_len: usize,
    ) -> Result<Self, ArchiveError> {
        let maximum = data_input_len.unwrap_or(1);
        if self.consumed > maximum || self.produced > output_len {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("archive encoder reported out-of-range progress"));
        }
        if data_input_len.is_some()
            && self.consumed == 0
            && self.produced == 0
            && (!matches!(self.status, EncodeStatus::NeedOutput) || output_len != 0)
        {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("archive encoder made no data progress"));
        }
        Ok(self)
    }
}

/// Incremental sequential archive encoder.
pub trait ArchiveEncoder {
    /// Processes one command into caller-owned output.
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError>;
}
