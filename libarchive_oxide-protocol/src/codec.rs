// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Caller-driven byte-codec protocol.

use crate::{ArchiveError, ErrorKind};

/// Whether the supplied input is the final input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfInput {
    /// Additional input may arrive.
    More,
    /// No additional input will arrive.
    End,
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

    /// Non-blocking, executor-safe drive used by async adapters.
    ///
    /// Unlike [`process`](Codec::process) this must never block the calling thread.
    /// `Ok(None)` means "would block" and requires a later wake.
    fn poll_process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        waker: &core::task::Waker,
    ) -> Result<Option<CodecStep>, ArchiveError> {
        let _ = waker;
        self.process(input, output, end).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::{CodecStatus, CodecStep};
    use crate::ErrorKind;

    #[test]
    fn rejects_out_of_range_and_stalled_progress() {
        let out_of_range = CodecStep {
            consumed: 2,
            produced: 0,
            status: CodecStatus::NeedInput,
        };
        assert_eq!(
            out_of_range.validate(1, 0).unwrap_err().kind(),
            ErrorKind::Protocol
        );

        let stalled = CodecStep {
            consumed: 0,
            produced: 0,
            status: CodecStatus::NeedInput,
        };
        assert_eq!(
            stalled.validate(1, 1).unwrap_err().kind(),
            ErrorKind::Protocol
        );
    }
}
