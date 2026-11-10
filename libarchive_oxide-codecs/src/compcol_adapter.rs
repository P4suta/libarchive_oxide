// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared protocol adapter for bounded `compcol` payload decoders.

use alloc::string::ToString;

use compcol::limit::LimitedDecoder;
use compcol::{Decoder as _, Error as CompcolError, Progress, Status};
use libarchive_oxide_protocol::{ArchiveError, CodecStatus, CodecStep, EndOfInput, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalState {
    Running,
    Finishing,
    Done,
    Failed,
}

/// Converts a `compcol` decoder into the workspace's exact-size codec protocol.
///
/// The format-specific module remains responsible for validating dictionary and allocation limits before constructing this adapter.
pub(crate) struct Adapter<D: compcol::Decoder> {
    decoder: LimitedDecoder<D>,
    terminal: TerminalState,
    format: &'static str,
    expected_packed: Option<u64>,
    consumed: u64,
    expected_unpacked: u64,
}

impl<D> Adapter<D>
where
    D: compcol::Decoder,
{
    pub(crate) fn new(
        decoder: D,
        format: &'static str,
        expected_packed: u64,
        expected_unpacked: u64,
    ) -> Self {
        Self {
            decoder: LimitedDecoder::new(decoder, expected_unpacked),
            terminal: TerminalState::Running,
            format,
            expected_packed: Some(expected_packed),
            consumed: 0,
            expected_unpacked,
        }
    }

    pub(crate) fn terminal_name(&self) -> &'static str {
        match self.terminal {
            TerminalState::Running => "running",
            TerminalState::Finishing => "finishing",
            TerminalState::Done => "done",
            TerminalState::Failed => "failed",
        }
    }

    pub(crate) fn consumed_bytes(&self) -> u64 {
        self.consumed
    }

    pub(crate) fn decoded_bytes(&self) -> u64 {
        self.decoder.bytes_written()
    }

    fn error(&self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format(self.format)
            .with_context(context)
    }

    fn codec_error(&self, error: CompcolError) -> ArchiveError {
        let kind = match error {
            CompcolError::Unsupported => ErrorKind::Unsupported,
            CompcolError::OutputLimitExceeded => ErrorKind::Limit,
            CompcolError::ChecksumMismatch | CompcolError::TrailerMismatch => ErrorKind::Integrity,
            CompcolError::OutputTooSmall => ErrorKind::Protocol,
            _ => ErrorKind::Malformed,
        };
        ArchiveError::new(kind)
            .with_format(self.format)
            .with_context(error.to_string())
    }

    fn validate_progress(
        &self,
        progress: Progress,
        input_len: usize,
        output_len: usize,
    ) -> Result<Progress, ArchiveError> {
        if progress.consumed > input_len || progress.written > output_len {
            return Err(self.error(
                ErrorKind::Protocol,
                "compressed payload codec returned an invalid progress count",
            ));
        }
        Ok(progress)
    }

    fn verify_done(&self) -> Result<(), ArchiveError> {
        if self
            .expected_packed
            .is_some_and(|expected| self.consumed != expected)
        {
            return Err(self.error(
                ErrorKind::Malformed,
                "payload codec ended before consuming the declared packed size",
            ));
        }
        if self.decoder.bytes_written() != self.expected_unpacked {
            return Err(self.error(
                ErrorKind::Malformed,
                "payload codec output differs from the declared unpacked size",
            ));
        }
        Ok(())
    }

    fn finish(
        &mut self,
        output: &mut [u8],
        consumed: usize,
        produced: usize,
    ) -> Result<CodecStep, ArchiveError> {
        self.terminal = TerminalState::Finishing;
        let result = self.decoder.finish(&mut output[produced..]);
        let (progress, status) = match result {
            Ok(value) => value,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(self.codec_error(error));
            },
        };
        let progress =
            self.validate_progress(progress, 0, output.len().saturating_sub(produced))?;
        let produced = produced.checked_add(progress.written).ok_or_else(|| {
            self.error(
                ErrorKind::Limit,
                "compressed payload produced-byte count overflowed",
            )
        })?;
        let status = match status {
            Status::StreamEnd => {
                self.verify_done()?;
                self.terminal = TerminalState::Done;
                CodecStatus::Done
            },
            Status::OutputFull => CodecStatus::NeedOutput,
            Status::InputEmpty => {
                self.terminal = TerminalState::Failed;
                return Err(self.error(
                    ErrorKind::Protocol,
                    "compressed payload finish requested additional input",
                ));
            },
        };
        Ok(CodecStep {
            consumed,
            produced,
            status,
        })
    }

    fn resume_terminal(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Option<CodecStep>, ArchiveError> {
        match self.terminal {
            TerminalState::Running => Ok(None),
            TerminalState::Done if input.is_empty() => Ok(Some(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            })),
            TerminalState::Done => Err(self.error(
                ErrorKind::Protocol,
                "input supplied after compressed payload completion",
            )),
            TerminalState::Failed => Err(self.error(
                ErrorKind::Protocol,
                "compressed payload decoder reused after failure",
            )),
            TerminalState::Finishing if input.is_empty() => self.finish(output, 0, 0).map(Some),
            TerminalState::Finishing => {
                self.terminal = TerminalState::Failed;
                Err(self.error(
                    ErrorKind::Protocol,
                    "input supplied after compressed payload finalization started",
                ))
            },
        }
    }

    pub(crate) fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if let Some(step) = self.resume_terminal(input, output)? {
            return Ok(step);
        }

        let input_len = u64::try_from(input.len()).map_err(|_| {
            self.error(
                ErrorKind::Limit,
                "compressed payload input length exceeds u64",
            )
        })?;
        let supplied_end = self.consumed.checked_add(input_len).ok_or_else(|| {
            self.error(
                ErrorKind::Limit,
                "compressed payload consumed-byte count overflowed",
            )
        })?;
        if self
            .expected_packed
            .is_some_and(|expected| supplied_end > expected)
        {
            self.terminal = TerminalState::Failed;
            return Err(self.error(
                ErrorKind::Malformed,
                "payload contains bytes beyond its declared packed size",
            ));
        }
        if matches!(end, EndOfInput::End)
            && self
                .expected_packed
                .is_some_and(|expected| supplied_end < expected)
        {
            self.terminal = TerminalState::Failed;
            return Err(self.error(ErrorKind::Malformed, "compressed payload is truncated"));
        }

        let decoded = self.decoder.decode(input, output);
        let (progress, status) = match decoded {
            Ok(value) => value,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(self.codec_error(error));
            },
        };
        let progress = self.validate_progress(progress, input.len(), output.len())?;
        self.consumed = self
            .consumed
            .checked_add(u64::try_from(progress.consumed).map_err(|_| {
                self.error(ErrorKind::Limit, "compressed payload progress exceeds u64")
            })?)
            .ok_or_else(|| {
                self.error(
                    ErrorKind::Limit,
                    "compressed payload consumed-byte count overflowed",
                )
            })?;

        if matches!(status, Status::StreamEnd) {
            self.verify_done()?;
            self.terminal = TerminalState::Done;
            return Ok(CodecStep {
                consumed: progress.consumed,
                produced: progress.written,
                status: CodecStatus::Done,
            });
        }

        if matches!(end, EndOfInput::End)
            && self
                .expected_packed
                .is_none_or(|expected| self.consumed == expected)
            && !matches!(status, Status::OutputFull)
        {
            return self.finish(output, progress.consumed, progress.written);
        }

        Ok(CodecStep {
            consumed: progress.consumed,
            produced: progress.written,
            status: match status {
                Status::InputEmpty => CodecStatus::NeedInput,
                Status::OutputFull => CodecStatus::NeedOutput,
                Status::StreamEnd => {
                    return Err(self.error(
                        ErrorKind::Protocol,
                        "compressed payload codec returned an inconsistent terminal status",
                    ));
                },
            },
        })
    }
}
