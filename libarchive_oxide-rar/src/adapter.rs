// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol adapter for bounded locally owned RAR payload decoders.

use alloc::string::ToString;

use libarchive_oxide_protocol::{ArchiveError, CodecStatus, CodecStep, EndOfInput, ErrorKind};

use crate::codec::{Decoder, Error as CodecError, Progress, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalState {
    Running,
    Finishing,
    Done,
    Failed,
}

pub(crate) struct Adapter<D: Decoder> {
    decoder: D,
    terminal: TerminalState,
    format: &'static str,
    expected_packed: Option<u64>,
    consumed: u64,
    expected_unpacked: u64,
    decoded: u64,
}

impl<D> Adapter<D>
where
    D: Decoder,
{
    pub(crate) fn new(
        decoder: D,
        format: &'static str,
        expected_packed: u64,
        expected_unpacked: u64,
    ) -> Self {
        Self {
            decoder,
            terminal: TerminalState::Running,
            format,
            expected_packed: Some(expected_packed),
            consumed: 0,
            expected_unpacked,
            decoded: 0,
        }
    }

    pub(crate) fn new_streaming(decoder: D, format: &'static str, expected_unpacked: u64) -> Self {
        Self {
            decoder,
            terminal: TerminalState::Running,
            format,
            expected_packed: None,
            consumed: 0,
            expected_unpacked,
            decoded: 0,
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
        self.decoded
    }

    pub(crate) fn decoder(&self) -> &D {
        &self.decoder
    }

    pub(crate) fn into_completed_decoder(self) -> Result<D, ArchiveError> {
        if self.terminal != TerminalState::Done {
            return Err(self.error(
                ErrorKind::Protocol,
                "compressed payload decoder continued before member completion",
            ));
        }
        self.verify_done()?;
        Ok(self.decoder)
    }

    fn error(&self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format(self.format)
            .with_context(context)
    }

    fn codec_error(&self, error: CodecError) -> ArchiveError {
        let kind = match error {
            CodecError::UnsupportedFilter => ErrorKind::Unsupported,
            CodecError::OutputLimitExceeded => ErrorKind::Limit,
            _ => ErrorKind::Malformed,
        };
        ArchiveError::new(kind)
            .with_format(self.format)
            .with_context(error.to_string())
    }

    fn remaining_output(&self) -> u64 {
        self.expected_unpacked.saturating_sub(self.decoded)
    }

    fn record_output(&mut self, written: usize) -> Result<(), CodecError> {
        let written = u64::try_from(written).map_err(|_| CodecError::OutputLimitExceeded)?;
        if written > self.remaining_output() {
            return Err(CodecError::OutputLimitExceeded);
        }
        self.decoded += written;
        Ok(())
    }

    fn decode_limited(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(Progress, Status), CodecError> {
        let remaining = self.remaining_output();
        if remaining == 0 {
            let mut probe = [0u8; 1];
            let (progress, status) = self.decoder.decode(input, &mut probe)?;
            if progress.written != 0 {
                return Err(CodecError::OutputLimitExceeded);
            }
            return Ok((
                Progress {
                    consumed: progress.consumed,
                    written: 0,
                },
                status,
            ));
        }
        let output_len =
            u64::try_from(output.len()).map_err(|_| CodecError::OutputLimitExceeded)?;
        let capacity = usize::try_from(remaining.min(output_len))
            .map_err(|_| CodecError::OutputLimitExceeded)?;
        let result = self.decoder.decode(input, &mut output[..capacity]);
        let (progress, status) = result?;
        self.record_output(progress.written)?;
        Ok((progress, status))
    }

    fn finish_limited(&mut self, output: &mut [u8]) -> Result<(Progress, Status), CodecError> {
        let remaining = self.remaining_output();
        if remaining == 0 {
            let mut probe = [0u8; 1];
            let (progress, status) = self.decoder.finish(&mut probe)?;
            if progress.written != 0 {
                return Err(CodecError::OutputLimitExceeded);
            }
            return Ok((
                Progress {
                    consumed: 0,
                    written: 0,
                },
                status,
            ));
        }
        let output_len =
            u64::try_from(output.len()).map_err(|_| CodecError::OutputLimitExceeded)?;
        let capacity = usize::try_from(remaining.min(output_len))
            .map_err(|_| CodecError::OutputLimitExceeded)?;
        let result = self.decoder.finish(&mut output[..capacity]);
        let (progress, status) = result?;
        self.record_output(progress.written)?;
        Ok((progress, status))
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

    fn validate_progress_or_fail(
        &mut self,
        progress: Progress,
        input_len: usize,
        output_len: usize,
    ) -> Result<Progress, ArchiveError> {
        match self.validate_progress(progress, input_len, output_len) {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.terminal = TerminalState::Failed;
                Err(error)
            },
        }
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
        if self.decoded != self.expected_unpacked {
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
        let result = self.finish_limited(&mut output[produced..]);
        let (progress, status) = match result {
            Ok(value) => value,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(self.codec_error(error));
            },
        };
        let progress =
            self.validate_progress_or_fail(progress, 0, output.len().saturating_sub(produced))?;
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

        let decoded = self.decode_limited(input, output);
        let (progress, status) = match decoded {
            Ok(value) => value,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(self.codec_error(error));
            },
        };
        let progress = self.validate_progress_or_fail(progress, input.len(), output.len())?;
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

#[cfg(test)]
mod tests {
    use super::{Adapter, TerminalState};
    use crate::codec::{Decoder, Error, Progress, Status};
    use libarchive_oxide_protocol::{EndOfInput, ErrorKind};

    struct InvalidProgressDecoder;

    impl Decoder for InvalidProgressDecoder {
        fn decode(
            &mut self,
            _input: &[u8],
            _output: &mut [u8],
        ) -> Result<(Progress, Status), Error> {
            Ok((
                Progress {
                    consumed: 0,
                    written: 2,
                },
                Status::OutputFull,
            ))
        }

        fn finish(&mut self, _output: &mut [u8]) -> Result<(Progress, Status), Error> {
            Err(Error::Corrupt)
        }
    }

    #[test]
    fn invalid_internal_progress_poisons_the_adapter() {
        let mut adapter = Adapter::new(InvalidProgressDecoder, "test-rar", 1, 4);
        let error = adapter
            .process(&[0], &mut [0], EndOfInput::More)
            .expect_err("a decoder cannot report more output than its slice");

        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(adapter.terminal, TerminalState::Failed);
    }
}
