// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust, caller-driven Zstandard codec state.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use libarchive_oxide_core::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];
const MAX_BLOCK: usize = 128 * 1024;
const MAX_FRAME_HEADER: usize = 18;
const BLOCK_HEADER: usize = 3;
const CHECKSUM: usize = 4;
const MAX_PENDING: usize = MAX_BLOCK + MAX_FRAME_HEADER + BLOCK_HEADER + CHECKSUM;
const ENCODER_WINDOW: usize = 1024;
const ENCODER_FRAME_HEADER: [u8; 6] = [0x28, 0xb5, 0x2f, 0xfd, 0, 0];
const ENCODER_FINAL_BLOCK: [u8; 3] = [1, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalState {
    Running,
    Done,
    Failed,
}

/// Incremental Zstandard decoder backed by `ruzstd`.
///
/// `ruzstd` consumes complete blocks, so this adapter retains at most one
/// maximum-sized block plus its framing. Concatenated frames are treated as one
/// logical outer-filter stream.
pub struct ZstdDecoder {
    decoder: ruzstd::decoding::FrameDecoder,
    pending: Vec<u8>,
    frame_active: bool,
    saw_frame: bool,
    terminal: TerminalState,
    limits: Limits,
}

impl ZstdDecoder {
    /// Creates an empty decoder with finite safe resource limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(Limits::safe())
    }

    /// Creates an empty decoder with caller-supplied resource limits.
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            decoder: ruzstd::decoding::FrameDecoder::new(),
            pending: Vec::new(),
            frame_active: false,
            saw_frame: false,
            terminal: TerminalState::Running,
            limits,
        }
    }

    fn malformed(context: impl Into<String>) -> ArchiveError {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zstd")
            .with_context(context)
    }

    fn frame_header_len(prefix: &[u8]) -> Option<usize> {
        let descriptor = *prefix.get(MAGIC.len())?;
        let single_segment = descriptor & 0x20 != 0;
        let dictionary = [0, 1, 2, 4].get(usize::from(descriptor & 0x03)).copied()?;
        let content_size = [usize::from(single_segment), 2, 4, 8]
            .get(usize::from(descriptor >> 6))
            .copied()?;
        Some(MAGIC.len() + 1 + usize::from(!single_segment) + dictionary + content_size)
    }

    fn frame_window_size(prefix: &[u8]) -> Result<u64, ArchiveError> {
        let descriptor = *prefix
            .get(MAGIC.len())
            .ok_or_else(|| Self::malformed("truncated Zstandard frame descriptor"))?;
        let single_segment = descriptor & 0x20 != 0;
        let dictionary_size = [0, 1, 2, 4]
            .get(usize::from(descriptor & 0x03))
            .copied()
            .ok_or_else(|| Self::malformed("invalid Zstandard dictionary identifier flag"))?;
        let content_size_flag = descriptor >> 6;
        let content_size_length = match content_size_flag {
            0 if single_segment => 1,
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(Self::malformed("invalid Zstandard content-size flag")),
        };
        let mut cursor = MAGIC.len() + 1;
        let window = if single_segment {
            None
        } else {
            let window_descriptor = *prefix
                .get(cursor)
                .ok_or_else(|| Self::malformed("truncated Zstandard window descriptor"))?;
            cursor += 1;
            let window_log = 10_u32 + u32::from(window_descriptor >> 3);
            let base = 1_u64
                .checked_shl(window_log)
                .ok_or_else(|| Self::malformed("Zstandard window size overflow"))?;
            let add = (base >> 3)
                .checked_mul(u64::from(window_descriptor & 0x07))
                .ok_or_else(|| Self::malformed("Zstandard window size overflow"))?;
            Some(
                base.checked_add(add)
                    .ok_or_else(|| Self::malformed("Zstandard window size overflow"))?,
            )
        };
        cursor = cursor
            .checked_add(dictionary_size)
            .ok_or_else(|| Self::malformed("Zstandard frame header size overflow"))?;
        let content_size = match content_size_length {
            0 => None,
            1 => Some(u64::from(*prefix.get(cursor).ok_or_else(|| {
                Self::malformed("truncated Zstandard content size")
            })?)),
            2 => {
                let bytes: [u8; 2] = prefix
                    .get(cursor..cursor + 2)
                    .ok_or_else(|| Self::malformed("truncated Zstandard content size"))?
                    .try_into()
                    .map_err(|_| Self::malformed("invalid Zstandard content size"))?;
                Some(u64::from(u16::from_le_bytes(bytes)) + 256)
            },
            4 => {
                let bytes: [u8; 4] = prefix
                    .get(cursor..cursor + 4)
                    .ok_or_else(|| Self::malformed("truncated Zstandard content size"))?
                    .try_into()
                    .map_err(|_| Self::malformed("invalid Zstandard content size"))?;
                Some(u64::from(u32::from_le_bytes(bytes)))
            },
            8 => {
                let bytes: [u8; 8] = prefix
                    .get(cursor..cursor + 8)
                    .ok_or_else(|| Self::malformed("truncated Zstandard content size"))?
                    .try_into()
                    .map_err(|_| Self::malformed("invalid Zstandard content size"))?;
                Some(u64::from_le_bytes(bytes))
            },
            _ => return Err(Self::malformed("invalid Zstandard content-size length")),
        };
        window.or(content_size).ok_or_else(|| {
            Self::malformed("Zstandard frame has neither a window nor a content size")
        })
    }

    fn check_frame_memory(&self, prefix: &[u8]) -> Result<(), ArchiveError> {
        let Some(limit) = self.limits.codec_memory() else {
            return Ok(());
        };
        let window = usize::try_from(Self::frame_window_size(prefix)?).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zstd")
                .with_context("Zstandard window exceeds the platform address space")
        })?;
        let required = window.checked_add(MAX_PENDING).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zstd")
                .with_context("Zstandard codec-memory accounting overflow")
        })?;
        if required > limit {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("zstd")
                .with_context("Zstandard frame exceeds the configured codec-memory budget"));
        }
        Ok(())
    }

    fn discard_pending(&mut self, consumed: usize) {
        if consumed == 0 {
            return;
        }
        self.pending.copy_within(consumed.., 0);
        self.pending.truncate(self.pending.len() - consumed);
    }

    fn status_after_progress(
        &mut self,
        produced: usize,
        output_length: usize,
        end: EndOfInput,
    ) -> Result<CodecStatus, ArchiveError> {
        if self.decoder.is_finished() && self.decoder.can_collect() == 0 {
            if let Some(expected) = self.decoder.get_checksum_from_data() {
                let calculated = self
                    .decoder
                    .get_calculated_checksum()
                    .ok_or_else(|| Self::malformed("Zstandard checksum state was not available"))?;
                if calculated != expected {
                    return Err(Self::malformed("Zstandard frame checksum mismatch"));
                }
            }
            self.saw_frame = true;
            self.frame_active = false;
            self.decoder = ruzstd::decoding::FrameDecoder::new();
        }
        if !self.frame_active {
            if self.pending.is_empty() {
                if matches!(end, EndOfInput::End) {
                    self.terminal = TerminalState::Done;
                    return Ok(CodecStatus::Done);
                }
                return Ok(CodecStatus::NeedInput);
            }
            if self.pending.len() >= MAGIC.len() && !self.pending.starts_with(MAGIC) {
                return Err(Self::malformed("non-frame trailing filter data"));
            }
            if matches!(end, EndOfInput::End) && self.pending.len() < MAGIC.len() {
                return Err(Self::malformed("truncated Zstandard frame header"));
            }
            return Ok(CodecStatus::NeedInput);
        }
        if matches!(end, EndOfInput::End) && produced == 0 && !self.pending.is_empty() {
            return Err(Self::malformed(
                "Zstandard frame ended before its terminal block",
            ));
        }
        if self.decoder.can_collect() != 0
            || !self.pending.is_empty()
            || (output_length != 0 && produced == output_length)
        {
            Ok(CodecStatus::NeedOutput)
        } else if matches!(end, EndOfInput::End) {
            Err(Self::malformed(
                "Zstandard frame ended before its terminal block",
            ))
        } else {
            Ok(CodecStatus::NeedInput)
        }
    }

    fn terminal_step(&self, input: &[u8]) -> Result<Option<CodecStep>, ArchiveError> {
        match self.terminal {
            TerminalState::Running => Ok(None),
            TerminalState::Failed => Err(Self::malformed(
                "Zstandard decoder cannot continue after malformed input",
            )),
            TerminalState::Done if input.is_empty() => Ok(Some(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            })),
            TerminalState::Done => Err(Self::malformed(
                "data follows the completed Zstandard stream",
            )),
        }
    }
}

impl Default for ZstdDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ZstdDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZstdDecoder")
            .field("pending", &self.pending.len())
            .field("frame_active", &self.frame_active)
            .field("saw_frame", &self.saw_frame)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl Codec for ZstdDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if let Some(step) = self.terminal_step(input)? {
            return Ok(step);
        }

        let pending_limit = if self.frame_active {
            MAX_PENDING
        } else {
            MAX_FRAME_HEADER
        };
        let available = pending_limit.saturating_sub(self.pending.len());
        let consumed = available.min(input.len());
        self.pending.extend_from_slice(&input[..consumed]);
        // `End` describes the caller's whole slice, not the prefix accepted by
        // this bounded adapter.  Treat a partially-consumed slice as `More`;
        // the caller will present the remainder with `End` again.
        let effective_end = if consumed == input.len() {
            end
        } else {
            EndOfInput::More
        };

        if !self.frame_active {
            if self.pending.len() < MAGIC.len() {
                if matches!(effective_end, EndOfInput::End) {
                    let context = if self.saw_frame && self.pending.is_empty() {
                        self.terminal = TerminalState::Done;
                        return Ok(CodecStep {
                            consumed,
                            produced: 0,
                            status: CodecStatus::Done,
                        });
                    } else {
                        "truncated Zstandard frame header"
                    };
                    return Err(Self::malformed(context));
                }
                return Ok(CodecStep {
                    consumed,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            }
            if !self.pending.starts_with(MAGIC) {
                return Err(Self::malformed("invalid Zstandard frame magic"));
            }
            let Some(header_len) = Self::frame_header_len(&self.pending) else {
                if matches!(effective_end, EndOfInput::End) {
                    return Err(Self::malformed("truncated Zstandard frame header"));
                }
                return Ok(CodecStep {
                    consumed,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            };
            if self.pending.len() < header_len {
                if matches!(effective_end, EndOfInput::End) {
                    return Err(Self::malformed("truncated Zstandard frame header"));
                }
                return Ok(CodecStep {
                    consumed,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            }
            self.check_frame_memory(&self.pending[..header_len])?;
            self.frame_active = true;
        }

        // The variable frame header is preflighted above. `ruzstd` reports a
        // partial block as successful zero progress. Every actual error is
        // terminal: retrying after an error can reuse mutated decoder state and
        // turn malformed input into a process-aborting panic.
        let (decoded_input, produced) = match self.decoder.decode_from_to(&self.pending, output) {
            Ok(progress) => progress,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                self.decoder = ruzstd::decoding::FrameDecoder::new();
                return Err(Self::malformed(error.to_string()));
            },
        };
        if decoded_input > self.pending.len() {
            if matches!(effective_end, EndOfInput::End) {
                return Err(Self::malformed("truncated Zstandard frame checksum"));
            }
            return Ok(CodecStep {
                consumed,
                produced: 0,
                status: CodecStatus::NeedInput,
            });
        }
        self.discard_pending(decoded_input);
        let status = self.status_after_progress(produced, output.len(), effective_end)?;
        Ok(CodecStep {
            consumed,
            produced,
            status,
        })
    }
}

/// Push-style Zstandard encoder using bounded raw 1 KiB blocks.
///
/// Raw blocks are standards-compliant Zstandard frames. The fixed window keeps
/// working memory independent of total input size and makes suspension at any
/// caller-provided output boundary explicit.
pub struct ZstdEncoder {
    frame_header_offset: usize,
    block: [u8; ENCODER_WINDOW],
    block_len: usize,
    block_output_offset: usize,
    block_ready: bool,
    block_header: [u8; BLOCK_HEADER],
    block_header_offset: usize,
    final_block_offset: usize,
    finishing: bool,
    encoded_input: u64,
    limits: Limits,
}

impl fmt::Debug for ZstdEncoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZstdEncoder")
            .field("block_len", &self.block_len)
            .field("block_ready", &self.block_ready)
            .field("finishing", &self.finishing)
            .finish_non_exhaustive()
    }
}

impl ZstdEncoder {
    /// Creates an encoder after checking its fixed workspace against `limits`.
    pub fn with_limits(limits: Limits) -> Result<Self, ArchiveError> {
        if limits
            .codec_memory()
            .is_some_and(|limit| limit < core::mem::size_of::<Self>())
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("zstd")
                .with_context("Zstandard encoder exceeds the configured codec-memory budget"));
        }
        Ok(Self {
            frame_header_offset: 0,
            block: [0; ENCODER_WINDOW],
            block_len: 0,
            block_output_offset: 0,
            block_ready: false,
            block_header: [0; BLOCK_HEADER],
            block_header_offset: BLOCK_HEADER,
            final_block_offset: 0,
            finishing: false,
            encoded_input: 0,
            limits,
        })
    }

    fn drain_bytes(bytes: &[u8], offset: &mut usize, output: &mut [u8], produced: &mut usize) {
        let count = (bytes.len() - *offset).min(output.len() - *produced);
        output[*produced..*produced + count].copy_from_slice(&bytes[*offset..*offset + count]);
        *offset += count;
        *produced += count;
    }

    fn prepare_block(&mut self) -> Result<(), ArchiveError> {
        let header = u32::try_from(self.block_len).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format("zstd")
                .with_context("Zstandard block size overflow")
        })? << 3;
        self.block_header
            .copy_from_slice(&header.to_le_bytes()[..BLOCK_HEADER]);
        self.block_header_offset = 0;
        self.block_output_offset = 0;
        self.block_ready = true;
        Ok(())
    }

    fn drain_block(&mut self, output: &mut [u8], produced: &mut usize) {
        if self.block_header_offset != self.block_header.len() {
            Self::drain_bytes(
                &self.block_header,
                &mut self.block_header_offset,
                output,
                produced,
            );
        }
        if self.block_header_offset == self.block_header.len() && *produced < output.len() {
            Self::drain_bytes(
                &self.block[..self.block_len],
                &mut self.block_output_offset,
                output,
                produced,
            );
        }
        if self.block_output_offset == self.block_len {
            self.block_len = 0;
            self.block_output_offset = 0;
            self.block_ready = false;
        }
    }

    fn encode_data(
        &mut self,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ArchiveError> {
        if self.finishing {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format("zstd")
                .with_context("Zstandard data supplied after finalization started"));
        }
        let mut consumed = 0;
        let mut produced = 0;
        if self.frame_header_offset != ENCODER_FRAME_HEADER.len() {
            Self::drain_bytes(
                &ENCODER_FRAME_HEADER,
                &mut self.frame_header_offset,
                output,
                &mut produced,
            );
        }
        while produced < output.len() && consumed < data.len() {
            if self.block_ready {
                self.drain_block(output, &mut produced);
                continue;
            }
            let count = (ENCODER_WINDOW - self.block_len).min(data.len() - consumed);
            let next = self
                .encoded_input
                .checked_add(u64::try_from(count).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zstd")
                        .with_context("Zstandard input length exceeds the format address space")
                })?)
                .ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("zstd")
                        .with_context("Zstandard input byte count overflow")
                })?;
            if self
                .limits
                .decoded_total()
                .is_some_and(|maximum| next > maximum)
            {
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("zstd")
                    .with_context("Zstandard input exceeds the configured decoded-byte budget"));
            }
            self.block[self.block_len..self.block_len + count]
                .copy_from_slice(&data[consumed..consumed + count]);
            self.block_len += count;
            consumed += count;
            self.encoded_input = next;
            if self.block_len == ENCODER_WINDOW {
                self.prepare_block()?;
            }
        }
        Ok((consumed, produced))
    }

    fn finish_frame(&mut self, output: &mut [u8]) -> Result<(usize, bool), ArchiveError> {
        self.finishing = true;
        let mut produced = 0;
        if self.frame_header_offset != ENCODER_FRAME_HEADER.len() {
            Self::drain_bytes(
                &ENCODER_FRAME_HEADER,
                &mut self.frame_header_offset,
                output,
                &mut produced,
            );
        }
        if self.frame_header_offset == ENCODER_FRAME_HEADER.len() && produced < output.len() {
            if self.block_len != 0 && !self.block_ready {
                self.prepare_block()?;
            }
            if self.block_ready {
                self.drain_block(output, &mut produced);
            }
        }
        if self.frame_header_offset == ENCODER_FRAME_HEADER.len()
            && !self.block_ready
            && self.block_len == 0
            && produced < output.len()
        {
            Self::drain_bytes(
                &ENCODER_FINAL_BLOCK,
                &mut self.final_block_offset,
                output,
                &mut produced,
            );
        }
        Ok((
            produced,
            self.final_block_offset == ENCODER_FINAL_BLOCK.len(),
        ))
    }
}

impl Codec for ZstdEncoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if self.finishing {
            if !input.is_empty() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("zstd")
                    .with_context("input supplied after Zstandard finalization started"));
            }
            if self.final_block_offset == ENCODER_FINAL_BLOCK.len() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            let (produced, done) = self.finish_frame(output)?;
            return Ok(CodecStep {
                consumed: 0,
                produced,
                status: if done {
                    CodecStatus::Done
                } else {
                    CodecStatus::NeedOutput
                },
            });
        }
        let (consumed, mut produced) = self.encode_data(input, output)?;
        if consumed != input.len() || produced == output.len() {
            return Ok(CodecStep {
                consumed,
                produced,
                status: CodecStatus::NeedOutput,
            });
        }
        if matches!(end, EndOfInput::More) {
            return Ok(CodecStep {
                consumed,
                produced,
                status: CodecStatus::NeedInput,
            });
        }
        let (finished, done) = self.finish_frame(&mut output[produced..])?;
        produced += finished;
        Ok(CodecStep {
            consumed,
            produced,
            status: if done {
                CodecStatus::Done
            } else {
                CodecStatus::NeedOutput
            },
        })
    }
}

/// Collects one deterministic frame by driving the bounded incremental encoder.
///
/// The returned frame necessarily owns memory proportional to its encoded
/// length; the encoder workspace itself remains fixed and is checked by
/// `limits`.
pub fn encode_frame(input: &[u8], limits: Limits) -> Result<Vec<u8>, ArchiveError> {
    let mut encoder = ZstdEncoder::with_limits(limits)?;
    let mut frame = Vec::new();
    let mut input_offset = 0;
    let mut buffer = [0_u8; 4096];
    loop {
        let step = encoder
            .process(&input[input_offset..], &mut buffer, EndOfInput::End)?
            .validate(input.len() - input_offset, buffer.len())?;
        input_offset += step.consumed;
        frame.extend_from_slice(&buffer[..step.produced]);
        if step.status == CodecStatus::Done {
            return Ok(frame);
        }
        if step.consumed == 0 && step.produced == 0 {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format("zstd")
                .with_context("Zstandard encoder made no progress"));
        }
    }
}
