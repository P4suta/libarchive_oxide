// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust, caller-driven Zstandard codec state.

use std::fmt;

use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind};

const MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];
const MAX_BLOCK: usize = 128 * 1024;
const MAX_FRAME_HEADER: usize = 18;
const BLOCK_HEADER: usize = 3;
const CHECKSUM: usize = 4;
const MAX_PENDING: usize = MAX_BLOCK + MAX_FRAME_HEADER + BLOCK_HEADER + CHECKSUM;

/// Incremental Zstandard decoder backed by `ruzstd`.
///
/// `ruzstd` consumes complete blocks, so this adapter retains at most one
/// maximum-sized block plus its framing. Concatenated frames are treated as one
/// logical outer-filter stream.
pub(crate) struct ZstdDecoder {
    decoder: ruzstd::decoding::FrameDecoder,
    pending: Vec<u8>,
    frame_active: bool,
    saw_frame: bool,
    done: bool,
}

impl ZstdDecoder {
    pub(crate) fn new() -> Self {
        Self {
            decoder: ruzstd::decoding::FrameDecoder::new(),
            pending: Vec::with_capacity(MAX_PENDING),
            frame_active: false,
            saw_frame: false,
            done: false,
        }
    }

    fn malformed(context: impl Into<String>) -> ArchiveError {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zstd")
            .with_context(context)
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
                    self.done = true;
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
            .field("done", &self.done)
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
        if self.done {
            if input.is_empty() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            return Err(Self::malformed(
                "data follows the completed Zstandard stream",
            ));
        }

        let available = MAX_PENDING.saturating_sub(self.pending.len());
        let consumed = available.min(input.len());
        self.pending.extend_from_slice(&input[..consumed]);

        if !self.frame_active {
            if self.pending.len() < MAGIC.len() {
                if matches!(end, EndOfInput::End) {
                    let context = if self.saw_frame && self.pending.is_empty() {
                        self.done = true;
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
            self.frame_active = true;
        }

        let result = self.decoder.decode_from_to(&self.pending, output);
        let (decoded_input, produced) = match result {
            Ok(progress) => progress,
            Err(_)
                if matches!(end, EndOfInput::More)
                    && self.pending.len() < MAX_PENDING
                    && consumed != 0 =>
            {
                return Ok(CodecStep {
                    consumed,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            },
            Err(error) => return Err(Self::malformed(error.to_string())),
        };
        if decoded_input > self.pending.len() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::malformed("truncated Zstandard frame checksum"));
            }
            return Ok(CodecStep {
                consumed,
                produced: 0,
                status: CodecStatus::NeedInput,
            });
        }
        self.discard_pending(decoded_input);
        let status = self.status_after_progress(produced, output.len(), end)?;
        Ok(CodecStep {
            consumed,
            produced,
            status,
        })
    }
}

/// Encodes one deterministic, bounded frame chunk.
pub(crate) fn encode_frame(input: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(input, ruzstd::encoding::CompressionLevel::Fastest)
}
