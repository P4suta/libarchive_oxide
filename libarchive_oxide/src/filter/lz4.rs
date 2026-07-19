// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust, caller-driven LZ4 frame codec state.

use std::fmt;
use std::hash::Hasher;
use std::io::{self, Write};

use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind};
use twox_hash::XxHash32;

const MAGIC: &[u8; 4] = &[0x04, 0x22, 0x4d, 0x18];
const MIN_HEADER: usize = 7;
const MAX_BLOCK: usize = 4 * 1024 * 1024;
const MAX_PENDING: usize = MAX_BLOCK + 4 + 4 + 19;
const WINDOW: usize = 64 * 1024;

const FLG_VERSION_MASK: u8 = 0b1100_0000;
const FLG_VERSION_ONE: u8 = 0b0100_0000;
const FLG_INDEPENDENT: u8 = 0b0010_0000;
const FLG_BLOCK_CHECKSUM: u8 = 0b0001_0000;
const FLG_CONTENT_SIZE: u8 = 0b0000_1000;
const FLG_CONTENT_CHECKSUM: u8 = 0b0000_0100;
const FLG_RESERVED: u8 = 0b0000_0010;
const FLG_DICTIONARY: u8 = 0b0000_0001;
const BD_BLOCK_SIZE_MASK: u8 = 0b0111_0000;
const BD_RESERVED_MASK: u8 = !BD_BLOCK_SIZE_MASK;
const BLOCK_UNCOMPRESSED: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Header,
    Blocks,
}

/// Incremental LZ4 frame decoder backed by `lz4_flex` block primitives.
///
/// The adapter parses only the standard frame envelope. Compressed blocks are
/// delegated to `lz4_flex`, while framing, checksums, concatenation, and
/// caller-driven progress remain explicit. Memory is bounded to one maximum
/// frame block, one decoded block, and the 64 KiB linked-block dictionary.
pub(crate) struct Lz4Decoder {
    state: State,
    pending: Vec<u8>,
    decoded: Vec<u8>,
    decoded_position: usize,
    dictionary: Vec<u8>,
    max_block: usize,
    flags: u8,
    content_size: Option<u64>,
    content_length: u64,
    content_hasher: XxHash32,
    saw_frame: bool,
    done: bool,
}

impl Lz4Decoder {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Header,
            pending: Vec::with_capacity(MAX_PENDING),
            decoded: Vec::new(),
            decoded_position: 0,
            dictionary: Vec::with_capacity(WINDOW),
            max_block: 0,
            flags: FLG_INDEPENDENT,
            content_size: None,
            content_length: 0,
            content_hasher: XxHash32::with_seed(0),
            saw_frame: false,
            done: false,
        }
    }

    fn malformed(context: impl Into<String>) -> ArchiveError {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("lz4")
            .with_context(context)
    }

    fn unsupported(context: impl Into<String>) -> ArchiveError {
        ArchiveError::new(ErrorKind::Unsupported)
            .with_format("lz4")
            .with_context(context)
    }

    fn discard_pending(&mut self, consumed: usize) {
        if consumed == 0 {
            return;
        }
        self.pending.copy_within(consumed.., 0);
        self.pending.truncate(self.pending.len() - consumed);
    }

    fn independent(&self) -> bool {
        self.flags & FLG_INDEPENDENT != 0
    }

    fn block_checksum(&self) -> bool {
        self.flags & FLG_BLOCK_CHECKSUM != 0
    }

    fn content_checksum(&self) -> bool {
        self.flags & FLG_CONTENT_CHECKSUM != 0
    }

    fn digest32(hasher: &XxHash32) -> u32 {
        let bytes = hasher.finish().to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn drain_decoded(&mut self, output: &mut [u8]) -> usize {
        let available = self.decoded.len() - self.decoded_position;
        let copied = available.min(output.len());
        output[..copied]
            .copy_from_slice(&self.decoded[self.decoded_position..self.decoded_position + copied]);
        self.decoded_position += copied;
        if self.decoded_position == self.decoded.len() {
            self.decoded.clear();
            self.decoded_position = 0;
        }
        copied
    }

    fn parse_header(&mut self) -> Result<bool, ArchiveError> {
        if self.pending.len() < MIN_HEADER {
            return Ok(false);
        }
        if !self.pending.starts_with(MAGIC) {
            return Err(Self::malformed("non-frame trailing filter data"));
        }

        let flags = self.pending[4];
        let descriptor = self.pending[5];
        let header_length = MIN_HEADER
            + usize::from(flags & FLG_CONTENT_SIZE != 0) * 8
            + usize::from(flags & FLG_DICTIONARY != 0) * 4;
        if self.pending.len() < header_length {
            return Ok(false);
        }
        if flags & FLG_VERSION_MASK != FLG_VERSION_ONE {
            return Err(Self::malformed("unsupported LZ4 frame version"));
        }
        if flags & FLG_RESERVED != 0 || descriptor & BD_RESERVED_MASK != 0 {
            return Err(Self::malformed("reserved LZ4 frame bits are set"));
        }
        if flags & FLG_DICTIONARY != 0 {
            return Err(Self::unsupported(
                "LZ4 frame dictionaries are not supported",
            ));
        }

        let block_code = (descriptor & BD_BLOCK_SIZE_MASK) >> 4;
        self.max_block = match block_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => MAX_BLOCK,
            _ => return Err(Self::malformed("unsupported LZ4 maximum block size")),
        };

        let expected_header_checksum = self.pending[header_length - 1];
        let mut header_hasher = XxHash32::with_seed(0);
        header_hasher.write(&self.pending[4..header_length - 1]);
        if header_hasher.finish().to_le_bytes()[1] != expected_header_checksum {
            return Err(Self::malformed("LZ4 frame header checksum mismatch"));
        }

        let mut optional = 6;
        self.content_size = if flags & FLG_CONTENT_SIZE != 0 {
            let size = u64::from_le_bytes(
                self.pending[optional..optional + 8]
                    .try_into()
                    .map_err(|_| Self::malformed("invalid LZ4 content size"))?,
            );
            optional += 8;
            Some(size)
        } else {
            None
        };
        debug_assert_eq!(
            optional + 1,
            header_length,
            "dictionary IDs were rejected above"
        );

        self.flags = flags;
        self.content_length = 0;
        self.content_hasher = XxHash32::with_seed(0);
        self.dictionary.clear();
        self.discard_pending(header_length);
        self.state = State::Blocks;
        Ok(true)
    }

    fn verify_checksum(bytes: &[u8], expected: u32, context: &str) -> Result<(), ArchiveError> {
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(bytes);
        if Self::digest32(&hasher) == expected {
            Ok(())
        } else {
            Err(Self::malformed(context))
        }
    }

    fn update_dictionary(&mut self) {
        if self.independent() {
            return;
        }
        if self.decoded.len() >= WINDOW {
            self.dictionary.clear();
            self.dictionary
                .extend_from_slice(&self.decoded[self.decoded.len() - WINDOW..]);
            return;
        }
        let keep = self
            .dictionary
            .len()
            .min(WINDOW.saturating_sub(self.decoded.len()));
        let start = self.dictionary.len() - keep;
        self.dictionary.copy_within(start.., 0);
        self.dictionary.truncate(keep);
        self.dictionary.extend_from_slice(&self.decoded);
    }

    fn finish_frame(&mut self, record_length: usize) -> Result<(), ArchiveError> {
        if let Some(expected) = self.content_size
            && self.content_length != expected
        {
            return Err(Self::malformed(format!(
                "LZ4 content size mismatch: expected {expected}, decoded {}",
                self.content_length
            )));
        }
        if self.content_checksum() {
            let expected = u32::from_le_bytes(
                self.pending[4..8]
                    .try_into()
                    .map_err(|_| Self::malformed("truncated LZ4 content checksum"))?,
            );
            if Self::digest32(&self.content_hasher) != expected {
                return Err(Self::malformed("LZ4 content checksum mismatch"));
            }
        }
        self.discard_pending(record_length);
        self.state = State::Header;
        self.saw_frame = true;
        Ok(())
    }

    fn parse_block(&mut self) -> Result<bool, ArchiveError> {
        if self.pending.len() < 4 {
            return Ok(false);
        }
        let record = u32::from_le_bytes(
            self.pending[..4]
                .try_into()
                .map_err(|_| Self::malformed("invalid LZ4 block header"))?,
        );
        if record == 0 {
            let record_length = 4 + usize::from(self.content_checksum()) * 4;
            if self.pending.len() < record_length {
                return Ok(false);
            }
            self.finish_frame(record_length)?;
            return Ok(true);
        }

        let uncompressed = record & BLOCK_UNCOMPRESSED != 0;
        let block_length = (record & !BLOCK_UNCOMPRESSED) as usize;
        if block_length == 0 || block_length > self.max_block {
            return Err(Self::malformed("LZ4 block exceeds the declared maximum"));
        }
        let record_length = 4 + block_length + usize::from(self.block_checksum()) * 4;
        if self.pending.len() < record_length {
            return Ok(false);
        }
        let block = &self.pending[4..4 + block_length];
        if self.block_checksum() {
            let expected = u32::from_le_bytes(
                self.pending[4 + block_length..record_length]
                    .try_into()
                    .map_err(|_| Self::malformed("truncated LZ4 block checksum"))?,
            );
            Self::verify_checksum(block, expected, "LZ4 block checksum mismatch")?;
        }

        self.decoded.clear();
        if uncompressed {
            self.decoded.extend_from_slice(block);
        } else {
            self.decoded.resize(self.max_block, 0);
            let decoded = if self.independent() {
                lz4_flex::block::decompress_into(block, &mut self.decoded)
            } else {
                lz4_flex::block::decompress_into_with_dict(
                    block,
                    &mut self.decoded,
                    &self.dictionary,
                )
            }
            .map_err(|error| Self::malformed(error.to_string()))?;
            self.decoded.truncate(decoded);
        }

        self.content_length = self
            .content_length
            .checked_add(
                u64::try_from(self.decoded.len())
                    .map_err(|_| Self::malformed("LZ4 decoded length overflow"))?,
            )
            .ok_or_else(|| Self::malformed("LZ4 decoded length overflow"))?;
        if let Some(expected) = self.content_size
            && self.content_length > expected
        {
            return Err(Self::malformed(
                "LZ4 decoded data exceeds the declared content size",
            ));
        }
        if self.content_checksum() {
            self.content_hasher.write(&self.decoded);
        }
        self.update_dictionary();
        self.decoded_position = 0;
        self.discard_pending(record_length);
        Ok(true)
    }

    fn truncated(&self) -> ArchiveError {
        match self.state {
            State::Header => Self::malformed("truncated LZ4 frame header"),
            State::Blocks => Self::malformed("LZ4 frame ended before its terminal block"),
        }
    }
}

impl Default for Lz4Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Lz4Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lz4Decoder")
            .field("state", &self.state)
            .field("pending", &self.pending.len())
            .field("decoded", &(self.decoded.len() - self.decoded_position))
            .field("dictionary", &self.dictionary.len())
            .field("saw_frame", &self.saw_frame)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Codec for Lz4Decoder {
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
            return Err(Self::malformed("data follows the completed LZ4 stream"));
        }

        let available = MAX_PENDING.saturating_sub(self.pending.len());
        let consumed = available.min(input.len());
        self.pending.extend_from_slice(&input[..consumed]);
        let effective_end = if consumed == input.len() {
            end
        } else {
            EndOfInput::More
        };
        if output.is_empty() {
            let status = if !self.decoded.is_empty()
                || !self.pending.is_empty()
                || matches!(self.state, State::Blocks)
            {
                CodecStatus::NeedOutput
            } else if matches!(effective_end, EndOfInput::End) {
                if self.saw_frame {
                    self.done = true;
                    CodecStatus::Done
                } else {
                    return Err(self.truncated());
                }
            } else {
                CodecStatus::NeedInput
            };
            return Ok(CodecStep {
                consumed,
                produced: 0,
                status,
            });
        }

        let mut produced = self.drain_decoded(output);
        while produced < output.len() {
            let progressed = match self.state {
                State::Header => self.parse_header()?,
                State::Blocks => self.parse_block()?,
            };
            if !progressed {
                break;
            }
            produced += self.drain_decoded(&mut output[produced..]);
        }

        let status = if self.decoded_position != self.decoded.len()
            || (!output.is_empty() && produced == output.len())
        {
            CodecStatus::NeedOutput
        } else if matches!(effective_end, EndOfInput::End) {
            if self.state == State::Header && self.pending.is_empty() && self.saw_frame {
                self.done = true;
                CodecStatus::Done
            } else {
                return Err(self.truncated());
            }
        } else {
            CodecStatus::NeedInput
        };
        Ok(CodecStep {
            consumed,
            produced,
            status,
        })
    }
}

/// Encodes one deterministic, checksummed 64 KiB-bounded LZ4 frame chunk.
pub(crate) fn encode_frame(input: &[u8]) -> io::Result<Vec<u8>> {
    let info = lz4_flex::frame::FrameInfo::new()
        .content_size(Some(input.len() as u64))
        .block_size(lz4_flex::frame::BlockSize::Max64KB)
        .block_mode(lz4_flex::frame::BlockMode::Independent)
        .block_checksums(true)
        .content_checksum(true);
    let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
    encoder.write_all(input)?;
    encoder.finish().map_err(io::Error::from)
}
