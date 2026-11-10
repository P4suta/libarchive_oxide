// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded lzop framing with Safe Rust LZO1X decompression.
//!
//! The decoder accepts methods 1, 2, and 3 because all three use the same LZO1X bitstream on disk.
//! Stored and compressed blocks are checksum-verified.
//! The deterministic writer uses the standard stored-block fallback, keeping the default build free of an unsafe or copyleft LZO compressor.

use alloc::vec::Vec;
use core::mem;

use libarchive_oxide_protocol::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const MAGIC: &[u8; 9] = b"\x89LZO\0\r\n\x1a\n";
const MAX_HEADER_BYTES: usize = 300;
const MAX_BLOCK_BYTES: usize = 64 * 1024 * 1024;
const WRITER_BLOCK_BYTES: usize = 256 * 1024;

const FLAG_ADLER32_UNCOMPRESSED: u32 = 0x0001;
const FLAG_ADLER32_COMPRESSED: u32 = 0x0002;
const FLAG_EXTRA_FIELD: u32 = 0x0040;
const FLAG_CRC32_UNCOMPRESSED: u32 = 0x0100;
const FLAG_CRC32_COMPRESSED: u32 = 0x0200;
const FLAG_FILTER: u32 = 0x0800;
const FLAG_CRC32_HEADER: u32 = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodePhase {
    Header,
    ExtraLength,
    ExtraPayload,
    ExtraChecksum,
    BlockHeader,
    BlockData,
    Output,
    BetweenMembers,
    Done,
    Failed,
}

/// Incremental decoder for concatenated lzop members.
#[derive(Debug)]
pub struct LzopDecoder {
    decoded_limit: Option<u64>,
    codec_limit: Option<usize>,
    metadata_limit: Option<usize>,
    decoded: u64,
    phase: DecodePhase,
    header: [u8; MAX_HEADER_BYTES],
    header_len: usize,
    flags: u32,
    small: [u8; 16],
    small_len: usize,
    extra_remaining: usize,
    uncompressed_size: usize,
    compressed_size: usize,
    expected_uncompressed: Option<u32>,
    expected_compressed: Option<u32>,
    block: Vec<u8>,
    output: Vec<u8>,
    output_pos: usize,
}

impl LzopDecoder {
    /// Creates a bounded lzop decoder.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            decoded_limit: limits.decoded_total(),
            codec_limit: limits.codec_memory(),
            metadata_limit: limits.metadata_bytes(),
            decoded: 0,
            phase: DecodePhase::Header,
            header: [0; MAX_HEADER_BYTES],
            header_len: 0,
            flags: 0,
            small: [0; 16],
            small_len: 0,
            extra_remaining: 0,
            uncompressed_size: 0,
            compressed_size: 0,
            expected_uncompressed: None,
            expected_compressed: None,
            block: Vec::new(),
            output: Vec::new(),
            output_pos: 0,
        }
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.phase = DecodePhase::Failed;
        lzop_error(kind, context)
    }

    fn reset_header(&mut self) {
        self.header_len = 0;
        self.phase = DecodePhase::Header;
    }

    fn finish_header(&mut self) -> Result<(), ArchiveError> {
        let header = &self.header[..self.header_len];
        let parsed = parse_header(header).map_err(|(kind, context)| self.fail(kind, context))?;
        self.flags = parsed.flags;
        self.small_len = 0;
        self.phase = if parsed.has_extra {
            DecodePhase::ExtraLength
        } else {
            DecodePhase::BlockHeader
        };
        Ok(())
    }

    fn finish_extra_length(&mut self) -> Result<(), ArchiveError> {
        let length = usize::try_from(be32(&self.small[..4]))
            .map_err(|_| self.fail(ErrorKind::Limit, "lzop extra-field size exceeds usize"))?;
        if self.metadata_limit.is_some_and(|maximum| length > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "lzop extra field exceeds the metadata budget",
            ));
        }
        self.extra_remaining = length;
        self.small_len = 0;
        self.phase = if length == 0 {
            DecodePhase::ExtraChecksum
        } else {
            DecodePhase::ExtraPayload
        };
        Ok(())
    }

    fn block_header_needed(&self) -> usize {
        if self.small_len < 4 {
            return 4;
        }
        let uncompressed = be32(&self.small[..4]);
        if uncompressed == 0 {
            return 4;
        }
        if self.small_len < 8 {
            return 8;
        }
        let compressed = be32(&self.small[4..8]);
        let mut needed = 8;
        if self.flags & (FLAG_ADLER32_UNCOMPRESSED | FLAG_CRC32_UNCOMPRESSED) != 0 {
            needed += 4;
        }
        if compressed < uncompressed
            && self.flags & (FLAG_ADLER32_COMPRESSED | FLAG_CRC32_COMPRESSED) != 0
        {
            needed += 4;
        }
        needed
    }

    fn finish_block_header(&mut self) -> Result<(), ArchiveError> {
        let uncompressed_u32 = be32(&self.small[..4]);
        if uncompressed_u32 == 0 {
            self.small_len = 0;
            self.phase = DecodePhase::BetweenMembers;
            return Ok(());
        }
        let compressed_u32 = be32(&self.small[4..8]);
        if compressed_u32 == 0 || compressed_u32 > uncompressed_u32 {
            return Err(self.fail(
                ErrorKind::Malformed,
                "lzop block has an invalid compressed size",
            ));
        }
        let uncompressed = usize::try_from(uncompressed_u32)
            .map_err(|_| self.fail(ErrorKind::Limit, "lzop block size exceeds usize"))?;
        let compressed = usize::try_from(compressed_u32)
            .map_err(|_| self.fail(ErrorKind::Limit, "lzop block size exceeds usize"))?;
        if uncompressed > MAX_BLOCK_BYTES {
            return Err(self.fail(
                ErrorKind::Limit,
                "lzop block exceeds the 64 MiB format safety bound",
            ));
        }
        let workspace = if compressed < uncompressed {
            compressed.checked_add(uncompressed)
        } else {
            Some(compressed)
        }
        .ok_or_else(|| self.fail(ErrorKind::Limit, "lzop block workspace size overflow"))?;
        if self.codec_limit.is_some_and(|maximum| workspace > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "lzop block exceeds the codec-memory budget",
            ));
        }
        let count = u64::from(uncompressed_u32);
        let next = self
            .decoded
            .checked_add(count)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "lzop decoded-byte count overflow"))?;
        if self.decoded_limit.is_some_and(|maximum| next > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "lzop decoded output exceeds the configured limit",
            ));
        }

        let mut offset = 8;
        let expected_uncompressed =
            if self.flags & (FLAG_ADLER32_UNCOMPRESSED | FLAG_CRC32_UNCOMPRESSED) != 0 {
                let value = be32(&self.small[offset..offset + 4]);
                offset += 4;
                Some(value)
            } else {
                None
            };
        let expected_compressed = if compressed < uncompressed
            && self.flags & (FLAG_ADLER32_COMPRESSED | FLAG_CRC32_COMPRESSED) != 0
        {
            Some(be32(&self.small[offset..offset + 4]))
        } else {
            None
        };

        self.uncompressed_size = uncompressed;
        self.compressed_size = compressed;
        self.expected_uncompressed = expected_uncompressed;
        self.expected_compressed = expected_compressed;
        self.small_len = 0;
        self.block = Vec::new();
        self.block
            .try_reserve_exact(compressed)
            .map_err(|_| self.fail(ErrorKind::Limit, "cannot allocate bounded lzop block"))?;
        self.decoded = next;
        self.phase = DecodePhase::BlockData;
        Ok(())
    }

    fn finish_block_data(&mut self) -> Result<(), ArchiveError> {
        if let Some(expected) = self.expected_compressed {
            let actual = block_checksum(&self.block, self.flags & FLAG_CRC32_COMPRESSED != 0);
            if actual != expected {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "lzop compressed-block checksum mismatch",
                ));
            }
        }

        let output = if self.compressed_size == self.uncompressed_size {
            mem::take(&mut self.block)
        } else {
            let mut decoded = Vec::new();
            decoded
                .try_reserve_exact(self.uncompressed_size)
                .map_err(|_| {
                    self.fail(
                        ErrorKind::Limit,
                        "cannot allocate bounded lzop output block",
                    )
                })?;
            decoded.resize(self.uncompressed_size, 0);
            let produced = lzo::decompress_into(&self.block, &mut decoded)
                .map_err(|_| self.fail(ErrorKind::Malformed, "invalid LZO1X compressed block"))?;
            if produced != self.uncompressed_size {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "LZO1X block decoded to an unexpected size",
                ));
            }
            self.block.clear();
            decoded
        };

        if let Some(expected) = self.expected_uncompressed {
            let actual = block_checksum(&output, self.flags & FLAG_CRC32_UNCOMPRESSED != 0);
            if actual != expected {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "lzop uncompressed-block checksum mismatch",
                ));
            }
        }
        self.output = output;
        self.output_pos = 0;
        self.phase = DecodePhase::Output;
        Ok(())
    }

    fn drain_output(&mut self, output: &mut [u8]) -> usize {
        let available = self.output.len().saturating_sub(self.output_pos);
        let count = available.min(output.len());
        if count != 0 {
            output[..count].copy_from_slice(&self.output[self.output_pos..self.output_pos + count]);
            self.output_pos += count;
        }
        if self.output_pos == self.output.len() {
            self.output = Vec::new();
            self.output_pos = 0;
            self.phase = DecodePhase::BlockHeader;
        }
        count
    }

    fn truncated(&mut self) -> ArchiveError {
        self.fail(ErrorKind::Malformed, "truncated lzop stream")
    }
}

impl Codec for LzopDecoder {
    #[allow(clippy::too_many_lines)] // Direct phase dispatch keeps all input/output accounting visible.
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if self.phase == DecodePhase::Failed {
            return Err(lzop_error(
                ErrorKind::Protocol,
                "lzop decoder was used after a terminal error",
            ));
        }
        if self.phase == DecodePhase::Done {
            if input.is_empty() {
                return Ok(codec_step(0, 0, CodecStatus::Done));
            }
            return Err(self.fail(ErrorKind::Protocol, "input supplied after lzop completion"));
        }

        let mut consumed = 0;
        let mut produced = 0;
        loop {
            match self.phase {
                DecodePhase::Header => {
                    let needed = header_needed(&self.header[..self.header_len])
                        .map_err(|(kind, context)| self.fail(kind, context))?;
                    if self.header_len == needed {
                        self.finish_header()?;
                        continue;
                    }
                    if consumed == input.len() {
                        if matches!(end, EndOfInput::End) {
                            return Err(self.truncated());
                        }
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                    }
                    if self.header_len == self.header.len() {
                        return Err(
                            self.fail(ErrorKind::Malformed, "lzop header exceeds its format bound")
                        );
                    }
                    self.header[self.header_len] = input[consumed];
                    self.header_len += 1;
                    consumed += 1;
                },
                DecodePhase::ExtraLength => {
                    if self.small_len == 4 {
                        self.finish_extra_length()?;
                        continue;
                    }
                    if consumed == input.len() {
                        if matches!(end, EndOfInput::End) {
                            return Err(self.truncated());
                        }
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                    }
                    self.small[self.small_len] = input[consumed];
                    self.small_len += 1;
                    consumed += 1;
                },
                DecodePhase::ExtraPayload => {
                    let count = self.extra_remaining.min(input.len() - consumed);
                    consumed += count;
                    self.extra_remaining -= count;
                    if self.extra_remaining == 0 {
                        self.phase = DecodePhase::ExtraChecksum;
                        self.small_len = 0;
                        continue;
                    }
                    if matches!(end, EndOfInput::End) {
                        return Err(self.truncated());
                    }
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                },
                DecodePhase::ExtraChecksum => {
                    if self.small_len == 4 {
                        self.small_len = 0;
                        self.phase = DecodePhase::BlockHeader;
                        continue;
                    }
                    if consumed == input.len() {
                        if matches!(end, EndOfInput::End) {
                            return Err(self.truncated());
                        }
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                    }
                    self.small[self.small_len] = input[consumed];
                    self.small_len += 1;
                    consumed += 1;
                },
                DecodePhase::BlockHeader => {
                    let needed = self.block_header_needed();
                    if self.small_len == needed {
                        self.finish_block_header()?;
                        continue;
                    }
                    if consumed == input.len() {
                        if matches!(end, EndOfInput::End) {
                            return Err(self.truncated());
                        }
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                    }
                    self.small[self.small_len] = input[consumed];
                    self.small_len += 1;
                    consumed += 1;
                },
                DecodePhase::BlockData => {
                    let remaining = self.compressed_size - self.block.len();
                    let count = remaining.min(input.len() - consumed);
                    self.block
                        .extend_from_slice(&input[consumed..consumed + count]);
                    consumed += count;
                    if self.block.len() == self.compressed_size {
                        self.finish_block_data()?;
                        continue;
                    }
                    if matches!(end, EndOfInput::End) {
                        return Err(self.truncated());
                    }
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                },
                DecodePhase::Output => {
                    produced += self.drain_output(&mut output[produced..]);
                    if self.phase == DecodePhase::Output {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                },
                DecodePhase::BetweenMembers => {
                    if consumed < input.len() {
                        self.reset_header();
                        continue;
                    }
                    if matches!(end, EndOfInput::End) {
                        self.phase = DecodePhase::Done;
                        return Ok(codec_step(consumed, produced, CodecStatus::Done));
                    }
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                },
                DecodePhase::Done => {
                    return Ok(codec_step(consumed, produced, CodecStatus::Done));
                },
                DecodePhase::Failed => {
                    return Err(lzop_error(
                        ErrorKind::Protocol,
                        "lzop decoder entered a failed state",
                    ));
                },
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodePhase {
    Header,
    Collect,
    BlockHeader,
    BlockData,
    EndMark,
    Done,
    Failed,
}

/// Deterministic incremental lzop stored-block writer.
#[derive(Debug)]
pub struct LzopEncoder {
    plain_limit: Option<u64>,
    plain: u64,
    phase: EncodePhase,
    header: [u8; 38],
    header_pos: usize,
    block: Vec<u8>,
    block_capacity: usize,
    block_pos: usize,
    block_header: [u8; 12],
    block_header_pos: usize,
    end_pos: usize,
}

impl LzopEncoder {
    /// Creates a deterministic stored-block writer with bounded buffering.
    ///
    /// # Errors
    ///
    /// Returns a limit error when no byte of block workspace is permitted.
    pub fn new(limits: Limits) -> Result<Self, ArchiveError> {
        let block_capacity = limits.codec_memory().map_or(WRITER_BLOCK_BYTES, |maximum| {
            maximum.min(WRITER_BLOCK_BYTES)
        });
        if block_capacity == 0 {
            return Err(lzop_error(
                ErrorKind::Limit,
                "lzop writer requires at least one byte of codec workspace",
            ));
        }
        let mut block = Vec::new();
        block
            .try_reserve_exact(block_capacity)
            .map_err(|_| lzop_error(ErrorKind::Limit, "cannot allocate lzop writer block"))?;
        Ok(Self {
            plain_limit: limits.decoded_total(),
            plain: 0,
            phase: EncodePhase::Header,
            header: canonical_header(),
            header_pos: 0,
            block,
            block_capacity,
            block_pos: 0,
            block_header: [0; 12],
            block_header_pos: 0,
            end_pos: 0,
        })
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.phase = EncodePhase::Failed;
        lzop_error(kind, context)
    }

    fn prepare_block(&mut self) -> Result<(), ArchiveError> {
        let size = u32::try_from(self.block.len())
            .map_err(|_| self.fail(ErrorKind::Limit, "lzop writer block exceeds u32"))?;
        self.block_header[..4].copy_from_slice(&size.to_be_bytes());
        self.block_header[4..8].copy_from_slice(&size.to_be_bytes());
        self.block_header[8..12].copy_from_slice(&adler32(&self.block).to_be_bytes());
        self.block_header_pos = 0;
        self.block_pos = 0;
        self.phase = EncodePhase::BlockHeader;
        Ok(())
    }

    fn accept(&mut self, input: &[u8]) -> Result<(), ArchiveError> {
        let count = u64::try_from(input.len())
            .map_err(|_| self.fail(ErrorKind::Limit, "lzop input size exceeds u64"))?;
        let next = self
            .plain
            .checked_add(count)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "lzop input-byte count overflow"))?;
        if self.plain_limit.is_some_and(|maximum| next > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "lzop input exceeds the configured decoded-byte limit",
            ));
        }
        self.block.extend_from_slice(input);
        self.plain = next;
        Ok(())
    }
}

impl Codec for LzopEncoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if self.phase == EncodePhase::Failed {
            return Err(lzop_error(
                ErrorKind::Protocol,
                "lzop encoder was used after a terminal error",
            ));
        }
        if self.phase == EncodePhase::Done {
            if input.is_empty() {
                return Ok(codec_step(0, 0, CodecStatus::Done));
            }
            return Err(self.fail(ErrorKind::Protocol, "input supplied after lzop completion"));
        }

        let mut consumed = 0;
        let mut produced = 0;
        loop {
            match self.phase {
                EncodePhase::Header => {
                    let count = (self.header.len() - self.header_pos).min(output.len() - produced);
                    output[produced..produced + count]
                        .copy_from_slice(&self.header[self.header_pos..self.header_pos + count]);
                    self.header_pos += count;
                    produced += count;
                    if self.header_pos != self.header.len() {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    self.phase = EncodePhase::Collect;
                },
                EncodePhase::Collect => {
                    let room = self.block_capacity - self.block.len();
                    let count = room.min(input.len() - consumed);
                    self.accept(&input[consumed..consumed + count])?;
                    consumed += count;
                    if self.block.len() == self.block_capacity {
                        self.prepare_block()?;
                        continue;
                    }
                    if consumed < input.len() {
                        continue;
                    }
                    if matches!(end, EndOfInput::End) {
                        if self.block.is_empty() {
                            self.phase = EncodePhase::EndMark;
                        } else {
                            self.prepare_block()?;
                        }
                        continue;
                    }
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedInput));
                },
                EncodePhase::BlockHeader => {
                    let count = (self.block_header.len() - self.block_header_pos)
                        .min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(
                        &self.block_header[self.block_header_pos..self.block_header_pos + count],
                    );
                    self.block_header_pos += count;
                    produced += count;
                    if self.block_header_pos != self.block_header.len() {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    self.phase = EncodePhase::BlockData;
                },
                EncodePhase::BlockData => {
                    let count = (self.block.len() - self.block_pos).min(output.len() - produced);
                    output[produced..produced + count]
                        .copy_from_slice(&self.block[self.block_pos..self.block_pos + count]);
                    self.block_pos += count;
                    produced += count;
                    if self.block_pos != self.block.len() {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    self.block.clear();
                    self.block_pos = 0;
                    self.phase = EncodePhase::Collect;
                },
                EncodePhase::EndMark => {
                    let count = (4 - self.end_pos).min(output.len() - produced);
                    output[produced..produced + count].fill(0);
                    self.end_pos += count;
                    produced += count;
                    if self.end_pos != 4 {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    self.phase = EncodePhase::Done;
                    return Ok(codec_step(consumed, produced, CodecStatus::Done));
                },
                EncodePhase::Done => {
                    return Ok(codec_step(consumed, produced, CodecStatus::Done));
                },
                EncodePhase::Failed => {
                    return Err(lzop_error(
                        ErrorKind::Protocol,
                        "lzop encoder entered a failed state",
                    ));
                },
            }
            if produced == output.len() {
                return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ParsedHeader {
    flags: u32,
    has_extra: bool,
}

fn header_needed(bytes: &[u8]) -> Result<usize, (ErrorKind, &'static str)> {
    if bytes.len() < MAGIC.len() {
        if !MAGIC.starts_with(bytes) {
            return Err((ErrorKind::Malformed, "invalid lzop magic"));
        }
        return Ok(MAGIC.len());
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err((ErrorKind::Malformed, "invalid lzop magic"));
    }
    if bytes.len() < 13 {
        return Ok(13);
    }
    let version = be16(&bytes[9..11]);
    let mut offset = 13;
    if version >= 0x0940 {
        offset += 2;
    }
    offset += 1;
    if version >= 0x0940 {
        offset += 1;
    }
    if bytes.len() < offset + 4 {
        return Ok(offset + 4);
    }
    let flags = be32(&bytes[offset..offset + 4]);
    offset += 4;
    if flags & FLAG_FILTER != 0 {
        offset += 4;
    }
    offset += 4;
    offset += if version >= 0x0940 { 8 } else { 4 };
    if bytes.len() < offset + 1 {
        return Ok(offset + 1);
    }
    let name_len = usize::from(bytes[offset]);
    let needed = offset
        .checked_add(1 + name_len + 4)
        .ok_or((ErrorKind::Limit, "lzop header length overflow"))?;
    if needed > MAX_HEADER_BYTES {
        return Err((ErrorKind::Malformed, "lzop header exceeds its format bound"));
    }
    Ok(needed)
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, (ErrorKind, &'static str)> {
    if header_needed(bytes)? != bytes.len() {
        return Err((ErrorKind::Malformed, "incomplete lzop header"));
    }
    let version = be16(&bytes[9..11]);
    if version < 0x0900 {
        return Err((ErrorKind::Unsupported, "unsupported pre-0.9 lzop stream"));
    }
    let mut offset = 13;
    if version >= 0x0940 {
        let required = be16(&bytes[offset..offset + 2]);
        if required < 0x0900 {
            return Err((ErrorKind::Malformed, "invalid lzop required version"));
        }
        offset += 2;
    }
    let method = bytes[offset];
    offset += 1;
    if !(1..=3).contains(&method) {
        return Err((
            ErrorKind::Unsupported,
            "unsupported lzop compression method",
        ));
    }
    if version >= 0x0940 {
        let level = bytes[offset];
        offset += 1;
        if level > 9 {
            return Err((ErrorKind::Malformed, "invalid lzop compression level"));
        }
    }
    let flags = be32(&bytes[offset..offset + 4]);
    let expected = be32(&bytes[bytes.len() - 4..]);
    let payload = &bytes[MAGIC.len()..bytes.len() - 4];
    let actual = if flags & FLAG_CRC32_HEADER != 0 {
        crc32(payload)
    } else {
        adler32(payload)
    };
    if actual != expected {
        return Err((ErrorKind::Malformed, "lzop header checksum mismatch"));
    }
    Ok(ParsedHeader {
        flags,
        has_extra: flags & FLAG_EXTRA_FIELD != 0,
    })
}

fn block_checksum(bytes: &[u8], crc: bool) -> u32 {
    if crc { crc32(bytes) } else { adler32(bytes) }
}

fn canonical_header() -> [u8; 38] {
    let mut header = [0_u8; 38];
    header[..9].copy_from_slice(MAGIC);
    header[9..11].copy_from_slice(&0x1030_u16.to_be_bytes());
    header[11..13].copy_from_slice(&0x0940_u16.to_be_bytes());
    header[13..15].copy_from_slice(&0x0940_u16.to_be_bytes());
    header[15] = 1;
    header[16] = 5;
    header[17..21].copy_from_slice(&0x0300_000d_u32.to_be_bytes());
    header[21..25].copy_from_slice(&0o100_644_u32.to_be_bytes());
    let checksum = adler32(&header[9..34]);
    header[34..38].copy_from_slice(&checksum.to_be_bytes());
    header
}

fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let (mut a, mut b) = (1_u32, 0_u32);
    for chunk in bytes.chunks(5_552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MODULUS;
        b %= MODULUS;
    }
    (b << 16) | a
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

const fn codec_step(consumed: usize, produced: usize, status: CodecStatus) -> CodecStep {
    CodecStep {
        consumed,
        produced,
        status,
    }
}

fn lzop_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("lzop")
        .with_context(context)
}
