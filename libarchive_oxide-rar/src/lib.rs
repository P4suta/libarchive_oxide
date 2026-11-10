// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded caller-driven adapters for clean-room RAR3 and RAR5 payload codecs.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::fmt;

use libarchive_oxide_protocol::{ArchiveError, Codec, CodecStep, EndOfInput, ErrorKind, Limits};

mod adapter;
mod codec;
mod rar3;
mod rar5;
#[cfg(test)]
mod test_support;

use crate::adapter::Adapter;

/// Fixed RAR3 sliding dictionary allocated while the complete payload is decoded.
pub const RAR3_DICTIONARY_BYTES: usize = 4 * 1024 * 1024;
/// Conservative allowance for RAR3 tables, VM programs/queue, and filter scratch.
pub const RAR3_AUXILIARY_BYTES: usize = 512 * 1024;
/// Smallest valid RAR5 dictionary/window.
pub const RAR5_MIN_WINDOW_BYTES: usize = 128 * 1024;
/// Largest RAR5/RAR7 dictionary/window representable by the wire format.
pub const RAR5_MAX_WINDOW_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Conservative allowance for RAR5 tables, queues, and filter descriptors.
const RAR5_AUXILIARY_BYTES: usize = 2 * 1024 * 1024;
/// Largest RAR5 compressed block body encoded by its three-byte size field.
const RAR5_MAX_BLOCK_BYTES: usize = 0x00ff_ffff;
/// Largest block header: flags, checksum, and a three-byte body size.
const RAR5_MAX_BLOCK_HEADER_BYTES: usize = 5;

/// Compression algorithm generation carried by a RAR5-family file header.
///
/// RAR7 headers can request either generation 1 or generation 0 with an exact generation-1 dictionary size, so this is deliberately independent of the dictionary layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rar5Algorithm {
    /// Original RAR 5.0 compression algorithm.
    Generation0,
    /// RAR 7.0 compression algorithm with the extended distance alphabet.
    Generation1,
}

impl Rar5Algorithm {
    const fn distance_codes(self) -> usize {
        match self {
            Self::Generation0 => 64,
            Self::Generation1 => 80,
        }
    }
}

fn checked_usize(value: u64, format: &'static str) -> Result<usize, ArchiveError> {
    usize::try_from(value).map_err(|_| {
        ArchiveError::new(ErrorKind::Limit)
            .with_format(format)
            .with_context("RAR payload size exceeds the address space")
    })
}

fn check_output_budget(
    unpacked_size: u64,
    limits: Limits,
    format: &'static str,
) -> Result<(), ArchiveError> {
    if limits
        .entry_bytes()
        .is_some_and(|maximum| unpacked_size > maximum)
        || limits
            .decoded_total()
            .is_some_and(|maximum| unpacked_size > maximum)
    {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_format(format)
            .with_context("RAR payload exceeds the configured decoded-byte budget"));
    }
    Ok(())
}

/// Bounded RAR3 LZ77/Huffman payload decoder.
pub struct Rar3Decoder {
    inner: Adapter<rar3::Decoder>,
}

impl Rar3Decoder {
    /// Creates a decoder after preflighting all whole-payload buffers.
    pub fn new(packed_size: u64, unpacked_size: u64, limits: Limits) -> Result<Self, ArchiveError> {
        const FORMAT: &str = "rar-legacy";
        let ppmd_model_limit = Self::preflight(packed_size, unpacked_size, limits)?;
        Ok(Self {
            inner: Adapter::new(
                rar3::Decoder::with_unpack_size_and_ppmd_limit(unpacked_size, ppmd_model_limit),
                FORMAT,
                packed_size,
                unpacked_size,
            ),
        })
    }

    /// Continues a solid RAR3 member with the completed member's dictionary,
    /// Huffman lengths, and LZ distance history.
    pub fn continue_solid(
        self,
        packed_size: u64,
        unpacked_size: u64,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        const FORMAT: &str = "rar-legacy";
        let ppmd_model_limit = Self::preflight(packed_size, unpacked_size, limits)?;
        let mut decoder = self.inner.into_completed_decoder()?;
        decoder
            .continue_solid(unpacked_size, ppmd_model_limit)
            .map_err(|error| {
                let (kind, context) = if error == codec::Error::OutputLimitExceeded {
                    (
                        ErrorKind::Limit,
                        "retained RAR3 PPMd model exceeds the new codec-memory budget",
                    )
                } else {
                    (
                        ErrorKind::Protocol,
                        "RAR3 solid decoder state is not reusable",
                    )
                };
                ArchiveError::new(kind)
                    .with_format(FORMAT)
                    .with_context(context)
            })?;
        Ok(Self {
            inner: Adapter::new(decoder, FORMAT, packed_size, unpacked_size),
        })
    }

    fn preflight(
        packed_size: u64,
        unpacked_size: u64,
        limits: Limits,
    ) -> Result<Option<usize>, ArchiveError> {
        const FORMAT: &str = "rar-legacy";
        check_output_budget(unpacked_size, limits, FORMAT)?;
        let packed = checked_usize(packed_size, FORMAT)?;
        let unpacked = checked_usize(unpacked_size, FORMAT)?;
        let buffered = packed.checked_add(unpacked).ok_or_else(|| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("RAR3 buffered payload size overflowed")
        })?;
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| buffered > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("RAR3 whole-payload buffers exceed the in-flight budget"));
        }
        let workspace = RAR3_DICTIONARY_BYTES
            .checked_add(RAR3_AUXILIARY_BYTES)
            .and_then(|value| value.checked_add(packed.checked_mul(2)?))
            .and_then(|value| value.checked_add(unpacked))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format(FORMAT)
                    .with_context("RAR3 codec-memory estimate overflowed")
            })?;
        match limits.codec_memory() {
            Some(maximum) if workspace > maximum => Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("RAR3 decoder exceeds the codec-memory budget")),
            Some(maximum) => Ok(Some(maximum - workspace)),
            None => Ok(None),
        }
    }
}

impl fmt::Debug for Rar3Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rar3Decoder")
            .field("terminal", &self.inner.terminal_name())
            .field("packed_bytes", &self.inner.consumed_bytes())
            .field("decoded_bytes", &self.inner.decoded_bytes())
            .finish_non_exhaustive()
    }
}

impl Codec for Rar3Decoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        self.inner.process(input, output, end)
    }
}

#[derive(Clone, Debug, Default)]
struct Rar5BlockGuard {
    header: [u8; RAR5_MAX_BLOCK_HEADER_BYTES],
    header_len: usize,
    body_remaining: usize,
    in_flight_limit: Option<usize>,
}

impl Rar5BlockGuard {
    const fn new(in_flight_limit: Option<usize>) -> Self {
        Self {
            header: [0; RAR5_MAX_BLOCK_HEADER_BYTES],
            header_len: 0,
            body_remaining: 0,
            in_flight_limit,
        }
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("rar5")
            .with_context(context)
    }

    fn accepted_prefix(&self, input: &[u8]) -> Result<usize, ArchiveError> {
        let mut preview = self.clone();
        preview.observe_until_boundary(input)
    }

    fn observe(&mut self, mut input: &[u8]) -> Result<(), ArchiveError> {
        while !input.is_empty() {
            let consumed = self.observe_until_boundary(input)?;
            if consumed == 0 {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 block guard made no input progress",
                ));
            }
            input = &input[consumed..];
        }
        Ok(())
    }

    fn observe_until_boundary(&mut self, input: &[u8]) -> Result<usize, ArchiveError> {
        let mut consumed_total = 0usize;
        while consumed_total < input.len() {
            if self.body_remaining != 0 {
                let consumed = self
                    .body_remaining
                    .min(input.len().saturating_sub(consumed_total));
                self.body_remaining -= consumed;
                consumed_total += consumed;
                if self.body_remaining == 0 {
                    return Ok(consumed_total);
                }
                continue;
            }

            if self.header_len == 0 {
                self.header[0] = input[consumed_total];
                self.header_len = 1;
                consumed_total += 1;
            }
            let byte_count = usize::from((self.header[0] >> 3) & 7);
            if byte_count > 2 {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 compressed block uses an invalid size-field width",
                ));
            }
            let required = 3 + byte_count;
            let copied =
                (required - self.header_len).min(input.len().saturating_sub(consumed_total));
            self.header[self.header_len..self.header_len + copied]
                .copy_from_slice(&input[consumed_total..consumed_total + copied]);
            self.header_len += copied;
            consumed_total += copied;
            if self.header_len != required {
                continue;
            }

            let size_byte_1 = if byte_count >= 1 { self.header[3] } else { 0 };
            let size_byte_2 = if byte_count == 2 { self.header[4] } else { 0 };
            let size = usize::try_from(u32::from_le_bytes([
                self.header[2],
                size_byte_1,
                size_byte_2,
                0,
            ]))
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "RAR5 compressed block size exceeds the address space",
                )
            })?;
            let expected_checksum =
                0x5a ^ self.header[0] ^ self.header[2] ^ size_byte_1 ^ size_byte_2;
            if self.header[1] != expected_checksum || size == 0 {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 compressed block header is invalid",
                ));
            }
            let frame = required.checked_add(size).ok_or_else(|| {
                Self::error(
                    ErrorKind::Limit,
                    "RAR5 compressed block frame size overflowed",
                )
            })?;
            if self.in_flight_limit.is_some_and(|maximum| frame > maximum) {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "RAR5 compressed block exceeds the in-flight budget",
                ));
            }
            self.header_len = 0;
            self.body_remaining = size;
        }
        Ok(consumed_total)
    }
}

/// Bounded RAR5 LZ77/Huffman payload decoder.
pub struct Rar5Decoder {
    inner: Adapter<rar5::Decoder>,
    block_guard: Rar5BlockGuard,
}

impl Rar5Decoder {
    /// Creates a decoder after validating the exact RAR5 window and buffers.
    pub fn new(
        packed_size: u64,
        unpacked_size: u64,
        window_size: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::new_with_algorithm(
            packed_size,
            unpacked_size,
            window_size,
            Rar5Algorithm::Generation0,
            limits,
        )
    }

    /// Creates a decoder for an explicit RAR5-family compression generation.
    pub fn new_with_algorithm(
        packed_size: u64,
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::build(
            Some(packed_size),
            unpacked_size,
            window_size,
            algorithm,
            limits,
        )
    }

    /// Creates a decoder whose packed extent ends when the caller supplies [`EndOfInput::End`].
    ///
    /// This is used for split-volume streams, where each physical header only declares its own part size.
    /// The decoded size and every encoded block remain preflighted and exact.
    pub fn new_streaming(
        unpacked_size: u64,
        window_size: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::new_streaming_with_algorithm(
            unpacked_size,
            window_size,
            Rar5Algorithm::Generation0,
            limits,
        )
    }

    /// Creates an extent-delimited decoder for an explicit generation.
    pub fn new_streaming_with_algorithm(
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Self::build(None, unpacked_size, window_size, algorithm, limits)
    }

    /// Continues a solid archive member while retaining the completed member's dictionary, Huffman tables, and LZ distance history.
    ///
    /// The previous member must have reached [`CodecStatus::Done`](libarchive_oxide_protocol::CodecStatus::Done).
    /// Per-entry byte counters, exact extents, block framing, and output budgets are reset for the new member; a different dictionary size is rejected.
    pub fn continue_solid(
        self,
        packed_size: u64,
        unpacked_size: u64,
        window_size: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let algorithm = self.inner.decoder().algorithm();
        self.continue_solid_with_extent(
            Some(packed_size),
            unpacked_size,
            window_size,
            algorithm,
            limits,
        )
    }

    /// Continues a solid member after validating its compression generation.
    pub fn continue_solid_with_algorithm(
        self,
        packed_size: u64,
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        self.continue_solid_with_extent(
            Some(packed_size),
            unpacked_size,
            window_size,
            algorithm,
            limits,
        )
    }

    /// Continues a solid member whose packed extent ends when its owner supplies [`EndOfInput::End`].
    ///
    /// This combines solid dictionary reuse with physical-volume streaming:
    /// the decoded size remains exact and bounded, while the packed size is the sum of independently declared volume parts.
    pub fn continue_solid_streaming(
        self,
        unpacked_size: u64,
        window_size: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let algorithm = self.inner.decoder().algorithm();
        self.continue_solid_with_extent(None, unpacked_size, window_size, algorithm, limits)
    }

    /// Continues an extent-delimited solid member after validating generation.
    pub fn continue_solid_streaming_with_algorithm(
        self,
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        self.continue_solid_with_extent(None, unpacked_size, window_size, algorithm, limits)
    }

    fn continue_solid_with_extent(
        self,
        packed_size: Option<u64>,
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        const FORMAT: &str = "rar5";
        Self::preflight(packed_size, unpacked_size, window_size, limits)?;
        if self.inner.decoder().window_size() != window_size {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(FORMAT)
                .with_context("RAR5 solid member changes the dictionary size"));
        }
        if self.inner.decoder().algorithm() != algorithm {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(FORMAT)
                .with_context("RAR5 solid member changes the compression generation"));
        }
        let mut decoder = self.inner.into_completed_decoder()?;
        decoder.continue_solid(unpacked_size).map_err(|_| {
            ArchiveError::new(ErrorKind::Protocol)
                .with_format(FORMAT)
                .with_context("RAR5 solid decoder state is not reusable")
        })?;
        let inner = match packed_size {
            Some(packed_size) => Adapter::new(decoder, FORMAT, packed_size, unpacked_size),
            None => Adapter::new_streaming(decoder, FORMAT, unpacked_size),
        };
        Ok(Self {
            inner,
            block_guard: Rar5BlockGuard::new(limits.in_flight_bytes()),
        })
    }

    fn build(
        packed_size: Option<u64>,
        unpacked_size: u64,
        window_size: usize,
        algorithm: Rar5Algorithm,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        const FORMAT: &str = "rar5";
        Self::preflight(packed_size, unpacked_size, window_size, limits)?;
        let decoder = rar5::Decoder::with_unpack_size_window_and_algorithm(
            unpacked_size,
            window_size,
            algorithm,
        );
        let inner = match packed_size {
            Some(packed_size) => Adapter::new(decoder, FORMAT, packed_size, unpacked_size),
            None => Adapter::new_streaming(decoder, FORMAT, unpacked_size),
        };
        Ok(Self {
            inner,
            block_guard: Rar5BlockGuard::new(limits.in_flight_bytes()),
        })
    }

    fn preflight(
        packed_size: Option<u64>,
        unpacked_size: u64,
        window_size: usize,
        limits: Limits,
    ) -> Result<(), ArchiveError> {
        const FORMAT: &str = "rar5";
        check_output_budget(unpacked_size, limits, FORMAT)?;
        if window_size < RAR5_MIN_WINDOW_BYTES
            || u64::try_from(window_size).map_or(true, |size| size > RAR5_MAX_WINDOW_BYTES)
        {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(FORMAT)
                .with_context("RAR5 dictionary is outside the format range"));
        }
        let maximum_block_frame = RAR5_MAX_BLOCK_BYTES + RAR5_MAX_BLOCK_HEADER_BYTES;
        let buffered = packed_size
            .unwrap_or(maximum_block_frame as u64)
            .min(maximum_block_frame as u64)
            .min(
                limits
                    .in_flight_bytes()
                    .map_or(maximum_block_frame as u64, |maximum| maximum as u64),
            );
        let buffered = usize::try_from(buffered).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("RAR5 block buffer estimate exceeds the address space")
        })?;
        let workspace = window_size
            .checked_mul(5)
            .and_then(|value| value.checked_div(2))
            .and_then(|value| value.checked_add(buffered.checked_mul(2)?))
            .and_then(|value| value.checked_add(RAR5_AUXILIARY_BYTES))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format(FORMAT)
                    .with_context("RAR5 codec-memory estimate overflowed")
            })?;
        if limits
            .codec_memory()
            .is_some_and(|maximum| workspace > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("RAR5 dictionary and filters exceed the codec-memory budget"));
        }
        Ok(())
    }
}

impl fmt::Debug for Rar5Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rar5Decoder")
            .field("terminal", &self.inner.terminal_name())
            .field("packed_bytes", &self.inner.consumed_bytes())
            .field("decoded_bytes", &self.inner.decoded_bytes())
            .field("block_guard", &self.block_guard)
            .finish_non_exhaustive()
    }
}

impl Codec for Rar5Decoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        let accepted = self.block_guard.accepted_prefix(input)?;
        let accepted_end = if accepted < input.len() {
            EndOfInput::More
        } else {
            end
        };
        let step = self
            .inner
            .process(&input[..accepted], output, accepted_end)?;
        self.block_guard.observe(&input[..step.consumed])?;
        Ok(step)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::vec::Vec;

    use libarchive_oxide_protocol::{Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

    use super::{
        RAR3_AUXILIARY_BYTES, RAR3_DICTIONARY_BYTES, RAR5_AUXILIARY_BYTES, Rar3Decoder,
        Rar5Algorithm, Rar5Decoder,
    };
    use crate::test_support::{drive_codec, try_drive_codec};

    // Raw payload from libarchive's BSD-licensed test_read_format_rar_compress_normal.rar fixture.
    // The surrounding RAR container is intentionally absent; this tests only the codec boundary.
    const RAR3_TEST_TEXT: &[u8] = &[
        0x08, 0x00, 0xc8, 0xfe, 0x8c, 0xf7, 0xa1, 0x78, 0x77, 0xb7, 0x59, 0xa2, 0xb8, 0x31, 0x07,
        0xfc, 0x4b, 0x95, 0xff, 0xc2, 0x28, 0xa7, 0xcc, 0xf3, 0x4a, 0xdb, 0x88, 0x3d, 0xe6, 0xa0,
    ];

    // Raw payload produced by RARLAB's `rar a -ma5 -m3`; decoded bytes are 200 ASCII 'A' bytes followed by a newline.
    const RAR5_A200: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];

    fn completed_rar3() -> Rar3Decoder {
        let mut decoder = Rar3Decoder::new(30, 20, Limits::safe()).expect("bounded RAR3 decoder");
        let mut output = [0_u8; 20];
        let step = decoder
            .process(RAR3_TEST_TEXT, &mut output, EndOfInput::End)
            .expect("complete RAR3 member");
        assert_eq!(step.consumed, RAR3_TEST_TEXT.len());
        assert_eq!(step.produced, output.len());
        assert_eq!(output, *b"test text document\r\n");
        if step.status != CodecStatus::Done {
            let step = decoder
                .process(&[], &mut [], EndOfInput::End)
                .expect("finalize RAR3 member");
            assert_eq!(step.status, CodecStatus::Done);
        }
        decoder
    }

    fn completed_rar5() -> Rar5Decoder {
        let mut decoder =
            Rar5Decoder::new(16, 201, 128 * 1024, Limits::safe()).expect("bounded RAR5 decoder");
        let mut output = [0_u8; 201];
        let step = decoder
            .process(RAR5_A200, &mut output, EndOfInput::End)
            .expect("complete RAR5 member");
        assert_eq!(step.consumed, RAR5_A200.len());
        assert_eq!(step.produced, output.len());
        assert_eq!(step.status, CodecStatus::NeedOutput);
        let step = decoder
            .process(&[], &mut [], EndOfInput::End)
            .expect("finalize output-full RAR5 member");
        assert_eq!(step.status, CodecStatus::Done);
        decoder
    }

    #[test]
    fn rar3_real_payload_is_chunk_invariant() {
        for (input_chunk, output_chunk) in [(1, 1), (7, 3), (64, 64)] {
            let decoded = drive_codec(
                Rar3Decoder::new(30, 20, Limits::safe()).expect("bounded RAR3 decoder"),
                RAR3_TEST_TEXT,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, b"test text document\r\n");
        }
    }

    #[test]
    fn rar3_solid_continuation_requires_completion_and_rechecks_budgets() {
        let premature = Rar3Decoder::new(30, 20, Limits::safe())
            .expect("fresh decoder")
            .continue_solid(1, 2, Limits::safe())
            .expect_err("unfinished decoder cannot continue");
        assert_eq!(premature.kind(), ErrorKind::Protocol);

        let limited = completed_rar3()
            .continue_solid(1, 2, Limits::safe().with_entry_bytes(Some(1)))
            .expect_err("continued output is independently bounded");
        assert_eq!(limited.kind(), ErrorKind::Limit);
    }

    #[test]
    fn rar5_real_payload_is_chunk_invariant() {
        let mut expected = Vec::from([b'A'; 200]);
        expected.push(b'\n');
        for (input_chunk, output_chunk) in [(1, 1), (5, 7), (64, 64)] {
            let decoded = drive_codec(
                Rar5Decoder::new(16, 201, 128 * 1024, Limits::safe())
                    .expect("bounded RAR5 decoder"),
                RAR5_A200,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn rar5_streaming_extent_uses_caller_end_instead_of_total_packed_size() {
        let mut expected = Vec::from([b'A'; 200]);
        expected.push(b'\n');
        for (input_chunk, output_chunk) in [(1, 1), (5, 7), (64, 64)] {
            let decoded = drive_codec(
                Rar5Decoder::new_streaming(201, 128 * 1024, Limits::safe())
                    .expect("bounded streaming RAR5 decoder"),
                RAR5_A200,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn rar5_solid_continuation_resets_member_bounds_and_retains_decoder_state() {
        let continued = completed_rar5()
            .continue_solid(16, 201, 128 * 1024, Limits::safe())
            .expect("completed decoder continues");
        let plain = drive_codec(continued, RAR5_A200, 3, 17);
        let mut expected = Vec::from([b'A'; 200]);
        expected.push(b'\n');
        assert_eq!(plain, expected);

        let premature = Rar5Decoder::new(16, 201, 128 * 1024, Limits::safe())
            .expect("fresh decoder")
            .continue_solid(16, 201, 128 * 1024, Limits::safe())
            .expect_err("unfinished decoder cannot continue");
        assert_eq!(premature.kind(), ErrorKind::Protocol);

        let streamed = completed_rar5()
            .continue_solid_streaming(201, 128 * 1024, Limits::safe())
            .expect("completed decoder continues without a total packed extent");
        let plain = drive_codec(streamed, RAR5_A200, 1, 13);
        let mut expected = Vec::from([b'A'; 200]);
        expected.push(b'\n');
        assert_eq!(plain, expected);
    }

    #[test]
    fn rar5_solid_continuation_rechecks_dictionary_and_output_budgets() {
        let changed_window = completed_rar5()
            .continue_solid(16, 201, 256 * 1024, Limits::safe())
            .expect_err("solid dictionary size must remain stable");
        assert_eq!(changed_window.kind(), ErrorKind::Malformed);

        let over_budget = completed_rar5()
            .continue_solid(
                16,
                201,
                128 * 1024,
                Limits::safe().with_entry_bytes(Some(200)),
            )
            .expect_err("each solid member is preflighted independently");
        assert_eq!(over_budget.kind(), ErrorKind::Limit);

        let changed_algorithm = completed_rar5()
            .continue_solid_with_algorithm(
                16,
                201,
                128 * 1024,
                Rar5Algorithm::Generation1,
                Limits::safe(),
            )
            .expect_err("solid stream cannot change compression generation");
        assert_eq!(changed_algorithm.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rar5_consumes_at_most_one_self_described_block_per_call() {
        let input = [RAR5_A200, RAR5_A200].concat();
        let mut decoder = Rar5Decoder::new(input.len() as u64, 402, 128 * 1024, Limits::safe())
            .expect("bounded two-block stream");
        let mut output = [0u8; 1];

        let step = decoder
            .process(&input, &mut output, EndOfInput::More)
            .expect("first compressed block");

        assert_eq!(step.consumed, RAR5_A200.len());
    }

    #[test]
    fn rar3_rejects_buffering_and_workspace_over_budget_before_allocation() {
        let buffered = RAR3_TEST_TEXT.len() + 20;
        let error = Rar3Decoder::new(
            30,
            20,
            Limits::safe().with_in_flight_bytes(Some(buffered - 1)),
        )
        .expect_err("RAR3 buffers its complete input and output");
        assert_eq!(error.kind(), ErrorKind::Limit);

        let error = Rar3Decoder::new(
            30,
            20,
            Limits::safe().with_codec_memory(Some(RAR3_DICTIONARY_BYTES - 1)),
        )
        .expect_err("RAR3 fixed dictionary exceeds budget");
        assert_eq!(error.kind(), ErrorKind::Limit);

        let exact_workspace =
            RAR3_DICTIONARY_BYTES + RAR3_AUXILIARY_BYTES + 2 * RAR3_TEST_TEXT.len() + 20;
        Rar3Decoder::new(
            RAR3_TEST_TEXT.len() as u64,
            20,
            Limits::safe().with_codec_memory(Some(exact_workspace)),
        )
        .expect("RAR3 VM workspace exact boundary");
        let error = Rar3Decoder::new(
            RAR3_TEST_TEXT.len() as u64,
            20,
            Limits::safe().with_codec_memory(Some(exact_workspace - 1)),
        )
        .expect_err("one byte below RAR3 VM workspace must fail before allocation");
        assert_eq!(error.kind(), ErrorKind::Limit);
    }

    #[test]
    fn rar5_rejects_invalid_window_and_buffering_over_budget() {
        let invalid = Rar5Decoder::new(16, 201, 64 * 1024, Limits::safe())
            .expect_err("RAR5 window must meet the format minimum");
        assert_eq!(invalid.kind(), ErrorKind::Malformed);

        let old_workspace_estimate = 2 * (128 * 1024) + 2 * 16 + RAR5_AUXILIARY_BYTES;
        let filter_workspace = Rar5Decoder::new(
            16,
            201,
            128 * 1024,
            Limits::safe().with_codec_memory(Some(old_workspace_estimate)),
        )
        .expect_err("Delta filtering needs a third half-window scratch region");
        assert_eq!(filter_workspace.kind(), ErrorKind::Limit);

        Rar5Decoder::new(
            u64::from(u32::MAX) + 1,
            201,
            128 * 1024,
            Limits::safe().with_in_flight_bytes(Some(16)),
        )
        .expect("declared packed size does not imply whole-entry buffering");

        let decoded = drive_codec(
            Rar5Decoder::new(
                RAR5_A200.len() as u64,
                201,
                128 * 1024,
                Limits::safe().with_in_flight_bytes(Some(RAR5_A200.len())),
            )
            .expect("one complete block frame fits the exact in-flight budget"),
            RAR5_A200,
            1,
            7,
        );
        assert_eq!(decoded.len(), 201);

        let mut oversized_block = RAR5_A200.to_vec();
        oversized_block[1] = 0x94; // 0x5a ^ flags 0xc0 ^ declared size 14
        oversized_block[2] = 14;
        let limited = try_drive_codec(
            Rar5Decoder::new(
                oversized_block.len() as u64,
                201,
                128 * 1024,
                Limits::safe().with_in_flight_bytes(Some(16)),
            )
            .expect("total packed size fits while its block does not"),
            &oversized_block,
            1,
            17,
        )
        .expect_err("RAR5 block frame exceeds in-flight budget");
        assert_eq!(limited.kind(), ErrorKind::Limit);
    }

    #[test]
    fn rar7_accepts_fractional_dictionary_for_new_and_compatibility_algorithms() {
        let dictionary = 132 * 1024;
        Rar5Decoder::new_with_algorithm(
            1,
            1,
            dictionary,
            Rar5Algorithm::Generation1,
            Limits::safe(),
        )
        .expect("RAR7 supports exact non-power-of-two dictionaries");

        Rar5Decoder::new_with_algorithm(
            1,
            1,
            dictionary,
            Rar5Algorithm::Generation0,
            Limits::safe(),
        )
        .expect("RAR7 can pair its exact dictionary with the compatibility algorithm");
    }

    #[test]
    fn truncation_and_declared_size_mismatches_fail_closed() {
        let truncated = try_drive_codec(
            Rar5Decoder::new(15, 201, 128 * 1024, Limits::safe()).expect("bounded RAR5 decoder"),
            &RAR5_A200[..15],
            1,
            17,
        )
        .expect_err("truncated RAR5 block");
        assert!(matches!(
            truncated.kind(),
            ErrorKind::Malformed | ErrorKind::Integrity
        ));

        let size_mismatch = try_drive_codec(
            Rar3Decoder::new(30, 21, Limits::safe()).expect("bounded RAR3 decoder"),
            RAR3_TEST_TEXT,
            30,
            64,
        )
        .expect_err("declared RAR3 output size mismatch");
        assert!(matches!(
            size_mismatch.kind(),
            ErrorKind::Malformed | ErrorKind::Integrity
        ));
    }
}
