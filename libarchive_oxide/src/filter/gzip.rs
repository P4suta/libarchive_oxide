// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gzip encoder and decoder.
//!
//! Implements RFC 1952 framing over `miniz_oxide` raw DEFLATE. The decoder
//! buffers incomplete variable-length headers across `step` calls.

use alloc::boxed::Box;
use alloc::vec::Vec;

use libarchive_oxide_core::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::deflate::stream::deflate as deflate_stream;
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

/// Length of the gzip trailer (CRC32 + ISIZE).
const TRAILER_LEN: usize = 8;

type Result<T> = core::result::Result<T, ArchiveError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    NeedInput,
    NeedOutput,
    Done,
}

#[derive(Debug, Clone, Copy)]
struct Step {
    consumed: usize,
    produced: usize,
    status: Status,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    Body,
    Trailer,
    Done,
}

/// gzip decompressor.
///
/// `InflateState` is boxed to bound the size of dispatch enums.
pub struct GzipDecoder {
    phase: Phase,
    inflate: Box<InflateState>,
    trailer: [u8; TRAILER_LEN],
    trailer_len: usize,
    crc: Crc32,
    output_size: u32,
    decoded_total: u64,
    limits: Limits,
    /// Incomplete RFC 1952 header bytes.
    header_buf: Vec<u8>,
}

impl core::fmt::Debug for GzipDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GzipDecoder").finish_non_exhaustive()
    }
}

impl GzipDecoder {
    /// Creates a new gzip decompressor with mandatory resource limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            phase: Phase::Header,
            inflate: Box::new(InflateState::new(DataFormat::Raw)),
            trailer: [0; TRAILER_LEN],
            trailer_len: 0,
            crc: Crc32::new(),
            output_size: 0,
            decoded_total: 0,
            limits,
            header_buf: Vec::new(),
        }
    }

    fn malformed(message: &'static str) -> ArchiveError {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("gzip")
            .with_context(message)
    }

    fn verify_trailer(&self) -> Result<()> {
        let expected_crc = u32::from_le_bytes([
            self.trailer[0],
            self.trailer[1],
            self.trailer[2],
            self.trailer[3],
        ]);
        let expected_size = u32::from_le_bytes([
            self.trailer[4],
            self.trailer[5],
            self.trailer[6],
            self.trailer[7],
        ]);
        if self.crc.finalize() != expected_crc {
            return Err(Self::malformed("CRC32 mismatch"));
        }
        if self.output_size != expected_size {
            return Err(Self::malformed("ISIZE mismatch"));
        }
        Ok(())
    }

    fn account_output(&mut self, output: &[u8]) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }
        let next = self
            .decoded_total
            .checked_add(output.len() as u64)
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format("gzip")
                    .with_context("decoded byte count overflow")
            })?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| next > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("gzip")
                .with_context("decoded stream exceeds configured limit"));
        }
        self.crc.update(output);
        self.output_size = self
            .output_size
            .wrapping_add(u32::try_from(output.len()).unwrap_or(u32::MAX));
        self.decoded_total = next;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn step_legacy(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step> {
        match self.phase {
            Phase::Header => {
                // `prev` is how many header bytes were already accumulated from earlier chunks. The
                // fast path (`prev == 0`, the whole-slice caller) parses `input` directly and never
                // touches the buffer; a continuation appends this chunk and re-parses the prefix.
                let prev = self.header_buf.len();
                let complete = if prev == 0 {
                    gzip_header_len(input)?
                } else {
                    let next = prev.checked_add(input.len()).ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Limit)
                            .with_format("gzip")
                            .with_context("gzip header length overflow")
                    })?;
                    if self
                        .limits
                        .metadata_bytes()
                        .is_some_and(|maximum| next > maximum)
                    {
                        return Err(ArchiveError::new(ErrorKind::Limit)
                            .with_format("gzip")
                            .with_context("gzip header exceeds metadata limit"));
                    }
                    self.header_buf.extend_from_slice(input);
                    gzip_header_len(&self.header_buf)?
                };
                if let Some(hlen) = complete {
                    // `hlen` indexes the accumulated header; the bytes it covers from *this* chunk are
                    // `hlen - prev`. Body bytes appended past the header stay in the caller's input
                    // (we do not consume them), so freeing the accumulator loses nothing.
                    self.header_buf = Vec::new();
                    self.phase = Phase::Body;
                    Ok(Step {
                        consumed: hlen - prev,
                        produced: 0,
                        status: Status::NeedOutput,
                    })
                } else {
                    // Header still incomplete: on the fast path this chunk had not yet been buffered,
                    // so buffer it now. Consuming the whole chunk keeps the driver's input cursor and
                    // our accumulation in lockstep.
                    if prev == 0 {
                        if self
                            .limits
                            .metadata_bytes()
                            .is_some_and(|maximum| input.len() > maximum)
                        {
                            return Err(ArchiveError::new(ErrorKind::Limit)
                                .with_format("gzip")
                                .with_context("gzip header exceeds metadata limit"));
                        }
                        self.header_buf.extend_from_slice(input);
                    }
                    Ok(Step {
                        consumed: input.len(),
                        produced: 0,
                        status: Status::NeedInput,
                    })
                }
            },
            Phase::Body => {
                // `miniz_oxide`'s streaming `inflate` errors on a zero-length input under
                // `MZFlush::None`. With incremental feeding the body phase can be entered before any
                // body byte has arrived (the header was consumed on the previous chunk), so ask for
                // more input rather than calling `inflate` with nothing. The whole-slice driver never
                // hits this (its body input is non-empty until consumed); trailing flush is `finish`.
                if input.is_empty() {
                    return Ok(Step {
                        consumed: 0,
                        produced: 0,
                        status: Status::NeedInput,
                    });
                }
                let res = inflate(&mut self.inflate, input, output, MZFlush::None);
                let status = match res.status {
                    Ok(MZStatus::StreamEnd) => {
                        self.phase = Phase::Trailer;
                        Status::NeedOutput
                    },
                    Ok(_) => {
                        if res.bytes_written == output.len() {
                            Status::NeedOutput
                        } else {
                            Status::NeedInput
                        }
                    },
                    Err(_) => return Err(Self::malformed("inflate error")),
                };
                if res.bytes_written > 0 {
                    self.account_output(&output[..res.bytes_written])?;
                }
                Ok(Step {
                    consumed: res.bytes_consumed,
                    produced: res.bytes_written,
                    status,
                })
            },
            Phase::Trailer => {
                let take = input.len().min(TRAILER_LEN - self.trailer_len);
                self.trailer[self.trailer_len..self.trailer_len + take]
                    .copy_from_slice(&input[..take]);
                self.trailer_len += take;
                let status = if self.trailer_len == TRAILER_LEN {
                    self.verify_trailer()?;
                    self.phase = Phase::Done;
                    Status::Done
                } else {
                    Status::NeedInput
                };
                Ok(Step {
                    consumed: take,
                    produced: 0,
                    status,
                })
            },
            Phase::Done => Ok(Step {
                consumed: 0,
                produced: 0,
                status: Status::Done,
            }),
        }
    }

    fn finish_legacy(&mut self, output: &mut [u8]) -> Result<Step> {
        if self.phase == Phase::Body {
            let res = inflate(&mut self.inflate, &[], output, MZFlush::Finish);
            match res.status {
                Ok(MZStatus::StreamEnd) => {
                    self.phase = Phase::Trailer;
                    if res.bytes_written > 0 {
                        self.account_output(&output[..res.bytes_written])?;
                    }
                    return Ok(Step {
                        consumed: 0,
                        produced: res.bytes_written,
                        status: Status::NeedOutput,
                    });
                },
                Ok(_) => {
                    if res.bytes_written > 0 {
                        self.account_output(&output[..res.bytes_written])?;
                    }
                    let status = if res.bytes_written > 0 {
                        Status::NeedOutput
                    } else {
                        return Err(Self::malformed("truncated deflate stream"));
                    };
                    return Ok(Step {
                        consumed: 0,
                        produced: res.bytes_written,
                        status,
                    });
                },
                Err(_) => return Err(Self::malformed("inflate error")),
            }
        }
        if self.phase == Phase::Header {
            return Err(Self::malformed("truncated header"));
        }
        if self.phase == Phase::Trailer {
            return Err(Self::malformed("truncated trailer"));
        }
        Ok(Step {
            consumed: 0,
            produced: 0,
            status: Status::Done,
        })
    }
}

impl Codec for GzipDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<CodecStep, ArchiveError> {
        let step = self.step_legacy(input, output)?;
        if step.status == Status::Done {
            return CodecStep {
                consumed: step.consumed,
                produced: step.produced,
                status: CodecStatus::Done,
            }
            .validate(input.len(), output.len());
        }

        if matches!(end, EndOfInput::End) && step.consumed == input.len() && step.produced == 0 {
            let final_step = self.finish_legacy(output)?;
            let status = match final_step.status {
                Status::Done => CodecStatus::Done,
                Status::NeedOutput => CodecStatus::NeedOutput,
                Status::NeedInput => {
                    return Err(Self::malformed("codec requested input after end of stream"));
                },
            };
            return CodecStep {
                consumed: step.consumed,
                produced: final_step.produced,
                status,
            }
            .validate(input.len(), output.len());
        }

        let status = match step.status {
            Status::NeedInput => CodecStatus::NeedInput,
            Status::NeedOutput => CodecStatus::NeedOutput,
            Status::Done => CodecStatus::Done,
        };
        CodecStep {
            consumed: step.consumed,
            produced: step.produced,
            status,
        }
        .validate(input.len(), output.len())
    }
}

/// Raw DEFLATE (RFC 1951) inflate with no framing.
///
/// The gzip decoder above wraps this same `miniz_oxide` raw-inflate core in RFC 1952
/// header/trailer handling; the 7z Deflate coder, by contrast, stores bare deflate
/// blocks with no header, trailer, or checksum, so it drives the raw core directly.
/// The window is a fixed 32 KiB, so the decoder's working set is inherently bounded;
/// a `decoded_total` guard adds decompression-bomb defense on top.
#[cfg(feature = "sevenz")]
pub(crate) struct RawInflateDecoder {
    inflate: Box<InflateState>,
    limits: Limits,
    decoded_total: u64,
    done: bool,
}

#[cfg(feature = "sevenz")]
impl core::fmt::Debug for RawInflateDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawInflateDecoder")
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "sevenz")]
impl RawInflateDecoder {
    /// Creates a raw-DEFLATE decompressor with mandatory resource limits.
    #[must_use]
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            inflate: Box::new(InflateState::new(DataFormat::Raw)),
            limits,
            decoded_total: 0,
            done: false,
        }
    }

    fn account_output(&mut self, produced: usize) -> Result<()> {
        if produced == 0 {
            return Ok(());
        }
        let next = self
            .decoded_total
            .checked_add(produced as u64)
            .ok_or_else(|| gzip_error(ErrorKind::Limit, "decoded byte count overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| next > maximum)
        {
            return Err(gzip_error(
                ErrorKind::Limit,
                "decoded stream exceeds configured limit",
            ));
        }
        self.decoded_total = next;
        Ok(())
    }
}

#[cfg(feature = "sevenz")]
impl Codec for RawInflateDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<CodecStep, ArchiveError> {
        if self.done {
            if input.is_empty() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            return Err(gzip_error(
                ErrorKind::Malformed,
                "data follows the completed deflate stream",
            ));
        }
        // `miniz_oxide`'s streaming `inflate` errors on empty input under `MZFlush::None`, so an
        // empty chunk is handled explicitly: flush the tail at end-of-input, otherwise wait.
        if input.is_empty() {
            if !matches!(end, EndOfInput::End) {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            }
            let res = inflate(&mut self.inflate, &[], output, MZFlush::Finish);
            let produced = res.bytes_written;
            self.account_output(produced)?;
            return match res.status {
                Ok(MZStatus::StreamEnd) => {
                    self.done = true;
                    CodecStep {
                        consumed: 0,
                        produced,
                        status: CodecStatus::Done,
                    }
                    .validate(input.len(), output.len())
                },
                Ok(_) if produced > 0 => CodecStep {
                    consumed: 0,
                    produced,
                    status: CodecStatus::NeedOutput,
                }
                .validate(input.len(), output.len()),
                _ => Err(gzip_error(ErrorKind::Malformed, "truncated deflate stream")),
            };
        }

        let res = inflate(&mut self.inflate, input, output, MZFlush::None);
        let consumed = res.bytes_consumed;
        let produced = res.bytes_written;
        self.account_output(produced)?;
        match res.status {
            Ok(MZStatus::StreamEnd) => {
                self.done = true;
                return CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                }
                .validate(input.len(), output.len());
            },
            Ok(_) | Err(MZError::Buf) => {},
            Err(_) => return Err(gzip_error(ErrorKind::Malformed, "inflate error")),
        }
        // Report progress in a shape the driver can always advance on: output-full asks for more
        // output; input-drained asks for more input; a genuine no-progress stall is malformed.
        let status = if produced == output.len() {
            CodecStatus::NeedOutput
        } else if consumed == input.len() {
            CodecStatus::NeedInput
        } else if consumed == 0 && produced == 0 {
            return Err(gzip_error(ErrorKind::Malformed, "deflate stream stalled"));
        } else {
            CodecStatus::NeedOutput
        };
        CodecStep {
            consumed,
            produced,
            status,
        }
        .validate(input.len(), output.len())
    }
}

const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodePhase {
    Header,
    Body,
    Trailer,
    Done,
}

/// Incremental gzip compressor.
///
/// Plaintext is consumed directly by miniz's deflate state; only the fixed
/// header/trailer and compressor workspace are retained.
pub struct GzipEncoder {
    phase: EncodePhase,
    compressor: Box<CompressorOxide>,
    header_position: usize,
    trailer: [u8; TRAILER_LEN],
    trailer_position: usize,
    crc: Crc32,
    input_size: u32,
    encoded_input: u64,
    limits: Limits,
}

impl core::fmt::Debug for GzipEncoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GzipEncoder")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl GzipEncoder {
    /// Creates a new gzip compressor with mandatory resource limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        let flags = create_comp_flags_from_zip_params(6, 0, 0);
        Self {
            phase: EncodePhase::Header,
            compressor: Box::new(CompressorOxide::new(flags)),
            header_position: 0,
            trailer: [0; TRAILER_LEN],
            trailer_position: 0,
            crc: Crc32::new(),
            input_size: 0,
            encoded_input: 0,
            limits,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_codec(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<CodecStep, ArchiveError> {
        if matches!(self.phase, EncodePhase::Done) {
            if !input.is_empty() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("gzip")
                    .with_context("input supplied after gzip completion"));
            }
            return Ok(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            });
        }

        let mut consumed_total = 0;
        let mut produced = 0;
        if matches!(self.phase, EncodePhase::Header) {
            let count = (GZIP_HEADER.len() - self.header_position).min(output.len());
            output[..count]
                .copy_from_slice(&GZIP_HEADER[self.header_position..self.header_position + count]);
            self.header_position += count;
            produced += count;
            if self.header_position != GZIP_HEADER.len() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced,
                    status: CodecStatus::NeedOutput,
                });
            }
            self.phase = EncodePhase::Body;
            if produced == output.len() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced,
                    status: CodecStatus::NeedOutput,
                });
            }
        }

        if matches!(self.phase, EncodePhase::Body) {
            let flush = if matches!(end, EndOfInput::End) {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            let result =
                deflate_stream(&mut self.compressor, input, &mut output[produced..], flush);
            let consumed = result.bytes_consumed;
            consumed_total = consumed;
            let next = self
                .encoded_input
                .checked_add(consumed as u64)
                .ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("gzip")
                        .with_context("encoded input byte count overflow")
                })?;
            if self
                .limits
                .decoded_total()
                .is_some_and(|maximum| next > maximum)
            {
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("gzip")
                    .with_context("encoded input exceeds configured limit"));
            }
            self.crc.update(&input[..consumed]);
            self.input_size = self
                .input_size
                .wrapping_add(u32::try_from(consumed).unwrap_or(u32::MAX));
            self.encoded_input = next;
            produced += result.bytes_written;
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    self.trailer[..4].copy_from_slice(&self.crc.finalize().to_le_bytes());
                    self.trailer[4..].copy_from_slice(&self.input_size.to_le_bytes());
                    self.phase = EncodePhase::Trailer;
                    if produced == output.len() {
                        return Ok(CodecStep {
                            consumed,
                            produced,
                            status: CodecStatus::NeedOutput,
                        });
                    }
                },
                Ok(_) => {
                    let status = if produced == output.len() || matches!(end, EndOfInput::End) {
                        CodecStatus::NeedOutput
                    } else {
                        CodecStatus::NeedInput
                    };
                    return CodecStep {
                        consumed,
                        produced,
                        status,
                    }
                    .validate(input.len(), output.len());
                },
                Err(MZError::Buf) if input.is_empty() && matches!(end, EndOfInput::More) => {
                    return Ok(CodecStep {
                        consumed: 0,
                        produced,
                        status: CodecStatus::NeedInput,
                    });
                },
                Err(_) => {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format("gzip")
                        .with_context("deflate encoder failed"));
                },
            }
        }

        if matches!(self.phase, EncodePhase::Trailer) {
            if consumed_total != input.len() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_format("gzip")
                    .with_context("deflate finished with unconsumed plaintext"));
            }
            let count = (TRAILER_LEN - self.trailer_position).min(output.len() - produced);
            output[produced..produced + count].copy_from_slice(
                &self.trailer[self.trailer_position..self.trailer_position + count],
            );
            self.trailer_position += count;
            produced += count;
            if self.trailer_position == TRAILER_LEN {
                self.phase = EncodePhase::Done;
                return Ok(CodecStep {
                    consumed: consumed_total,
                    produced,
                    status: CodecStatus::Done,
                });
            }
            return Ok(CodecStep {
                consumed: consumed_total,
                produced,
                status: CodecStatus::NeedOutput,
            });
        }

        Ok(CodecStep {
            consumed: consumed_total,
            produced,
            status: CodecStatus::Done,
        })
    }
}

impl Codec for GzipEncoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> core::result::Result<CodecStep, ArchiveError> {
        self.process_codec(input, output, end)?
            .validate(input.len(), output.len())
    }
}

/// Computes the IEEE CRC-32 of `data` (bitwise; no table, `no_std`).
///
/// Shared primitive: gzip framing, the zip writer, and 7z all use the same polynomial
/// (`0xEDB88320`). One-shot convenience over [`Crc32`]; identical result to feeding `data` in
/// a single [`Crc32::update`].
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finalize()
}

/// Incremental IEEE CRC-32 (bitwise; no table, `no_std`), polynomial `0xEDB88320`.
///
/// The streaming dual of [`crc32`]: the zip writer's `write_chunk` folds each plaintext chunk in
/// as it arrives, without buffering the whole entry just to checksum it. Feeding all bytes through
/// one or many `update` calls yields the same value as the one-shot [`crc32`].
#[derive(Clone, Copy, Debug)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Starts a fresh CRC-32 accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Folds `data` into the running checksum.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
            }
        }
        self.state = crc;
    }

    /// Consumes the accumulator and returns the final CRC-32 value.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }
}

/// Returns the full length of the gzip header (RFC 1952). Returns `None` if the whole header is not yet available.
fn gzip_header_len(b: &[u8]) -> Result<Option<usize>> {
    if b.len() < 10 {
        return Ok(None);
    }
    if b[0] != 0x1f || b[1] != 0x8b {
        return Err(gzip_error(ErrorKind::Malformed, "bad magic"));
    }
    if b[2] != 8 {
        return Err(gzip_error(
            ErrorKind::Unsupported,
            "non-deflate compression method",
        ));
    }
    let flg = b[3];
    let mut pos = 10;

    // FEXTRA
    if flg & 0x04 != 0 {
        if b.len() < pos + 2 {
            return Ok(None);
        }
        let xlen = u16::from_le_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    // FNAME
    if flg & 0x08 != 0 {
        match nul_terminated(b, pos) {
            Some(next) => pos = next,
            None => return Ok(None),
        }
    }
    // FCOMMENT
    if flg & 0x10 != 0 {
        match nul_terminated(b, pos) {
            Some(next) => pos = next,
            None => return Ok(None),
        }
    }
    // FHCRC
    if flg & 0x02 != 0 {
        pos += 2;
    }

    if b.len() < pos {
        return Ok(None);
    }
    Ok(Some(pos))
}

fn gzip_error(kind: ErrorKind, message: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("gzip")
        .with_context(message)
}

/// Skips over a NUL-terminated string starting at `start` and returns the position just past the terminator. Returns `None` if incomplete.
fn nul_terminated(b: &[u8], start: usize) -> Option<usize> {
    let rest = b.get(start..)?;
    rest.iter().position(|&x| x == 0).map(|i| start + i + 1)
}
