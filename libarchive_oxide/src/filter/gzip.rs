//! gzip decode filter (bridges `miniz_oxide`'s streaming inflate to the sans-IO `Transform`).
//!
//! gzip framing (RFC 1952: header + raw deflate body + CRC32/ISIZE trailer) is
//! interpreted here, and the body is delegated to `miniz_oxide::inflate::stream` (which manages the 32KB window internally).
//! This makes it behave, from the caller's viewpoint, as a [`Transform`] with the same shape as our hand-written filters.
//!
//! # Header that spans multiple feeds
//!
//! The gzip header is variable-length (optional FEXTRA / FNAME / FCOMMENT / FHCRC) and may be split
//! across several `step` calls when the caller feeds bytes incrementally (the sans-IO source
//! pipeline drives exactly this). [`GzipDecoder`] therefore accumulates the header prefix internally
//! until it is complete: each `step` in the header phase consumes only the header bytes present in
//! that chunk and reports [`Status::NeedInput`] while it is still short. The whole-slice caller
//! (the std layer) hits the fast path — the header is complete on the first call and nothing is
//! buffered. This is the genuine streaming path that lets a hand-written filter compose end-to-end
//! with the incremental format source.

use alloc::boxed::Box;
use alloc::vec::Vec;

use libarchive_oxide_core::filter::{Decoder, Encoder, Filter, FilterId};
use libarchive_oxide_core::transform::{Status, Step, Transform};
use libarchive_oxide_core::{Error, Result};

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use super::push::PushBridge;

/// Length of the gzip trailer (CRC32 + ISIZE).
const TRAILER_LEN: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    Body,
    Trailer,
    Done,
}

/// gzip decompressor. Plugs into the format layer with the same shape as a `Filter`.
///
/// `InflateState` is large (~10 KB of Huffman/window state), so it is boxed here at its source:
/// `GzipDecoder` stays one word wide, which keeps the sealed `AnyDecoder` enum small and balanced
/// with the reused adapters. The box is a plain owning pointer, not a trait object.
pub struct GzipDecoder {
    phase: Phase,
    inflate: Box<InflateState>,
    trailer_left: usize,
    /// Accumulated header prefix when the RFC 1952 header spans multiple `step` chunks. Empty on the
    /// fast path (a caller that hands over the whole header at once) and freed once the header is
    /// parsed; it only ever grows while the header itself is still incomplete.
    header_buf: Vec<u8>,
}

impl core::fmt::Debug for GzipDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GzipDecoder").finish_non_exhaustive()
    }
}

impl Default for GzipDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipDecoder {
    /// Creates a new gzip decompressor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: Phase::Header,
            inflate: Box::new(InflateState::new(DataFormat::Raw)),
            trailer_left: TRAILER_LEN,
            header_buf: Vec::new(),
        }
    }
}

impl Transform for GzipDecoder {
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step> {
        match self.phase {
            Phase::Header => {
                // `prev` is how many header bytes were already accumulated from earlier chunks. The
                // fast path (`prev == 0`, the whole-slice caller) parses `input` directly and never
                // touches the buffer; a continuation appends this chunk and re-parses the prefix.
                let prev = self.header_buf.len();
                let complete = if prev == 0 {
                    gzip_header_len(input)?
                } else {
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
                        status: Status::MoreOutput,
                    })
                } else {
                    // Header still incomplete: on the fast path this chunk had not yet been buffered,
                    // so buffer it now. Consuming the whole chunk keeps the driver's input cursor and
                    // our accumulation in lockstep.
                    if prev == 0 {
                        self.header_buf.extend_from_slice(input);
                    }
                    Ok(Step {
                        consumed: input.len(),
                        produced: 0,
                        status: Status::NeedInput,
                    })
                }
            }
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
                        Status::MoreOutput
                    }
                    Ok(_) => {
                        if res.bytes_written == output.len() {
                            Status::MoreOutput
                        } else {
                            Status::NeedInput
                        }
                    }
                    Err(_) => return Err(Error::Malformed("gzip: inflate error")),
                };
                Ok(Step {
                    consumed: res.bytes_consumed,
                    produced: res.bytes_written,
                    status,
                })
            }
            Phase::Trailer => {
                let take = input.len().min(self.trailer_left);
                self.trailer_left -= take;
                let status = if self.trailer_left == 0 {
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
            }
            Phase::Done => Ok(Step {
                consumed: 0,
                produced: 0,
                status: Status::Done,
            }),
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
        if self.phase == Phase::Body {
            let res = inflate(&mut self.inflate, &[], output, MZFlush::Finish);
            match res.status {
                Ok(MZStatus::StreamEnd) => {
                    self.phase = Phase::Trailer;
                    return Ok(Step {
                        consumed: 0,
                        produced: res.bytes_written,
                        status: Status::MoreOutput,
                    });
                }
                Ok(_) => {
                    let status = if res.bytes_written > 0 {
                        Status::MoreOutput
                    } else {
                        Status::Done
                    };
                    return Ok(Step {
                        consumed: 0,
                        produced: res.bytes_written,
                        status,
                    });
                }
                Err(_) => return Err(Error::Malformed("gzip: inflate error")),
            }
        }
        Ok(Step {
            consumed: 0,
            produced: 0,
            status: Status::Done,
        })
    }
}

impl Filter for GzipDecoder {
    const ID: FilterId = FilterId::Gzip;
}

impl Decoder for GzipDecoder {}

/// gzip compressor — the dual of [`GzipDecoder`]. Buffers plaintext, then emits an RFC 1952 frame
/// (header + raw DEFLATE via `miniz_oxide` + CRC32/ISIZE trailer). Stays `no_std`.
pub struct GzipEncoder(PushBridge);

impl core::fmt::Debug for GzipEncoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GzipEncoder").finish_non_exhaustive()
    }
}

impl Default for GzipEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipEncoder {
    /// Creates a new gzip compressor.
    #[must_use]
    pub fn new() -> Self {
        Self(PushBridge::new())
    }
}

impl Transform for GzipEncoder {
    fn step(&mut self, input: &[u8], _output: &mut [u8]) -> Result<Step> {
        Ok(self.0.push(input))
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Step> {
        self.0.drain(output, |plain| Ok(gzip_frame(plain)))
    }
}

impl Filter for GzipEncoder {
    const ID: FilterId = FilterId::Gzip;
}

impl Encoder for GzipEncoder {}

/// Wraps `plain` into a complete gzip frame.
fn gzip_frame(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Header: magic, CM=deflate(8), no flags, mtime=0, XFL=0, OS=unknown(0xff).
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff]);
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(plain, 6));
    out.extend_from_slice(&crc32(plain).to_le_bytes());
    // ISIZE is the input size modulo 2^32 (per spec).
    let isize_field = u32::try_from(plain.len() & 0xFFFF_FFFF).unwrap_or(0);
    out.extend_from_slice(&isize_field.to_le_bytes());
    out
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
        return Err(Error::Malformed("gzip: bad magic"));
    }
    if b[2] != 8 {
        return Err(Error::Unsupported("gzip: non-deflate method"));
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

/// Skips over a NUL-terminated string starting at `start` and returns the position just past the terminator. Returns `None` if incomplete.
fn nul_terminated(b: &[u8], start: usize) -> Option<usize> {
    let rest = b.get(start..)?;
    rest.iter().position(|&x| x == 0).map(|i| start + i + 1)
}
