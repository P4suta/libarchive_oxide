//! gzip decode filter (bridges `miniz_oxide`'s streaming inflate to the sans-IO `Transform`).
//!
//! gzip framing (RFC 1952: header + raw deflate body + CRC32/ISIZE trailer) is
//! interpreted here, and the body is delegated to `miniz_oxide::inflate::stream` (which manages the 32KB window internally).
//! This makes it behave, from the caller's viewpoint, as a [`Transform`] with the same shape as our hand-written filters.
//!
//! P2 assumption: the header fits within the input of the first `step` call (the arca std layer
//! always passes the whole slice, so this always holds). Buffering headers that span across incremental feeds is a later refinement.

use arca_core::filter::{Decoder, Filter, FilterId};
use arca_core::transform::{Status, Step, Transform};
use arca_core::{Error, Result};

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

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
pub struct GzipDecoder {
    phase: Phase,
    inflate: InflateState,
    trailer_left: usize,
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
            inflate: InflateState::new(DataFormat::Raw),
            trailer_left: TRAILER_LEN,
        }
    }
}

impl Transform for GzipDecoder {
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step> {
        match self.phase {
            Phase::Header => match gzip_header_len(input)? {
                None => Ok(Step {
                    consumed: 0,
                    produced: 0,
                    status: Status::NeedInput,
                }),
                Some(hlen) => {
                    self.phase = Phase::Body;
                    Ok(Step {
                        consumed: hlen,
                        produced: 0,
                        status: Status::MoreOutput,
                    })
                }
            },
            Phase::Body => {
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
