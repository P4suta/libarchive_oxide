// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `std::io::Read` decoder adapter.
//!
//! Input is buffered during `step`. `finish` constructs the decoder and drains
//! output through [`Transform`](libarchive_oxide_core::Transform).

use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{Cursor, Read};

use libarchive_oxide_core::transform::{Status, Step};
use libarchive_oxide_core::{Error, Result};

/// Buffers input and drives a concrete `Read` decoder.
///
/// The decoder is boxed to bound the size of dispatch enums.
pub(crate) enum PullBridge<D> {
    /// Still receiving compressed input.
    Buffering(Vec<u8>),
    /// Input complete; the decoder is running.
    Decoding(Box<D>),
    /// The decoder reached end of stream.
    Done,
}

impl<D: Read> PullBridge<D> {
    /// A fresh bridge in the buffering state.
    pub(crate) fn new() -> Self {
        Self::Buffering(Vec::new())
    }

    /// Feed compressed bytes. They are buffered until `drain` is first called.
    pub(crate) fn push(&mut self, input: &[u8]) -> Step {
        if let Self::Buffering(buf) = self {
            buf.extend_from_slice(input);
            Step {
                consumed: input.len(),
                produced: 0,
                status: Status::NeedInput,
            }
        } else {
            Step {
                consumed: 0,
                produced: 0,
                status: Status::MoreOutput,
            }
        }
    }

    /// Construct the decoder from the buffered input (via `make`) on first call, then pull
    /// one chunk of decoded output. Returns [`Status::Done`] once the stream ends.
    pub(crate) fn drain(
        &mut self,
        output: &mut [u8],
        make: impl FnOnce(Cursor<Vec<u8>>) -> Result<D>,
    ) -> Result<Step> {
        if let Self::Buffering(buf) = self {
            let data = core::mem::take(buf);
            *self = Self::Decoding(Box::new(make(Cursor::new(data))?));
        }
        match self {
            Self::Decoding(decoder) => {
                let n = decoder
                    .read(output)
                    .map_err(|_| Error::Malformed("decode error"))?;
                if n == 0 {
                    *self = Self::Done;
                    Ok(Step {
                        consumed: 0,
                        produced: 0,
                        status: Status::Done,
                    })
                } else {
                    Ok(Step {
                        consumed: 0,
                        produced: n,
                        status: Status::MoreOutput,
                    })
                }
            },
            // Only reachable as `Done`; `Buffering` was converted above.
            _ => Ok(Step {
                consumed: 0,
                produced: 0,
                status: Status::Done,
            }),
        }
    }
}
