// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Buffered encoder adapter.
//!
//! Buffers plaintext, compresses once, and drains output. Requires `alloc`.

use alloc::vec::Vec;

use libarchive_oxide_core::transform::{Status, Step};
use libarchive_oxide_core::Result;

/// Accumulates plaintext during `push`, then on `drain` compresses it once and streams it out.
pub(crate) enum PushBridge {
    /// Still receiving plaintext.
    Buffering(Vec<u8>),
    /// Plaintext compressed; streaming the result from `pos`.
    Draining { data: Vec<u8>, pos: usize },
    /// The compressed output has been fully emitted.
    Done,
}

impl PushBridge {
    /// A fresh bridge in the buffering state.
    pub(crate) fn new() -> Self {
        Self::Buffering(Vec::new())
    }

    /// Feed plaintext. It is buffered until `drain` is first called.
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

    /// Compress the buffered plaintext (via `compress`) on first call, then emit one chunk.
    pub(crate) fn drain(
        &mut self,
        output: &mut [u8],
        compress: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Step> {
        if let Self::Buffering(buf) = self {
            let plain = core::mem::take(buf);
            *self = Self::Draining {
                data: compress(&plain)?,
                pos: 0,
            };
        }
        match self {
            Self::Draining { data, pos } => {
                let remaining = data.len() - *pos;
                if remaining == 0 || output.is_empty() {
                    if remaining == 0 {
                        *self = Self::Done;
                        return Ok(Step {
                            consumed: 0,
                            produced: 0,
                            status: Status::Done,
                        });
                    }
                    return Ok(Step {
                        consumed: 0,
                        produced: 0,
                        status: Status::MoreOutput,
                    });
                }
                let n = remaining.min(output.len());
                output[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Ok(Step {
                    consumed: 0,
                    produced: n,
                    status: Status::MoreOutput,
                })
            },
            _ => Ok(Step {
                consumed: 0,
                produced: 0,
                status: Status::Done,
            }),
        }
    }
}
