//! Bridge from a pull-based (`std::io::Read`) decoder to the sans-IO `Transform`.
//!
//! Reused decoder crates (`ruzstd`, `lzma-rust2`, `lz4_flex`) expose a `Read`-based API.
//! This bridge conforms them fully to the push-style [`Transform`]: compressed input is
//! accumulated during `step`, and on `finish` a `Read` decoder is constructed over the
//! buffered bytes and drained into the caller's output. The seam is sealed inside here, so
//! from the caller's viewpoint these adapters are indistinguishable from a hand-written
//! filter (origin-opaque).
//!
//! Matching the whole-slice source model of P1/P2, the compressed input is buffered in full
//! before decoding. A truly incremental Read-to-sans-IO pump is a later refinement.

use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{Cursor, Read};

use arca_core::transform::{Status, Step};
use arca_core::{Error, Result};

/// Accumulates compressed input, then drives a `Read`-based decoder `D` to produce output.
///
/// The concrete decoder `D` can be large (e.g. an LZMA reader carries several KB of window/state),
/// so the running decoder is held behind a `Box<D>` — an owning pointer to a fully monomorphized
/// type, **not** a trait object. This keeps every adapter (and the sealed `AnyDecoder` enum that
/// wraps them) one word wide regardless of which codec `D` is.
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
            }
            // Only reachable as `Done`; `Buffering` was converted above.
            _ => Ok(Step {
                consumed: 0,
                produced: 0,
                status: Status::Done,
            }),
        }
    }
}
