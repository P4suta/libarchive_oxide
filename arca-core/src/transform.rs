//! Base layer: the sans-IO byte transform [`Transform`].
//!
//! This is the foundation for everything. Compression filters, and (eventually) format
//! serialization too, all sit on top of this single allocation-free, caller-owned primitive.
//!
//! # Why step instead of push/pull
//!
//! The original sketch had two methods, `push`/`pull`, but that forces the transformer to hold
//! an internal output buffer (i.e. an allocation). The more elegant primitive (allocation-free,
//! fully caller-driven) is the zlib-style "one step = consume an input slice and produce into an
//! output slice." push (a source where bytes arrive) and pull (`Read`-like consumption) are derived
//! on the std side as **adapters** built on top of this `step`. The base layer is therefore kept
//! minimal, pure, and allocation-free.

use crate::Result;
use alloc::vec::Vec;

/// The result of one step: how much input was consumed, how much output was produced, and what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// Number of bytes consumed from `input`.
    pub consumed: usize,
    /// Number of bytes produced into `output`.
    pub produced: usize,
    /// What this transformer needs next.
    pub status: Status,
}

impl Step {
    /// A state making no progress (0 consumed, 0 produced) that requests more input.
    pub const STALLED: Self = Self {
        consumed: 0,
        produced: 0,
        status: Status::NeedInput,
    };
}

/// The action the caller should take after [`Transform::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Giving it more input bytes will let it make progress.
    NeedInput,
    /// Input still remains but the output is full. Call again with a larger (or emptied) output.
    MoreOutput,
    /// The logical end of stream has been reached. Subsequent `step` calls produce 0.
    Done,
}

/// A sans-IO byte-to-byte transformer.
///
/// # Contract
///
/// - `step` consumes an arbitrary amount from `input`, produces an arbitrary amount into `output`, and returns a [`Step`].
/// - No allocation is forced. All buffers are owned by the caller.
/// - Once input is exhausted, call `finish` to drain any trailing output held internally.
/// - Implementations may be `no_std` (hand-written filters) or `std` (adapters over reused crates).
///   That difference does not leak into the caller's types (origin-opaque).
pub trait Transform {
    /// Advance one step, consuming `input` and producing into `output`.
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step>;

    /// Signal end of input and drain the held-back output into `output`.
    ///
    /// May be called repeatedly with a larger `output` until it returns [`Status::Done`].
    fn finish(&mut self, output: &mut [u8]) -> Result<Step>;
}

/// A convenience function that runs all in-memory input through a [`Transform`] and collects the output into a [`Vec`].
///
/// Usable even in environments without std (`alloc` only). The typical path for the std layer is to pass
/// a slice mmapped from a file. A truly incremental driver is provided on the std adapter side.
pub fn decode_to_vec(t: &mut dyn Transform, mut input: &[u8]) -> Result<Vec<u8>> {
    const CHUNK: usize = 16 * 1024;
    let mut out = Vec::new();
    let mut buf = [0u8; CHUNK];

    loop {
        let step = t.step(input, &mut buf)?;
        out.extend_from_slice(&buf[..step.produced]);
        input = &input[step.consumed..];
        if step.status == Status::Done {
            break;
        }
        // Once step stops making progress, drain the tail via finish.
        if step.consumed == 0 && step.produced == 0 {
            break;
        }
    }

    loop {
        let step = t.finish(&mut buf)?;
        out.extend_from_slice(&buf[..step.produced]);
        if step.status == Status::Done || step.produced == 0 {
            break;
        }
    }

    Ok(out)
}
