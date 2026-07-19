// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sans-IO byte transform.
//!
//! Callers provide input and output buffers. Adapters may expose push, pull, or
//! `std::io` interfaces.

use crate::Result;
use alloc::vec::Vec;

/// Result of one transform step.
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
    /// Requests input without consuming or producing bytes.
    pub const STALLED: Self = Self {
        consumed: 0,
        produced: 0,
        status: Status::NeedInput,
    };
}

/// The action the caller should take after [`Transform::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// More input is required.
    NeedInput,
    /// More output capacity is required.
    MoreOutput,
    /// End of stream.
    Done,
}

/// A sans-IO byte-to-byte transformer.
///
/// # Contract
///
/// - `step` reports consumed and produced byte counts.
/// - The caller owns all provided buffers.
/// - `finish` drains buffered output after the final input.
pub trait Transform {
    /// Advance one step, consuming `input` and producing into `output`.
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step>;

    /// Signal end of input and drain the held-back output into `output`.
    ///
    /// May be called repeatedly with a larger `output` until it returns [`Status::Done`].
    fn finish(&mut self, output: &mut [u8]) -> Result<Step>;
}

/// Runs a transform over a slice and returns all output.
pub fn decode_to_vec<T: Transform + ?Sized>(t: &mut T, input: &[u8]) -> Result<Vec<u8>> {
    decode_to_vec_capped(t, input, usize::MAX)
}

/// Runs a transform with an output limit.
///
/// Returns [`Error::LimitExceeded`](crate::Error::LimitExceeded) when output
/// exceeds `max_output`.
pub fn decode_to_vec_capped<T: Transform + ?Sized>(
    t: &mut T,
    mut input: &[u8],
    max_output: usize,
) -> Result<Vec<u8>> {
    const CHUNK: usize = 16 * 1024;
    let mut out = Vec::new();
    let mut buf = [0u8; CHUNK];

    let push = |out: &mut alloc::vec::Vec<u8>, chunk: &[u8]| -> Result<()> {
        if out.len().saturating_add(chunk.len()) > max_output {
            return Err(crate::Error::LimitExceeded("decompressed size exceeds cap"));
        }
        out.extend_from_slice(chunk);
        Ok(())
    };

    loop {
        let step = t.step(input, &mut buf)?;
        push(&mut out, &buf[..step.produced])?;
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
        push(&mut out, &buf[..step.produced])?;
        if step.status == Status::Done || step.produced == 0 {
            break;
        }
    }

    Ok(out)
}
