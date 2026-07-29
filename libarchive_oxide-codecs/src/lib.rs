// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable, bounded, caller-driven archive codecs.
//!
//! This crate contains only `no_std + alloc` codec state machines. Filesystem,
//! threads, blocking I/O, async runtimes, and native libraries belong in the
//! `libarchive_oxide` adapter crate.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "aes7z")]
pub mod aes7z;
#[cfg(feature = "bcj")]
pub mod bcj;
#[cfg(feature = "delta")]
pub mod delta;
#[cfg(feature = "deflate")]
pub mod gzip;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "lzw")]
pub mod lzw;
#[cfg(feature = "lzx")]
pub mod lzx;
#[cfg(feature = "zstd")]
pub mod zstd;

#[cfg(all(
    test,
    any(
        feature = "aes7z",
        feature = "bcj",
        feature = "deflate",
        feature = "delta",
        feature = "lzw"
    )
))]
#[allow(clippy::expect_used)]
mod test_support {
    use alloc::{vec, vec::Vec};

    use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, EndOfInput, ErrorKind};

    /// Drives a codec directly with bounded input and output slices.
    ///
    /// This deliberately has no `Read`/`Write` adapter: unit tests exercise the
    /// same caller-driven protocol that remains available in `no_std` builds.
    pub(crate) fn drive_codec<C: Codec>(
        codec: C,
        input: &[u8],
        input_chunk: usize,
        output_chunk: usize,
    ) -> Vec<u8> {
        try_drive_codec(codec, input, input_chunk, output_chunk)
            .expect("codec must accept the fixture")
    }

    /// Fallible counterpart to [`drive_codec`] for malformed-input tests.
    pub(crate) fn try_drive_codec<C: Codec>(
        mut codec: C,
        input: &[u8],
        input_chunk: usize,
        output_chunk: usize,
    ) -> Result<Vec<u8>, ArchiveError> {
        assert!(input_chunk > 0);
        assert!(output_chunk > 0);

        let mut input_pos = 0;
        let mut decoded = Vec::new();
        let mut output = vec![0; output_chunk];

        loop {
            let supplied = (input.len() - input_pos).min(input_chunk);
            let current = &input[input_pos..input_pos + supplied];
            let end = if input_pos + supplied == input.len() {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = codec
                .process(current, &mut output, end)
                .and_then(|step| step.validate(current.len(), output.len()))?;

            input_pos += step.consumed;
            decoded.extend_from_slice(&output[..step.produced]);

            match step.status {
                CodecStatus::Done => {
                    if input_pos != input.len() {
                        return Err(ArchiveError::new(ErrorKind::Protocol)
                            .with_context("codec left input unconsumed"));
                    }
                    return Ok(decoded);
                },
                CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                    if step.consumed == 0 && step.produced == 0 {
                        return Err(ArchiveError::new(ErrorKind::Protocol)
                            .with_context("codec stalled before completion"));
                    }
                },
                _ => {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_context("codec returned an unknown status"));
                },
            }
        }
    }
}
