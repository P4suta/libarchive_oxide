// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::{vec, vec::Vec};

use libarchive_oxide_protocol::{ArchiveError, Codec, CodecStatus, EndOfInput, ErrorKind};

pub(crate) fn drive_codec<C: Codec>(
    codec: C,
    input: &[u8],
    input_chunk: usize,
    output_chunk: usize,
) -> Vec<u8> {
    try_drive_codec(codec, input, input_chunk, output_chunk).expect("codec must accept the fixture")
}

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
