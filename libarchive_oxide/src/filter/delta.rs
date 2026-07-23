// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Delta decode filter as a sans-I/O [`Codec`].
//!
//! The 7z/XZ delta filter reconstructs each output byte by adding the byte
//! `distance` positions back in the already-decoded history. It is fully
//! per-byte and carries no partial-instruction state, so any input chunking
//! yields the same output. `distance` is `1..=256`; the history ring is a fixed
//! 256-byte buffer indexed modulo 256.

use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput};

/// The delta filter's fixed maximum distance (and history ring size).
const MAX_DISTANCE: usize = 256;
/// Mask folding a ring index into `0..MAX_DISTANCE`.
const DIS_MASK: usize = MAX_DISTANCE - 1;

/// Incremental delta decoder. Decode-only: it inverts the encoder by adding the
/// historical byte back to each delta-coded input byte.
pub(crate) struct DeltaDecoder {
    distance: usize,
    history: [u8; MAX_DISTANCE],
    pos: u8,
}

impl DeltaDecoder {
    /// Builds a decoder for `distance` (clamped to the valid `1..=256` range).
    pub(crate) fn new(distance: usize) -> Self {
        Self {
            distance: distance.clamp(1, MAX_DISTANCE),
            history: [0; MAX_DISTANCE],
            pos: 0,
        }
    }
}

impl core::fmt::Debug for DeltaDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeltaDecoder")
            .field("distance", &self.distance)
            .finish_non_exhaustive()
    }
}

impl Codec for DeltaDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        let count = input.len().min(output.len());
        for (dst, &coded) in output[..count].iter_mut().zip(&input[..count]) {
            let pos = self.pos as usize;
            let history = self.history[self.distance.wrapping_add(pos) & DIS_MASK];
            let value = coded.wrapping_add(history);
            *dst = value;
            self.history[pos & DIS_MASK] = value;
            self.pos = self.pos.wrapping_sub(1);
        }
        if count > 0 {
            // `consumed == produced`; the status is only consulted on zero progress.
            return Ok(CodecStep {
                consumed: count,
                produced: count,
                status: CodecStatus::NeedInput,
            });
        }
        // Output is always non-empty here, so zero progress means the input is empty.
        let status = match end {
            EndOfInput::End => CodecStatus::Done,
            EndOfInput::More => CodecStatus::NeedInput,
        };
        Ok(CodecStep {
            consumed: 0,
            produced: 0,
            status,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use lzma_rust2::filter::delta::{DeltaReader, DeltaWriter};

    use super::*;
    use crate::codec_read::CodecReader;

    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x0f1e_2d3c_4b5a_6978;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    struct ChunkReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.data.len() - self.pos).min(self.chunk).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn encode(distance: usize, data: &[u8]) -> Vec<u8> {
        let mut writer = DeltaWriter::new(Cursor::new(Vec::new()), distance);
        writer.write_all(data).unwrap();
        writer.into_inner().into_inner()
    }

    fn arca_decode(distance: usize, encoded: &[u8], out_chunk: usize, in_chunk: usize) -> Vec<u8> {
        let inner = ChunkReader {
            data: encoded.to_vec(),
            pos: 0,
            chunk: in_chunk,
        };
        let mut reader = CodecReader::new(inner, DeltaDecoder::new(distance), "delta");
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn delta_round_trips_against_lzma_rust2_at_every_distance() {
        let data = pseudo_random(70_007);
        for distance in [1usize, 2, 3, 4, 16, 255, 256] {
            let encoded = encode(distance, &data);
            // Reference reader reconstructs the input.
            let mut reference = Vec::new();
            DeltaReader::new(Cursor::new(encoded.clone()), distance)
                .read_to_end(&mut reference)
                .unwrap();
            assert_eq!(reference, data, "reference mismatch at distance {distance}");
            // arca decodes byte-identically at any chunking.
            for (out_chunk, in_chunk) in [(1, 1), (3, 7), (256, 5), (65536, 65536)] {
                assert_eq!(
                    arca_decode(distance, &encoded, out_chunk, in_chunk),
                    data,
                    "arca mismatch at distance {distance}, out={out_chunk}, in={in_chunk}"
                );
            }
        }
    }
}
