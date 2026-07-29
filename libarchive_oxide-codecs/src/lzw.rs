// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unix `compress(1)` LZW as a bounded, caller-driven decoder.
//!
//! The wire format is the three-byte `1f 9d` header followed by LSB-first
//! variable-width LZW codes. The adapter uses `compcol`'s safe Rust state
//! machine, but owns the archive-facing resource and protocol boundary:
//! dictionary memory is rejected before allocation, decoded output is
//! bounded, reserved header bits fail closed, and every progress count is
//! validated before it reaches a caller.

use alloc::string::ToString;
use core::fmt;

use compcol::limit::LimitedDecoder;
use compcol::lzw;
use compcol::{Decoder as _, Error as CompcolError, Progress, Status};
use libarchive_oxide_core::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

/// Two fixed 65,536-entry dictionary arrays plus the longest pending string.
///
/// `compcol::lzw::Decoder` allocates a `u16` prefix table, a `u8` suffix
/// table, and at most one 65,536-byte expansion pending caller output.
pub const DECODER_WORKSPACE_BYTES: usize = 256 * 1024;

const MAGIC: [u8; 2] = [0x1f, 0x9d];
const RESERVED_HEADER_BITS: u8 = 0x60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalState {
    Running,
    Done,
    Failed,
}

/// Incremental decoder for the Unix `.Z` / `compress(1)` stream format.
pub struct CompressDecoder {
    decoder: LimitedDecoder<lzw::Decoder>,
    terminal: TerminalState,
    header: [u8; 3],
    header_len: usize,
}

impl CompressDecoder {
    /// Creates a decoder with finite safe limits.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] before allocating the dictionary when the
    /// configured codec-memory budget is smaller than
    /// [`DECODER_WORKSPACE_BYTES`].
    pub fn new() -> Result<Self, ArchiveError> {
        Self::with_limits(Limits::safe())
    }

    /// Creates a decoder with caller-supplied resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] before allocating the dictionary when the
    /// configured codec-memory budget cannot hold the fixed LZW workspace.
    pub fn with_limits(limits: Limits) -> Result<Self, ArchiveError> {
        if limits
            .codec_memory()
            .is_some_and(|limit| limit < DECODER_WORKSPACE_BYTES)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format("compress")
                .with_context("compress/LZW dictionary exceeds the codec-memory budget"));
        }
        let decoded_limit = limits.decoded_total().unwrap_or(u64::MAX);
        Ok(Self {
            decoder: LimitedDecoder::new(lzw::Decoder::new(), decoded_limit),
            terminal: TerminalState::Running,
            header: [0; 3],
            header_len: 0,
        })
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("compress")
            .with_context(context)
    }

    fn codec_error(error: CompcolError) -> ArchiveError {
        let kind = match error {
            CompcolError::Unsupported => ErrorKind::Unsupported,
            CompcolError::OutputLimitExceeded => ErrorKind::Limit,
            CompcolError::ChecksumMismatch | CompcolError::TrailerMismatch => ErrorKind::Integrity,
            CompcolError::OutputTooSmall => ErrorKind::Protocol,
            _ => ErrorKind::Malformed,
        };
        ArchiveError::new(kind)
            .with_format("compress")
            .with_context(error.to_string())
    }

    fn validate_progress(
        progress: Progress,
        input_len: usize,
        output_len: usize,
    ) -> Result<Progress, ArchiveError> {
        if progress.consumed > input_len || progress.written > output_len {
            return Err(Self::error(
                ErrorKind::Protocol,
                "compress/LZW decoder returned an invalid progress count",
            ));
        }
        Ok(progress)
    }

    fn record_header(&mut self, consumed: &[u8]) -> Result<(), ArchiveError> {
        let count = (self.header.len() - self.header_len).min(consumed.len());
        self.header[self.header_len..self.header_len + count].copy_from_slice(&consumed[..count]);
        self.header_len += count;
        if self.header_len < self.header.len() {
            return Ok(());
        }
        if self.header[..2] != MAGIC {
            return Err(Self::error(
                ErrorKind::Malformed,
                "compress/LZW stream has an invalid magic header",
            ));
        }
        if self.header[2] & RESERVED_HEADER_BITS != 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "compress/LZW header sets reserved option bits",
            ));
        }
        Ok(())
    }

    fn finish(
        &mut self,
        output: &mut [u8],
        consumed: usize,
        produced: usize,
    ) -> Result<CodecStep, ArchiveError> {
        if self.header_len == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "compress/LZW stream ended before its header",
            ));
        }
        let (progress, status) = self
            .decoder
            .finish(&mut output[produced..])
            .map_err(Self::codec_error)?;
        let progress = Self::validate_progress(progress, 0, output.len().saturating_sub(produced))?;
        let produced = produced.checked_add(progress.written).ok_or_else(|| {
            Self::error(
                ErrorKind::Limit,
                "compress/LZW produced-byte count overflowed",
            )
        })?;
        let status = match status {
            Status::StreamEnd => {
                self.terminal = TerminalState::Done;
                CodecStatus::Done
            },
            Status::OutputFull => CodecStatus::NeedOutput,
            Status::InputEmpty => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "compress/LZW finish returned a non-terminal input request",
                ));
            },
        };
        Ok(CodecStep {
            consumed,
            produced,
            status,
        })
    }
}

impl fmt::Debug for CompressDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressDecoder")
            .field("terminal", &self.terminal)
            .field("header_len", &self.header_len)
            .field("decoded_bytes", &self.decoder.bytes_written())
            .finish_non_exhaustive()
    }
}

impl Codec for CompressDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.terminal {
            TerminalState::Done if input.is_empty() => {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            },
            TerminalState::Done => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "input supplied after compress/LZW completion",
                ));
            },
            TerminalState::Failed => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "compress/LZW decoder reused after failure",
                ));
            },
            TerminalState::Running => {},
        }

        let decoded = self.decoder.decode(input, output);
        let (progress, status) = match decoded {
            Ok(result) => result,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(Self::codec_error(error));
            },
        };
        let progress = match Self::validate_progress(progress, input.len(), output.len()) {
            Ok(progress) => progress,
            Err(error) => {
                self.terminal = TerminalState::Failed;
                return Err(error);
            },
        };
        if let Err(error) = self.record_header(&input[..progress.consumed]) {
            self.terminal = TerminalState::Failed;
            return Err(error);
        }

        if matches!(end, EndOfInput::End)
            && progress.consumed == input.len()
            && !matches!(status, Status::OutputFull)
        {
            return self
                .finish(output, progress.consumed, progress.written)
                .inspect_err(|_| self.terminal = TerminalState::Failed);
        }

        let status = match status {
            Status::OutputFull => CodecStatus::NeedOutput,
            Status::InputEmpty => {
                if output.is_empty() && progress.consumed != 0 {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                }
            },
            Status::StreamEnd => {
                if progress.consumed != input.len() {
                    self.terminal = TerminalState::Failed;
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "compress/LZW stream has trailing encoded bytes",
                    ));
                }
                self.terminal = TerminalState::Done;
                CodecStatus::Done
            },
        };
        Ok(CodecStep {
            consumed: progress.consumed,
            produced: progress.written,
            status,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::{vec, vec::Vec};

    use libarchive_oxide_core::{Codec as _, ErrorKind};

    use super::*;
    use crate::test_support::{drive_codec, try_drive_codec};

    const COMPRESS_HELLO_WORLD: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90,
        0x01,
    ];
    const BSDTAR_SEED_TAR: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x73, 0xca, 0x94, 0x21, 0xe3, 0x82, 0x0e, 0x1e, 0x3a, 0x00, 0x12, 0x2a,
        0x5c, 0xc8, 0xb0, 0xa1, 0xc3, 0x87, 0x10, 0x23, 0x4a, 0x9c, 0x48, 0x11, 0x00, 0x8c, 0x8b,
        0x36, 0x32, 0x82, 0xb0, 0x78, 0xb1, 0xe3, 0xc6, 0x8e, 0x1e, 0x39, 0x82, 0xec, 0x38, 0x63,
        0x06, 0x88, 0x18, 0x35, 0x64, 0xcc, 0x90, 0x21, 0x23, 0x06, 0x8c, 0x19, 0x1a, 0x61, 0xb8,
        0xbc, 0x01, 0xa3, 0x06, 0x00, 0x10, 0x30, 0x2a, 0xea, 0xdc, 0xc9, 0xb3, 0xa7, 0x4f, 0x00,
        0x75, 0xe6, 0xd0, 0x09, 0x23, 0x87, 0xe3, 0xcf, 0xa3, 0x48, 0x45, 0x86, 0x1c, 0x09, 0x63,
        0x63, 0xd2, 0xa7, 0x50, 0xa3, 0x4a, 0x9d, 0x5a, 0x71, 0x4e, 0x18, 0x33, 0x65, 0x5e, 0xcc,
        0xa9, 0x23, 0x86, 0x4c, 0x1a, 0x39, 0x65, 0xc6, 0xd0, 0x79, 0x23, 0x27, 0xcf, 0x0b, 0x33,
        0x69, 0xd8, 0x94, 0x29, 0x78, 0x50, 0x01, 0xd5, 0xb7, 0x70, 0xe3, 0xca, 0x9d, 0x4b, 0xb7,
        0xae, 0xdd, 0xbb, 0x78, 0xf3, 0xea, 0xdd, 0xcb, 0xb7, 0xaf, 0xdf, 0xbf, 0x80, 0x03, 0x0b,
        0x1e, 0x4c, 0xb8, 0xb0, 0xe1, 0xc3, 0x88, 0x13, 0x2b, 0x5e, 0xcc, 0xb8, 0xb1, 0xe3, 0xa7,
    ];

    #[test]
    fn independent_compress_fixture_is_chunk_invariant() {
        // Produced independently by:
        // `printf "hello world" | compress -c | xxd -p`.
        for (input_chunk, output_chunk) in [(1, 1), (2, 3), (7, 5), (64, 64)] {
            let decoded = drive_codec(
                CompressDecoder::new().expect("safe LZW workspace"),
                COMPRESS_HELLO_WORLD,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, b"hello world");
        }
    }

    #[test]
    fn independent_bsdtar_tar_fixture_is_chunk_invariant() {
        // Produced independently by bsdtar 3.8.4:
        // `tar -acf seed.tar.Z -C fuzz/corpus/extraction_plan seed.txt`.
        // SHA-256(seed.tar.Z):
        // E1D4B4626FF85F13FEBABA6F58724065092831DF234E2D698E4540D84469A56F.
        for (input_chunk, output_chunk) in [(1, 1), (5, 7), (31, 257)] {
            let decoded = drive_codec(
                CompressDecoder::new().expect("safe LZW workspace"),
                BSDTAR_SEED_TAR,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded.len(), 2_048);
            assert_eq!(&decoded[..8], b"seed.txt");
            assert_eq!(&decoded[257..263], b"ustar\0");
            assert_eq!(&decoded[512..539], b"safe/subdirectory/file.txt\n");
        }
    }

    #[test]
    fn dictionary_budget_is_rejected_before_decoder_construction() {
        let error = CompressDecoder::with_limits(
            Limits::safe().with_codec_memory(Some(DECODER_WORKSPACE_BYTES - 1)),
        )
        .expect_err("undersized dictionary budget");
        assert_eq!(error.kind(), ErrorKind::Limit);
    }

    #[test]
    fn decoded_limit_fails_closed() {
        let error = try_drive_codec(
            CompressDecoder::with_limits(Limits::safe().with_decoded_total(Some(10)))
                .expect("bounded decoder"),
            COMPRESS_HELLO_WORLD,
            1,
            1,
        )
        .expect_err("fixture expands past ten bytes");
        assert_eq!(error.kind(), ErrorKind::Limit);
    }

    #[test]
    fn malformed_headers_and_truncation_are_typed() {
        for malformed in [
            Vec::new(),
            vec![0x1f],
            vec![0x1f, 0x9d],
            vec![0x1f, 0x9d, 0xf0],
            vec![0x1f, 0x9d, 0x88],
            vec![0, 0, 0],
        ] {
            let error = try_drive_codec(
                CompressDecoder::new().expect("safe LZW workspace"),
                &malformed,
                1,
                8,
            )
            .expect_err("malformed stream");
            assert!(
                matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Unsupported),
                "unexpected error for {malformed:02x?}: {error}"
            );
        }
    }

    #[test]
    fn input_after_completion_is_a_protocol_error() {
        let mut decoder = CompressDecoder::new().expect("safe LZW workspace");
        let mut output = [0; 64];
        let step = decoder
            .process(COMPRESS_HELLO_WORLD, &mut output, EndOfInput::End)
            .expect("valid fixture");
        assert_eq!(step.status, CodecStatus::Done);
        let error = decoder
            .process(b"x", &mut output, EndOfInput::End)
            .expect_err("terminal decoder rejects input");
        assert_eq!(error.kind(), ErrorKind::Protocol);
    }
}
