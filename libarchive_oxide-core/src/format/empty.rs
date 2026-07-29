// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decoder for a zero-byte archive.

use crate::{
    ArchiveDecoder, ArchiveError, ArchiveMetadata, DecodeEvent, DecodeStep, EndOfInput, ErrorKind,
};

/// Decoder for the canonical empty archive.
///
/// The enclosing format detector installs this decoder only after observing
/// end-of-input with zero decoded bytes. The decoder still enforces that
/// invariant so explicit provider use cannot silently discard data.
#[derive(Debug, Default)]
pub struct EmptyDecoder {
    metadata_emitted: bool,
}

impl EmptyDecoder {
    /// Creates a decoder awaiting an explicit empty end-of-input.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            metadata_emitted: false,
        }
    }
}

impl ArchiveDecoder for EmptyDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        _output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if !input.is_empty() {
            let kind = if self.metadata_emitted {
                ErrorKind::Protocol
            } else {
                ErrorKind::Malformed
            };
            return Err(ArchiveError::new(kind)
                .with_format("empty")
                .with_context("empty archive contains input bytes"));
        }
        if !self.metadata_emitted {
            if matches!(end, EndOfInput::More) {
                return Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::NeedInput,
                });
            }
            self.metadata_emitted = true;
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::ArchiveMetadata(ArchiveMetadata::new()),
            });
        }
        Ok(DecodeStep {
            consumed: 0,
            produced: 0,
            event: DecodeEvent::Done,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_eof_then_emits_metadata_and_done() {
        let mut decoder = EmptyDecoder::new();
        let mut scratch = [];
        let need = decoder
            .step(&[], &mut scratch, EndOfInput::More)
            .expect("empty prefix");
        assert!(matches!(need.event, DecodeEvent::NeedInput));

        let metadata = decoder
            .step(&[], &mut scratch, EndOfInput::End)
            .expect("empty eof");
        assert!(matches!(metadata.event, DecodeEvent::ArchiveMetadata(_)));

        let done = decoder
            .step(&[], &mut scratch, EndOfInput::End)
            .expect("terminal state");
        assert!(matches!(done.event, DecodeEvent::Done));
    }

    #[test]
    fn rejects_any_payload() {
        let mut decoder = EmptyDecoder::new();
        let error = decoder
            .step(b"x", &mut [], EndOfInput::End)
            .expect_err("non-empty input must not be discarded");
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }
}
