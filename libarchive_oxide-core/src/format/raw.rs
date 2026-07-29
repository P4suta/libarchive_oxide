// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit single-entry raw-stream decoder.

use crate::{
    ArchiveDecoder, ArchiveError, ArchiveMetadata, ArchivePath, Chunk, DecodeEvent, DecodeStep,
    EndOfInput, EntryKind, EntryMetadata, ErrorKind, Limits,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ArchiveMetadata,
    Entry,
    Data,
    Done,
}

/// Treats the entire decoded byte stream as one file named `data`.
///
/// Raw input has no distinguishing signature, so automatic probing never
/// selects this decoder. Callers must opt in with an explicit format hint.
#[derive(Debug)]
pub struct RawDecoder {
    phase: Phase,
    remaining: Option<u64>,
}

impl RawDecoder {
    /// Creates a decoder at the start of an explicitly selected raw stream.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(Limits::safe())
    }

    /// Creates a decoder with an explicit total payload budget.
    #[must_use]
    pub const fn with_limits(limits: Limits) -> Self {
        Self {
            phase: Phase::ArchiveMetadata,
            remaining: limits.decoded_total(),
        }
    }
}

impl Default for RawDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveDecoder for RawDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        _output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self.phase {
            Phase::ArchiveMetadata => {
                self.phase = Phase::Entry;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::ArchiveMetadata(ArchiveMetadata::new()),
                })
            },
            Phase::Entry => {
                self.phase = Phase::Data;
                let metadata =
                    EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("data"))
                        .size(None)
                        .try_build()?;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::Entry(metadata),
                })
            },
            Phase::Data if !input.is_empty() => {
                if self.remaining == Some(0) {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("raw")
                        .with_context("raw payload exceeds decoded byte limit"));
                }
                let input_length = u64::try_from(input.len()).unwrap_or(u64::MAX);
                let count = self.remaining.map_or(input.len(), |remaining| {
                    usize::try_from(remaining.min(input_length)).unwrap_or(input.len())
                });
                if let Some(remaining) = &mut self.remaining {
                    *remaining = remaining.saturating_sub(u64::try_from(count).unwrap_or(u64::MAX));
                }
                Ok(DecodeStep {
                    consumed: count,
                    produced: 0,
                    event: DecodeEvent::Data(Chunk::new(&input[..count])),
                })
            },
            Phase::Data if matches!(end, EndOfInput::More) => Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedInput,
            }),
            Phase::Data => {
                self.phase = Phase::Done;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::EndEntry,
                })
            },
            Phase::Done => Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::Done,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_one_unknown_size_entry_and_borrows_every_input_chunk() {
        let mut decoder = RawDecoder::new();
        let mut scratch = [];

        let metadata = decoder
            .step(b"abc", &mut scratch, EndOfInput::More)
            .expect("archive metadata");
        assert!(matches!(metadata.event, DecodeEvent::ArchiveMetadata(_)));

        let entry = decoder
            .step(b"abc", &mut scratch, EndOfInput::More)
            .expect("entry");
        let DecodeEvent::Entry(entry) = entry.event else {
            panic!("expected raw entry");
        };
        assert_eq!(entry.path().as_bytes(), b"data");
        assert_eq!(entry.size(), None);

        let data = decoder
            .step(b"abc", &mut scratch, EndOfInput::More)
            .expect("data");
        let DecodeEvent::Data(chunk) = data.event else {
            panic!("expected raw data");
        };
        assert_eq!(data.consumed, 3);
        assert_eq!(chunk.as_bytes(), b"abc");

        let need = decoder
            .step(&[], &mut scratch, EndOfInput::More)
            .expect("need input");
        assert!(matches!(need.event, DecodeEvent::NeedInput));

        let end = decoder
            .step(&[], &mut scratch, EndOfInput::End)
            .expect("end entry");
        assert!(matches!(end.event, DecodeEvent::EndEntry));
        let done = decoder
            .step(&[], &mut scratch, EndOfInput::End)
            .expect("done");
        assert!(matches!(done.event, DecodeEvent::Done));
    }

    #[test]
    fn explicit_empty_raw_stream_still_has_one_empty_entry() {
        let mut decoder = RawDecoder::new();
        let mut scratch = [];
        assert!(matches!(
            decoder
                .step(&[], &mut scratch, EndOfInput::End)
                .expect("metadata")
                .event,
            DecodeEvent::ArchiveMetadata(_)
        ));
        assert!(matches!(
            decoder
                .step(&[], &mut scratch, EndOfInput::End)
                .expect("entry")
                .event,
            DecodeEvent::Entry(_)
        ));
        assert!(matches!(
            decoder
                .step(&[], &mut scratch, EndOfInput::End)
                .expect("end")
                .event,
            DecodeEvent::EndEntry
        ));
    }

    #[test]
    fn decoded_limit_is_enforced_before_excess_input_is_consumed() {
        let mut decoder = RawDecoder::with_limits(Limits::safe().with_decoded_total(Some(3)));
        let mut scratch = [];
        let _ = decoder
            .step(b"abcd", &mut scratch, EndOfInput::End)
            .expect("metadata");
        let _ = decoder
            .step(b"abcd", &mut scratch, EndOfInput::End)
            .expect("entry");
        let data = decoder
            .step(b"abcd", &mut scratch, EndOfInput::End)
            .expect("bounded data");
        assert_eq!(data.consumed, 3);
        let error = decoder
            .step(b"d", &mut scratch, EndOfInput::End)
            .expect_err("limit");
        assert_eq!(error.kind(), ErrorKind::Limit);
    }
}
