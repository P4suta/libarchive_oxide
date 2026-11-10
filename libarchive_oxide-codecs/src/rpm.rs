// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, caller-driven RPM payload-wrapper decoder.
//!
//! RPM is exposed as an outer filter because its archive payload is normally a separately compressed cpio stream.
//! This decoder validates and removes the fixed lead, signature header, and main header without retaining either header body.
//! The bytes after the main header are emitted unchanged so a following filter layer can decode the payload compression.

use libarchive_oxide_protocol::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const LEAD_LEN: usize = 96;
const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const HEADER_LEN: usize = 16;
const HEADER_MAGIC_AND_VERSION: [u8; 8] = [0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
const INDEX_ENTRY_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Lead,
    SignatureHeader,
    SignatureBody { remaining: usize },
    MainHeader,
    MainBody { remaining: usize },
    Payload,
    Done,
    Failed,
}

/// Incrementally removes one RPM package wrapper and emits its payload bytes.
///
/// Header index and store data are skipped rather than allocated.
/// Their declared combined size is nevertheless checked against the metadata limit before any body byte is consumed.
#[derive(Debug)]
pub struct RpmDecoder {
    state: State,
    lead_seen: usize,
    lead_magic: [u8; LEAD_MAGIC.len()],
    header: [u8; HEADER_LEN],
    header_seen: usize,
    decoded: u64,
    decoded_limit: Option<u64>,
    metadata_limit: Option<usize>,
}

impl RpmDecoder {
    /// Creates an RPM wrapper decoder with caller-supplied resource limits.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            state: State::Lead,
            lead_seen: 0,
            lead_magic: [0; LEAD_MAGIC.len()],
            header: [0; HEADER_LEN],
            header_seen: 0,
            decoded: 0,
            decoded_limit: limits.decoded_total(),
            metadata_limit: limits.metadata_bytes(),
        }
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.state = State::Failed;
        rpm_error(kind, context)
    }

    fn consume_lead(&mut self, input: &[u8]) -> Result<usize, ArchiveError> {
        let count = (LEAD_LEN - self.lead_seen).min(input.len());
        let magic_remaining = LEAD_MAGIC.len().saturating_sub(self.lead_seen);
        let magic_count = count.min(magic_remaining);
        if magic_count != 0 {
            self.lead_magic[self.lead_seen..self.lead_seen + magic_count]
                .copy_from_slice(&input[..magic_count]);
        }
        self.lead_seen += count;
        if self.lead_seen >= LEAD_MAGIC.len() && self.lead_magic != LEAD_MAGIC {
            return Err(self.fail(ErrorKind::Malformed, "invalid RPM lead magic"));
        }
        if self.lead_seen == LEAD_LEN {
            self.state = State::SignatureHeader;
        }
        Ok(count)
    }

    fn consume_header(&mut self, input: &[u8], signature: bool) -> Result<usize, ArchiveError> {
        let count = (HEADER_LEN - self.header_seen).min(input.len());
        self.header[self.header_seen..self.header_seen + count].copy_from_slice(&input[..count]);
        self.header_seen += count;
        if self.header_seen != HEADER_LEN {
            return Ok(count);
        }

        if self.header[..8] != HEADER_MAGIC_AND_VERSION {
            return Err(self.fail(ErrorKind::Malformed, "invalid RPM header magic or version"));
        }
        let index_count = be_u32(&self.header[8..12]);
        let store_len = be_u32(&self.header[12..16]);
        let index_bytes = usize::try_from(index_count)
            .ok()
            .and_then(|value| value.checked_mul(INDEX_ENTRY_LEN));
        let store_bytes = usize::try_from(store_len).ok();
        let body = index_bytes
            .zip(store_bytes)
            .and_then(|(index, store)| index.checked_add(store))
            .ok_or_else(|| {
                self.fail(
                    ErrorKind::Limit,
                    "RPM header size exceeds the platform address space",
                )
            })?;
        if self.metadata_limit.is_some_and(|maximum| body > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "RPM header exceeds the configured metadata limit",
            ));
        }
        let padding = if signature {
            (8 - (store_bytes.unwrap_or(0) % 8)) % 8
        } else {
            0
        };
        let remaining = body.checked_add(padding).ok_or_else(|| {
            self.fail(
                ErrorKind::Limit,
                "RPM header padding exceeds the platform address space",
            )
        })?;
        self.header_seen = 0;
        self.state = match (signature, remaining) {
            (true, 0) => State::MainHeader,
            (true, remaining) => State::SignatureBody { remaining },
            (false, 0) => State::Payload,
            (false, remaining) => State::MainBody { remaining },
        };
        Ok(count)
    }

    fn consume_body(&mut self, input_len: usize, signature: bool) -> usize {
        let remaining = match self.state {
            State::SignatureBody { remaining } | State::MainBody { remaining } => remaining,
            _ => 0,
        };
        let count = remaining.min(input_len);
        let remaining = remaining - count;
        self.state = if remaining != 0 {
            if signature {
                State::SignatureBody { remaining }
            } else {
                State::MainBody { remaining }
            }
        } else if signature {
            State::MainHeader
        } else {
            State::Payload
        };
        count
    }

    fn copy_payload(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ArchiveError> {
        let count = input.len().min(output.len());
        let increment = u64::try_from(count)
            .map_err(|_| self.fail(ErrorKind::Limit, "RPM payload byte count exceeds u64"))?;
        let next = self
            .decoded
            .checked_add(increment)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "RPM payload byte count overflowed"))?;
        if self.decoded_limit.is_some_and(|maximum| next > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "RPM payload exceeds the configured decoded limit",
            ));
        }
        output[..count].copy_from_slice(&input[..count]);
        self.decoded = next;
        Ok(count)
    }
}

impl Codec for RpmDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            State::Failed => {
                return Err(rpm_error(
                    ErrorKind::Protocol,
                    "RPM decoder was used after a terminal error",
                ));
            },
            State::Done => {
                if input.is_empty() {
                    return Ok(codec_step(0, 0, CodecStatus::Done));
                }
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after RPM decoder completion",
                ));
            },
            _ => {},
        }

        let mut consumed = 0;
        let mut produced = 0;
        while consumed < input.len() {
            let count = match self.state {
                State::Lead => self.consume_lead(&input[consumed..])?,
                State::SignatureHeader => self.consume_header(&input[consumed..], true)?,
                State::SignatureBody { .. } => self.consume_body(input.len() - consumed, true),
                State::MainHeader => self.consume_header(&input[consumed..], false)?,
                State::MainBody { .. } => self.consume_body(input.len() - consumed, false),
                State::Payload => {
                    if output.is_empty() {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    let count = self.copy_payload(&input[consumed..], &mut output[produced..])?;
                    consumed += count;
                    produced += count;
                    if consumed != input.len() {
                        return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                    }
                    break;
                },
                State::Done | State::Failed => {
                    return Err(rpm_error(
                        ErrorKind::Protocol,
                        "RPM decoder entered a terminal state while processing input",
                    ));
                },
            };
            consumed += count;
        }

        if matches!(end, EndOfInput::End) {
            if self.state != State::Payload {
                return Err(self.fail(ErrorKind::Malformed, "truncated RPM wrapper header"));
            }
            self.state = State::Done;
            Ok(codec_step(consumed, produced, CodecStatus::Done))
        } else {
            Ok(codec_step(consumed, produced, CodecStatus::NeedInput))
        }
    }
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

const fn codec_step(consumed: usize, produced: usize, status: CodecStatus) -> CodecStep {
    CodecStep {
        consumed,
        produced,
        status,
    }
}

fn rpm_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("rpm")
        .with_context(context)
}
