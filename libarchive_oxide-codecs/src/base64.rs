// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded RFC 4648 Base64 codecs.

use libarchive_oxide_protocol::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PADDING: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    Finishing,
    Done,
    Failed,
}

/// Incremental RFC 4648 Base64 decoder.
///
/// ASCII whitespace is ignored.
/// Padding and unused trailing bits must be canonical, and any non-whitespace byte after padding fails closed.
#[derive(Debug)]
pub struct Base64Decoder {
    limit: Option<u64>,
    decoded: u64,
    quartet: [u8; 4],
    quartet_len: usize,
    pending: [u8; 3],
    pending_len: usize,
    pending_pos: usize,
    padded: bool,
    state: State,
}

impl Base64Decoder {
    /// Creates a decoder with explicit resource limits.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limit: limits.decoded_total(),
            decoded: 0,
            quartet: [0; 4],
            quartet_len: 0,
            pending: [0; 3],
            pending_len: 0,
            pending_pos: 0,
            padded: false,
            state: State::Running,
        }
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.state = State::Failed;
        base64_error(kind, context)
    }

    fn drain(&mut self, output: &mut [u8]) -> usize {
        let available = self.pending_len.saturating_sub(self.pending_pos);
        let count = available.min(output.len());
        if count != 0 {
            output[..count]
                .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + count]);
            self.pending_pos += count;
        }
        if self.pending_pos == self.pending_len {
            self.pending_len = 0;
            self.pending_pos = 0;
        }
        count
    }

    fn decode_quartet(&mut self) -> Result<(), ArchiveError> {
        let [first, second, third, fourth] = self.quartet;
        if first == PADDING || second == PADDING {
            return Err(self.fail(
                ErrorKind::Malformed,
                "Base64 padding appears before the final two symbols",
            ));
        }
        self.pending[0] = (first << 2) | (second >> 4);
        self.pending_len = match (third, fourth) {
            (PADDING, PADDING) => {
                if second & 0x0f != 0 {
                    return Err(self.fail(
                        ErrorKind::Malformed,
                        "Base64 has non-zero unused bits before double padding",
                    ));
                }
                self.padded = true;
                1
            },
            (PADDING, _) => {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "Base64 padding is followed by a data symbol",
                ));
            },
            (third, PADDING) => {
                if third & 0x03 != 0 {
                    return Err(self.fail(
                        ErrorKind::Malformed,
                        "Base64 has non-zero unused bits before padding",
                    ));
                }
                self.pending[1] = (second << 4) | (third >> 2);
                self.padded = true;
                2
            },
            (third, fourth) => {
                self.pending[1] = (second << 4) | (third >> 2);
                self.pending[2] = (third << 6) | fourth;
                3
            },
        };
        self.pending_pos = 0;
        self.quartet_len = 0;
        let produced = u64::try_from(self.pending_len)
            .map_err(|_| self.fail(ErrorKind::Limit, "Base64 decoded-byte count exceeds u64"))?;
        let next = self
            .decoded
            .checked_add(produced)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "Base64 decoded-byte count overflow"))?;
        if self.limit.is_some_and(|maximum| next > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "Base64 decoded output exceeds the configured limit",
            ));
        }
        self.decoded = next;
        Ok(())
    }
}

impl Codec for Base64Decoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            State::Failed => {
                return Err(base64_error(
                    ErrorKind::Protocol,
                    "Base64 decoder was used after a terminal error",
                ));
            },
            State::Done => {
                if input.is_empty() {
                    return Ok(codec_step(0, 0, CodecStatus::Done));
                }
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after Base64 completion",
                ));
            },
            State::Finishing | State::Running => {},
        }

        let mut consumed = 0;
        let mut produced = self.drain(output);
        if self.pending_len != 0 {
            return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
        }

        while consumed < input.len() {
            let byte = input[consumed];
            if byte.is_ascii_whitespace() {
                consumed += 1;
                continue;
            }
            if self.padded {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "non-whitespace data follows Base64 padding",
                ));
            }
            let symbol = decode_symbol(byte)
                .ok_or_else(|| self.fail(ErrorKind::Malformed, "invalid Base64 alphabet symbol"))?;
            self.quartet[self.quartet_len] = symbol;
            self.quartet_len += 1;
            consumed += 1;
            if self.quartet_len == self.quartet.len() {
                self.decode_quartet()?;
                produced += self.drain(&mut output[produced..]);
                if self.pending_len != 0 {
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                }
            }
        }

        if matches!(end, EndOfInput::End) {
            if self.quartet_len != 0 {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "Base64 input ends inside an incomplete quartet",
                ));
            }
            self.state = State::Done;
            Ok(codec_step(consumed, produced, CodecStatus::Done))
        } else {
            Ok(codec_step(consumed, produced, CodecStatus::NeedInput))
        }
    }
}

/// Incremental RFC 4648 Base64 encoder with canonical `=` padding.
#[derive(Debug)]
pub struct Base64Encoder {
    limit: Option<u64>,
    plain: u64,
    triple: [u8; 3],
    triple_len: usize,
    pending: [u8; 4],
    pending_len: usize,
    pending_pos: usize,
    state: State,
}

impl Base64Encoder {
    /// Creates an encoder with explicit plaintext limits.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limit: limits.decoded_total(),
            plain: 0,
            triple: [0; 3],
            triple_len: 0,
            pending: [0; 4],
            pending_len: 0,
            pending_pos: 0,
            state: State::Running,
        }
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.state = State::Failed;
        base64_error(kind, context)
    }

    fn drain(&mut self, output: &mut [u8]) -> usize {
        let available = self.pending_len.saturating_sub(self.pending_pos);
        let count = available.min(output.len());
        if count != 0 {
            output[..count]
                .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + count]);
            self.pending_pos += count;
        }
        if self.pending_pos == self.pending_len {
            self.pending_len = 0;
            self.pending_pos = 0;
        }
        count
    }

    fn encode_triple(&mut self, final_block: bool) {
        let first = self.triple[0];
        let second = self.triple[1];
        let third = self.triple[2];
        self.pending[0] = ALPHABET[usize::from(first >> 2)];
        self.pending[1] = ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))];
        self.pending[2] = if final_block && self.triple_len == 1 {
            b'='
        } else {
            ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))]
        };
        self.pending[3] = if final_block && self.triple_len < 3 {
            b'='
        } else {
            ALPHABET[usize::from(third & 0x3f)]
        };
        self.pending_len = 4;
        self.pending_pos = 0;
        self.triple = [0; 3];
        self.triple_len = 0;
    }
}

impl Codec for Base64Encoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            State::Failed => {
                return Err(base64_error(
                    ErrorKind::Protocol,
                    "Base64 encoder was used after a terminal error",
                ));
            },
            State::Done => {
                if input.is_empty() {
                    return Ok(codec_step(0, 0, CodecStatus::Done));
                }
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after Base64 completion",
                ));
            },
            State::Finishing | State::Running => {},
        }

        let input_length = u64::try_from(input.len())
            .map_err(|_| self.fail(ErrorKind::Limit, "Base64 input length exceeds u64"))?;
        let projected = self
            .plain
            .checked_add(input_length)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "Base64 plaintext byte count overflow"))?;
        if self.limit.is_some_and(|maximum| projected > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "Base64 plaintext exceeds the configured limit",
            ));
        }

        let mut consumed = 0;
        let mut produced = self.drain(output);
        if self.pending_len != 0 {
            return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
        }
        if self.state == State::Finishing {
            self.state = State::Done;
            return Ok(codec_step(consumed, produced, CodecStatus::Done));
        }

        while consumed < input.len() {
            self.triple[self.triple_len] = input[consumed];
            self.triple_len += 1;
            self.plain += 1;
            consumed += 1;
            if self.triple_len == self.triple.len() {
                self.encode_triple(false);
                produced += self.drain(&mut output[produced..]);
                if self.pending_len != 0 {
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                }
            }
        }

        if matches!(end, EndOfInput::End) {
            if self.triple_len != 0 {
                self.encode_triple(true);
                self.state = State::Finishing;
                produced += self.drain(&mut output[produced..]);
                if self.pending_len != 0 {
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                }
            }
            self.state = State::Done;
            Ok(codec_step(consumed, produced, CodecStatus::Done))
        } else {
            Ok(codec_step(consumed, produced, CodecStatus::NeedInput))
        }
    }
}

fn decode_symbol(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(PADDING),
        _ => None,
    }
}

const fn codec_step(consumed: usize, produced: usize, status: CodecStatus) -> CodecStep {
    CodecStep {
        consumed,
        produced,
        status,
    }
}

fn base64_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("base64")
        .with_context(context)
}
