// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, caller-driven POSIX uuencode codecs.
//!
//! The decoder accepts the historical space and backtick spellings of a zero six-bit value and either LF or CRLF line endings.
//! It deliberately decodes one member beginning at byte zero and rejects prefix or trailing material.
//! The encoder emits the canonical libarchive-compatible spelling (`begin 644 -`, 45-byte data lines, backticks for zero, and `end`).

use libarchive_oxide_protocol::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const HEADER: &[u8] = b"begin 644 -\n";
const TRAILER: &[u8] = b"`\nend\n";
const MAX_LINE_BYTES: usize = 1_024;
const MAX_DATA_BYTES: usize = 45;
const MAX_ENCODED_LINE_BYTES: usize = 62;

/// Fixed line and decoded-byte buffering required by [`UuencodeDecoder`].
pub const DECODER_WORKSPACE_BYTES: usize = MAX_LINE_BYTES + MAX_DATA_BYTES;

/// Fixed plaintext and encoded-line buffering required by [`UuencodeEncoder`].
pub const ENCODER_WORKSPACE_BYTES: usize = MAX_DATA_BYTES + MAX_ENCODED_LINE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeState {
    Header,
    Data,
    End,
    TrailerSeen,
    Done,
    Failed,
}

#[derive(Debug)]
enum ParsedLine {
    Header,
    Data {
        bytes: [u8; MAX_DATA_BYTES],
        len: usize,
    },
    Zero,
    End,
}

/// Incremental decoder for one POSIX uuencoded member.
#[derive(Debug)]
pub struct UuencodeDecoder {
    limit: Option<u64>,
    decoded: u64,
    line: [u8; MAX_LINE_BYTES],
    line_len: usize,
    pending: [u8; MAX_DATA_BYTES],
    pending_len: usize,
    pending_pos: usize,
    state: DecodeState,
}

impl UuencodeDecoder {
    /// Creates a decoder with caller-supplied resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] before decoding when the codec-memory budget cannot hold the fixed line workspace.
    pub fn new(limits: Limits) -> Result<Self, ArchiveError> {
        if limits
            .codec_memory()
            .is_some_and(|maximum| maximum < DECODER_WORKSPACE_BYTES)
        {
            return Err(uuencode_error(
                ErrorKind::Limit,
                "uuencode decoder workspace exceeds the codec-memory budget",
            ));
        }
        Ok(Self {
            limit: limits.decoded_total(),
            decoded: 0,
            line: [0; MAX_LINE_BYTES],
            line_len: 0,
            pending: [0; MAX_DATA_BYTES],
            pending_len: 0,
            pending_pos: 0,
            state: DecodeState::Header,
        })
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.state = DecodeState::Failed;
        uuencode_error(kind, context)
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

    fn complete_line(&mut self) -> Result<(), ArchiveError> {
        let mut content_len = self.line_len;
        if content_len != 0 && self.line[content_len - 1] == b'\r' {
            content_len -= 1;
        }
        if self.line[..content_len].contains(&b'\r') {
            return Err(self.fail(
                ErrorKind::Malformed,
                "uuencode line contains a bare carriage return",
            ));
        }
        let parsed = parse_line(self.state, &self.line[..content_len])
            .map_err(|context| self.fail(ErrorKind::Malformed, context))?;
        self.line_len = 0;
        match parsed {
            ParsedLine::Header => self.state = DecodeState::Data,
            ParsedLine::Zero => self.state = DecodeState::End,
            ParsedLine::End => self.state = DecodeState::TrailerSeen,
            ParsedLine::Data { bytes, len } => {
                let count = u64::try_from(len).map_err(|_| {
                    self.fail(ErrorKind::Limit, "uuencode decoded-byte count exceeds u64")
                })?;
                let next = self.decoded.checked_add(count).ok_or_else(|| {
                    self.fail(ErrorKind::Limit, "uuencode decoded-byte count overflow")
                })?;
                if self.limit.is_some_and(|maximum| next > maximum) {
                    return Err(self.fail(
                        ErrorKind::Limit,
                        "uuencode decoded output exceeds the configured limit",
                    ));
                }
                self.pending[..len].copy_from_slice(&bytes[..len]);
                self.pending_len = len;
                self.pending_pos = 0;
                self.decoded = next;
            },
        }
        Ok(())
    }

    fn finish_input(
        &mut self,
        consumed: usize,
        produced: usize,
    ) -> Result<CodecStep, ArchiveError> {
        if self.line_len != 0 {
            return Err(self.fail(
                ErrorKind::Malformed,
                "uuencode input ends inside an unterminated line",
            ));
        }
        if self.state != DecodeState::TrailerSeen {
            return Err(self.fail(
                ErrorKind::Malformed,
                "uuencode input ends before the zero line and end trailer",
            ));
        }
        self.state = DecodeState::Done;
        Ok(codec_step(consumed, produced, CodecStatus::Done))
    }
}

impl Codec for UuencodeDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            DecodeState::Failed => {
                return Err(uuencode_error(
                    ErrorKind::Protocol,
                    "uuencode decoder was used after a terminal error",
                ));
            },
            DecodeState::Done => {
                if input.is_empty() {
                    return Ok(codec_step(0, 0, CodecStatus::Done));
                }
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after uuencode completion",
                ));
            },
            DecodeState::Header
            | DecodeState::Data
            | DecodeState::End
            | DecodeState::TrailerSeen => {},
        }

        let mut consumed = 0;
        let mut produced = self.drain(output);
        if self.pending_len != 0 {
            return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
        }

        while consumed < input.len() {
            if self.state == DecodeState::TrailerSeen {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "trailing bytes follow the uuencode end trailer",
                ));
            }
            let byte = input[consumed];
            consumed += 1;
            if byte == b'\n' {
                self.complete_line()?;
                produced += self.drain(&mut output[produced..]);
                if self.pending_len != 0 {
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                }
                continue;
            }
            if self.line_len == self.line.len() {
                return Err(self.fail(
                    ErrorKind::Malformed,
                    "uuencode line exceeds the bounded line length",
                ));
            }
            self.line[self.line_len] = byte;
            self.line_len += 1;
        }

        if matches!(end, EndOfInput::End) {
            self.finish_input(consumed, produced)
        } else {
            Ok(codec_step(consumed, produced, CodecStatus::NeedInput))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodeState {
    Running,
    NeedTrailer,
    TrailerPending,
    Done,
    Failed,
}

/// Incremental canonical uuencode encoder.
#[derive(Debug)]
pub struct UuencodeEncoder {
    limit: Option<u64>,
    plain: u64,
    block: [u8; MAX_DATA_BYTES],
    block_len: usize,
    pending: [u8; MAX_ENCODED_LINE_BYTES],
    pending_len: usize,
    pending_pos: usize,
    state: EncodeState,
}

impl UuencodeEncoder {
    /// Creates an encoder with caller-supplied plaintext and memory limits.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] before encoding when the codec-memory budget cannot hold the fixed line workspace.
    pub fn new(limits: Limits) -> Result<Self, ArchiveError> {
        if limits
            .codec_memory()
            .is_some_and(|maximum| maximum < ENCODER_WORKSPACE_BYTES)
        {
            return Err(uuencode_error(
                ErrorKind::Limit,
                "uuencode encoder workspace exceeds the codec-memory budget",
            ));
        }
        let mut pending = [0; MAX_ENCODED_LINE_BYTES];
        pending[..HEADER.len()].copy_from_slice(HEADER);
        Ok(Self {
            limit: limits.decoded_total(),
            plain: 0,
            block: [0; MAX_DATA_BYTES],
            block_len: 0,
            pending,
            pending_len: HEADER.len(),
            pending_pos: 0,
            state: EncodeState::Running,
        })
    }

    fn fail(&mut self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        self.state = EncodeState::Failed;
        uuencode_error(kind, context)
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

    fn encode_line(&mut self) {
        self.pending[0] = encode_symbol(u8::try_from(self.block_len).unwrap_or(0));
        let mut encoded = 1;
        for group in self.block[..self.block_len].chunks(3) {
            let first = group[0];
            let second = group.get(1).copied().unwrap_or(0);
            let third = group.get(2).copied().unwrap_or(0);
            let symbols = [
                first >> 2,
                ((first & 0x03) << 4) | (second >> 4),
                ((second & 0x0f) << 2) | (third >> 6),
                third & 0x3f,
            ];
            for symbol in symbols {
                self.pending[encoded] = encode_symbol(symbol);
                encoded += 1;
            }
        }
        self.pending[encoded] = b'\n';
        self.pending_len = encoded + 1;
        self.pending_pos = 0;
        self.block_len = 0;
    }

    fn prepare_trailer(&mut self) {
        self.pending[..TRAILER.len()].copy_from_slice(TRAILER);
        self.pending_len = TRAILER.len();
        self.pending_pos = 0;
        self.state = EncodeState::TrailerPending;
    }

    fn finish(&mut self, output: &mut [u8], consumed: usize, mut produced: usize) -> CodecStep {
        if self.state == EncodeState::Running && self.block_len != 0 {
            self.encode_line();
            self.state = EncodeState::NeedTrailer;
            produced += self.drain(&mut output[produced..]);
            if self.pending_len != 0 {
                return codec_step(consumed, produced, CodecStatus::NeedOutput);
            }
        }
        if matches!(self.state, EncodeState::Running | EncodeState::NeedTrailer) {
            self.prepare_trailer();
            produced += self.drain(&mut output[produced..]);
            if self.pending_len != 0 {
                return codec_step(consumed, produced, CodecStatus::NeedOutput);
            }
        }
        self.state = EncodeState::Done;
        codec_step(consumed, produced, CodecStatus::Done)
    }
}

impl Codec for UuencodeEncoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            EncodeState::Failed => {
                return Err(uuencode_error(
                    ErrorKind::Protocol,
                    "uuencode encoder was used after a terminal error",
                ));
            },
            EncodeState::Done => {
                if input.is_empty() {
                    return Ok(codec_step(0, 0, CodecStatus::Done));
                }
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after uuencode completion",
                ));
            },
            EncodeState::NeedTrailer | EncodeState::TrailerPending if !input.is_empty() => {
                return Err(self.fail(
                    ErrorKind::Protocol,
                    "input supplied after uuencode finalization began",
                ));
            },
            EncodeState::Running | EncodeState::NeedTrailer | EncodeState::TrailerPending => {},
        }

        let input_len = u64::try_from(input.len())
            .map_err(|_| self.fail(ErrorKind::Limit, "uuencode input length exceeds u64"))?;
        let projected = self
            .plain
            .checked_add(input_len)
            .ok_or_else(|| self.fail(ErrorKind::Limit, "uuencode plaintext byte count overflow"))?;
        if self.limit.is_some_and(|maximum| projected > maximum) {
            return Err(self.fail(
                ErrorKind::Limit,
                "uuencode plaintext exceeds the configured limit",
            ));
        }

        let mut consumed = 0;
        let mut produced = self.drain(output);
        if self.pending_len != 0 {
            return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
        }
        if self.state == EncodeState::TrailerPending {
            self.state = EncodeState::Done;
            return Ok(codec_step(consumed, produced, CodecStatus::Done));
        }

        while consumed < input.len() {
            let count = (self.block.len() - self.block_len).min(input.len() - consumed);
            self.block[self.block_len..self.block_len + count]
                .copy_from_slice(&input[consumed..consumed + count]);
            self.block_len += count;
            self.plain += u64::try_from(count).unwrap_or(0);
            consumed += count;
            if self.block_len == self.block.len() {
                self.encode_line();
                produced += self.drain(&mut output[produced..]);
                if self.pending_len != 0 {
                    return Ok(codec_step(consumed, produced, CodecStatus::NeedOutput));
                }
            }
        }

        if matches!(end, EndOfInput::End) {
            Ok(self.finish(output, consumed, produced))
        } else {
            Ok(codec_step(consumed, produced, CodecStatus::NeedInput))
        }
    }
}

fn parse_line(state: DecodeState, line: &[u8]) -> Result<ParsedLine, &'static str> {
    match state {
        DecodeState::Header => parse_header(line).map(|()| ParsedLine::Header),
        DecodeState::Data => parse_data_line(line),
        DecodeState::End => {
            if line == b"end" {
                Ok(ParsedLine::End)
            } else {
                Err("uuencode zero line is not followed by an end trailer")
            }
        },
        DecodeState::TrailerSeen => Err("trailing line follows the uuencode end trailer"),
        DecodeState::Done | DecodeState::Failed => Err("invalid terminal uuencode parser state"),
    }
}

fn parse_header(line: &[u8]) -> Result<(), &'static str> {
    if line.len() < 11 || !line.starts_with(b"begin ") {
        return Err("uuencode member has an invalid begin header");
    }
    if !line[6..9].iter().all(|byte| matches!(byte, b'0'..=b'7')) || line[9] != b' ' {
        return Err("uuencode begin header has an invalid three-digit octal mode");
    }
    let name = &line[10..];
    if name.is_empty() || !name.iter().all(|byte| matches!(byte, b' '..=b'~')) {
        return Err("uuencode begin header has an invalid member name");
    }
    Ok(())
}

fn parse_data_line(line: &[u8]) -> Result<ParsedLine, &'static str> {
    let (&count_symbol, encoded) = line
        .split_first()
        .ok_or("uuencode data section contains an empty line")?;
    let count = usize::from(decode_symbol(count_symbol)?);
    if count > MAX_DATA_BYTES {
        return Err("uuencode data line declares more than 45 bytes");
    }
    if count == 0 {
        return if encoded.is_empty() {
            Ok(ParsedLine::Zero)
        } else {
            Err("uuencode zero line contains trailing symbols")
        };
    }
    let symbol_count = count.div_ceil(3) * 4;
    if encoded.len() != symbol_count {
        return Err("uuencode data line length does not match its byte count");
    }

    let mut decoded = [0; MAX_DATA_BYTES];
    let mut decoded_len = 0;
    for symbols in encoded.as_chunks::<4>().0 {
        let values = [
            decode_symbol(symbols[0])?,
            decode_symbol(symbols[1])?,
            decode_symbol(symbols[2])?,
            decode_symbol(symbols[3])?,
        ];
        let bytes = [
            (values[0] << 2) | (values[1] >> 4),
            (values[1] << 4) | (values[2] >> 2),
            (values[2] << 6) | values[3],
        ];
        let remaining = count - decoded_len;
        let take = remaining.min(3);
        if take == 1 && (values[1] & 0x0f != 0 || values[2] != 0 || values[3] != 0) {
            return Err("uuencode data line has non-zero unused bits");
        }
        if take == 2 && (values[2] & 0x03 != 0 || values[3] != 0) {
            return Err("uuencode data line has non-zero unused bits");
        }
        decoded[decoded_len..decoded_len + take].copy_from_slice(&bytes[..take]);
        decoded_len += take;
    }
    Ok(ParsedLine::Data {
        bytes: decoded,
        len: decoded_len,
    })
}

fn decode_symbol(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b' '..=b'`' => Ok((byte - b' ') & 0x3f),
        _ => Err("uuencode line contains a symbol outside the historical alphabet"),
    }
}

const fn encode_symbol(value: u8) -> u8 {
    if value == 0 { b'`' } else { value + b' ' }
}

const fn codec_step(consumed: usize, produced: usize, status: CodecStatus) -> CodecStep {
    CodecStep {
        consumed,
        produced,
        status,
    }
}

fn uuencode_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("uuencode")
        .with_context(context)
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use libarchive_oxide_protocol::{Codec, CodecStatus, EndOfInput, ErrorKind};

    use super::{
        DECODER_WORKSPACE_BYTES, ENCODER_WORKSPACE_BYTES, UuencodeDecoder, UuencodeEncoder,
    };
    use libarchive_oxide_protocol::Limits;

    const CAT_MEMBER: &[u8] = b"begin 644 cat.txt\n#0V%T\n`\nend\n";
    const CANONICAL_CAT: &[u8] = b"begin 644 -\n#0V%T\n`\nend\n";

    #[test]
    fn decodes_documented_cat_member_across_chunk_boundaries() {
        for input_chunk in 1..=CAT_MEMBER.len() {
            for output_chunk in 1..=4 {
                let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
                assert_eq!(
                    drive(decoder, CAT_MEMBER, input_chunk, output_chunk),
                    b"Cat"
                );
            }
        }
    }

    #[test]
    fn encoder_has_a_canonical_default_member() {
        for input_chunk in 1..=3 {
            for output_chunk in 1..=8 {
                let encoder = UuencodeEncoder::new(Limits::safe()).expect("encoder");
                assert_eq!(
                    drive(encoder, b"Cat", input_chunk, output_chunk),
                    CANONICAL_CAT
                );
            }
        }
        let encoder = UuencodeEncoder::new(Limits::safe()).expect("encoder");
        assert_eq!(drive(encoder, b"", 1, 1), b"begin 644 -\n`\nend\n");
    }

    #[test]
    fn round_trips_multiple_lines_with_one_byte_slices() {
        let plain: Vec<u8> = (0_u8..=127).collect();
        let codec = UuencodeEncoder::new(Limits::safe()).expect("encoder");
        let armored = drive(codec, &plain, 1, 1);
        assert_eq!(armored.split(|byte| *byte == b'\n').count(), 7);
        let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
        assert_eq!(drive(decoder, &armored, 1, 1), plain);
    }

    #[test]
    fn accepts_crlf_and_posix_space_zero_symbols() {
        let member = b"begin 600 a name\r\n!00  \r\n \r\nend\r\n";
        let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
        assert_eq!(drive(decoder, member, 1, 1), b"A");
    }

    #[test]
    fn rejects_every_truncated_cat_prefix() {
        for end in 0..CAT_MEMBER.len() {
            let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
            let error = try_drive(decoder, &CAT_MEMBER[..end], 3, 2)
                .expect_err("truncated member must fail");
            assert_eq!(error.kind(), ErrorKind::Malformed, "prefix length {end}");
        }
    }

    #[test]
    fn rejects_malformed_headers_lines_padding_and_trailers() {
        let malformed: &[&[u8]] = &[
            b"junk\nbegin 644 x\n`\nend\n",
            b"begin 64 x\n`\nend\n",
            b"begin 648 x\n`\nend\n",
            b"begin 644 \n`\nend\n",
            b"begin 644 x\rjunk\n`\nend\n",
            b"begin 644 x\n\n`\nend\n",
            b"begin 644 x\nN\n`\nend\n",
            b"begin 644 x\n#0V%\n`\nend\n",
            b"begin 644 x\n#0V%T`\n`\nend\n",
            b"begin 644 x\n!01``\n`\nend\n",
            b"begin 644 x\n!00a`\n`\nend\n",
            b"begin 644 x\n!00\x7f`\n`\nend\n",
            b"begin 644 x\n`x\nend\n",
            b"begin 644 x\n`\nnope\n",
            b"begin 644 x\n`\nend\ntrailing",
            b"begin 644 x\n`\nend\nbegin 644 y\n`\nend\n",
        ];
        for member in malformed {
            let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
            let error = try_drive(decoder, member, member.len().max(1), 64)
                .expect_err("malformed member must fail");
            assert_eq!(error.kind(), ErrorKind::Malformed, "{member:?}");
        }
    }

    #[test]
    fn rejects_overlong_line_without_unbounded_growth() {
        let mut member = b"begin 644 x\n".to_vec();
        member.extend(vec![b'!'; 1_025]);
        member.extend_from_slice(b"\n`\nend\n");
        let decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
        let error = try_drive(decoder, &member, 17, 8).expect_err("line limit");
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decoded_and_plaintext_limits_fail_closed() {
        let limits = Limits::safe().with_decoded_total(Some(2));
        let decoder = UuencodeDecoder::new(limits).expect("decoder");
        assert_eq!(
            try_drive(decoder, CAT_MEMBER, CAT_MEMBER.len(), 64)
                .expect_err("decoded limit")
                .kind(),
            ErrorKind::Limit
        );

        let mut encoder = UuencodeEncoder::new(limits).expect("encoder");
        let mut output = [0x5a; 64];
        let error = encoder
            .process(b"Cat", &mut output, EndOfInput::End)
            .expect_err("plaintext limit");
        assert_eq!(error.kind(), ErrorKind::Limit);
        assert_eq!(output, [0x5a; 64], "preflight must precede output");
    }

    #[test]
    fn workspace_limits_are_checked_before_construction() {
        let decoder_limit = Limits::safe().with_codec_memory(Some(DECODER_WORKSPACE_BYTES - 1));
        assert_eq!(
            UuencodeDecoder::new(decoder_limit)
                .expect_err("decoder workspace")
                .kind(),
            ErrorKind::Limit
        );
        let encoder_limit = Limits::safe().with_codec_memory(Some(ENCODER_WORKSPACE_BYTES - 1));
        assert_eq!(
            UuencodeEncoder::new(encoder_limit)
                .expect_err("encoder workspace")
                .kind(),
            ErrorKind::Limit
        );
    }

    #[test]
    fn terminal_errors_poison_and_completion_rejects_more_input() {
        let mut decoder = UuencodeDecoder::new(Limits::safe()).expect("decoder");
        let mut output = [0; 64];
        assert_eq!(
            decoder
                .process(b"bad\n", &mut output, EndOfInput::End)
                .expect_err("malformed")
                .kind(),
            ErrorKind::Malformed
        );
        assert_eq!(
            decoder
                .process(b"", &mut output, EndOfInput::End)
                .expect_err("poisoned")
                .kind(),
            ErrorKind::Protocol
        );

        let mut codec = UuencodeEncoder::new(Limits::safe()).expect("encoder");
        let armored = drive_mut(&mut codec, b"", 1, 64).expect("finish");
        assert_eq!(armored, b"begin 644 -\n`\nend\n");
        assert_eq!(
            codec
                .process(b"x", &mut output, EndOfInput::End)
                .expect_err("post-completion input")
                .kind(),
            ErrorKind::Protocol
        );
    }

    fn drive<C: Codec>(codec: C, input: &[u8], input_chunk: usize, output_chunk: usize) -> Vec<u8> {
        try_drive(codec, input, input_chunk, output_chunk).expect("fixture must decode")
    }

    fn try_drive<C: Codec>(
        mut codec: C,
        input: &[u8],
        input_chunk: usize,
        output_chunk: usize,
    ) -> Result<Vec<u8>, libarchive_oxide_protocol::ArchiveError> {
        drive_mut(&mut codec, input, input_chunk, output_chunk)
    }

    fn drive_mut<C: Codec>(
        codec: &mut C,
        input: &[u8],
        input_chunk: usize,
        output_chunk: usize,
    ) -> Result<Vec<u8>, libarchive_oxide_protocol::ArchiveError> {
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
                .process(current, &mut output, end)?
                .validate(current.len(), output.len())?;
            input_pos += step.consumed;
            decoded.extend_from_slice(&output[..step.produced]);
            match step.status {
                CodecStatus::Done => {
                    assert_eq!(input_pos, input.len());
                    return Ok(decoded);
                },
                CodecStatus::NeedInput => assert_eq!(step.consumed, current.len()),
                CodecStatus::NeedOutput => {},
                _ => panic!("unexpected future codec status"),
            }
        }
    }
}
