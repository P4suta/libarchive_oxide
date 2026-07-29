// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, incremental WARC 1.0 and WARC 1.1 reader.
//!
//! Each WARC record is exposed as one regular-file entry whose data is the
//! record's content block. Validated WARC named fields are retained as
//! `warc` metadata extensions. Paths are deterministic and collision-free:
//! `warc/<20-digit sequence>/<percent-encoded WARC-Record-ID>.record` when the
//! identifier fits the path budget, otherwise
//! `warc/<20-digit sequence>.record`.

use alloc::format;
use alloc::vec::Vec;

use crate::metadata::{ArchivePath, EntryMetadata, Extension};
use crate::protocol::{ArchiveDecoder, Chunk, DecodeEvent, DecodeStep, EndOfInput, ProbeResult};
use crate::{ArchiveError, EntryKind, ErrorKind, Limits};

const SIGNATURE_10: &[u8] = b"WARC/1.0\r\n";
const SIGNATURE_11: &[u8] = b"WARC/1.1\r\n";
const HEADER_END: &[u8] = b"\r\n\r\n";
const RECORD_END: &[u8] = b"\r\n\r\n";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

#[derive(Debug)]
enum WarcState {
    Header,
    Data { remaining: u64 },
    Trailer { matched: usize },
    Done,
}

#[derive(Debug)]
struct NamedField {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// Incremental read-only decoder for uncompressed WARC 1.0 and 1.1 files.
#[derive(Debug)]
pub struct WarcDecoder {
    limits: Limits,
    state: WarcState,
    header: Vec<u8>,
    entries: u64,
    decoded: u64,
}

impl WarcDecoder {
    /// Creates a WARC decoder with mandatory resource budgets.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: WarcState::Header,
            header: Vec::new(),
            entries: 0,
            decoded: 0,
        }
    }

    /// Detects only the exact, CRLF-terminated WARC 1.0 and 1.1 signatures.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() >= SIGNATURE_10.len() {
            if prefix.starts_with(SIGNATURE_10) || prefix.starts_with(SIGNATURE_11) {
                ProbeResult::Match(())
            } else {
                ProbeResult::NoMatch
            }
        } else if SIGNATURE_10.starts_with(prefix) || SIGNATURE_11.starts_with(prefix) {
            ProbeResult::NeedMore {
                minimum: SIGNATURE_10.len(),
            }
        } else {
            ProbeResult::NoMatch
        }
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("warc")
            .with_context(context)
    }

    fn append_header_byte(&mut self, byte: u8) -> Result<(), ArchiveError> {
        let next =
            self.header.len().checked_add(1).ok_or_else(|| {
                Self::error(ErrorKind::Limit, "WARC record header length overflow")
            })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| next > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "WARC record header exceeds the metadata budget",
            ));
        }
        self.header.push(byte);
        Ok(())
    }

    fn count_entry(&mut self) -> Result<u64, ArchiveError> {
        let sequence = self
            .entries
            .checked_add(1)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "WARC record count overflow"))?;
        if self.limits.entries().is_some_and(|limit| sequence > limit) {
            return Err(Self::error(
                ErrorKind::Limit,
                "WARC record count exceeds the configured limit",
            ));
        }
        self.entries = sequence;
        Ok(sequence)
    }

    #[allow(clippy::too_many_lines)] // Validation and metadata accounting stay in wire order.
    fn parse_header(
        &self,
        bytes: &[u8],
        sequence: u64,
    ) -> Result<(EntryMetadata, u64), ArchiveError> {
        let body = bytes.strip_suffix(HEADER_END).ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "WARC header parser called before terminator",
            )
        })?;
        let mut lines = CrLfLines::new(body);
        let version = lines.next().ok_or_else(|| {
            Self::error(
                ErrorKind::Malformed,
                "WARC record is missing a version line",
            )
        })??;
        let version_value = match version {
            b"WARC/1.0" => b"1.0".as_slice(),
            b"WARC/1.1" => b"1.1".as_slice(),
            _ => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "unsupported or malformed WARC version line",
                ));
            },
        };

        let mut fields: Vec<NamedField> = Vec::new();
        let mut retained_bytes = extension_cost(b"version", version_value)?;
        for line in lines {
            let line = line?;
            if line
                .first()
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                let field = fields.last_mut().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Malformed,
                        "WARC header continuation has no preceding field",
                    )
                })?;
                let continuation = trim_ows(line);
                validate_field_value(continuation)?;
                let separator = usize::from(!field.value.is_empty() && !continuation.is_empty());
                retained_bytes = self.account_retained_metadata(
                    retained_bytes,
                    separator.checked_add(continuation.len()).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "WARC metadata size overflow")
                    })?,
                )?;
                if separator != 0 {
                    field.value.push(b' ');
                }
                field.value.extend_from_slice(continuation);
                continue;
            }

            let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
                Self::error(ErrorKind::Malformed, "WARC named field is missing ':'")
            })?;
            let name = &line[..colon];
            let value = trim_ows(&line[colon + 1..]);
            validate_field_name(name)?;
            validate_field_value(value)?;
            retained_bytes =
                self.account_retained_metadata(retained_bytes, extension_cost(name, value)?)?;
            fields.push(NamedField {
                name: name.to_vec(),
                value: value.to_vec(),
            });
        }

        for field in &fields {
            core::str::from_utf8(&field.value).map_err(|_| {
                Self::error(
                    ErrorKind::Malformed,
                    "WARC named field value is not valid UTF-8",
                )
            })?;
        }

        reject_duplicate_singletons(&fields)?;
        let length_field = find_field(&fields, b"content-length").ok_or_else(|| {
            Self::error(
                ErrorKind::Malformed,
                "WARC record is missing Content-Length",
            )
        })?;
        let content_length = parse_content_length(&length_field.value)?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|limit| content_length > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "WARC content block exceeds the per-entry limit",
            ));
        }

        let record_id = find_field(&fields, b"warc-record-id").map(|field| field.value.as_slice());
        let path = self.record_path(sequence, record_id)?;
        self.account_retained_metadata(retained_bytes, path.len())?;
        let mut builder = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(path))
            .size(Some(content_length))
            .mode(Some(0o644))
            .extension(Extension::new(
                "warc",
                b"version".to_vec(),
                version_value.to_vec(),
            ));
        for field in fields {
            builder = builder.extension(Extension::new("warc", field.name, field.value));
        }
        Ok((builder.try_build()?, content_length))
    }

    fn account_retained_metadata(
        &self,
        current: usize,
        additional: usize,
    ) -> Result<usize, ArchiveError> {
        let total = current
            .checked_add(additional)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "WARC metadata size overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| total > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "retained WARC metadata exceeds the metadata budget",
            ));
        }
        Ok(total)
    }

    fn record_path(
        &self,
        sequence: u64,
        record_id: Option<&[u8]>,
    ) -> Result<alloc::string::String, ArchiveError> {
        let fallback = format!("warc/{sequence:020}.record");
        let limit = self.limits.path_bytes();
        if limit.is_some_and(|maximum| fallback.len() > maximum) {
            return Err(Self::error(
                ErrorKind::Limit,
                "generated WARC entry path exceeds the path budget",
            ));
        }
        let Some(record_id) = record_id.filter(|value| !value.is_empty()) else {
            return Ok(fallback);
        };

        let encoded_len = record_id.iter().try_fold(0_usize, |length, byte| {
            length.checked_add(if is_path_byte(*byte) { 1 } else { 3 })
        });
        let Some(encoded_len) = encoded_len else {
            return Ok(fallback);
        };
        let prefix = format!("warc/{sequence:020}/");
        let Some(candidate_len) = prefix
            .len()
            .checked_add(encoded_len)
            .and_then(|length| length.checked_add(".record".len()))
        else {
            return Ok(fallback);
        };
        if limit.is_some_and(|maximum| candidate_len > maximum) {
            return Ok(fallback);
        }

        let mut bytes = prefix.into_bytes();
        for byte in record_id {
            if is_path_byte(*byte) {
                bytes.push(*byte);
            } else {
                bytes.extend_from_slice(&[
                    b'%',
                    HEX[usize::from(*byte >> 4)],
                    HEX[usize::from(*byte & 0x0f)],
                ]);
            }
        }
        bytes.extend_from_slice(b".record");
        alloc::string::String::from_utf8(bytes).map_err(|_| {
            Self::error(
                ErrorKind::Protocol,
                "generated WARC entry path is not UTF-8",
            )
        })
    }
}

impl ArchiveDecoder for WarcDecoder {
    #[allow(clippy::too_many_lines)] // One match arm per explicit framing state is easier to audit.
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        _output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self.state {
            WarcState::Done => {
                if !input.is_empty() {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "input supplied after WARC completion",
                    ));
                }
                Ok(step(0, DecodeEvent::Done))
            },
            WarcState::Data { remaining } => {
                if remaining == 0 {
                    self.state = WarcState::Trailer { matched: 0 };
                    return Ok(step(0, DecodeEvent::EndEntry));
                }
                if input.is_empty() {
                    if matches!(end, EndOfInput::End) {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "truncated WARC content block",
                        ));
                    }
                    return Ok(step(0, DecodeEvent::NeedInput));
                }
                let count = input
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let count_u64 = u64::try_from(count).map_err(|_| {
                    Self::error(ErrorKind::Limit, "WARC decoded byte count overflow")
                })?;
                let decoded = self.decoded.checked_add(count_u64).ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "WARC decoded byte count overflow")
                })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|limit| decoded > limit)
                {
                    return Err(Self::error(
                        ErrorKind::Limit,
                        "WARC decoded total exceeds the configured limit",
                    ));
                }
                self.decoded = decoded;
                self.state = WarcState::Data {
                    remaining: remaining - count_u64,
                };
                Ok(step(count, DecodeEvent::Data(Chunk::new(&input[..count]))))
            },
            WarcState::Trailer { mut matched } => {
                let mut consumed = 0;
                while consumed < input.len() && matched < RECORD_END.len() {
                    if input[consumed] != RECORD_END[matched] {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "WARC record is missing its CRLF CRLF trailer",
                        ));
                    }
                    consumed += 1;
                    matched += 1;
                }
                if matched == RECORD_END.len() {
                    self.state = WarcState::Header;
                    return Ok(step(consumed, DecodeEvent::NeedInput));
                }
                self.state = WarcState::Trailer { matched };
                if matches!(end, EndOfInput::End) {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WARC record trailer",
                    ));
                }
                Ok(step(consumed, DecodeEvent::NeedInput))
            },
            WarcState::Header => {
                if input.is_empty() {
                    if matches!(end, EndOfInput::End) {
                        if self.header.is_empty() && self.entries != 0 {
                            self.state = WarcState::Done;
                            return Ok(step(0, DecodeEvent::Done));
                        }
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "truncated or empty WARC record header",
                        ));
                    }
                    return Ok(step(0, DecodeEvent::NeedInput));
                }

                let mut consumed = 0;
                while consumed < input.len() {
                    self.append_header_byte(input[consumed])?;
                    consumed += 1;
                    if self.header.ends_with(HEADER_END) {
                        let sequence = self.count_entry()?;
                        let header = core::mem::take(&mut self.header);
                        let (metadata, content_length) = self.parse_header(&header, sequence)?;
                        self.state = WarcState::Data {
                            remaining: content_length,
                        };
                        return Ok(step(consumed, DecodeEvent::Entry(metadata)));
                    }
                }
                if matches!(end, EndOfInput::End) {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WARC record header",
                    ));
                }
                Ok(step(consumed, DecodeEvent::NeedInput))
            },
        }
    }
}

fn step(consumed: usize, event: DecodeEvent<'_>) -> DecodeStep<'_> {
    DecodeStep {
        consumed,
        produced: 0,
        event,
    }
}

struct CrLfLines<'a> {
    remaining: &'a [u8],
    done: bool,
}

impl<'a> CrLfLines<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            done: false,
        }
    }
}

impl<'a> Iterator for CrLfLines<'a> {
    type Item = Result<&'a [u8], ArchiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if let Some(index) = self
            .remaining
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            let line = &self.remaining[..index];
            self.remaining = &self.remaining[index + 2..];
            return Some(Ok(line));
        }
        self.done = true;
        if self
            .remaining
            .iter()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
        {
            Some(Err(WarcDecoder::error(
                ErrorKind::Malformed,
                "WARC header uses invalid line framing",
            )))
        } else {
            Some(Ok(core::mem::take(&mut self.remaining)))
        }
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn validate_field_name(name: &[u8]) -> Result<(), ArchiveError> {
    core::str::from_utf8(name).map_err(|_| {
        WarcDecoder::error(
            ErrorKind::Malformed,
            "WARC named field name is not valid UTF-8",
        )
    })?;
    if name.is_empty()
        || name
            .iter()
            .any(|byte| *byte <= b' ' || *byte == 0x7f || b"()<>@,;:\\\"/[]?={}".contains(byte))
    {
        return Err(WarcDecoder::error(
            ErrorKind::Malformed,
            "invalid WARC named field name",
        ));
    }
    Ok(())
}

fn validate_field_value(value: &[u8]) -> Result<(), ArchiveError> {
    if value
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(WarcDecoder::error(
            ErrorKind::Malformed,
            "invalid control byte in WARC named field value",
        ));
    }
    Ok(())
}

fn find_field<'a>(fields: &'a [NamedField], name: &[u8]) -> Option<&'a NamedField> {
    fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case(name))
}

fn extension_cost(name: &[u8], value: &[u8]) -> Result<usize, ArchiveError> {
    core::mem::size_of::<Extension>()
        .checked_add("warc".len())
        .and_then(|total| total.checked_add(name.len()))
        .and_then(|total| total.checked_add(value.len()))
        .ok_or_else(|| WarcDecoder::error(ErrorKind::Limit, "WARC metadata size overflow"))
}

fn reject_duplicate_singletons(fields: &[NamedField]) -> Result<(), ArchiveError> {
    for singleton in [
        b"content-length".as_slice(),
        b"warc-record-id".as_slice(),
        b"warc-type".as_slice(),
        b"warc-date".as_slice(),
    ] {
        if fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(singleton))
            .nth(1)
            .is_some()
        {
            return Err(WarcDecoder::error(
                ErrorKind::Malformed,
                "duplicate singleton WARC named field",
            ));
        }
    }
    Ok(())
}

fn parse_content_length(value: &[u8]) -> Result<u64, ArchiveError> {
    if value.is_empty() {
        return Err(WarcDecoder::error(
            ErrorKind::Malformed,
            "empty WARC Content-Length",
        ));
    }
    value.iter().try_fold(0_u64, |length, byte| {
        if !byte.is_ascii_digit() {
            return Err(WarcDecoder::error(
                ErrorKind::Malformed,
                "invalid WARC Content-Length",
            ));
        }
        length
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| WarcDecoder::error(ErrorKind::Malformed, "WARC Content-Length overflow"))
    })
}

const fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ArchiveDecoder;
    use core::fmt::Write as _;

    fn record(version: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!(
            "WARC/{version}\r\n{headers}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\r\n\r\n");
        bytes
    }

    fn drive(bytes: &[u8], chunk: usize, limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        let mut decoder = WarcDecoder::new(limits);
        let mut offset = 0;
        let mut data = Vec::new();
        loop {
            let available = (offset + chunk).min(bytes.len());
            let end = if available == bytes.len() {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = decoder
                .step(&bytes[offset..available], &mut [], end)?
                .validate(available - offset, 0)?;
            offset += step.consumed;
            match step.event {
                DecodeEvent::Data(chunk) => data.extend_from_slice(chunk.as_bytes()),
                DecodeEvent::Done => return Ok(data),
                DecodeEvent::NeedInput if step.consumed == 0 && available != bytes.len() => {
                    return Err(WarcDecoder::error(
                        ErrorKind::Protocol,
                        "test driver stalled before exposing its input",
                    ));
                },
                _ => {},
            }
        }
    }

    #[test]
    fn exact_probe_is_bounded() {
        assert_eq!(
            WarcDecoder::probe(b"WARC/1."),
            ProbeResult::NeedMore { minimum: 10 }
        );
        assert_eq!(WarcDecoder::probe(SIGNATURE_10), ProbeResult::Match(()));
        assert_eq!(WarcDecoder::probe(SIGNATURE_11), ProbeResult::Match(()));
        assert_eq!(WarcDecoder::probe(b"WARC/1.2\r\n"), ProbeResult::NoMatch);
        assert_eq!(WarcDecoder::probe(b"WARC/1.1\n"), ProbeResult::NoMatch);
    }

    #[test]
    fn every_chunk_boundary_decodes_both_versions() {
        let mut bytes = record(
            "1.0",
            "wArC-ReCoRd-Id: <urn:uuid:first>\r\nWARC-Type: resource\r\n",
            b"one",
        );
        bytes.extend_from_slice(&record("1.1", "WARC-Type: metadata\r\n", b"two"));
        for chunk in 1..=bytes.len() {
            assert_eq!(drive(&bytes, chunk, Limits::safe()).unwrap(), b"onetwo");
        }
    }

    #[test]
    fn malformed_lengths_duplicates_and_trailers_fail() {
        for bytes in [
            b"WARC/1.1\r\nWARC-Type: resource\r\n\r\n".as_slice(),
            b"WARC/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx\r\n\r\n",
            b"WARC/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n",
            b"WARC/1.1\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n\r\n\r\n",
            b"WARC/1.1\r\nContent-Length: 1\r\n\r\nx\n\n",
        ] {
            assert_eq!(
                drive(bytes, bytes.len().max(1), Limits::safe())
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
        }
    }

    #[test]
    fn configured_limits_cover_headers_entries_paths_and_data() {
        let bytes = record(
            "1.1",
            "WARC-Record-ID: <urn:uuid:one>\r\nWARC-Type: resource\r\n",
            b"body",
        );
        for limits in [
            Limits::safe().with_metadata_bytes(Some(9)),
            Limits::safe().with_entries(Some(0)),
            Limits::safe().with_path_bytes(Some(4)),
            Limits::safe().with_entry_bytes(Some(3)),
            Limits::safe().with_decoded_total(Some(3)),
        ] {
            assert_eq!(
                drive(&bytes, bytes.len(), limits).unwrap_err().kind(),
                ErrorKind::Limit
            );
        }
    }

    #[test]
    fn many_tiny_fields_cannot_amplify_retained_metadata() {
        let mut headers = alloc::string::String::new();
        for index in 0..10 {
            write!(headers, "X-{index}:\r\n").unwrap();
        }
        let bytes = record("1.1", &headers, b"");
        let error = drive(
            &bytes,
            bytes.len(),
            Limits::safe().with_metadata_bytes(Some(150)),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Limit);
    }
}
