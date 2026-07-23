// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `eXtensible` `ARchive` (`.xar`) read-only, seek-native provider (RM-305).
//!
//! Parses the 28-byte big-endian header, inflates the zlib (RFC-1950) compressed
//! TOC into bounded UTF-8 XML, walks the `<file>` tree with a hand-rolled bounded
//! pull-scanner (no DOM, no XML crate), and streams heap payloads per file in
//! `<= 64 KiB` chunks. Supported data encodings: `application/octet-stream`
//! (stored) and `application/x-gzip` (zlib RFC-1950). Every other encoding, and
//! `application/x-bzip2`, surface a structured `Unsupported` error at read time.

use std::io::{Read, Seek, SeekFrom};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Limits, Owner, PathEncoding, Timestamp,
};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::{ReaderEvent, StreamError};

/// The 4-byte XAR magic (`'x' 'a' 'r' '!'`), big-endian `0x7861_7221`.
const MAGIC: u32 = 0x7861_7221;
/// The minimal (and canonical) header length.
const MIN_HEADER: u16 = 28;
/// Streaming chunk size for both TOC inflate and heap payload decode.
const BUFFER: usize = 64 * 1024;
/// Cap on `<file>` element nesting depth.
const MAX_DEPTH: usize = 256;

// ════════════════════════════════════════════════════════════════════════════
// Error helper
// ════════════════════════════════════════════════════════════════════════════

fn xar_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("xar")
            .with_context(context),
    )
}

// ════════════════════════════════════════════════════════════════════════════
// Parsed structures
// ════════════════════════════════════════════════════════════════════════════

/// Heap data-blob encoding classified at TOC-parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XarEncoding {
    /// `application/octet-stream`: raw copy, stored size equals decoded length.
    Stored,
    /// `application/x-gzip`: a zlib (RFC-1950) stream — the XAR default.
    Zlib,
    /// A recognized-but-unsupported or unknown encoding style.
    Unsupported,
}

/// The heap window and decode plan for a regular file.
#[derive(Debug, Clone, Copy)]
struct XarData {
    encoding: XarEncoding,
    /// Heap-relative offset of the stored blob.
    offset: u64,
    /// Stored (on-heap) size in bytes.
    stored_size: u64,
    /// Decoded length in bytes.
    length: u64,
}

/// A fully-resolved TOC entry with its `/`-joined path.
#[derive(Debug, Clone)]
struct XarFile {
    path: Vec<u8>,
    kind: EntryKind,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    data: Option<XarData>,
}

// ════════════════════════════════════════════════════════════════════════════
// Reader
// ════════════════════════════════════════════════════════════════════════════

/// Streaming heap-payload decoder for the currently-open entry.
enum Payload {
    /// Copy `remaining` bytes straight from the heap.
    Stored { remaining: u64 },
    /// Inflate a zlib stream, `comp_remaining` compressed bytes left on the heap.
    Zlib {
        comp_remaining: u64,
        state: Box<InflateState>,
        in_buf: Vec<u8>,
        in_pos: usize,
        in_len: usize,
        finished: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XarPhase {
    Idle,
    Data { remaining: u64 },
    Unsupported,
    EndEntry,
    Done,
}

/// Seek-capable read-only `eXtensible` `ARchive` reader.
pub(crate) struct XarSeekReader<R> {
    input: R,
    limits: Limits,
    archive_metadata: Option<ArchiveMetadata>,
    heap_start: u64,
    file_length: u64,
    files: Vec<XarFile>,
    next_file: usize,
    phase: XarPhase,
    payload: Option<Payload>,
    event_data: Vec<u8>,
    decoded_total: u64,
}

impl<R> std::fmt::Debug for XarSeekReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XarSeekReader")
            .field("files", &self.files.len())
            .field("next_file", &self.next_file)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> XarSeekReader<R> {
    pub(crate) fn new(mut input: R, limits: Limits) -> core::result::Result<Self, StreamError> {
        let file_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;

        let mut header = [0_u8; MIN_HEADER as usize];
        input.read_exact(&mut header).map_err(StreamError::io)?;
        if be32(&header, 0) != MAGIC {
            return Err(xar_error(ErrorKind::Malformed, "bad xar magic"));
        }
        let size = be16(&header, 4);
        if size < MIN_HEADER {
            return Err(xar_error(ErrorKind::Malformed, "xar header size too small"));
        }
        if be16(&header, 6) != 1 {
            return Err(xar_error(ErrorKind::Unsupported, "unsupported xar version"));
        }
        let toc_comp = be64(&header, 8);
        let toc_uncomp = be64(&header, 16);

        let toc_start = u64::from(size);
        if toc_start > file_length {
            return Err(xar_error(
                ErrorKind::Malformed,
                "xar header size beyond end of file",
            ));
        }
        let heap_start = toc_start
            .checked_add(toc_comp)
            .filter(|&end| end <= file_length)
            .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar TOC region beyond end of file"))?;

        // Bound the decoded TOC by the metadata budget before inflating.
        if let Some(maximum) = limits.metadata_bytes() {
            if toc_uncomp > maximum as u64 {
                return Err(xar_error(
                    ErrorKind::Limit,
                    "xar TOC exceeds metadata limit",
                ));
            }
        }
        let toc_uncomp_usize = usize::try_from(toc_uncomp)
            .map_err(|_| xar_error(ErrorKind::Limit, "xar TOC exceeds address space"))?;

        input
            .seek(SeekFrom::Start(toc_start))
            .map_err(StreamError::io)?;
        let xml = inflate_toc(&mut input, toc_comp, toc_uncomp_usize)?;

        let files = parse_toc(&xml, limits)?;

        Ok(Self {
            input,
            limits,
            archive_metadata: Some(ArchiveMetadata::new()),
            heap_start,
            file_length,
            files,
            next_file: 0,
            phase: XarPhase::Idle,
            payload: None,
            event_data: Vec::with_capacity(BUFFER),
            decoded_total: 0,
        })
    }

    pub(crate) fn next_event(&mut self) -> core::result::Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        if let Some(metadata) = self.archive_metadata.take() {
            return Ok(ReaderEvent::ArchiveMetadata(metadata));
        }
        loop {
            match self.phase {
                XarPhase::Idle => {
                    let Some(record) = self.files.get(self.next_file).cloned() else {
                        self.phase = XarPhase::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    self.next_file += 1;
                    let metadata = self.prepare_record(&record)?;
                    return Ok(ReaderEvent::Entry(metadata));
                },
                XarPhase::Data { remaining: 0 } => {
                    self.payload = None;
                    self.phase = XarPhase::EndEntry;
                },
                XarPhase::Data { remaining } => {
                    let amount = usize::try_from(remaining.min(BUFFER as u64))
                        .map_err(|_| xar_error(ErrorKind::Limit, "chunk exceeds address space"))?;
                    self.event_data.resize(amount, 0);
                    let count = self.read_payload_chunk(amount)?;
                    if count == 0 {
                        return Err(xar_error(
                            ErrorKind::Integrity,
                            "xar heap blob shorter than declared length",
                        ));
                    }
                    self.event_data.truncate(count);
                    self.phase = XarPhase::Data {
                        remaining: remaining - count as u64,
                    };
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                XarPhase::Unsupported => {
                    return Err(xar_error(
                        ErrorKind::Unsupported,
                        "xar data encoding is unsupported",
                    ));
                },
                XarPhase::EndEntry => {
                    self.phase = XarPhase::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                XarPhase::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> core::result::Result<(), StreamError> {
        match self.phase {
            XarPhase::Data { mut remaining } => {
                let mut scratch = vec![0_u8; BUFFER];
                while remaining != 0 {
                    let amount = usize::try_from(remaining.min(BUFFER as u64))
                        .map_err(|_| xar_error(ErrorKind::Limit, "chunk exceeds address space"))?;
                    let count = self.read_payload_into(&mut scratch[..amount])?;
                    if count == 0 {
                        return Err(xar_error(
                            ErrorKind::Integrity,
                            "xar heap blob shorter than declared length",
                        ));
                    }
                    remaining -= count as u64;
                }
                self.payload = None;
                self.phase = XarPhase::EndEntry;
                Ok(())
            },
            XarPhase::Unsupported => {
                self.phase = XarPhase::EndEntry;
                Ok(())
            },
            XarPhase::EndEntry => Ok(()),
            XarPhase::Idle | XarPhase::Done => Err(xar_error(
                ErrorKind::Protocol,
                "skip_entry called without an open xar entry",
            )),
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.input
    }

    pub(crate) fn source_ref(&self) -> &R {
        &self.input
    }

    fn prepare_record(
        &mut self,
        record: &XarFile,
    ) -> core::result::Result<EntryMetadata, StreamError> {
        match record.data {
            Some(data) if record.kind == EntryKind::File => {
                self.begin_payload(data)?;
            },
            _ => {
                self.payload = None;
                self.phase = XarPhase::EndEntry;
            },
        }

        let size = match record.kind {
            EntryKind::File => record.data.map(|d| d.length),
            EntryKind::Dir => Some(0),
            _ => None,
        };
        let owner = Owner {
            uid: record.uid,
            gid: record.gid,
            user: None,
            group: None,
        };
        let link_target = record
            .link_target
            .clone()
            .map(|target| ArchivePath::from_encoded(target, PathEncoding::Utf8));
        let builder = EntryMetadata::builder(
            record.kind,
            ArchivePath::from_encoded(record.path.clone(), PathEncoding::Utf8),
        )
        .size(size)
        .mode(record.mode)
        .owner(owner)
        .times(EntryTimes {
            modified: record.mtime,
            accessed: None,
            changed: None,
            created: None,
        })
        .link_target(link_target);
        Ok(builder.build())
    }

    /// Seeks to the heap blob and installs the decode state for `data`.
    fn begin_payload(&mut self, data: XarData) -> core::result::Result<(), StreamError> {
        let blob_start = self
            .heap_start
            .checked_add(data.offset)
            .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar heap offset overflow"))?;
        let blob_end = blob_start
            .checked_add(data.stored_size)
            .filter(|&end| end <= self.file_length)
            .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar heap blob beyond end of file"))?;
        let _ = blob_end;

        // decoded-total budget.
        if let Some(maximum) = self.limits.decoded_total() {
            if self
                .decoded_total
                .checked_add(data.length)
                .is_none_or(|total| total > maximum)
            {
                return Err(xar_error(
                    ErrorKind::Limit,
                    "xar decoded total exceeds limit",
                ));
            }
        }

        match data.encoding {
            XarEncoding::Stored => {
                if data.stored_size != data.length {
                    return Err(xar_error(
                        ErrorKind::Malformed,
                        "xar stored blob size and length disagree",
                    ));
                }
                self.input
                    .seek(SeekFrom::Start(blob_start))
                    .map_err(StreamError::io)?;
                self.payload = Some(Payload::Stored {
                    remaining: data.stored_size,
                });
                self.phase = if data.length == 0 {
                    XarPhase::EndEntry
                } else {
                    XarPhase::Data {
                        remaining: data.length,
                    }
                };
            },
            XarEncoding::Zlib => {
                self.input
                    .seek(SeekFrom::Start(blob_start))
                    .map_err(StreamError::io)?;
                self.payload = Some(Payload::Zlib {
                    comp_remaining: data.stored_size,
                    state: Box::new(InflateState::new(DataFormat::Zlib)),
                    in_buf: vec![0_u8; BUFFER],
                    in_pos: 0,
                    in_len: 0,
                    finished: false,
                });
                self.phase = if data.length == 0 {
                    XarPhase::EndEntry
                } else {
                    XarPhase::Data {
                        remaining: data.length,
                    }
                };
            },
            XarEncoding::Unsupported => {
                self.payload = None;
                self.phase = XarPhase::Unsupported;
            },
        }
        Ok(())
    }

    /// Fills the first `amount` bytes of `event_data`, returning bytes produced.
    fn read_payload_chunk(&mut self, amount: usize) -> core::result::Result<usize, StreamError> {
        let mut filled = 0;
        while filled < amount {
            let produced = read_payload(
                &mut self.input,
                self.payload.as_mut(),
                &mut self.event_data[filled..amount],
            )?;
            if produced == 0 {
                break;
            }
            filled += produced;
        }
        self.account_decoded(filled)?;
        Ok(filled)
    }

    fn read_payload_into(&mut self, out: &mut [u8]) -> core::result::Result<usize, StreamError> {
        let mut filled = 0;
        while filled < out.len() {
            let produced =
                read_payload(&mut self.input, self.payload.as_mut(), &mut out[filled..])?;
            if produced == 0 {
                break;
            }
            filled += produced;
        }
        self.account_decoded(filled)?;
        Ok(filled)
    }

    fn account_decoded(&mut self, count: usize) -> core::result::Result<(), StreamError> {
        self.decoded_total = self
            .decoded_total
            .checked_add(count as u64)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| self.decoded_total > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "xar decoded total exceeds limit",
            ));
        }
        Ok(())
    }
}

/// Reads up to `out.len()` decoded bytes from the current payload; `0` = blob end.
fn read_payload<R: Read>(
    input: &mut R,
    payload: Option<&mut Payload>,
    out: &mut [u8],
) -> core::result::Result<usize, StreamError> {
    let Some(payload) = payload else {
        return Ok(0);
    };
    if out.is_empty() {
        return Ok(0);
    }
    match payload {
        Payload::Stored { remaining } => {
            if *remaining == 0 {
                return Ok(0);
            }
            let want = usize::try_from(*remaining)
                .unwrap_or(usize::MAX)
                .min(out.len());
            let count = input.read(&mut out[..want]).map_err(StreamError::io)?;
            if count == 0 {
                return Err(xar_error(
                    ErrorKind::Malformed,
                    "xar heap ended before the stored blob",
                ));
            }
            *remaining -= count as u64;
            Ok(count)
        },
        Payload::Zlib {
            comp_remaining,
            state,
            in_buf,
            in_pos,
            in_len,
            finished,
        } => {
            loop {
                if *finished {
                    return Ok(0);
                }
                if *in_pos == *in_len && *comp_remaining > 0 {
                    let want = usize::try_from(*comp_remaining)
                        .unwrap_or(usize::MAX)
                        .min(in_buf.len());
                    let count = input.read(&mut in_buf[..want]).map_err(StreamError::io)?;
                    if count == 0 {
                        return Err(xar_error(
                            ErrorKind::Malformed,
                            "xar heap ended before the compressed blob",
                        ));
                    }
                    *in_pos = 0;
                    *in_len = count;
                    *comp_remaining -= count as u64;
                }
                let flush = if *comp_remaining == 0 {
                    MZFlush::Finish
                } else {
                    MZFlush::None
                };
                let result = inflate(state, &in_buf[*in_pos..*in_len], out, flush);
                *in_pos += result.bytes_consumed;
                match result.status {
                    Ok(MZStatus::StreamEnd) => {
                        *finished = true;
                        return Ok(result.bytes_written);
                    },
                    Ok(_) => {
                        if result.bytes_written != 0 {
                            return Ok(result.bytes_written);
                        }
                        // No output yet: loop to feed more input.
                        if *in_pos == *in_len && *comp_remaining == 0 {
                            return Err(xar_error(
                                ErrorKind::Malformed,
                                "xar zlib blob ended without stream end",
                            ));
                        }
                    },
                    Err(MZError::Buf) => {
                        if result.bytes_written != 0 {
                            return Ok(result.bytes_written);
                        }
                        if *in_pos == *in_len && *comp_remaining == 0 {
                            return Err(xar_error(
                                ErrorKind::Malformed,
                                "xar zlib blob ended without stream end",
                            ));
                        }
                    },
                    Err(_) => {
                        return Err(xar_error(ErrorKind::Malformed, "xar zlib decode failed"));
                    },
                }
            }
        },
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TOC inflate
// ════════════════════════════════════════════════════════════════════════════

/// Streams the zlib-compressed TOC into a `Vec` capped at `expected` bytes.
fn inflate_toc<R: Read>(
    input: &mut R,
    comp_len: u64,
    expected: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    let mut comp_remaining = comp_len;
    let mut compressed = vec![0_u8; BUFFER];
    let mut scratch = vec![0_u8; BUFFER];
    let mut state = InflateState::new(DataFormat::Zlib);
    let mut output: Vec<u8> = Vec::with_capacity(expected.min(BUFFER));

    loop {
        let count = usize::try_from(comp_remaining.min(BUFFER as u64))
            .map_err(|_| xar_error(ErrorKind::Limit, "xar TOC chunk exceeds address space"))?;
        if count != 0 {
            input
                .read_exact(&mut compressed[..count])
                .map_err(StreamError::io)?;
            comp_remaining -= count as u64;
        }
        let mut start = 0;
        loop {
            let flush = if comp_remaining == 0 {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            let result = inflate(&mut state, &compressed[start..count], &mut scratch, flush);
            start += result.bytes_consumed;
            if output
                .len()
                .checked_add(result.bytes_written)
                .is_none_or(|size| size > expected)
            {
                return Err(xar_error(
                    ErrorKind::Malformed,
                    "xar TOC inflated beyond its declared length",
                ));
            }
            output.extend_from_slice(&scratch[..result.bytes_written]);
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    if output.len() != expected {
                        return Err(xar_error(
                            ErrorKind::Malformed,
                            "xar TOC length does not match its header",
                        ));
                    }
                    return Ok(output);
                },
                Ok(_) if result.bytes_consumed != 0 || result.bytes_written != 0 => {},
                Ok(_) | Err(MZError::Buf) => {
                    if comp_remaining == 0 && start >= count {
                        return Err(xar_error(
                            ErrorKind::Malformed,
                            "xar TOC ended without stream end",
                        ));
                    }
                    break;
                },
                Err(_) => {
                    return Err(xar_error(ErrorKind::Malformed, "xar TOC decode failed"));
                },
            }
            if start >= count && comp_remaining != 0 {
                break;
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Bounded XML pull-scanner
// ════════════════════════════════════════════════════════════════════════════

/// The leaf element whose text we are currently accumulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    None,
    Name,
    Type,
    Mode,
    Uid,
    Gid,
    Mtime,
    Link,
    Length,
    Size,
    Offset,
}

/// One open `<file>` element on the DFS stack.
#[derive(Debug, Default)]
struct Frame {
    name: Option<Vec<u8>>,
    kind: Option<EntryKind>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    has_data: bool,
    encoding: Option<XarEncoding>,
    offset: Option<u64>,
    stored_size: Option<u64>,
    length: Option<u64>,
    /// Set once the frame has been finalized into `files` (path known).
    path: Option<Vec<u8>>,
}

/// Parses the inflated TOC XML into a flat, DFS-pre-order list of resolved files.
#[allow(clippy::too_many_lines)]
fn parse_toc(xml: &[u8], limits: Limits) -> core::result::Result<Vec<XarFile>, StreamError> {
    let mut files: Vec<XarFile> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut sink = Sink::None;
    let mut text: Vec<u8> = Vec::new();
    // Inside an `<ea>` extended-attribute block, whose children mirror `<data>`
    // (name/offset/size/length/encoding). Those must NOT overwrite the file's own
    // name or data plan, so all leaf capture is suppressed until `</ea>`.
    let mut in_ea = false;
    let mut i = 0usize;
    let len = xml.len();

    while i < len {
        if xml[i] == b'<' {
            // Commit any pending leaf text first is handled at end-tag; a new tag
            // starting means structured markup begins.
            if i + 1 >= len {
                return Err(xar_error(ErrorKind::Malformed, "xar TOC truncated tag"));
            }
            match xml[i + 1] {
                b'!' => {
                    // Comment, CDATA, or DOCTYPE — skip to matching '>' (or '-->').
                    if xml[i..].starts_with(b"<!--") {
                        i = find(xml, i + 4, b"-->").map(|p| p + 3).ok_or_else(|| {
                            xar_error(ErrorKind::Malformed, "xar unterminated comment")
                        })?;
                    } else {
                        i = find_byte(xml, i + 2, b'>').map(|p| p + 1).ok_or_else(|| {
                            xar_error(ErrorKind::Malformed, "xar unterminated markup")
                        })?;
                    }
                    continue;
                },
                b'?' => {
                    i = find(xml, i + 2, b"?>")
                        .map(|p| p + 2)
                        .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar unterminated PI"))?;
                    continue;
                },
                b'/' => {
                    // End tag.
                    let close = find_byte(xml, i + 2, b'>').ok_or_else(|| {
                        xar_error(ErrorKind::Malformed, "xar unterminated end tag")
                    })?;
                    let tag = trim(&xml[i + 2..close]);
                    if tag == b"file" {
                        finalize_frame(&mut stack, &mut files, &limits)?;
                        stack.pop();
                    } else if tag == b"ea" {
                        in_ea = false;
                    } else if sink != Sink::None {
                        if !in_ea {
                            commit_text(&mut stack, sink, &text)?;
                        }
                        sink = Sink::None;
                        text.clear();
                    }
                    i = close + 1;
                    continue;
                },
                _ => {},
            }

            // Start tag (possibly self-closing).
            let close = find_byte(xml, i + 1, b'>')
                .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar unterminated start tag"))?;
            let raw = &xml[i + 1..close];
            let self_closing = raw.last() == Some(&b'/');
            let inner = if self_closing {
                &raw[..raw.len() - 1]
            } else {
                raw
            };
            let (name, attrs) = split_tag(inner);

            match name {
                b"file" => {
                    if stack.len() >= MAX_DEPTH {
                        return Err(xar_error(
                            ErrorKind::Limit,
                            "xar file nesting exceeds depth cap",
                        ));
                    }
                    // Emit the parent directory before its first child.
                    finalize_frame(&mut stack, &mut files, &limits)?;
                    stack.push(Frame::default());
                    if self_closing {
                        finalize_frame(&mut stack, &mut files, &limits)?;
                        stack.pop();
                    }
                },
                b"ea" => {
                    if !self_closing {
                        in_ea = true;
                    }
                },
                b"data" if !in_ea => {
                    if let Some(frame) = stack.last_mut() {
                        frame.has_data = true;
                    }
                },
                b"encoding" if !in_ea => {
                    if let Some(style) = attribute(attrs, b"style") {
                        let enc = classify_encoding(&style);
                        if let Some(frame) = stack.last_mut() {
                            frame.encoding = Some(enc);
                        }
                    }
                },
                b"name" if !self_closing => {
                    sink = Sink::Name;
                    text.clear();
                },
                b"type" if !self_closing => {
                    sink = Sink::Type;
                    text.clear();
                },
                b"mode" if !self_closing => {
                    sink = Sink::Mode;
                    text.clear();
                },
                b"uid" if !self_closing => {
                    sink = Sink::Uid;
                    text.clear();
                },
                b"gid" if !self_closing => {
                    sink = Sink::Gid;
                    text.clear();
                },
                b"mtime" if !self_closing => {
                    sink = Sink::Mtime;
                    text.clear();
                },
                b"link" if !self_closing => {
                    sink = Sink::Link;
                    text.clear();
                },
                b"length" if !self_closing => {
                    sink = Sink::Length;
                    text.clear();
                },
                b"size" if !self_closing => {
                    sink = Sink::Size;
                    text.clear();
                },
                b"offset" if !self_closing => {
                    sink = Sink::Offset;
                    text.clear();
                },
                _ => {},
            }
            i = close + 1;
        } else {
            // Character data.
            let next = find_byte(xml, i, b'<').unwrap_or(len);
            if sink != Sink::None {
                text.extend_from_slice(&xml[i..next]);
            }
            i = next;
        }
    }

    if !stack.is_empty() {
        return Err(xar_error(ErrorKind::Malformed, "xar TOC has unclosed file"));
    }
    Ok(files)
}

/// Finalizes the top frame into `files` if it carries name+type and has not been
/// emitted yet. Used both when descending into a child and when closing a file.
fn finalize_frame(
    stack: &mut [Frame],
    files: &mut Vec<XarFile>,
    limits: &Limits,
) -> core::result::Result<(), StreamError> {
    let Some((last, parents)) = stack.split_last_mut() else {
        return Ok(());
    };
    if last.path.is_some() {
        return Ok(());
    }
    let name = last
        .name
        .as_deref()
        .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar file without a name"))?;
    validate_name(name)?;
    let kind = last
        .kind
        .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar file without a type"))?;

    let parent_path = parents.iter().rev().find_map(|frame| frame.path.as_deref());
    let mut path = match parent_path {
        Some(prefix) if !prefix.is_empty() => {
            let mut p = prefix.to_vec();
            p.push(b'/');
            p.extend_from_slice(name);
            p
        },
        _ => name.to_vec(),
    };

    if let Some(maximum) = limits.path_bytes() {
        if path.len() > maximum {
            return Err(xar_error(
                ErrorKind::Limit,
                "xar path exceeds configured limit",
            ));
        }
    }
    if let Some(maximum) = limits.entries() {
        if files.len() as u64 >= maximum {
            return Err(xar_error(
                ErrorKind::Limit,
                "xar entry count exceeds configured limit",
            ));
        }
    }

    let data = if kind == EntryKind::File && last.has_data {
        let length = last.length.unwrap_or(0);
        let stored_size = last.stored_size.unwrap_or(length);
        let offset = last
            .offset
            .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar data without an offset"))?;
        if let Some(maximum) = limits.entry_bytes() {
            if length > maximum {
                return Err(xar_error(
                    ErrorKind::Limit,
                    "xar entry size exceeds configured limit",
                ));
            }
        }
        Some(XarData {
            encoding: last.encoding.unwrap_or(XarEncoding::Stored),
            offset,
            stored_size,
            length,
        })
    } else {
        None
    };

    let record = XarFile {
        path: path.clone(),
        kind,
        mode: last.mode,
        uid: last.uid,
        gid: last.gid,
        mtime: last.mtime,
        link_target: last.link_target.clone(),
        data,
    };
    last.path = Some(std::mem::take(&mut path));
    files.push(record);
    Ok(())
}

/// Commits accumulated leaf text to the top frame's corresponding field.
fn commit_text(
    stack: &mut [Frame],
    sink: Sink,
    text: &[u8],
) -> core::result::Result<(), StreamError> {
    let Some(frame) = stack.last_mut() else {
        return Ok(());
    };
    match sink {
        Sink::Name => frame.name = Some(xml_unescape(trim(text))),
        Sink::Type => frame.kind = Some(map_kind(trim(text))),
        Sink::Mode => {
            frame.mode = parse_octal(trim(text));
        },
        Sink::Uid => frame.uid = parse_u64(trim(text)),
        Sink::Gid => frame.gid = parse_u64(trim(text)),
        Sink::Mtime => frame.mtime = parse_iso8601(trim(text)),
        Sink::Link => frame.link_target = Some(xml_unescape(trim(text))),
        Sink::Length => {
            frame.length = Some(
                parse_u64(trim(text))
                    .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar bad data length"))?,
            );
        },
        Sink::Size => {
            frame.stored_size = Some(
                parse_u64(trim(text))
                    .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar bad data size"))?,
            );
        },
        Sink::Offset => {
            frame.offset = Some(
                parse_u64(trim(text))
                    .ok_or_else(|| xar_error(ErrorKind::Malformed, "xar bad data offset"))?,
            );
        },
        Sink::None => {},
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// Small helpers
// ════════════════════════════════════════════════════════════════════════════

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn find_byte(haystack: &[u8], from: usize, byte: u8) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    haystack[from..]
        .iter()
        .position(|&b| b == byte)
        .map(|p| p + from)
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |p| p + 1);
    &bytes[start..end]
}

/// Splits a start-tag body into `(tag_name, remaining_attrs)`.
fn split_tag(inner: &[u8]) -> (&[u8], &[u8]) {
    let inner = trim(inner);
    let split = inner
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(inner.len());
    (&inner[..split], &inner[split..])
}

/// Extracts the quoted value of `key` from an attribute run.
fn attribute(attrs: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < attrs.len() {
        while i < attrs.len() && attrs[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < attrs.len() && attrs[i] != b'=' && !attrs[i].is_ascii_whitespace() {
            i += 1;
        }
        let name = &attrs[name_start..i];
        while i < attrs.len() && attrs[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= attrs.len() || attrs[i] != b'=' {
            if name.is_empty() {
                break;
            }
            continue;
        }
        i += 1; // skip '='
        while i < attrs.len() && attrs[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= attrs.len() {
            break;
        }
        let quote = attrs[i];
        if quote != b'"' && quote != b'\'' {
            break;
        }
        i += 1;
        let value_start = i;
        while i < attrs.len() && attrs[i] != quote {
            i += 1;
        }
        if i > attrs.len() {
            break;
        }
        let value = &attrs[value_start..i.min(attrs.len())];
        if name == key {
            return Some(xml_unescape(value));
        }
        i += 1; // skip closing quote
    }
    None
}

fn classify_encoding(style: &[u8]) -> XarEncoding {
    match style {
        b"application/octet-stream" => XarEncoding::Stored,
        b"application/x-gzip" => XarEncoding::Zlib,
        _ => XarEncoding::Unsupported,
    }
}

fn map_kind(type_bytes: &[u8]) -> EntryKind {
    match type_bytes {
        b"directory" => EntryKind::Dir,
        b"symlink" => EntryKind::Symlink,
        _ => EntryKind::File,
    }
}

/// Rejects empty, `.`/`..`, and any `/`-bearing basename.
fn validate_name(name: &[u8]) -> core::result::Result<(), StreamError> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(xar_error(
            ErrorKind::Malformed,
            "xar file has an invalid name",
        ));
    }
    Ok(())
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

fn parse_octal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &b in bytes {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(value)
}

/// Best-effort ISO-8601 (`YYYY-MM-DDThh:mm:ssZ`) → UNIX timestamp; `None` on any
/// deviation so a malformed mtime never fails a read.
fn parse_iso8601(bytes: &[u8]) -> Option<Timestamp> {
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let year = i64::try_from(parse_u64(&bytes[0..4])?).ok()?;
    let month = i64::try_from(parse_u64(&bytes[5..7])?).ok()?;
    let day = i64::try_from(parse_u64(&bytes[8..10])?).ok()?;
    let hour = i64::try_from(parse_u64(&bytes[11..13])?).ok()?;
    let minute = i64::try_from(parse_u64(&bytes[14..16])?).ok()?;
    let second = i64::try_from(parse_u64(&bytes[17..19])?).ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?;
    Some(Timestamp { secs, nanos: 0 })
}

/// Decodes the five standard XML entities; leaves unknown `&…;` runs literal.
fn xml_unescape(input: &[u8]) -> Vec<u8> {
    if !input.contains(&b'&') {
        return input.to_vec();
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&' {
            if input[i..].starts_with(b"&amp;") {
                out.push(b'&');
                i += 5;
                continue;
            } else if input[i..].starts_with(b"&lt;") {
                out.push(b'<');
                i += 4;
                continue;
            } else if input[i..].starts_with(b"&gt;") {
                out.push(b'>');
                i += 4;
                continue;
            } else if input[i..].starts_with(b"&quot;") {
                out.push(b'"');
                i += 6;
                continue;
            } else if input[i..].starts_with(b"&apos;") {
                out.push(b'\'');
                i += 6;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}
