// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, seek-native LHA/LZH reader.
//!
//! `delharc` supplies the fixed-dictionary streaming method decoders, while the sibling codec crate supplies bounded whole-payload LH2/LH3 decoding.
//! This adapter owns the container/resource boundary: header reads are metered as metadata before an upstream allocation can grow, declared extents are checked against the source, and every output/path/count/workspace budget is validated before a method decoder is constructed.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use delharc::crc::Crc16;
use delharc::decode::DecoderAny;
use delharc::header::ext::{
    EXT_HEADER_COMMENT, EXT_HEADER_FILENAME, EXT_HEADER_PATH, EXT_HEADER_UNIX_GROUP,
    EXT_HEADER_UNIX_OWNER, EXT_HEADER_UNIX_PERM, EXT_HEADER_UNIX_UIDGID,
};
use delharc::{LhaDecodeReader, LhaError, LhaHeader, MsDosAttrs};
use libarchive_oxide_codecs::lha::{Lh2Decoder, Lh3Decoder};
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, Codec, CodecStatus, CodecStep, EndOfInput,
    EntryKind, EntryMetadata, EntryTimes, ErrorKind, Extension, FormatId, Limits, Owner,
    ProbeResult, Timestamp,
};

use crate::{ReaderEvent, StreamError};

const BUFFER: usize = 64 * 1024;
const LHA_MIN_HEADER: usize = 22;
const MAX_SFX_BYTES: u64 = 20 * 1024;
const SFX_WINDOW: usize = 4 * 1024;
const BUFFERED_CODEC_INPUT_WINDOW: usize = 8 * 1024;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn lha_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("lha")
            .with_context(context),
    )
}

#[derive(Debug, Clone, Copy)]
enum Region {
    Metadata,
    Payload { remaining: u64 },
}

#[derive(Debug)]
struct GuardState {
    region: Region,
    metadata_remaining: Option<usize>,
    metadata_limit_hit: bool,
}

impl GuardState {
    const fn new(metadata_remaining: Option<usize>) -> Self {
        Self {
            region: Region::Metadata,
            metadata_remaining,
            metadata_limit_hit: false,
        }
    }
}

/// Reader whose shared state changes automatically from a declared payload extent back to metered header bytes.
/// A single read never crosses that boundary, so decoder look-ahead cannot consume a following header.
struct Guarded<R> {
    inner: Arc<Mutex<R>>,
    control: Arc<Mutex<GuardState>>,
    file_length: u64,
}

impl<R> fmt::Debug for Guarded<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Guarded")
            .field("file_length", &self.file_length)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Read for Guarded<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let allowed = {
            let mut state = locked(&self.control);
            match state.region {
                Region::Metadata => match state.metadata_remaining {
                    Some(0) => {
                        state.metadata_limit_hit = true;
                        return Err(io::Error::other("LHA metadata budget exceeded"));
                    },
                    Some(remaining) => output.len().min(remaining),
                    None => output.len(),
                },
                Region::Payload { remaining: 0 } => return Ok(0),
                Region::Payload { remaining } => {
                    usize::try_from(remaining.min(u64::try_from(output.len()).unwrap_or(u64::MAX)))
                        .unwrap_or(output.len())
                },
            }
        };
        let count = locked(&self.inner).read(&mut output[..allowed])?;
        let mut state = locked(&self.control);
        match &mut state.region {
            Region::Metadata => {
                if let Some(remaining) = &mut state.metadata_remaining {
                    *remaining = remaining.saturating_sub(count);
                }
            },
            Region::Payload { remaining } => {
                *remaining = remaining.saturating_sub(count as u64);
            },
        }
        Ok(count)
    }
}

impl<R: Seek> Guarded<R> {
    fn finish_payload(&mut self) -> Result<(), StreamError> {
        let remaining = match locked(&self.control).region {
            Region::Payload { remaining } => remaining,
            Region::Metadata => 0,
        };
        if remaining != 0 {
            let position = locked(&self.inner)
                .stream_position()
                .map_err(StreamError::io)?;
            let end = position
                .checked_add(remaining)
                .filter(|&end| end <= self.file_length)
                .ok_or_else(|| {
                    lha_error(ErrorKind::Malformed, "LHA payload extends beyond source")
                })?;
            locked(&self.inner)
                .seek(SeekFrom::Start(end))
                .map_err(StreamError::io)?;
        }
        locked(&self.control).region = Region::Metadata;
        Ok(())
    }

    fn payload_fits(&mut self, length: u64) -> Result<(), StreamError> {
        let position = locked(&self.inner)
            .stream_position()
            .map_err(StreamError::io)?;
        position
            .checked_add(length)
            .filter(|&end| end <= self.file_length)
            .ok_or_else(|| lha_error(ErrorKind::Malformed, "LHA payload extends beyond source"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ArchiveMetadata,
    Entry,
    Data,
    Unsupported,
    EndEntry,
    Advance,
    Header,
    Done,
}

enum LhaMemberReader<R: Read> {
    Standard(LhaDecodeReader<R>),
    Buffered(Box<BufferedMemberReader<R>>),
}

impl<R: Read> LhaMemberReader<R> {
    fn header(&self) -> &LhaHeader {
        match self {
            Self::Standard(reader) => reader.header(),
            Self::Buffered(reader) => &reader.header,
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Standard(reader) => reader.len(),
            Self::Buffered(reader) => reader.output_remaining,
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn is_decoder_supported(&self) -> bool {
        match self {
            Self::Standard(reader) => reader.is_decoder_supported(),
            Self::Buffered(_) => true,
        }
    }

    fn verify_crc(&mut self) -> Result<(), StreamError> {
        match self {
            Self::Standard(reader) => verify_standard_crc(reader),
            Self::Buffered(reader) => reader.finish_and_verify(),
        }
    }

    fn into_inner(self) -> R {
        match self {
            Self::Standard(reader) => reader.into_inner(),
            Self::Buffered(reader) => {
                let BufferedMemberReader { source, .. } = *reader;
                source
            },
        }
    }
}

impl<R: Read> Read for LhaMemberReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Standard(reader) => reader.read(output),
            Self::Buffered(reader) => reader.read(output),
        }
    }
}

struct BufferedMemberReader<R: Read> {
    header: LhaHeader,
    source: R,
    decoder: BufferedDecoder,
    input: [u8; BUFFERED_CODEC_INPUT_WINDOW],
    input_start: usize,
    input_end: usize,
    packed_remaining: u64,
    output_remaining: u64,
    crc: Crc16,
    done: bool,
}

enum BufferedDecoder {
    Lh2(Box<Lh2Decoder>),
    Lh3(Lh3Decoder),
}

impl Codec for BufferedDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self {
            Self::Lh2(decoder) => decoder.process(input, output, end),
            Self::Lh3(decoder) => decoder.process(input, output, end),
        }
    }
}

impl<R: Read> BufferedMemberReader<R> {
    fn new(header: LhaHeader, source: R, decoder: BufferedDecoder) -> Self {
        let packed_remaining = header.compressed_size;
        let output_remaining = header.original_size;
        Self {
            header,
            source,
            decoder,
            input: [0; BUFFERED_CODEC_INPUT_WINDOW],
            input_start: 0,
            input_end: 0,
            packed_remaining,
            output_remaining,
            crc: Crc16::default(),
            done: false,
        }
    }

    fn fill_input(&mut self) -> io::Result<()> {
        if self.input_start != self.input_end || self.packed_remaining == 0 {
            return Ok(());
        }
        let amount = usize::try_from(
            self.packed_remaining
                .min(BUFFERED_CODEC_INPUT_WINDOW as u64),
        )
        .unwrap_or(BUFFERED_CODEC_INPUT_WINDOW);
        let count = self.source.read(&mut self.input[..amount])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "LHA buffered payload is truncated",
            ));
        }
        self.input_start = 0;
        self.input_end = count;
        self.packed_remaining = self.packed_remaining.saturating_sub(count as u64);
        Ok(())
    }

    fn advance_input(&mut self, consumed: usize) -> io::Result<()> {
        self.input_start = self.input_start.checked_add(consumed).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "LHA buffered codec input offset overflow",
            )
        })?;
        if self.input_start > self.input_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LHA buffered codec consumed beyond its input window",
            ));
        }
        if self.input_start == self.input_end {
            self.input_start = 0;
            self.input_end = 0;
        }
        Ok(())
    }

    fn codec_end(&self) -> EndOfInput {
        if self.packed_remaining == 0 {
            EndOfInput::End
        } else {
            EndOfInput::More
        }
    }

    fn finish_and_verify(&mut self) -> Result<(), StreamError> {
        if self.output_remaining != 0 {
            return Err(lha_error(
                ErrorKind::Malformed,
                "LHA buffered payload ended before declared output size",
            ));
        }
        while !self.done {
            self.fill_input().map_err(StreamError::io)?;
            let end = self.codec_end();
            let input = &self.input[self.input_start..self.input_end];
            let mut probe = [0_u8; 1];
            let step = self
                .decoder
                .process(input, &mut probe, end)
                .map_err(StreamError::archive)?
                .validate(input.len(), probe.len())
                .map_err(StreamError::archive)?;
            self.advance_input(step.consumed).map_err(StreamError::io)?;
            if step.produced != 0 {
                return Err(lha_error(
                    ErrorKind::Malformed,
                    "LHA buffered codec produced bytes beyond the declared output size",
                ));
            }
            if step.status == CodecStatus::Done {
                self.done = true;
            } else if step.consumed == 0 {
                return Err(lha_error(
                    ErrorKind::Protocol,
                    "LHA buffered codec stalled while validating its terminator",
                ));
            }
        }
        if self.crc.sum16() != self.header.file_crc {
            return Err(lha_error(
                ErrorKind::Integrity,
                "LHA payload CRC16 mismatch",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for BufferedMemberReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.output_remaining == 0 {
            return Ok(0);
        }
        let amount =
            usize::try_from(self.output_remaining.min(output.len() as u64)).unwrap_or(output.len());
        loop {
            self.fill_input()?;
            let end = self.codec_end();
            let input = &self.input[self.input_start..self.input_end];
            let step = self
                .decoder
                .process(input, &mut output[..amount], end)
                .map_err(codec_io_error)?
                .validate(input.len(), amount)
                .map_err(codec_io_error)?;
            self.advance_input(step.consumed)?;
            if step.produced as u64 > self.output_remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LHA buffered codec exceeded the declared output size",
                ));
            }
            self.output_remaining -= step.produced as u64;
            self.crc.digest(&output[..step.produced]);
            if step.status == CodecStatus::Done {
                if self.output_remaining != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LHA buffered codec ended before the declared output size",
                    ));
                }
                self.done = true;
            }
            if step.produced != 0 {
                return Ok(step.produced);
            }
            match step.status {
                CodecStatus::Done => return Ok(0),
                CodecStatus::NeedInput if step.consumed != 0 => {},
                CodecStatus::NeedOutput => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LHA buffered codec requested output without making progress",
                    ));
                },
                CodecStatus::NeedInput => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LHA buffered codec requested input without making progress",
                    ));
                },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LHA buffered codec returned an unknown status",
                    ));
                },
            }
        }
    }
}

fn codec_io_error(error: ArchiveError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Streaming LHA reader over a seekable source.
pub(crate) struct LhaSeekReader<R: Read + Seek> {
    reader: Option<LhaMemberReader<Guarded<R>>>,
    source: Option<Guarded<R>>,
    input: Arc<Mutex<R>>,
    control: Arc<Mutex<GuardState>>,
    limits: Limits,
    phase: Phase,
    event_data: Vec<u8>,
    event_chunk: usize,
    entries: u64,
    declared_total: u64,
    sfx_offset: u64,
}

impl<R: Read + Seek> fmt::Debug for LhaSeekReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LhaSeekReader")
            .field("phase", &self.phase)
            .field("entries", &self.entries)
            .field("declared_total", &self.declared_total)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> LhaSeekReader<R> {
    pub(crate) fn new(mut input: R, limits: Limits) -> Result<Self, StreamError> {
        let file_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let mut marker = [0_u8; 2];
        let marker_length = read_up_to(&mut input, &mut marker).map_err(StreamError::io)?;
        input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let sfx_offset = if marker_length == marker.len() && marker == *b"MZ" {
            Self::find_sfx_header(&mut input)?.ok_or_else(|| {
                lha_error(
                    ErrorKind::Limit,
                    "LHA header was not found within the 20 KiB SFX prefix limit",
                )
            })?
        } else {
            0
        };
        input
            .seek(SeekFrom::Start(sfx_offset))
            .map_err(StreamError::io)?;
        let event_chunk = limits.in_flight_bytes().unwrap_or(BUFFER).min(BUFFER);
        let control = Arc::new(Mutex::new(GuardState::new(limits.metadata_bytes())));
        let input = Arc::new(Mutex::new(input));
        let guarded = Guarded {
            inner: Arc::clone(&input),
            control: Arc::clone(&control),
            file_length,
        };
        let mut this = Self {
            reader: None,
            source: Some(guarded),
            input,
            control,
            limits,
            phase: Phase::ArchiveMetadata,
            event_data: Vec::with_capacity(event_chunk),
            event_chunk,
            entries: 0,
            declared_total: 0,
            sfx_offset,
        };
        if !this.parse_next_header()? {
            return Err(lha_error(
                ErrorKind::Malformed,
                "LHA archive has no member header",
            ));
        }
        Ok(this)
    }

    pub(crate) fn find_sfx_header(input: &mut R) -> Result<Option<u64>, StreamError> {
        let original = input.stream_position().map_err(StreamError::io)?;
        let result = find_sfx_header(input);
        input
            .seek(SeekFrom::Start(original))
            .map_err(StreamError::io)?;
        result
    }

    pub(crate) fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        loop {
            match self.phase {
                Phase::ArchiveMetadata => {
                    self.phase = Phase::Entry;
                    let metadata = if self.sfx_offset == 0 {
                        ArchiveMetadata::new()
                    } else {
                        ArchiveMetadata::new().with_extension(Extension::new(
                            "lha",
                            b"sfx-prefix-bytes".to_vec(),
                            self.sfx_offset.to_le_bytes().to_vec(),
                        ))
                    };
                    return Ok(ReaderEvent::ArchiveMetadata(metadata));
                },
                Phase::Entry => {
                    let reader = self.reader.as_ref().ok_or_else(|| {
                        lha_error(ErrorKind::Protocol, "LHA member reader is absent")
                    })?;
                    let metadata = metadata_from_header(reader.header(), self.limits)?;
                    if reader.header().is_directory() {
                        self.phase = Phase::EndEntry;
                    } else if !reader.is_decoder_supported() {
                        self.phase = Phase::Unsupported;
                    } else {
                        self.phase = Phase::Data;
                    }
                    return Ok(ReaderEvent::Entry(metadata));
                },
                Phase::Data => {
                    let control = Arc::clone(&self.control);
                    let reader = self.reader.as_mut().ok_or_else(|| {
                        lha_error(ErrorKind::Protocol, "LHA member reader is absent")
                    })?;
                    if reader.is_empty() {
                        reader.verify_crc()?;
                        self.phase = Phase::EndEntry;
                        continue;
                    }
                    if self.event_chunk == 0 {
                        return Err(lha_error(
                            ErrorKind::Limit,
                            "LHA payload cannot progress under a zero in-flight byte limit",
                        ));
                    }
                    let amount = usize::try_from(reader.len().min(self.event_chunk as u64))
                        .map_err(|_| {
                            lha_error(ErrorKind::Limit, "LHA chunk exceeds address space")
                        })?;
                    self.event_data.resize(amount, 0);
                    let count = reader.read(&mut self.event_data).map_err(|error| {
                        map_read_error(&control, error, "LHA payload decode failed")
                    })?;
                    if count == 0 {
                        return Err(lha_error(
                            ErrorKind::Malformed,
                            "LHA payload ended before declared output size",
                        ));
                    }
                    self.event_data.truncate(count);
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                Phase::Unsupported => {
                    return Err(lha_error(
                        ErrorKind::Unsupported,
                        "LHA compression method is unsupported",
                    ));
                },
                Phase::EndEntry => {
                    self.phase = Phase::Advance;
                    return Ok(ReaderEvent::EndEntry);
                },
                Phase::Advance => {
                    self.release_current()?;
                    self.phase = Phase::Header;
                },
                Phase::Header => {
                    if self.parse_next_header()? {
                        self.phase = Phase::Entry;
                    } else {
                        self.phase = Phase::Done;
                    }
                },
                Phase::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> Result<(), StreamError> {
        match self.phase {
            Phase::Data => {
                if self.event_chunk == 0 {
                    return Err(lha_error(
                        ErrorKind::Limit,
                        "LHA payload cannot progress under a zero in-flight byte limit",
                    ));
                }
                let mut scratch = vec![0_u8; self.event_chunk];
                let control = Arc::clone(&self.control);
                let reader = self
                    .reader
                    .as_mut()
                    .ok_or_else(|| lha_error(ErrorKind::Protocol, "LHA member reader is absent"))?;
                while !reader.is_empty() {
                    let amount = usize::try_from(reader.len().min(self.event_chunk as u64))
                        .map_err(|_| {
                            lha_error(ErrorKind::Limit, "LHA chunk exceeds address space")
                        })?;
                    let count = reader.read(&mut scratch[..amount]).map_err(|error| {
                        map_read_error(&control, error, "LHA payload decode failed while skipping")
                    })?;
                    if count == 0 {
                        return Err(lha_error(
                            ErrorKind::Malformed,
                            "LHA payload ended before declared output size",
                        ));
                    }
                }
                reader.verify_crc()?;
                self.phase = Phase::EndEntry;
                Ok(())
            },
            Phase::Unsupported => {
                self.phase = Phase::EndEntry;
                Ok(())
            },
            Phase::EndEntry => Ok(()),
            Phase::ArchiveMetadata
            | Phase::Entry
            | Phase::Advance
            | Phase::Header
            | Phase::Done => Err(lha_error(
                ErrorKind::Protocol,
                "skip_entry called without an open LHA payload",
            )),
        }
    }

    pub(crate) fn into_inner(mut self) -> Result<R, ArchiveError> {
        if let Some(reader) = self.reader.take() {
            drop(reader.into_inner());
        }
        drop(self.source.take());
        let input = Arc::try_unwrap(self.input).map_err(|_| {
            ArchiveError::new(ErrorKind::Protocol)
                .with_format("lha")
                .with_context("LHA source still has outstanding owners")
        })?;
        Ok(input.into_inner().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn with_source<T>(&self, inspect: impl FnOnce(&R) -> T) -> T {
        let input = locked(&self.input);
        inspect(&input)
    }

    fn release_current(&mut self) -> Result<(), StreamError> {
        let reader = self
            .reader
            .take()
            .ok_or_else(|| lha_error(ErrorKind::Protocol, "LHA member reader is absent"))?;
        let mut guarded = reader.into_inner();
        guarded.finish_payload()?;
        self.source = Some(guarded);
        Ok(())
    }

    fn parse_next_header(&mut self) -> Result<bool, StreamError> {
        let mut guarded = self.source.take().ok_or_else(|| {
            lha_error(
                ErrorKind::Protocol,
                "LHA source is absent while parsing a header",
            )
        })?;
        locked(&self.control).region = Region::Metadata;
        let header_start = locked(&guarded.inner)
            .stream_position()
            .map_err(StreamError::io)?;
        let metadata_before = locked(&self.control).metadata_remaining;
        let header = match LhaHeader::read(&mut guarded) {
            Ok(Some(header)) => header,
            Ok(None) => {
                self.source = Some(guarded);
                return Ok(false);
            },
            Err(LhaError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                locked(&guarded.inner)
                    .seek(SeekFrom::Start(header_start))
                    .map_err(StreamError::io)?;
                let mut control = locked(&self.control);
                control.metadata_remaining = metadata_before;
                control.metadata_limit_hit = false;
                drop(control);
                self.source = Some(guarded);
                return Err(StreamError::io(error));
            },
            Err(LhaError::Io(_)) if locked(&self.control).metadata_limit_hit => {
                self.source = Some(guarded);
                return Err(lha_error(ErrorKind::Limit, "LHA metadata budget exceeded"));
            },
            Err(LhaError::Io(error)) if error.kind() != io::ErrorKind::UnexpectedEof => {
                self.source = Some(guarded);
                return Err(StreamError::io(error));
            },
            Err(_) => {
                self.source = Some(guarded);
                return Err(lha_error(
                    ErrorKind::Malformed,
                    "invalid or truncated LHA header",
                ));
            },
        };
        self.validate_header(&mut guarded, &header)?;
        locked(&self.control).region = Region::Payload {
            remaining: header.compressed_size,
        };
        let reader = if header.compression == *b"-lh2-" || header.compression == *b"-lh3-" {
            let decoder = if header.compression == *b"-lh2-" {
                BufferedDecoder::Lh2(Box::new(
                    Lh2Decoder::new(
                        header.compressed_size,
                        header.original_size,
                        BUFFERED_CODEC_INPUT_WINDOW,
                        self.limits,
                    )
                    .map_err(StreamError::archive)?,
                ))
            } else {
                BufferedDecoder::Lh3(
                    Lh3Decoder::new(
                        header.compressed_size,
                        header.original_size,
                        BUFFERED_CODEC_INPUT_WINDOW,
                        self.limits,
                    )
                    .map_err(StreamError::archive)?,
                )
            };
            LhaMemberReader::Buffered(Box::new(BufferedMemberReader::new(
                header, guarded, decoder,
            )))
        } else {
            let decoder = DecoderAny::new_from_header(&header, guarded);
            let mut reader = LhaDecodeReader::default();
            reader.begin_with_header_and_decoder(header, decoder);
            LhaMemberReader::Standard(reader)
        };
        self.reader = Some(reader);
        Ok(true)
    }

    fn validate_header(
        &mut self,
        guarded: &mut Guarded<R>,
        header: &LhaHeader,
    ) -> Result<(), StreamError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| lha_error(ErrorKind::Limit, "LHA entry count overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| self.entries > maximum)
        {
            return Err(lha_error(ErrorKind::Limit, "LHA entry count exceeds limit"));
        }
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| header.original_size > maximum)
        {
            return Err(lha_error(
                ErrorKind::Limit,
                "LHA entry exceeds output limit",
            ));
        }
        self.declared_total = self
            .declared_total
            .checked_add(header.original_size)
            .ok_or_else(|| lha_error(ErrorKind::Limit, "LHA decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| self.declared_total > maximum)
        {
            return Err(lha_error(
                ErrorKind::Limit,
                "LHA decoded total exceeds limit",
            ));
        }
        if header.original_size > usize::MAX as u64 {
            return Err(lha_error(
                ErrorKind::Limit,
                "LHA entry size exceeds this address space",
            ));
        }
        let workspace = method_workspace(header.compression);
        if self
            .limits
            .codec_memory()
            .zip(workspace)
            .is_some_and(|(maximum, required)| required > maximum)
        {
            return Err(lha_error(
                ErrorKind::Limit,
                "LHA method dictionary exceeds codec memory limit",
            ));
        }
        let _ = metadata_from_header(header, self.limits)?;
        guarded.payload_fits(header.compressed_size)?;
        Ok(())
    }
}

fn find_sfx_header<R: Read + Seek>(input: &mut R) -> Result<Option<u64>, StreamError> {
    input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    let mut marker = [0_u8; 2];
    if read_up_to(input, &mut marker).map_err(StreamError::io)? != marker.len() || marker != *b"MZ"
    {
        return Ok(None);
    }

    let mut window = [0_u8; SFX_WINDOW + LHA_MIN_HEADER];
    let mut block_start = 0_u64;
    while block_start <= MAX_SFX_BYTES {
        input
            .seek(SeekFrom::Start(block_start))
            .map_err(StreamError::io)?;
        let length = read_up_to(input, &mut window).map_err(StreamError::io)?;
        let candidate_bytes = usize::try_from(MAX_SFX_BYTES - block_start)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .min(SFX_WINDOW)
            .min(length.saturating_sub(LHA_MIN_HEADER - 1));
        for relative in 0..candidate_bytes {
            let candidate = &window[relative..];
            if looks_like_lha_header(candidate) {
                return block_start
                    .checked_add(relative as u64)
                    .map(Some)
                    .ok_or_else(|| lha_error(ErrorKind::Limit, "LHA SFX offset overflow"));
            }
        }
        if length < window.len() {
            return Ok(None);
        }
        block_start = block_start
            .checked_add(SFX_WINDOW as u64)
            .ok_or_else(|| lha_error(ErrorKind::Limit, "LHA SFX scan offset overflow"))?;
    }
    Ok(None)
}

fn looks_like_lha_header(candidate: &[u8]) -> bool {
    candidate.len() >= LHA_MIN_HEADER
        && matches!(
            FormatId::probe(&candidate[..7]),
            ProbeResult::Match(FormatId::Lha)
        )
        && candidate[20] <= 3
}

fn read_up_to(reader: &mut impl Read, output: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < output.len() {
        match reader.read(&mut output[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn map_read_error(
    control: &Arc<Mutex<GuardState>>,
    error: io::Error,
    context: &'static str,
) -> StreamError {
    if let Some(archive) = crate::stream::archive_error_from_io(&error) {
        StreamError::archive(archive)
    } else if locked(control).metadata_limit_hit {
        lha_error(ErrorKind::Limit, "LHA metadata budget exceeded")
    } else if error.kind() == io::ErrorKind::WouldBlock {
        StreamError::io(error)
    } else if matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
    ) {
        lha_error(ErrorKind::Malformed, context)
    } else {
        StreamError::io(error)
    }
}

fn verify_standard_crc<R: Read>(reader: &LhaDecodeReader<R>) -> Result<(), StreamError> {
    reader.crc_check().map_err(|error| match error {
        LhaError::Checksum => lha_error(ErrorKind::Integrity, "LHA payload CRC16 mismatch"),
        _ => lha_error(ErrorKind::Malformed, "LHA payload verification failed"),
    })?;
    Ok(())
}

fn method_workspace(method: [u8; 5]) -> Option<usize> {
    match method.as_slice() {
        b"-lzs-" => Some(2 * 1024),
        b"-lz5-" | b"-lh1-" | b"-lh4-" => Some(4 * 1024),
        b"-lh2-" | b"-lh3-" | b"-lh5-" | b"-pm2-" => Some(8 * 1024),
        b"-pm1-" => Some(16 * 1024),
        b"-lh6-" => Some(32 * 1024),
        b"-lh7-" => Some(64 * 1024),
        b"-lhx-" => Some(512 * 1024),
        b"-lh0-" | b"-lz4-" | b"-pm0-" | b"-lhd-" => Some(0),
        _ => None,
    }
}

fn metadata_from_header(header: &LhaHeader, limits: Limits) -> Result<EntryMetadata, StreamError> {
    let mut path = raw_path(header);
    let mut link_target = None;
    if header.is_directory()
        && let Some(separator) = path.iter().position(|&byte| byte == b'|')
    {
        let target = path.split_off(separator + 1);
        path.pop();
        if target.is_empty() {
            return Err(lha_error(
                ErrorKind::Malformed,
                "LHA symbolic link target is empty",
            ));
        }
        link_target = Some(ArchivePath::from_bytes(target));
    }
    if path.is_empty() {
        return Err(lha_error(ErrorKind::Malformed, "LHA entry path is empty"));
    }
    if limits
        .path_bytes()
        .is_some_and(|maximum| path.len() > maximum)
    {
        return Err(lha_error(ErrorKind::Limit, "LHA entry path exceeds limit"));
    }
    let depth = path
        .split(|&byte| byte == b'/')
        .filter(|p| !p.is_empty())
        .count();
    if limits.nesting().is_some_and(|maximum| depth > maximum) {
        return Err(lha_error(
            ErrorKind::Limit,
            "LHA entry nesting exceeds limit",
        ));
    }

    let kind = if link_target.is_some() || header.msdos_attrs.contains(MsDosAttrs::SYMLINK) {
        EntryKind::Symlink
    } else if header.is_directory() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    let (mode, owner, comment, extensions) = metadata_extensions(header);
    let modified = header
        .parse_last_modified()
        .to_utc()
        .map(|time| Timestamp::new(time.timestamp(), time.timestamp_subsec_nanos()))
        .transpose()?;
    let mut builder = EntryMetadata::builder(kind, ArchivePath::from_bytes(path))
        .size(Some(if kind == EntryKind::Dir {
            0
        } else {
            header.original_size
        }))
        .mode(mode)
        .owner(owner)
        .times(EntryTimes {
            modified,
            accessed: None,
            changed: None,
            created: None,
        })
        .link_target(link_target)
        .comment(comment);
    for extension in extensions {
        builder = builder.extension(extension);
    }
    builder
        .try_build()
        .map_err(|_| lha_error(ErrorKind::Malformed, "invalid LHA entry metadata"))
}

fn metadata_extensions(
    header: &LhaHeader,
) -> (Option<u32>, Owner, Option<Vec<u8>>, Vec<Extension>) {
    let mut mode = None;
    let mut owner = Owner::default();
    let mut comment = None;
    let mut extensions = Vec::new();
    for extra in header.iter_extra() {
        let Some((&identifier, data)) = extra.split_first() else {
            continue;
        };
        match identifier {
            EXT_HEADER_UNIX_PERM if data.len() >= 2 => {
                mode = Some(u32::from(u16::from_le_bytes([data[0], data[1]])) & 0o7777);
            },
            EXT_HEADER_UNIX_UIDGID if data.len() >= 4 => {
                owner.gid = Some(u64::from(u16::from_le_bytes([data[0], data[1]])));
                owner.uid = Some(u64::from(u16::from_le_bytes([data[2], data[3]])));
            },
            EXT_HEADER_UNIX_GROUP => owner.group = Some(data.to_vec()),
            EXT_HEADER_UNIX_OWNER => owner.user = Some(data.to_vec()),
            EXT_HEADER_COMMENT => comment = Some(data.to_vec()),
            _ => {},
        }
        extensions.push(Extension::new("lha-extra", vec![identifier], data.to_vec()));
    }
    if !header.extended_area.is_empty() {
        extensions.push(Extension::new(
            "lha",
            b"extended-area".to_vec(),
            header.extended_area.to_vec(),
        ));
    }
    extensions.push(Extension::new(
        "lha",
        b"method".to_vec(),
        header.compression.to_vec(),
    ));
    extensions.push(Extension::new(
        "lha",
        b"header-level".to_vec(),
        vec![header.level],
    ));
    extensions.push(Extension::new(
        "lha",
        b"crc16".to_vec(),
        header.file_crc.to_le_bytes().to_vec(),
    ));
    (mode, owner, comment, extensions)
}

fn raw_path(header: &LhaHeader) -> Vec<u8> {
    let mut directory: Option<&[u8]> = None;
    let mut filename: &[u8] = &header.filename;
    for extra in header.iter_extra() {
        match extra {
            [EXT_HEADER_FILENAME, data @ ..] => filename = data,
            [EXT_HEADER_PATH, data @ ..] => directory = Some(data),
            _ => {},
        }
    }
    let mut path = Vec::new();
    if let Some(directory) = directory {
        append_path_bytes(&mut path, directory);
        if !path.is_empty() && !path.ends_with(b"/") {
            path.push(b'/');
        }
    }
    append_path_bytes(&mut path, filename);
    let leading_separators = path.iter().take_while(|&&byte| byte == b'/').count();
    if leading_separators != 0 {
        path.drain(..leading_separators);
    }
    while path.ends_with(b"/") && path.len() > 1 {
        path.pop();
    }
    path
}

fn append_path_bytes(output: &mut Vec<u8>, input: &[u8]) {
    for &byte in input {
        output.push(match byte {
            b'\\' | 0xff => b'/',
            other => other,
        });
    }
}
