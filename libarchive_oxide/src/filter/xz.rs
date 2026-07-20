// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust, caller-driven XZ/LZMA2 codec state.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;

use libarchive_oxide_core::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

const BUFFER: usize = 64 * 1024;
const MAX_HEADER: usize = 1024;
const MAX_STAGED: usize = BUFFER + MAX_HEADER + 32;
const XZ_MAGIC: &[u8; 6] = &[0xfd, b'7', b'z', b'X', b'Z', 0];
const INDEX_RECORD_BYTES: usize = size_of::<u64>() * 2;

enum InputMessage {
    Data(Vec<u8>),
    End,
}

#[derive(Debug)]
enum WorkerEvent {
    NeedInput,
    Output(Vec<u8>),
}

struct InputPipe {
    receiver: Receiver<InputMessage>,
    events: SyncSender<WorkerEvent>,
    current: Vec<u8>,
    position: usize,
    ended: bool,
}

impl Read for InputPipe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        loop {
            if self.position != self.current.len() {
                let copied = (self.current.len() - self.position).min(output.len() - written);
                output[written..written + copied]
                    .copy_from_slice(&self.current[self.position..self.position + copied]);
                self.position += copied;
                written += copied;
                if self.position == self.current.len() {
                    self.current.clear();
                    self.position = 0;
                }
                if written == output.len() {
                    return Ok(written);
                }
            }
            if self.ended {
                return Ok(written);
            }
            self.events.send(WorkerEvent::NeedInput).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "XZ codec owner was dropped")
            })?;
            match self.receiver.recv() {
                Ok(InputMessage::Data(bytes)) if bytes.is_empty() => {},
                Ok(InputMessage::Data(bytes)) => self.current = bytes,
                Ok(InputMessage::End) | Err(_) => {
                    self.ended = true;
                    return Ok(written);
                },
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Vli {
    value: u64,
    shift: u32,
    bytes: u8,
}

impl Vli {
    const fn new() -> Self {
        Self {
            value: 0,
            shift: 0,
            bytes: 0,
        }
    }

    fn push(&mut self, byte: u8) -> Result<Option<u64>, ArchiveError> {
        if self.bytes == 9 || self.shift >= 63 {
            return Err(malformed("XZ multibyte integer is too large"));
        }
        self.value |= u64::from(byte & 0x7f) << self.shift;
        self.shift += 7;
        self.bytes += 1;
        if byte & 0x80 == 0 {
            Ok(Some(self.value))
        } else if self.bytes == 9 {
            Err(malformed("XZ multibyte integer is too long"))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
enum ValidationState {
    StreamHeader,
    BlockHeaderSize,
    BlockHeader {
        total: usize,
    },
    LzmaControl,
    LzmaUncompressedSize {
        bytes: [u8; 2],
        used: usize,
    },
    LzmaCompressedHeader {
        control: u8,
        bytes: [u8; 5],
        used: usize,
    },
    LzmaPayload {
        remaining: usize,
    },
    BlockPadding {
        remaining: usize,
    },
    BlockChecksum {
        remaining: usize,
    },
    IndexCount {
        vli: Vli,
    },
    IndexRecord {
        remaining: u64,
        field: u8,
        vli: Vli,
    },
    IndexPadding {
        remaining: usize,
    },
    IndexCrc {
        remaining: usize,
    },
    Footer {
        remaining: usize,
    },
    StreamPadding,
    OpaqueMalformed,
}

#[derive(Debug)]
struct XzValidator {
    state: ValidationState,
    held: Vec<u8>,
    codec_memory: Option<usize>,
    check_size: usize,
    block_data_bytes: u64,
    index_bytes: u64,
    stream_padding: usize,
}

impl XzValidator {
    fn new(limits: Limits) -> Self {
        Self {
            state: ValidationState::StreamHeader,
            held: Vec::with_capacity(MAX_HEADER),
            codec_memory: limits.codec_memory(),
            check_size: 0,
            block_data_bytes: 0,
            index_bytes: 0,
            stream_padding: 0,
        }
    }

    fn retained(&self) -> usize {
        self.held.len()
    }

    fn release_held(&mut self, pending: &mut Vec<u8>) {
        pending.append(&mut self.held);
    }

    fn finish(&mut self, pending: &mut Vec<u8>) -> Result<(), ArchiveError> {
        if matches!(self.state, ValidationState::StreamPadding)
            && !self.stream_padding.is_multiple_of(4)
        {
            return Err(malformed(
                "XZ stream padding is not a multiple of four bytes",
            ));
        }
        self.release_held(pending);
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One exhaustive transition table for the XZ envelope.
    fn push(&mut self, byte: u8, pending: &mut Vec<u8>) -> Result<(), ArchiveError> {
        match &mut self.state {
            ValidationState::StreamHeader => {
                self.held.push(byte);
                if self.held.len() == 12 {
                    if !self.held.starts_with(XZ_MAGIC) {
                        return Err(malformed("invalid XZ stream magic"));
                    }
                    if self.held[6] != 0 {
                        return Err(malformed("invalid XZ stream flags"));
                    }
                    self.check_size = match self.held[7] {
                        0x00 => 0,
                        0x01 => 4,
                        0x04 => 8,
                        0x0a => 32,
                        _ => return Err(malformed("unsupported XZ check type")),
                    };
                    self.release_held(pending);
                    self.state = ValidationState::BlockHeaderSize;
                }
            },
            ValidationState::BlockHeaderSize => {
                self.held.push(byte);
                if byte == 0 {
                    self.release_held(pending);
                    self.index_bytes = 1;
                    self.state = ValidationState::IndexCount { vli: Vli::new() };
                } else {
                    let total = (usize::from(byte) + 1) * 4;
                    self.state = ValidationState::BlockHeader { total };
                }
            },
            ValidationState::BlockHeader { total } => {
                self.held.push(byte);
                if self.held.len() == *total {
                    validate_block_memory(&self.held, self.codec_memory)?;
                    self.release_held(pending);
                    self.block_data_bytes = 0;
                    self.state = ValidationState::LzmaControl;
                }
            },
            ValidationState::LzmaControl => {
                pending.push(byte);
                self.block_data_bytes = self
                    .block_data_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ block length overflow"))?;
                match byte {
                    0 => {
                        let remaining = usize::try_from((4 - (self.block_data_bytes % 4)) % 4)
                            .map_err(|_| malformed("XZ block padding overflow"))?;
                        self.state = if remaining == 0 {
                            ValidationState::BlockChecksum {
                                remaining: self.check_size,
                            }
                        } else {
                            ValidationState::BlockPadding { remaining }
                        };
                        self.skip_empty_block_tail();
                    },
                    1 | 2 => {
                        self.state = ValidationState::LzmaUncompressedSize {
                            bytes: [0; 2],
                            used: 0,
                        };
                    },
                    3..=0x7f => self.state = ValidationState::OpaqueMalformed,
                    control => {
                        self.state = ValidationState::LzmaCompressedHeader {
                            control,
                            bytes: [0; 5],
                            used: 0,
                        };
                    },
                }
            },
            ValidationState::LzmaUncompressedSize { bytes, used } => {
                pending.push(byte);
                self.block_data_bytes = self
                    .block_data_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ block length overflow"))?;
                bytes[*used] = byte;
                *used += 1;
                if *used == 2 {
                    let remaining = usize::from(u16::from_be_bytes(*bytes)) + 1;
                    self.state = ValidationState::LzmaPayload { remaining };
                }
            },
            ValidationState::LzmaCompressedHeader {
                control,
                bytes,
                used,
            } => {
                pending.push(byte);
                self.block_data_bytes = self
                    .block_data_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ block length overflow"))?;
                bytes[*used] = byte;
                *used += 1;
                let needed = 4 + usize::from(*control >= 0xc0);
                if *used == needed {
                    let remaining = usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) + 1;
                    self.state = ValidationState::LzmaPayload { remaining };
                }
            },
            ValidationState::LzmaPayload { remaining } => {
                pending.push(byte);
                self.block_data_bytes = self
                    .block_data_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ block length overflow"))?;
                *remaining -= 1;
                if *remaining == 0 {
                    self.state = ValidationState::LzmaControl;
                }
            },
            ValidationState::BlockPadding { remaining } => {
                pending.push(byte);
                *remaining -= 1;
                if *remaining == 0 {
                    self.state = ValidationState::BlockChecksum {
                        remaining: self.check_size,
                    };
                    self.skip_empty_block_tail();
                }
            },
            ValidationState::BlockChecksum { remaining } => {
                pending.push(byte);
                *remaining -= 1;
                if *remaining == 0 {
                    self.state = ValidationState::BlockHeaderSize;
                }
            },
            ValidationState::IndexCount { vli } => {
                self.held.push(byte);
                self.index_bytes = self
                    .index_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ index length overflow"))?;
                if let Some(records) = vli.push(byte)? {
                    validate_index_memory(records, self.codec_memory)?;
                    self.release_held(pending);
                    if records == 0 {
                        self.begin_index_padding()?;
                    } else {
                        self.state = ValidationState::IndexRecord {
                            remaining: records,
                            field: 0,
                            vli: Vli::new(),
                        };
                    }
                }
            },
            ValidationState::IndexRecord {
                remaining,
                field,
                vli,
            } => {
                pending.push(byte);
                self.index_bytes = self
                    .index_bytes
                    .checked_add(1)
                    .ok_or_else(|| malformed("XZ index length overflow"))?;
                if vli.push(byte)?.is_some() {
                    *vli = Vli::new();
                    if *field == 0 {
                        *field = 1;
                    } else {
                        *field = 0;
                        *remaining -= 1;
                        if *remaining == 0 {
                            self.begin_index_padding()?;
                        }
                    }
                }
            },
            ValidationState::IndexPadding { remaining } => {
                pending.push(byte);
                *remaining -= 1;
                if *remaining == 0 {
                    self.state = ValidationState::IndexCrc { remaining: 4 };
                }
            },
            ValidationState::IndexCrc { remaining } => {
                pending.push(byte);
                *remaining -= 1;
                if *remaining == 0 {
                    self.state = ValidationState::Footer { remaining: 12 };
                }
            },
            ValidationState::Footer { remaining } => {
                pending.push(byte);
                *remaining -= 1;
                if *remaining == 0 {
                    self.stream_padding = 0;
                    self.state = ValidationState::StreamPadding;
                }
            },
            ValidationState::StreamPadding => {
                if byte == 0 {
                    pending.push(byte);
                    self.stream_padding = self
                        .stream_padding
                        .checked_add(1)
                        .ok_or_else(|| malformed("XZ stream padding length overflow"))?;
                } else {
                    if !self.stream_padding.is_multiple_of(4) {
                        return Err(malformed(
                            "XZ stream padding is not a multiple of four bytes",
                        ));
                    }
                    self.held.push(byte);
                    self.state = ValidationState::StreamHeader;
                }
            },
            ValidationState::OpaqueMalformed => pending.push(byte),
        }
        Ok(())
    }

    fn skip_empty_block_tail(&mut self) {
        if matches!(self.state, ValidationState::BlockChecksum { remaining: 0 }) {
            self.state = ValidationState::BlockHeaderSize;
        }
    }

    fn begin_index_padding(&mut self) -> Result<(), ArchiveError> {
        let remaining = usize::try_from((4 - (self.index_bytes % 4)) % 4)
            .map_err(|_| malformed("XZ index padding overflow"))?;
        self.state = if remaining == 0 {
            ValidationState::IndexCrc { remaining: 4 }
        } else {
            ValidationState::IndexPadding { remaining }
        };
        Ok(())
    }
}

/// Bounded caller-driven decoder backed by `lzma-rust2`.
///
/// `lzma-rust2::XzReader` is a pull decoder. A two-message input channel and a
/// one-message output/event channel provide bounded backpressure while keeping
/// one decoder state for sync, Pipeline, futures-io, and Tokio callers. The
/// validator withholds allocation-bearing block headers and index counts until
/// their requested memory has passed `Limits::codec_memory`.
pub(crate) struct XzDecoder {
    sender: Option<SyncSender<InputMessage>>,
    events: Receiver<WorkerEvent>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
    validator: XzValidator,
    pending_input: Vec<u8>,
    pending_output: Vec<u8>,
    output_position: usize,
    end_sent: bool,
    done: bool,
    failure: Option<ArchiveError>,
}

impl XzDecoder {
    pub(crate) fn new(limits: Limits) -> Result<Self, ArchiveError> {
        let (sender, input) = mpsc::sync_channel(2);
        let (event_sender, events) = mpsc::sync_channel(2);
        let worker = thread::Builder::new()
            .name("libarchive-oxide-xz".into())
            .spawn(move || decode_worker(input, &event_sender))
            .map_err(|error| {
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("xz")
                    .with_context(format!("failed to start XZ decoder worker: {error}"))
            })?;
        Ok(Self {
            sender: Some(sender),
            events,
            worker: Some(worker),
            validator: XzValidator::new(limits),
            pending_input: Vec::with_capacity(MAX_STAGED),
            pending_output: Vec::new(),
            output_position: 0,
            end_sent: false,
            done: false,
            failure: None,
        })
    }

    fn fail(&mut self, error: ArchiveError) -> ArchiveError {
        self.sender.take();
        self.failure = Some(error.clone());
        error
    }

    fn finish_worker(&mut self) -> Result<(), ArchiveError> {
        self.sender.take();
        match self.worker.take().map(thread::JoinHandle::join) {
            Some(Ok(Ok(()))) => {
                self.done = true;
                Ok(())
            },
            Some(Ok(Err(error))) => {
                let kind = if error.kind() == io::ErrorKind::OutOfMemory {
                    ErrorKind::Limit
                } else {
                    ErrorKind::Malformed
                };
                let archive = ArchiveError::new(kind)
                    .with_format("xz")
                    .with_context(error.to_string());
                Err(self.fail(archive))
            },
            Some(Err(_)) => Err(self.fail(malformed("XZ decoder worker panicked"))),
            None => Err(self.fail(malformed("XZ decoder worker disconnected"))),
        }
    }

    fn drain_output(&mut self, output: &mut [u8]) -> usize {
        let available = self.pending_output.len() - self.output_position;
        let copied = available.min(output.len());
        output[..copied].copy_from_slice(
            &self.pending_output[self.output_position..self.output_position + copied],
        );
        self.output_position += copied;
        if self.output_position == self.pending_output.len() {
            self.pending_output.clear();
            self.output_position = 0;
        }
        copied
    }

    fn flush_input(&mut self) -> Result<bool, ArchiveError> {
        if self.pending_input.is_empty() {
            return Ok(true);
        }
        let bytes = std::mem::take(&mut self.pending_input);
        let Some(sender) = &self.sender else {
            return Err(self.fail(malformed("XZ decoder input is closed")));
        };
        match sender.try_send(InputMessage::Data(bytes)) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(InputMessage::Data(bytes))) => {
                self.pending_input = bytes;
                Ok(false)
            },
            Err(TrySendError::Disconnected(_)) => {
                Err(self.fail(malformed("XZ decoder worker stopped accepting input")))
            },
            Err(TrySendError::Full(InputMessage::End)) => unreachable!(),
        }
    }

    fn try_send_end(&mut self) -> Result<bool, ArchiveError> {
        if self.end_sent {
            return Ok(true);
        }
        let Some(sender) = &self.sender else {
            return Err(self.fail(malformed("XZ decoder input is closed")));
        };
        match sender.try_send(InputMessage::End) {
            Ok(()) => {
                self.end_sent = true;
                Ok(true)
            },
            Err(TrySendError::Full(InputMessage::End)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => {
                Err(self.fail(malformed("XZ decoder worker stopped before end of input")))
            },
            Err(TrySendError::Full(InputMessage::Data(_))) => unreachable!(),
        }
    }

    fn handle_event(&mut self, event: WorkerEvent, output: &mut [u8]) -> usize {
        match event {
            WorkerEvent::NeedInput => 0,
            WorkerEvent::Output(bytes) => {
                debug_assert!(self.pending_output.is_empty());
                self.pending_output = bytes;
                self.drain_output(output)
            },
        }
    }

    fn poll_event(&mut self, output: &mut [u8]) -> Result<Option<usize>, ArchiveError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(self.handle_event(event, output))),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.finish_worker()?;
                Ok(Some(0))
            },
        }
    }

    fn wait_event(&mut self, output: &mut [u8]) -> Result<usize, ArchiveError> {
        if let Ok(event) = self.events.recv() {
            Ok(self.handle_event(event, output))
        } else {
            self.finish_worker()?;
            Ok(0)
        }
    }
}

impl fmt::Debug for XzDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XzDecoder")
            .field("validator", &self.validator)
            .field("pending_input", &self.pending_input.len())
            .field(
                "pending_output",
                &(self.pending_output.len() - self.output_position),
            )
            .field("end_sent", &self.end_sent)
            .field("done", &self.done)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl Codec for XzDecoder {
    #[allow(clippy::too_many_lines)] // Progress, backpressure, and terminal ordering stay together.
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.done {
            if input.is_empty() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            return Err(self.fail(malformed("data follows the completed XZ stream")));
        }

        let mut consumed = 0;
        let mut produced = self.drain_output(output);
        loop {
            if self.done {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                });
            }
            while produced < output.len() {
                let Some(read) = self.poll_event(&mut output[produced..])? else {
                    break;
                };
                produced += read;
                if self.done || !self.pending_output.is_empty() {
                    break;
                }
            }
            if self.done {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                });
            }

            let flushed = self.flush_input()?;
            if flushed && consumed < input.len() {
                let retained = self
                    .pending_input
                    .len()
                    .checked_add(self.validator.retained())
                    .ok_or_else(|| self.fail(malformed("XZ staged input length overflow")))?;
                let accepted = (MAX_STAGED - retained).min(input.len() - consumed);
                for &byte in &input[consumed..consumed + accepted] {
                    if let Err(error) = self.validator.push(byte, &mut self.pending_input) {
                        return Err(self.fail(error));
                    }
                }
                consumed += accepted;
                let _ = self.flush_input()?;
            }

            let effective_end = matches!(end, EndOfInput::End) && consumed == input.len();
            if effective_end {
                if let Err(error) = self.validator.finish(&mut self.pending_input) {
                    return Err(self.fail(error));
                }
                if self.flush_input()? {
                    let _ = self.try_send_end()?;
                }
            }

            while produced < output.len() {
                let Some(read) = self.poll_event(&mut output[produced..])? else {
                    break;
                };
                produced += read;
                if self.done || !self.pending_output.is_empty() {
                    break;
                }
            }
            if self.done {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                });
            }
            if effective_end
                && self.end_sent
                && produced == 0
                && self.pending_output.is_empty()
                && !output.is_empty()
            {
                produced += self.wait_event(&mut output[produced..])?;
                continue;
            }
            if produced != 0 || consumed != 0 {
                let status = if !self.pending_output.is_empty()
                    || !self.pending_input.is_empty()
                    || consumed != input.len()
                    || (effective_end && !self.end_sent)
                    || produced == output.len()
                {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                };
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status,
                });
            }
            if effective_end && self.end_sent {
                produced += self.wait_event(&mut output[produced..])?;
                continue;
            }
            if !input.is_empty() || !self.pending_input.is_empty() {
                produced += self.wait_event(&mut output[produced..])?;
                continue;
            }
            return Ok(CodecStep {
                consumed: 0,
                produced,
                status: if output.is_empty() && !self.pending_output.is_empty() {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                },
            });
        }
    }
}

fn decode_worker(
    input: Receiver<InputMessage>,
    events: &SyncSender<WorkerEvent>,
) -> io::Result<()> {
    let pipe = InputPipe {
        receiver: input,
        events: events.clone(),
        current: Vec::new(),
        position: 0,
        ended: false,
    };
    let mut decoder = lzma_rust2::XzReader::new(pipe, true);
    let mut output = vec![0; BUFFER];
    loop {
        match decoder.read(&mut output) {
            Ok(0) => return Ok(()),
            Ok(read) => events
                .send(WorkerEvent::Output(output[..read].to_vec()))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "XZ codec owner was dropped")
                })?,
            Err(error) => return Err(error),
        }
    }
}

fn validate_block_memory(header: &[u8], codec_memory: Option<usize>) -> Result<(), ArchiveError> {
    let Some(limit) = codec_memory else {
        return Ok(());
    };
    if header.len() < 8 || header.len() > MAX_HEADER {
        return Err(malformed("invalid XZ block header size"));
    }
    let flags = header[1];
    let filters = usize::from(flags & 0x03) + 1;
    let data_end = header.len() - 4;
    let mut offset = 2;
    if flags & 0x40 != 0 {
        let _ = parse_vli(header, &mut offset, data_end)?;
    }
    if flags & 0x80 != 0 {
        let _ = parse_vli(header, &mut offset, data_end)?;
    }
    for _ in 0..filters {
        let filter = parse_vli(header, &mut offset, data_end)?;
        let properties = usize::try_from(parse_vli(header, &mut offset, data_end)?)
            .map_err(|_| malformed("XZ filter properties are too large"))?;
        let property_end = offset
            .checked_add(properties)
            .filter(|end| *end <= data_end)
            .ok_or_else(|| malformed("truncated XZ filter properties"))?;
        if filter == 0x21 {
            if properties != 1 {
                return Err(malformed("invalid LZMA2 properties size"));
            }
            let property = header[offset];
            let dictionary = decode_dictionary(property)?;
            let required = u64::from(lzma_rust2::lzma2_get_memory_usage(dictionary)) * 1024;
            if required > limit as u64 {
                return Err(ArchiveError::new(ErrorKind::Limit)
                    .with_format("xz")
                    .with_context(format!(
                        "LZMA2 workspace requires {required} bytes, limit is {limit}"
                    )));
            }
        }
        offset = property_end;
    }
    Ok(())
}

fn validate_index_memory(records: u64, codec_memory: Option<usize>) -> Result<(), ArchiveError> {
    let count = usize::try_from(records).map_err(|_| {
        ArchiveError::new(ErrorKind::Limit)
            .with_format("xz")
            .with_context("XZ index record count exceeds the platform address space")
    })?;
    let required = count.checked_mul(INDEX_RECORD_BYTES).ok_or_else(|| {
        ArchiveError::new(ErrorKind::Limit)
            .with_format("xz")
            .with_context("XZ index allocation size overflow")
    })?;
    if codec_memory.is_some_and(|limit| required > limit) {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_format("xz")
            .with_context(format!(
                "XZ index requires {required} bytes, codec workspace limit was exceeded"
            )));
    }
    Ok(())
}

fn decode_dictionary(property: u8) -> Result<u32, ArchiveError> {
    if property > 40 {
        return Err(malformed("invalid LZMA2 dictionary size"));
    }
    if property == 40 {
        return Ok(u32::MAX);
    }
    let base = 2 | u32::from(property & 1);
    Ok(base << (u32::from(property) / 2 + 11))
}

fn parse_vli(data: &[u8], offset: &mut usize, end: usize) -> Result<u64, ArchiveError> {
    let mut vli = Vli::new();
    while *offset < end {
        let byte = data[*offset];
        *offset += 1;
        if let Some(value) = vli.push(byte)? {
            return Ok(value);
        }
    }
    Err(malformed("incomplete XZ multibyte integer"))
}

fn malformed(context: impl Into<String>) -> ArchiveError {
    ArchiveError::new(ErrorKind::Malformed)
        .with_format("xz")
        .with_context(context)
}

/// Encodes one deterministic, CRC64-protected XZ stream.
pub(crate) fn encode_frame(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut writer = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))?;
    writer.write_all(input)?;
    writer.finish()
}
