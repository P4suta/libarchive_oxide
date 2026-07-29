// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded, caller-driven lzip/LZMA codec state.
//!
//! `lzma-rust2` exposes a safe pull-based raw LZMA reader. A bounded worker
//! bridge keeps that reader off async executor threads while preserving the
//! same [`Codec`] state machine for sync, Pipeline, futures-io, and Tokio
//! callers. The project-owned envelope parser deliberately does not use
//! `lzma_rust2::LzipReader`: that adapter treats any failed next-member header
//! as clean EOF, while this reader rejects corrupt and truncated members.

use std::fmt;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::thread;
use std::time::Duration;

use libarchive_oxide_core::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

use crate::filter::Crc32;

const BUFFER: usize = 64 * 1024;
const MAX_STAGED: usize = BUFFER;
const INPUT_WAIT: Duration = Duration::from_millis(10);
const HEADER_SIZE: u64 = 6;
const HEADER_BYTES: usize = 6;
const TRAILER_SIZE: usize = 20;
const LZIP_MAGIC: &[u8; 4] = b"LZIP";
const LZIP_VERSION: u8 = 1;
const MIN_DICTIONARY: u32 = 4 * 1024;
const MAX_DICTIONARY: u32 = 512 * 1024 * 1024;

enum InputMessage {
    Data(Vec<u8>),
    End,
}

#[derive(Debug)]
enum WorkerEvent {
    NeedInput,
    Output(Vec<u8>),
}

#[derive(Clone)]
struct EventSink {
    sender: SyncSender<WorkerEvent>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl EventSink {
    fn send(&self, event: WorkerEvent) -> Result<(), mpsc::SendError<WorkerEvent>> {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.wake_owner();
                Ok(())
            },
            Err(TrySendError::Full(event)) => {
                self.wake_owner();
                let result = self.sender.send(event);
                self.wake_owner();
                result
            },
            Err(TrySendError::Disconnected(event)) => Err(mpsc::SendError(event)),
        }
    }

    fn wake_owner(&self) {
        wake_cell(&self.waker);
    }
}

fn wake_cell(cell: &Mutex<Option<Waker>>) {
    let waker = match cell.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

struct InputPipe {
    receiver: Receiver<InputMessage>,
    events: EventSink,
    cancel: Arc<AtomicBool>,
    current: Vec<u8>,
    position: usize,
    end_received: bool,
    eof_read: bool,
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
            if self.end_received {
                if written == 0 {
                    self.eof_read = true;
                }
                return Ok(written);
            }
            let message = match self.receiver.try_recv() {
                Ok(message) => message,
                Err(TryRecvError::Empty) => loop {
                    ensure_worker_active(&self.cancel)?;
                    self.events.send(WorkerEvent::NeedInput).map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "lzip codec owner was dropped")
                    })?;
                    ensure_worker_active(&self.cancel)?;
                    match self.receiver.recv_timeout(INPUT_WAIT) {
                        Ok(message) => break message,
                        Err(RecvTimeoutError::Timeout) => {},
                        Err(RecvTimeoutError::Disconnected) => {
                            ensure_worker_active(&self.cancel)?;
                            self.end_received = true;
                            if written == 0 {
                                self.eof_read = true;
                            }
                            return Ok(written);
                        },
                    }
                },
                Err(TryRecvError::Disconnected) => {
                    ensure_worker_active(&self.cancel)?;
                    self.end_received = true;
                    if written == 0 {
                        self.eof_read = true;
                    }
                    return Ok(written);
                },
            };
            match message {
                InputMessage::Data(bytes) if bytes.is_empty() => {},
                InputMessage::Data(bytes) => self.current = bytes,
                InputMessage::End => {
                    self.end_received = true;
                    if written == 0 {
                        self.eof_read = true;
                    }
                    return Ok(written);
                },
            }
        }
    }
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    const fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    fn into_parts(self) -> (R, u64) {
        (self.inner, self.bytes_read)
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| invalid_data("lzip compressed member size overflow"))?;
        Ok(read)
    }
}

/// Bounded caller-driven lzip decoder backed by safe `lzma-rust2`.
pub(crate) struct LzipDecoder {
    sender: Option<SyncSender<InputMessage>>,
    events: Mutex<Receiver<WorkerEvent>>,
    waker_cell: Arc<Mutex<Option<Waker>>>,
    worker: Mutex<Option<thread::JoinHandle<io::Result<()>>>>,
    cancel: Arc<AtomicBool>,
    pending_input: Vec<u8>,
    pending_output: Vec<u8>,
    output_position: usize,
    end_sent: bool,
    input_disconnected: bool,
    done: bool,
    failure: Option<ArchiveError>,
}

impl LzipDecoder {
    pub(crate) fn new(limits: Limits) -> Result<Self, ArchiveError> {
        let (sender, input) = mpsc::sync_channel(2);
        let (event_sender, events) = mpsc::sync_channel(2);
        let waker_cell = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let sink = EventSink {
            sender: event_sender,
            waker: Arc::clone(&waker_cell),
        };
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new()
            .name("libarchive-oxide-lzip".into())
            .spawn(move || decode_worker(input, sink, limits, worker_cancel))
            .map_err(|error| {
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("lzip")
                    .with_context(format!("failed to start lzip decoder worker: {error}"))
            })?;
        Ok(Self {
            sender: Some(sender),
            events: Mutex::new(events),
            waker_cell,
            worker: Mutex::new(Some(worker)),
            cancel,
            pending_input: Vec::with_capacity(MAX_STAGED),
            pending_output: Vec::new(),
            output_position: 0,
            end_sent: false,
            input_disconnected: false,
            done: false,
            failure: None,
        })
    }

    fn fail(&mut self, error: ArchiveError) -> ArchiveError {
        self.cancel_worker();
        self.sender.take();
        self.failure = Some(error.clone());
        error
    }

    fn cancel_worker(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.sender.take();
        self.drain_events();

        let worker = match self.worker.get_mut() {
            Ok(worker) => worker,
            Err(poisoned) => poisoned.into_inner(),
        }
        .take();
        if let Some(worker) = worker {
            if worker.thread().id() == thread::current().id() {
                // A legal re-entrant waker can drop its owner on this worker.
                // Joining the current thread is impossible; cancellation is
                // already visible, so detaching lets this worker return as soon
                // as the wake callback unwinds instead of self-deadlocking.
                drop(worker);
                wake_cell(&self.waker_cell);
                return;
            }
            while !worker.is_finished() {
                self.drain_events();
                thread::yield_now();
            }
            self.drain_events();
            let _ = worker.join();
        }
        wake_cell(&self.waker_cell);
    }

    fn drain_events(&mut self) {
        let events = match self.events.get_mut() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        while events.try_recv().is_ok() {}
    }

    fn finish_worker(&mut self) -> Result<(), ArchiveError> {
        self.sender.take();
        let worker = match self.worker.get_mut() {
            Ok(worker) => worker.take(),
            Err(_) => return Err(self.fail(malformed("lzip worker handle was poisoned"))),
        };
        match worker.map(thread::JoinHandle::join) {
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
                    .with_format("lzip")
                    .with_context(error.to_string());
                Err(self.fail(archive))
            },
            Some(Err(_)) => Err(self.fail(malformed("lzip decoder worker panicked"))),
            None => Err(self.fail(malformed("lzip decoder worker disconnected"))),
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
        if self.input_disconnected {
            return Ok(false);
        }
        let bytes = std::mem::take(&mut self.pending_input);
        let Some(sender) = &self.sender else {
            return Err(self.fail(malformed("lzip decoder input is closed")));
        };
        match sender.try_send(InputMessage::Data(bytes)) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(InputMessage::Data(bytes))) => {
                self.pending_input = bytes;
                Ok(false)
            },
            Err(TrySendError::Disconnected(InputMessage::Data(bytes))) => {
                self.pending_input = bytes;
                self.input_disconnected = true;
                self.sender.take();
                Ok(false)
            },
            Err(TrySendError::Disconnected(InputMessage::End)) => Err(self.fail(malformed(
                "lzip decoder input queue returned the wrong disconnected message",
            ))),
            Err(TrySendError::Full(InputMessage::End)) => Err(self.fail(malformed(
                "lzip decoder input queue returned the wrong full message",
            ))),
        }
    }

    fn try_send_end(&mut self) -> Result<bool, ArchiveError> {
        if self.end_sent {
            return Ok(true);
        }
        if self.input_disconnected {
            return Ok(false);
        }
        let Some(sender) = &self.sender else {
            return Err(self.fail(malformed("lzip decoder input is closed")));
        };
        match sender.try_send(InputMessage::End) {
            Ok(()) => {
                self.end_sent = true;
                Ok(true)
            },
            Err(TrySendError::Full(InputMessage::End)) => Ok(false),
            Err(TrySendError::Disconnected(InputMessage::End)) => {
                self.input_disconnected = true;
                self.sender.take();
                Ok(false)
            },
            Err(TrySendError::Disconnected(InputMessage::Data(_))) => Err(self.fail(malformed(
                "lzip decoder input queue returned the wrong disconnected end marker",
            ))),
            Err(TrySendError::Full(InputMessage::Data(_))) => Err(self.fail(malformed(
                "lzip decoder input queue returned the wrong end marker",
            ))),
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
        let event = match self.events.get_mut() {
            Ok(events) => events.try_recv(),
            Err(_) => return Err(self.fail(malformed("lzip event receiver was poisoned"))),
        };
        match event {
            Ok(event) => Ok(Some(self.handle_event(event, output))),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.finish_worker()?;
                Ok(Some(0))
            },
        }
    }

    fn wait_event(&mut self, output: &mut [u8]) -> Result<usize, ArchiveError> {
        let event = match self.events.get_mut() {
            Ok(events) => events.recv(),
            Err(_) => return Err(self.fail(malformed("lzip event receiver was poisoned"))),
        };
        if let Ok(event) = event {
            Ok(self.handle_event(event, output))
        } else {
            self.finish_worker()?;
            Ok(0)
        }
    }

    fn register_waker(&self, waker: &Waker) {
        if let Ok(mut guard) = self.waker_cell.lock() {
            let refresh = guard
                .as_ref()
                .is_none_or(|existing| !existing.will_wake(waker));
            if refresh {
                *guard = Some(waker.clone());
            }
        }
    }

    fn pump(
        &mut self,
        output: &mut [u8],
        waker: Option<&Waker>,
    ) -> Result<Option<usize>, ArchiveError> {
        match waker {
            None => self.wait_event(output).map(Some),
            Some(waker) => {
                self.register_waker(waker);
                self.poll_event(output)
            },
        }
    }

    #[allow(clippy::too_many_lines)] // Progress, backpressure, and terminal ordering stay together.
    fn drive(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        waker: Option<&Waker>,
    ) -> Result<Option<CodecStep>, ArchiveError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.done {
            if input.is_empty() {
                return Ok(Some(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                }));
            }
            return Err(self.fail(malformed("data follows the completed lzip stream")));
        }

        let mut consumed = 0;
        let mut produced = self.drain_output(output);
        loop {
            if self.done {
                return Ok(Some(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                }));
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
                return Ok(Some(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                }));
            }

            let flushed = self.flush_input()?;
            if flushed && consumed < input.len() {
                let accepted = (MAX_STAGED - self.pending_input.len()).min(input.len() - consumed);
                self.pending_input
                    .extend_from_slice(&input[consumed..consumed + accepted]);
                consumed += accepted;
                let _ = self.flush_input()?;
            }

            let effective_end = matches!(end, EndOfInput::End) && consumed == input.len();
            if effective_end && self.flush_input()? {
                let _ = self.try_send_end()?;
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
                return Ok(Some(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                }));
            }
            if effective_end
                && produced == 0
                && self.pending_output.is_empty()
                && !output.is_empty()
            {
                let Some(read) = self.pump(&mut output[produced..], waker)? else {
                    return Ok(None);
                };
                produced += read;
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
                return Ok(Some(CodecStep {
                    consumed,
                    produced,
                    status,
                }));
            }
            if effective_end {
                if output.is_empty() && !self.pending_output.is_empty() {
                    return Ok(Some(CodecStep {
                        consumed,
                        produced,
                        status: CodecStatus::NeedOutput,
                    }));
                }
                let Some(read) = self.pump(&mut output[produced..], waker)? else {
                    return Ok(None);
                };
                produced += read;
                continue;
            }
            if !input.is_empty() || !self.pending_input.is_empty() {
                let Some(read) = self.pump(&mut output[produced..], waker)? else {
                    return Ok(None);
                };
                produced += read;
                continue;
            }
            return Ok(Some(CodecStep {
                consumed: 0,
                produced,
                status: if output.is_empty() && !self.pending_output.is_empty() {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                },
            }));
        }
    }
}

impl fmt::Debug for LzipDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LzipDecoder")
            .field("pending_input", &self.pending_input.len())
            .field(
                "pending_output",
                &(self.pending_output.len() - self.output_position),
            )
            .field("end_sent", &self.end_sent)
            .field("input_disconnected", &self.input_disconnected)
            .field("done", &self.done)
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for LzipDecoder {
    fn drop(&mut self) {
        self.cancel_worker();
    }
}

impl Codec for LzipDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        self.drive(input, output, end, None)?
            .ok_or_else(|| malformed("blocking lzip decoder yielded without synchronous progress"))
    }

    fn poll_process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        waker: &Waker,
    ) -> Result<Option<CodecStep>, ArchiveError> {
        self.drive(input, output, end, Some(waker))
    }
}

#[allow(clippy::too_many_lines)] // Member decode and all three trailer checks stay adjacent.
fn decode_worker(
    input: Receiver<InputMessage>,
    events: EventSink,
    limits: Limits,
    cancel: Arc<AtomicBool>,
) -> io::Result<()> {
    let waker_cell = Arc::clone(&events.waker);
    let result = (move || -> io::Result<()> {
        let mut pipe = InputPipe {
            receiver: input,
            events: events.clone(),
            cancel: Arc::clone(&cancel),
            current: Vec::new(),
            position: 0,
            end_received: false,
            eof_read: false,
        };
        let mut output = vec![0; BUFFER];
        let mut member_index = 0_u64;
        let mut decoded_total = 0_u64;

        loop {
            ensure_worker_active(&cancel)?;
            let Some(dictionary) = read_member_header(&mut pipe, member_index)? else {
                return Ok(());
            };
            ensure_worker_active(&cancel)?;
            validate_dictionary_memory(dictionary, limits.codec_memory())?;
            pipe.eof_read = false;

            let counting = CountingReader::new(pipe);
            let mut decoder =
                lzma_rust2::LzmaReader::new(counting, u64::MAX, 3, 0, 2, dictionary, None)?;
            let mut crc = Crc32::new();
            let mut data_size = 0_u64;
            loop {
                let remaining_budget = limits
                    .decoded_total()
                    .map(|maximum| maximum.saturating_sub(decoded_total));
                let probing_limit = remaining_budget == Some(0);
                let capacity = remaining_budget.map_or(output.len(), |remaining| {
                    usize::try_from(remaining.min(output.len() as u64))
                        .unwrap_or(output.len())
                        .max(1)
                });
                let read_result = decoder.read(&mut output[..capacity]);
                ensure_worker_active(&cancel)?;
                if decoder.inner().inner.eof_read {
                    return Err(invalid_data("truncated lzip LZMA payload"));
                }
                let read = read_result?;
                if read == 0 {
                    break;
                }
                if probing_limit {
                    return Err(out_of_memory(
                        "lzip decoded stream exceeds configured limit",
                    ));
                }
                let read_u64 = u64::try_from(read)
                    .map_err(|_| invalid_data("lzip decoded chunk length overflow"))?;
                data_size = data_size
                    .checked_add(read_u64)
                    .ok_or_else(|| invalid_data("lzip member data size overflow"))?;
                decoded_total = decoded_total
                    .checked_add(read_u64)
                    .ok_or_else(|| out_of_memory("lzip decoded-total counter overflow"))?;
                crc.update(&output[..read]);
                ensure_worker_active(&cancel)?;
                events
                    .send(WorkerEvent::Output(output[..read].to_vec()))
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "lzip codec owner was dropped")
                    })?;
                ensure_worker_active(&cancel)?;
            }

            let counting = decoder.into_inner();
            let (mut next_pipe, compressed_size) = counting.into_parts();
            let mut trailer = [0_u8; TRAILER_SIZE];
            next_pipe.read_exact(&mut trailer).map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    invalid_data("truncated lzip member trailer")
                } else {
                    error
                }
            })?;
            let expected_crc = u32::from_le_bytes(
                trailer[0..4]
                    .try_into()
                    .map_err(|_| invalid_data("invalid lzip CRC trailer"))?,
            );
            let expected_data_size = u64::from_le_bytes(
                trailer[4..12]
                    .try_into()
                    .map_err(|_| invalid_data("invalid lzip data-size trailer"))?,
            );
            let expected_member_size = u64::from_le_bytes(
                trailer[12..20]
                    .try_into()
                    .map_err(|_| invalid_data("invalid lzip member-size trailer"))?,
            );
            if crc.finalize() != expected_crc {
                return Err(invalid_data("lzip CRC32 mismatch"));
            }
            if data_size != expected_data_size {
                return Err(invalid_data("lzip uncompressed size mismatch"));
            }
            let actual_member_size = HEADER_SIZE
                .checked_add(compressed_size)
                .and_then(|size| size.checked_add(TRAILER_SIZE as u64))
                .ok_or_else(|| invalid_data("lzip member size overflow"))?;
            if actual_member_size != expected_member_size {
                return Err(invalid_data("lzip member size mismatch"));
            }

            pipe = next_pipe;
            member_index = member_index
                .checked_add(1)
                .ok_or_else(|| out_of_memory("lzip member count overflow"))?;
        }
    })();
    wake_cell(&waker_cell);
    result
}

fn read_member_header(pipe: &mut InputPipe, member_index: u64) -> io::Result<Option<u32>> {
    let mut header = [0_u8; HEADER_BYTES];
    let first = pipe.read(&mut header[..1])?;
    if first == 0 {
        return if member_index == 0 {
            Err(invalid_data("empty lzip stream"))
        } else {
            Ok(None)
        };
    }
    pipe.read_exact(&mut header[1..]).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid_data("truncated lzip member header")
        } else {
            error
        }
    })?;
    if &header[..4] != LZIP_MAGIC {
        return Err(invalid_data("invalid lzip member magic"));
    }
    if header[4] != LZIP_VERSION {
        return Err(invalid_data("unsupported lzip member version"));
    }
    decode_dictionary_size(header[5]).map(Some)
}

fn decode_dictionary_size(encoded: u8) -> io::Result<u32> {
    let base_log2 = u32::from(encoded & 0x1f);
    if !(12..=29).contains(&base_log2) {
        return Err(invalid_data("invalid lzip dictionary-size base"));
    }
    let fraction = u32::from(encoded >> 5);
    let base = 1_u32 << base_log2;
    let dictionary = base - (base >> 4) * fraction;
    if !(MIN_DICTIONARY..=MAX_DICTIONARY).contains(&dictionary) {
        return Err(invalid_data("lzip dictionary size is out of range"));
    }
    Ok(dictionary)
}

fn validate_dictionary_memory(dictionary: u32, limit: Option<usize>) -> io::Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let required_kib = lzma_rust2::lzma_get_memory_usage(dictionary, 3, 0)
        .map_err(|error| invalid_data(error.to_string()))?;
    let required = u64::from(required_kib)
        .checked_mul(1024)
        .ok_or_else(|| out_of_memory("lzip LZMA workspace size overflow"))?;
    if required > limit as u64 {
        return Err(out_of_memory(format!(
            "lzip LZMA workspace requires {required} bytes, limit is {limit}"
        )));
    }
    Ok(())
}

fn malformed(context: impl Into<String>) -> ArchiveError {
    ArchiveError::new(ErrorKind::Malformed)
        .with_format("lzip")
        .with_context(context)
}

fn invalid_data(context: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, context.into())
}

fn out_of_memory(context: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, context.into())
}

fn ensure_worker_active(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "lzip codec owner was dropped",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Wake, Waker};

    use super::wake_cell;

    struct LockProbe {
        cell: Arc<Mutex<Option<Waker>>>,
        acquired: Arc<AtomicBool>,
    }

    impl Wake for LockProbe {
        fn wake(self: Arc<Self>) {
            self.acquired
                .store(self.cell.try_lock().is_ok(), Ordering::SeqCst);
        }
    }

    #[test]
    fn wake_cell_releases_mutex_before_invoking_waker() {
        let cell = Arc::new(Mutex::new(None));
        let acquired = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(LockProbe {
            cell: Arc::clone(&cell),
            acquired: Arc::clone(&acquired),
        }));
        *cell.lock().expect("waker cell") = Some(waker);

        wake_cell(&cell);

        assert!(acquired.load(Ordering::SeqCst));
        assert!(cell.lock().expect("waker cell").is_none());
    }
}
