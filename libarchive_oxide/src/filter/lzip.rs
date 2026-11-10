// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded, caller-driven pull-codec state for lzip, LZMA, and ZIP `PPMd8`.
//!
//! `lzma-rust2` exposes a safe pull-based raw LZMA reader.
//! A bounded worker bridge keeps that reader off async executor threads while preserving the same [`Codec`] state machine for sync, Pipeline, futures-io, and Tokio callers.
//! The project-owned envelope parser deliberately does not use `lzma_rust2::LzipReader`: that adapter treats any failed next-member header as clean EOF, while this reader rejects corrupt and truncated members.

use std::collections::VecDeque;
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

#[cfg(feature = "lzip")]
use crate::filter::Crc32;

#[cfg(test)]
use super::worker::testing::{DriveCheckpoint, DriveSchedule};
use super::worker::{QUEUE_DEPTH, WorkerProgress};

const BUFFER: usize = 64 * 1024;
const MAX_STAGED: usize = BUFFER;
const INPUT_WAIT: Duration = Duration::from_millis(10);
#[cfg(feature = "lzip")]
const HEADER_SIZE: u64 = 6;
#[cfg(feature = "lzip")]
const HEADER_BYTES: usize = 6;
#[cfg(feature = "lzip")]
const TRAILER_SIZE: usize = 20;
#[cfg(feature = "lzip")]
const LZIP_MAGIC: &[u8; 4] = b"LZIP";
#[cfg(feature = "lzip")]
const LZIP_VERSION: u8 = 1;
#[cfg(any(feature = "lzma", feature = "xz"))]
const LZMA_HEADER_BYTES: usize = 13;
#[cfg(feature = "ppmd")]
const PPMD_WORKER_HEADER_BYTES: usize = 18;
#[cfg(feature = "lzip")]
const MIN_DICTIONARY: u32 = 4 * 1024;
#[cfg(feature = "lzip")]
const MAX_DICTIONARY: u32 = 512 * 1024 * 1024;

enum InputMessage {
    Data { bytes: Vec<u8>, token: Option<u64> },
    End,
}

#[derive(Debug)]
enum WorkerEvent {
    NeedInput,
    InputConsumed { token: u64, bytes: usize },
    Output(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputAccounting {
    Eager,
    Acknowledged,
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
    read_ahead: VecDeque<u8>,
    current: Vec<u8>,
    position: usize,
    current_token: Option<u64>,
    end_received: bool,
    eof_read: bool,
}

impl InputPipe {
    fn restore_read_ahead(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        let pending = self
            .read_ahead
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| out_of_memory("lzip read-ahead size overflow"))?;
        if pending > MAX_STAGED {
            return Err(out_of_memory("lzip read-ahead exceeds the staging limit"));
        }
        for byte in bytes.into_iter().rev() {
            self.read_ahead.push_front(byte);
        }
        Ok(())
    }

    fn report_current_consumed(&mut self) -> io::Result<()> {
        let Some(token) = self.current_token.take() else {
            return Ok(());
        };
        self.events
            .send(WorkerEvent::InputConsumed {
                token,
                bytes: self.position,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pull codec owner was dropped"))
    }

    #[cfg(any(feature = "lzma", feature = "xz", feature = "ppmd"))]
    fn finish(mut self) -> io::Result<()> {
        self.report_current_consumed()
    }
}

impl Read for InputPipe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if !self.read_ahead.is_empty() {
            return self.read_ahead.read(output);
        }
        let mut written = 0;
        loop {
            if self.position != self.current.len() {
                let checkpointed = self.current_token.is_some();
                // Keep LZMA refill buffers from acknowledging bytes after the end marker.
                let capacity = if checkpointed {
                    1
                } else {
                    output.len() - written
                };
                let copied = (self.current.len() - self.position).min(capacity);
                output[written..written + copied]
                    .copy_from_slice(&self.current[self.position..self.position + copied]);
                self.position += copied;
                written += copied;
                if self.position == self.current.len() {
                    self.report_current_consumed()?;
                    self.current.clear();
                    self.position = 0;
                }
                if checkpointed || written == output.len() {
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
                        io::Error::new(io::ErrorKind::BrokenPipe, "pull codec owner was dropped")
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
                InputMessage::Data { bytes, token } if bytes.is_empty() => {
                    if let Some(token) = token {
                        self.events
                            .send(WorkerEvent::InputConsumed { token, bytes: 0 })
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "pull codec owner was dropped",
                                )
                            })?;
                    }
                },
                InputMessage::Data { bytes, token } => {
                    self.current = bytes;
                    self.current_token = token;
                },
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

#[cfg(feature = "lzip")]
struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

#[cfg(feature = "lzip")]
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

#[cfg(feature = "lzip")]
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

/// Bounded caller-driven pull decoder backed by safe Rust codecs.
pub(crate) struct LzipDecoder {
    format: &'static str,
    sender: Option<SyncSender<InputMessage>>,
    events: Mutex<Receiver<WorkerEvent>>,
    waker_cell: Arc<Mutex<Option<Waker>>>,
    worker: Mutex<Option<thread::JoinHandle<io::Result<()>>>>,
    cancel: Arc<AtomicBool>,
    pending_input: Vec<u8>,
    pending_input_token: Option<u64>,
    pending_output: Vec<u8>,
    output_position: usize,
    input_accounting: InputAccounting,
    exact_in_flight: Option<(u64, usize)>,
    exact_committed: usize,
    next_input_token: u64,
    end_sent: bool,
    input_disconnected: bool,
    done: bool,
    failure: Option<ArchiveError>,
    #[cfg(test)]
    schedule: Option<Arc<DriveSchedule>>,
}

impl LzipDecoder {
    #[cfg(feature = "lzip")]
    pub(crate) fn new(limits: Limits) -> Result<Self, ArchiveError> {
        Self::with_worker(limits, "lzip", "libarchive-oxide-lzip", decode_worker)
    }

    #[cfg(feature = "lzma")]
    pub(crate) fn new_lzma(limits: Limits) -> Result<Self, ArchiveError> {
        Self::with_worker(limits, "lzma", "libarchive-oxide-lzma", decode_lzma_worker)
    }

    #[cfg(feature = "xz")]
    pub(crate) fn new_zip_lzma(
        limits: Limits,
        properties: u8,
        dictionary: u32,
        declared_size: u64,
    ) -> Result<Self, ArchiveError> {
        Self::new_zip_lzma_with_mode(
            limits,
            properties,
            dictionary,
            declared_size,
            InputAccounting::Eager,
        )
    }

    #[cfg(feature = "xz")]
    pub(crate) fn new_zip_lzma_checkpointed(
        limits: Limits,
        properties: u8,
        dictionary: u32,
    ) -> Result<Self, ArchiveError> {
        Self::new_zip_lzma_with_mode(
            limits,
            properties,
            dictionary,
            u64::MAX,
            InputAccounting::Acknowledged,
        )
    }

    #[cfg(feature = "xz")]
    fn new_zip_lzma_with_mode(
        limits: Limits,
        properties: u8,
        dictionary: u32,
        declared_size: u64,
        input_accounting: InputAccounting,
    ) -> Result<Self, ArchiveError> {
        let mut decoder = Self::with_worker(
            limits,
            "zip",
            "libarchive-oxide-zip-lzma",
            decode_lzma_worker,
        )?;
        decoder.pending_input.push(properties);
        decoder
            .pending_input
            .extend_from_slice(&dictionary.to_le_bytes());
        decoder
            .pending_input
            .extend_from_slice(&declared_size.to_le_bytes());
        decoder.input_accounting = input_accounting;
        Ok(decoder)
    }

    #[cfg(feature = "ppmd")]
    pub(crate) fn new_zip_ppmd(
        limits: Limits,
        parameters: u16,
        declared_size: u64,
    ) -> Result<Self, ArchiveError> {
        Self::new_zip_ppmd_with_mode(limits, parameters, declared_size, InputAccounting::Eager)
    }

    #[cfg(feature = "ppmd")]
    pub(crate) fn new_zip_ppmd_checkpointed(
        limits: Limits,
        parameters: u16,
    ) -> Result<Self, ArchiveError> {
        Self::new_zip_ppmd_with_mode(limits, parameters, u64::MAX, InputAccounting::Acknowledged)
    }

    #[cfg(feature = "ppmd")]
    fn new_zip_ppmd_with_mode(
        limits: Limits,
        parameters: u16,
        declared_size: u64,
        input_accounting: InputAccounting,
    ) -> Result<Self, ArchiveError> {
        let (order, memory_size, restoration) = validate_zip_ppmd_parameters(parameters, limits)?;
        let mut decoder = Self::with_worker(
            limits,
            "zip",
            "libarchive-oxide-zip-ppmd8",
            decode_ppmd_worker,
        )?;
        decoder
            .pending_input
            .extend_from_slice(&order.to_le_bytes());
        decoder
            .pending_input
            .extend_from_slice(&memory_size.to_le_bytes());
        decoder
            .pending_input
            .extend_from_slice(&restoration.to_le_bytes());
        decoder
            .pending_input
            .extend_from_slice(&declared_size.to_le_bytes());
        decoder.input_accounting = input_accounting;
        Ok(decoder)
    }

    fn with_worker(
        limits: Limits,
        format: &'static str,
        thread_name: &'static str,
        decode: fn(Receiver<InputMessage>, EventSink, Limits, Arc<AtomicBool>) -> io::Result<()>,
    ) -> Result<Self, ArchiveError> {
        let (sender, input) = mpsc::sync_channel(QUEUE_DEPTH);
        let (event_sender, events) = mpsc::sync_channel(QUEUE_DEPTH);
        let waker_cell = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let sink = EventSink {
            sender: event_sender,
            waker: Arc::clone(&waker_cell),
        };
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || decode(input, sink, limits, worker_cancel))
            .map_err(|error| {
                ArchiveError::new(ErrorKind::Capability)
                    .with_format(format)
                    .with_context(format!("failed to start {format} decoder worker: {error}"))
            })?;
        Ok(Self {
            format,
            sender: Some(sender),
            events: Mutex::new(events),
            waker_cell,
            worker: Mutex::new(Some(worker)),
            cancel,
            pending_input: Vec::with_capacity(MAX_STAGED),
            pending_input_token: None,
            pending_output: Vec::new(),
            output_position: 0,
            input_accounting: InputAccounting::Eager,
            exact_in_flight: None,
            exact_committed: 0,
            next_input_token: 0,
            end_sent: false,
            input_disconnected: false,
            done: false,
            failure: None,
            #[cfg(test)]
            schedule: None,
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
                // Joining the current thread is impossible; cancellation is already visible, so detaching lets this worker return as soon as the wake callback unwinds instead of self-deadlocking.
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
        let worker = if let Ok(worker) = self.worker.get_mut() {
            worker.take()
        } else {
            let error = decoder_malformed(self.format, "pull codec worker handle was poisoned");
            return Err(self.fail(error));
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
                    .with_format(self.format)
                    .with_context(error.to_string());
                Err(self.fail(archive))
            },
            Some(Err(_)) => {
                let error = decoder_malformed(self.format, "pull decoder worker panicked");
                Err(self.fail(error))
            },
            None => {
                let error = decoder_malformed(self.format, "pull decoder worker disconnected");
                Err(self.fail(error))
            },
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
        let token = self.pending_input_token.take();
        let Some(sender) = &self.sender else {
            let error = decoder_malformed(self.format, "pull decoder input is closed");
            return Err(self.fail(error));
        };
        match sender.try_send(InputMessage::Data { bytes, token }) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(InputMessage::Data { bytes, token })) => {
                self.pending_input = bytes;
                #[cfg(test)]
                if let Some(schedule) = &self.schedule {
                    schedule.pause(DriveCheckpoint::InputFull);
                }
                self.pending_input_token = token;
                Ok(false)
            },
            Err(TrySendError::Disconnected(InputMessage::Data { bytes, token })) => {
                self.pending_input = bytes;
                self.pending_input_token = token;
                self.input_disconnected = true;
                self.sender.take();
                Ok(false)
            },
            Err(TrySendError::Disconnected(InputMessage::End)) => {
                let error = decoder_malformed(
                    self.format,
                    "pull decoder input queue returned the wrong disconnected message",
                );
                Err(self.fail(error))
            },
            Err(TrySendError::Full(InputMessage::End)) => {
                let error = decoder_malformed(
                    self.format,
                    "pull decoder input queue returned the wrong full message",
                );
                Err(self.fail(error))
            },
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
            let error = decoder_malformed(self.format, "pull decoder input is closed");
            return Err(self.fail(error));
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
            Err(TrySendError::Disconnected(InputMessage::Data { .. })) => {
                let error = decoder_malformed(
                    self.format,
                    "pull decoder input queue returned the wrong disconnected end marker",
                );
                Err(self.fail(error))
            },
            Err(TrySendError::Full(InputMessage::Data { .. })) => {
                let error = decoder_malformed(
                    self.format,
                    "pull decoder input queue returned the wrong end marker",
                );
                Err(self.fail(error))
            },
        }
    }

    fn handle_event(
        &mut self,
        event: WorkerEvent,
        output: &mut [u8],
    ) -> Result<usize, ArchiveError> {
        match event {
            WorkerEvent::NeedInput => Ok(0),
            WorkerEvent::InputConsumed { token, bytes } => {
                let Some((expected, staged)) = self.exact_in_flight else {
                    let error = decoder_malformed(
                        self.format,
                        "pull worker acknowledged input without an exact checkpoint",
                    );
                    return Err(self.fail(error));
                };
                if token != expected || bytes > staged || self.exact_committed != 0 {
                    let error = decoder_malformed(
                        self.format,
                        "pull worker returned an invalid exact input checkpoint",
                    );
                    return Err(self.fail(error));
                }
                self.exact_in_flight = None;
                self.exact_committed = bytes;
                Ok(0)
            },
            WorkerEvent::Output(bytes) => {
                debug_assert_eq!(self.pending_output.len(), 0);
                self.pending_output = bytes;
                Ok(self.drain_output(output))
            },
        }
    }

    fn poll_event(&mut self, output: &mut [u8]) -> Result<Option<WorkerProgress>, ArchiveError> {
        let event = match self.events.get_mut() {
            Ok(events) => events.try_recv(),
            Err(_) => {
                return Err(self.fail(decoder_malformed(
                    self.format,
                    "pull codec event receiver was poisoned",
                )));
            },
        };
        match event {
            Ok(WorkerEvent::NeedInput) => Ok(Some(WorkerProgress::NeedInput)),
            Ok(event @ (WorkerEvent::Output(_) | WorkerEvent::InputConsumed { .. })) => Ok(Some(
                WorkerProgress::Output(self.handle_event(event, output)?),
            )),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.finish_worker()?;
                Ok(Some(WorkerProgress::Finished))
            },
        }
    }

    fn wait_event(&mut self, output: &mut [u8]) -> Result<usize, ArchiveError> {
        #[cfg(test)]
        if let Some(schedule) = &self.schedule {
            schedule.pause(DriveCheckpoint::Waiting);
        }
        let event = match self.events.get_mut() {
            Ok(events) => events.recv(),
            Err(_) => {
                return Err(self.fail(decoder_malformed(
                    self.format,
                    "pull codec event receiver was poisoned",
                )));
            },
        };
        if let Ok(event) = event {
            self.handle_event(event, output)
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

    fn take_exact_committed(
        &mut self,
        consumed: &mut usize,
        input_len: usize,
    ) -> Result<(), ArchiveError> {
        if self.input_accounting == InputAccounting::Eager || self.exact_committed == 0 {
            return Ok(());
        }
        let remaining = input_len.saturating_sub(*consumed);
        if self.exact_committed > remaining {
            let error = decoder_malformed(
                self.format,
                "checkpointed pull-codec input is missing from the caller buffer",
            );
            return Err(self.fail(error));
        }
        *consumed += self.exact_committed;
        self.exact_committed = 0;
        Ok(())
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
                    .map(|event| event.map(WorkerProgress::produced))
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
            let error = decoder_malformed(self.format, "data follows the completed pull stream");
            return Err(self.fail(error));
        }

        let mut consumed = 0;
        let mut produced = self.drain_output(output);
        'driving: loop {
            self.take_exact_committed(&mut consumed, input.len())?;
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
                produced += read.produced();
                if self.done || !self.pending_output.is_empty() {
                    break;
                }
            }
            self.take_exact_committed(&mut consumed, input.len())?;
            if self.done {
                return Ok(Some(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                }));
            }

            let flushed = self.flush_input()?;
            if flushed
                && consumed < input.len()
                && (self.input_accounting == InputAccounting::Eager
                    || self.exact_in_flight.is_none())
            {
                let accepted = (MAX_STAGED - self.pending_input.len()).min(input.len() - consumed);
                self.pending_input
                    .extend_from_slice(&input[consumed..consumed + accepted]);
                if self.input_accounting == InputAccounting::Acknowledged {
                    let token = self.next_input_token;
                    self.next_input_token =
                        self.next_input_token.checked_add(1).ok_or_else(|| {
                            let error = decoder_malformed(
                                self.format,
                                "checkpointed pull-codec input token overflow",
                            );
                            self.fail(error)
                        })?;
                    self.pending_input_token = Some(token);
                    self.exact_in_flight = Some((token, accepted));
                } else {
                    consumed += accepted;
                }
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
                match read {
                    WorkerProgress::NeedInput => continue 'driving,
                    WorkerProgress::Output(bytes) => produced += bytes,
                    WorkerProgress::Finished => {},
                }
                if self.done || !self.pending_output.is_empty() {
                    break;
                }
            }
            self.take_exact_committed(&mut consumed, input.len())?;
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
            .field("format", &self.format)
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
        self.drive(input, output, end, None)?.ok_or_else(|| {
            decoder_malformed(
                self.format,
                "blocking pull decoder yielded without synchronous progress",
            )
        })
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
#[cfg(feature = "lzip")]
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
            read_ahead: VecDeque::new(),
            current: Vec::new(),
            position: 0,
            current_token: None,
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

            let (counting, unread) = decoder.into_parts();
            let (mut next_pipe, fetched_size) = counting.into_parts();
            let unread_size = u64::try_from(unread.len())
                .map_err(|_| invalid_data("lzip read-ahead size overflow"))?;
            let compressed_size = fetched_size
                .checked_sub(unread_size)
                .ok_or_else(|| invalid_data("lzip read-ahead exceeds fetched input"))?;
            next_pipe.restore_read_ahead(unread)?;
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

#[cfg(any(feature = "lzma", feature = "xz"))]
fn decode_lzma_worker(
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
            current_token: None,
            read_ahead: VecDeque::new(),
            end_received: false,
            eof_read: false,
        };
        let mut header = [0_u8; LZMA_HEADER_BYTES];
        pipe.read_exact(&mut header).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                invalid_data("truncated LZMA-alone header")
            } else {
                error
            }
        })?;
        let properties = header[0];
        let dictionary = u32::from_le_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| invalid_data("invalid LZMA dictionary field"))?,
        );
        let declared_size = u64::from_le_bytes(
            header[5..13]
                .try_into()
                .map_err(|_| invalid_data("invalid LZMA size field"))?,
        );
        validate_lzma_memory(dictionary, properties, limits.codec_memory())?;
        if declared_size != u64::MAX
            && limits
                .decoded_total()
                .is_some_and(|maximum| declared_size > maximum)
        {
            return Err(out_of_memory(
                "LZMA declared size exceeds the configured decoded limit",
            ));
        }
        pipe.eof_read = false;
        let mut decoder = lzma_rust2::LzmaReader::new_with_props(
            pipe,
            declared_size,
            properties,
            dictionary,
            None,
        )?;
        let mut output = vec![0; BUFFER];
        let mut decoded_total = 0_u64;
        loop {
            ensure_worker_active(&cancel)?;
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
            if decoder.inner().eof_read && read_result.is_err() {
                return Err(invalid_data("truncated LZMA-alone payload"));
            }
            let read = read_result?;
            if read == 0 {
                decoder.into_inner().finish()?;
                return Ok(());
            }
            if probing_limit {
                return Err(out_of_memory(
                    "LZMA decoded stream exceeds configured limit",
                ));
            }
            let read_u64 = u64::try_from(read)
                .map_err(|_| invalid_data("LZMA decoded chunk length overflow"))?;
            decoded_total = decoded_total
                .checked_add(read_u64)
                .ok_or_else(|| out_of_memory("LZMA decoded-total counter overflow"))?;
            events
                .send(WorkerEvent::Output(output[..read].to_vec()))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "LZMA codec owner was dropped")
                })?;
        }
    })();
    wake_cell(&waker_cell);
    result
}

#[cfg(feature = "ppmd")]
fn read_ppmd_worker_header(pipe: &mut InputPipe) -> io::Result<(u32, u32, u16, u64)> {
    let mut header = [0_u8; PPMD_WORKER_HEADER_BYTES];
    pipe.read_exact(&mut header).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid_data("truncated ZIP PPMd worker header")
        } else {
            error
        }
    })?;
    let order = u32::from_le_bytes(
        header[0..4]
            .try_into()
            .map_err(|_| invalid_data("invalid ZIP PPMd order field"))?,
    );
    let memory_size = u32::from_le_bytes(
        header[4..8]
            .try_into()
            .map_err(|_| invalid_data("invalid ZIP PPMd memory field"))?,
    );
    let restoration = u16::from_le_bytes(
        header[8..10]
            .try_into()
            .map_err(|_| invalid_data("invalid ZIP PPMd restoration field"))?,
    );
    let declared_size = u64::from_le_bytes(
        header[10..18]
            .try_into()
            .map_err(|_| invalid_data("invalid ZIP PPMd size field"))?,
    );
    Ok((order, memory_size, restoration, declared_size))
}

#[cfg(feature = "ppmd")]
fn decode_ppmd_worker(
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
            current_token: None,
            read_ahead: VecDeque::new(),
            end_received: false,
            eof_read: false,
        };
        let (order, memory_size, restoration, declared_size) = read_ppmd_worker_header(&mut pipe)?;
        pipe.eof_read = false;
        let mut decoder =
            ppmd_rust::Ppmd8Decoder::new(pipe, order, memory_size, restoration.into())
                .map_err(ppmd_setup_io_error)?;
        let mut output = vec![0; BUFFER];
        let mut decoded_total = 0_u64;
        loop {
            ensure_worker_active(&cancel)?;
            if declared_size != u64::MAX && decoded_total == declared_size {
                decoder.into_inner().finish()?;
                return Ok(());
            }
            let remaining_budget = limits
                .decoded_total()
                .map(|maximum| maximum.saturating_sub(decoded_total));
            let probing_limit = remaining_budget == Some(0);
            let declared_remaining = declared_size.saturating_sub(decoded_total);
            let capacity = remaining_budget.map_or(output.len(), |remaining| {
                usize::try_from(remaining.min(output.len() as u64))
                    .unwrap_or(output.len())
                    .max(1)
            });
            let capacity = if declared_size == u64::MAX {
                capacity
            } else {
                usize::try_from(declared_remaining.min(capacity as u64))
                    .unwrap_or(capacity)
                    .max(1)
            };
            let read = decoder.read(&mut output[..capacity])?;
            ensure_worker_active(&cancel)?;
            if decoder.get_ref().eof_read {
                return Err(invalid_data("truncated ZIP PPMd range stream"));
            }
            if read == 0 {
                if declared_size != u64::MAX && decoded_total != declared_size {
                    return Err(invalid_data(
                        "ZIP PPMd stream ended before its declared size",
                    ));
                }
                decoder.into_inner().finish()?;
                return Ok(());
            }
            if probing_limit {
                return Err(out_of_memory(
                    "ZIP PPMd decoded stream exceeds configured limit",
                ));
            }
            let read_u64 = u64::try_from(read)
                .map_err(|_| invalid_data("ZIP PPMd decoded chunk length overflow"))?;
            decoded_total = decoded_total
                .checked_add(read_u64)
                .ok_or_else(|| out_of_memory("ZIP PPMd decoded-total counter overflow"))?;
            events
                .send(WorkerEvent::Output(output[..read].to_vec()))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "ZIP PPMd codec owner was dropped",
                    )
                })?;
        }
    })();
    wake_cell(&waker_cell);
    result
}

#[cfg(feature = "ppmd")]
fn validate_zip_ppmd_parameters(
    parameters: u16,
    limits: Limits,
) -> Result<(u32, u32, u16), ArchiveError> {
    let order = u32::from((parameters & 0x0f) + 1);
    let memory_mb = u32::from(((parameters >> 4) & 0xff) + 1);
    let memory_size = memory_mb.checked_mul(1024 * 1024).ok_or_else(|| {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("zip")
            .with_context("ZIP PPMd model size overflows")
    })?;
    let restoration = (parameters >> 12) & 0x0f;
    if !(2..=16).contains(&order) || restoration > 2 {
        return Err(ArchiveError::new(ErrorKind::Malformed)
            .with_format("zip")
            .with_context("invalid ZIP PPMd parameters"));
    }
    if limits
        .codec_memory()
        .is_some_and(|maximum| memory_size as usize > maximum)
    {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_format("zip")
            .with_context("ZIP PPMd model exceeds codec workspace limit"));
    }
    Ok((order, memory_size, restoration))
}

#[cfg(feature = "ppmd")]
fn ppmd_setup_io_error(error: ppmd_rust::Error) -> io::Error {
    match error {
        ppmd_rust::Error::MemoryAllocation => out_of_memory("ZIP PPMd model allocation failed"),
        ppmd_rust::Error::RangeDecoderInitialization => {
            invalid_data("invalid ZIP PPMd range decoder header")
        },
        ppmd_rust::Error::InvalidParameter => invalid_data("invalid ZIP PPMd parameters"),
        ppmd_rust::Error::IoError(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            invalid_data("truncated ZIP PPMd range header")
        },
        ppmd_rust::Error::IoError(error) => error,
    }
}

#[cfg(feature = "lzip")]
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

#[cfg(feature = "lzip")]
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

#[cfg(feature = "lzip")]
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

#[cfg(any(feature = "lzma", feature = "xz"))]
fn validate_lzma_memory(dictionary: u32, properties: u8, limit: Option<usize>) -> io::Result<()> {
    let required_kib = lzma_rust2::lzma_get_memory_usage_by_props(dictionary, properties)
        .map_err(|error| invalid_data(error.to_string()))?;
    let required = u64::from(required_kib)
        .checked_mul(1024)
        .ok_or_else(|| out_of_memory("LZMA workspace size overflow"))?;
    if limit.is_some_and(|maximum| required > maximum as u64) {
        return Err(out_of_memory(format!(
            "LZMA workspace requires {required} bytes"
        )));
    }
    Ok(())
}

fn decoder_malformed(format: &'static str, context: impl Into<String>) -> ArchiveError {
    ArchiveError::new(ErrorKind::Malformed)
        .with_format(format)
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
            "pull codec owner was dropped",
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

    #[test]
    fn input_request_retries_retained_bytes_before_waiting() {
        super::super::worker::testing::assert_retained_input_progress_with(
            b"LZIP",
            |bytes| super::InputMessage::Data { bytes, token: None },
            super::WorkerEvent::NeedInput,
            |message| match message {
                super::InputMessage::Data { bytes, .. } => Some(bytes),
                super::InputMessage::End => None,
            },
            |channels| {
                let mut decoder = super::LzipDecoder {
                    format: "lzip",
                    sender: Some(channels.sender),
                    events: Mutex::new(channels.events),
                    waker_cell: Arc::new(Mutex::new(None)),
                    worker: Mutex::new(None),
                    cancel: Arc::new(AtomicBool::new(false)),
                    pending_input: channels.retained,
                    pending_input_token: None,
                    pending_output: Vec::new(),
                    output_position: 0,
                    input_accounting: super::InputAccounting::Eager,
                    exact_in_flight: None,
                    exact_committed: 0,
                    next_input_token: 0,
                    end_sent: false,
                    input_disconnected: false,
                    done: false,
                    failure: None,
                    schedule: Some(channels.schedule),
                };
                let mut output = [0_u8; 1];
                decoder.drive(&[], &mut output, super::EndOfInput::More, None)
            },
        );
    }

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
