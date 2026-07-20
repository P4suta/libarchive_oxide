// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded pipelines and synchronous I/O adapters.

use std::fmt;
use std::io::{self, Read, Write};

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchiveDecoder, ArchiveEncoder, ArchiveError, ArchiveMetadata, Codec, CodecStatus, CpioDialect,
    DecodeEvent, EncodeCommand, EncodeStatus, EndOfInput, EntryMetadata, ErrorKind, FormatId,
    Limits, ProbeResult,
};

#[cfg(feature = "aes")]
use crate::SecretBytes;
use crate::filtered_io::SyncFilterWriter;
pub(crate) use crate::provider::BuiltinFormatEncoder as RuntimeEncoder;
use crate::provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, ProviderArchiveEncoder, ProviderSet,
    StaticCodecProviders, StaticFormatProviders, filter_name,
};
use crate::zip::ZipMethod;

const BUFFER: usize = 64 * 1024;
const DETECTION_MINIMUM: usize = 16 * 2048 + 6;

/// A caller-driven pipeline event.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum PipelineEvent<'a> {
    /// Feed more input or mark input complete.
    NeedInput,
    /// Archive-level metadata was discovered.
    ArchiveMetadata(ArchiveMetadata),
    /// A new entry begins.
    Entry(EntryMetadata),
    /// Entry body bytes, valid until the next pipeline call.
    Data(&'a [u8]),
    /// Current entry ended.
    EndEntry,
    /// Archive and every outer filter ended successfully.
    Done,
}

/// A synchronous high-level reader event.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ReaderEvent<'a> {
    /// Archive-level metadata was discovered.
    ArchiveMetadata(ArchiveMetadata),
    /// A new entry begins.
    Entry(EntryMetadata),
    /// Entry body bytes, valid until the next reader call.
    Data(&'a [u8]),
    /// Current entry ended.
    EndEntry,
    /// Archive and every outer filter ended successfully.
    Done,
}

#[derive(Debug)]
enum ErrorSource {
    Archive(ArchiveError),
    Io(io::Error),
}

/// Error from a synchronous archive stream.
#[derive(Debug)]
pub struct StreamError {
    source: ErrorSource,
}

impl StreamError {
    pub(crate) fn archive(error: ArchiveError) -> Self {
        Self {
            source: ErrorSource::Archive(error),
        }
    }

    pub(crate) fn io(error: io::Error) -> Self {
        Self {
            source: ErrorSource::Io(error),
        }
    }

    /// Archive error details, if this was a parsing/policy failure.
    #[must_use]
    pub fn archive_error(&self) -> Option<&ArchiveError> {
        match &self.source {
            ErrorSource::Archive(error) => Some(error),
            ErrorSource::Io(_) => None,
        }
    }

    /// I/O error details, if this originated in an adapter.
    #[must_use]
    pub fn io_error(&self) -> Option<&io::Error> {
        match &self.source {
            ErrorSource::Io(error) => Some(error),
            ErrorSource::Archive(_) => None,
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            ErrorSource::Archive(error) => error.fmt(f),
            ErrorSource::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match &self.source {
            ErrorSource::Archive(error) => error,
            ErrorSource::Io(error) => error,
        })
    }
}

impl From<ArchiveError> for StreamError {
    fn from(value: ArchiveError) -> Self {
        Self::archive(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerState {
    Running,
    Between { xz_padding: usize },
    Done,
}

#[derive(Debug)]
struct CodecLayer<S, D> {
    filter: FilterId,
    selection: S,
    codec: D,
    state: LayerState,
    output: Vec<u8>,
    output_start: usize,
    output_end: usize,
}

enum Drive {
    Ready,
    NeedInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterInputMode {
    Detect,
    Predecoded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinePhase {
    Reading,
    ArchiveDone,
    Done,
}

#[allow(clippy::large_enum_variant)]
enum OwnedPipelineEvent {
    NeedInput,
    ArchiveMetadata(ArchiveMetadata),
    Entry(EntryMetadata),
    Data,
    EndEntry,
    Done,
}

#[allow(clippy::large_enum_variant)]
enum OwnedReaderEvent {
    NeedInput,
    ArchiveMetadata(ArchiveMetadata),
    Entry(EntryMetadata),
    Data,
    EndEntry,
    Done,
}

/// Caller-driven, bounded filter-to-format pipeline.
///
/// Sync and async adapters differ only in how they respond to
/// [`PipelineEvent::NeedInput`].
#[derive(Debug)]
pub struct Pipeline<F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    formats: F,
    codecs: C,
    limits: Limits,
    initial_error: Option<ArchiveError>,
    input: Vec<u8>,
    input_start: usize,
    input_end: usize,
    input_finished: bool,
    layers: Vec<CodecLayer<C::Selection, C::Decoder>>,
    layer_capacity: usize,
    filter_depth: usize,
    decoder: Option<F::Decoder>,
    format: Option<FormatId>,
    event_data: Vec<u8>,
    decoder_scratch: Vec<u8>,
    decoder_stalled: bool,
    phase: PipelinePhase,
    filter_input: FilterInputMode,
}

impl<S, D> CodecLayer<S, D> {
    fn new(filter: FilterId, selection: S, codec: D, capacity: usize) -> Self {
        Self {
            filter,
            selection,
            codec,
            state: LayerState::Running,
            output: vec![0; capacity],
            output_start: 0,
            output_end: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.output[self.output_start..self.output_end]
    }

    fn compact(&mut self) {
        if self.output_start == 0 {
            return;
        }
        self.output
            .copy_within(self.output_start..self.output_end, 0);
        self.output_end -= self.output_start;
        self.output_start = 0;
    }
}

impl Pipeline<BuiltinFormatProviders, BuiltinCodecProviders> {
    /// Creates a pipeline with explicit resource limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self::with_filter_mode(
            limits,
            FilterInputMode::Detect,
            BuiltinFormatProviders,
            BuiltinCodecProviders,
        )
    }

    pub(crate) fn after_filter_adapters(limits: Limits) -> Self {
        Self::with_filter_mode(
            limits,
            FilterInputMode::Predecoded,
            BuiltinFormatProviders,
            BuiltinCodecProviders,
        )
    }
}

impl<F, C> Pipeline<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Creates a bounded pipeline from an explicitly registered provider set.
    #[must_use]
    pub fn with_providers(limits: Limits, providers: ProviderSet<F, C>) -> Self {
        let (formats, codecs) = providers.into_chains();
        Self::with_filter_mode(limits, FilterInputMode::Detect, formats, codecs)
    }

    fn with_filter_mode(
        limits: Limits,
        filter_input: FilterInputMode,
        formats: F,
        codecs: C,
    ) -> Self {
        let filter_depth = if filter_input == FilterInputMode::Detect {
            limits.filter_depth().unwrap_or(64)
        } else {
            0
        };
        let buffer_count = filter_depth.saturating_add(3);
        let configured = limits.in_flight_bytes().unwrap_or(usize::MAX);
        let capacity = if configured == usize::MAX {
            BUFFER
        } else {
            (configured / buffer_count.max(1)).min(BUFFER)
        };
        let initial_error = (capacity < DETECTION_MINIMUM).then(|| {
            ArchiveError::new(ErrorKind::Limit).with_context(
                "in-flight limit is too small for detection and configured filter depth",
            )
        });
        let capacity = capacity.max(1);
        Self {
            formats,
            codecs,
            limits,
            initial_error,
            input: vec![0; capacity],
            input_start: 0,
            input_end: 0,
            input_finished: false,
            layers: Vec::new(),
            layer_capacity: capacity,
            filter_depth,
            decoder: None,
            format: None,
            event_data: Vec::with_capacity(capacity),
            decoder_scratch: vec![0; capacity],
            decoder_stalled: false,
            phase: PipelinePhase::Reading,
            filter_input,
        }
    }

    /// Available capacity for [`Pipeline::feed`].
    #[must_use]
    pub fn feed_capacity(&self) -> usize {
        self.input.len() - (self.input_end - self.input_start)
    }

    fn compact_input(&mut self) {
        if self.input_start == 0 {
            return;
        }
        self.input.copy_within(self.input_start..self.input_end, 0);
        self.input_end -= self.input_start;
        self.input_start = 0;
    }

    /// Copies as many input bytes as fit in the bounded pipeline buffer.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<usize, ArchiveError> {
        if self.input_finished {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("input supplied after finish_input"));
        }
        if self.phase == PipelinePhase::Done {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("input supplied after pipeline completion"));
        }
        self.compact_input();
        let count = bytes.len().min(self.input.len() - self.input_end);
        self.input[self.input_end..self.input_end + count].copy_from_slice(&bytes[..count]);
        self.input_end += count;
        Ok(count)
    }

    /// Marks the byte source complete.
    pub fn finish_input(&mut self) -> Result<(), ArchiveError> {
        if self.input_finished {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("finish_input called more than once"));
        }
        if self.phase == PipelinePhase::Done {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("finish_input called after pipeline completion"));
        }
        self.input_finished = true;
        Ok(())
    }

    fn source(&self, layer: usize) -> &[u8] {
        if layer == 0 {
            &self.input[self.input_start..self.input_end]
        } else {
            self.layers[layer - 1].available()
        }
    }

    fn source_finished(&self, layer: usize) -> bool {
        if layer == 0 {
            self.input_finished && self.input_start == self.input_end
        } else {
            let previous = &self.layers[layer - 1];
            previous.state == LayerState::Done && previous.output_start == previous.output_end
        }
    }

    fn consume_source(&mut self, layer: usize, count: usize) {
        if layer == 0 {
            self.input_start += count;
        } else {
            self.layers[layer - 1].output_start += count;
        }
    }

    fn fill_source(&mut self, layer: usize, minimum: usize) -> Result<Drive, ArchiveError> {
        if self.source(layer).len() >= minimum || self.source_finished(layer) {
            return Ok(Drive::Ready);
        }
        if layer == 0 {
            return Ok(Drive::NeedInput);
        }
        self.drive_layer(layer - 1, minimum)
    }

    fn drive_between_members(&mut self, layer: usize) -> Result<Drive, ArchiveError> {
        loop {
            let (filter, mut padding) = match self.layers[layer].state {
                LayerState::Between { xz_padding } => (self.layers[layer].filter, xz_padding),
                LayerState::Running | LayerState::Done => return Ok(Drive::Ready),
            };

            if filter == FilterId::Xz {
                while self.source(layer).first() == Some(&0) {
                    self.consume_source(layer, 1);
                    padding = padding.checked_add(1).ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Limit)
                            .with_format("xz")
                            .with_context("XZ padding count overflow")
                    })?;
                    self.layers[layer].state = LayerState::Between {
                        xz_padding: padding,
                    };
                }
            }

            if self.source(layer).is_empty() {
                if self.source_finished(layer) {
                    if filter == FilterId::Xz && padding % 4 != 0 {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_format("xz")
                            .with_context("XZ stream padding is not a multiple of four"));
                    }
                    self.layers[layer].state = LayerState::Done;
                    return Ok(Drive::Ready);
                }
                if matches!(self.fill_source(layer, 1)?, Drive::NeedInput) {
                    return Ok(Drive::NeedInput);
                }
                continue;
            }

            if filter == FilterId::Xz && padding % 4 != 0 {
                return Err(ArchiveError::new(ErrorKind::Malformed)
                    .with_format("xz")
                    .with_context("XZ stream padding is not a multiple of four"));
            }
            match self.codecs.probe_codec(self.source(layer))? {
                ProbeResult::Match((next, selection)) if next == filter => {
                    let codec = self.codecs.codec_decoder(selection.clone(), self.limits)?;
                    self.layers[layer].selection = selection;
                    self.layers[layer].codec = codec;
                    self.layers[layer].state = LayerState::Running;
                    return Ok(Drive::Ready);
                },
                ProbeResult::NeedMore { minimum } if !self.source_finished(layer) => {
                    if matches!(self.fill_source(layer, minimum)?, Drive::NeedInput) {
                        return Ok(Drive::NeedInput);
                    }
                },
                _ => {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_format(filter_name(filter))
                        .with_context("non-member trailing data"));
                },
            }
        }
    }

    fn drive_layer(&mut self, layer: usize, minimum: usize) -> Result<Drive, ArchiveError> {
        loop {
            if self.layers[layer].available().len() >= minimum {
                return Ok(Drive::Ready);
            }
            self.layers[layer].compact();
            match self.layers[layer].state {
                LayerState::Done => return Ok(Drive::Ready),
                LayerState::Between { .. } => {
                    if matches!(self.drive_between_members(layer)?, Drive::NeedInput) {
                        return Ok(Drive::NeedInput);
                    }
                    continue;
                },
                LayerState::Running => {},
            }

            if self.source(layer).is_empty()
                && !self.source_finished(layer)
                && matches!(self.fill_source(layer, 1)?, Drive::NeedInput)
            {
                return Ok(Drive::NeedInput);
            }

            let end = if self.source_finished(layer) {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let source_len = self.source(layer).len();
            let output_len = self.layers[layer].output.len() - self.layers[layer].output_end;
            if output_len == 0 {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context("filter layer exhausted its bounded output buffer"));
            }
            let step = if layer == 0 {
                let start = self.input_start;
                let end_offset = self.input_end;
                let current = &mut self.layers[0];
                current.codec.process(
                    &self.input[start..end_offset],
                    &mut current.output[current.output_end..],
                    end,
                )
            } else {
                let (previous, current) = self.layers.split_at_mut(layer);
                let source = &mut previous[layer - 1];
                let current = &mut current[0];
                current.codec.process(
                    &source.output[source.output_start..source.output_end],
                    &mut current.output[current.output_end..],
                    end,
                )
            }?
            .validate(source_len, output_len)?;
            self.consume_source(layer, step.consumed);
            self.layers[layer].output_end += step.produced;
            if matches!(step.status, CodecStatus::Done) {
                self.layers[layer].state = LayerState::Between { xz_padding: 0 };
            }
            if self.layers[layer].available().len() >= minimum {
                return Ok(Drive::Ready);
            }
        }
    }

    fn plain(&self) -> &[u8] {
        self.layers.last().map_or_else(
            || &self.input[self.input_start..self.input_end],
            CodecLayer::available,
        )
    }

    fn plain_finished(&self) -> bool {
        self.layers.last().map_or(
            self.input_finished && self.input_start == self.input_end,
            |layer| layer.state == LayerState::Done && layer.output_start == layer.output_end,
        )
    }

    fn plain_exhausted(&self) -> bool {
        self.layers
            .last()
            .map_or(self.input_finished, |layer| layer.state == LayerState::Done)
    }

    fn consume_plain(&mut self, count: usize) {
        if let Some(layer) = self.layers.last_mut() {
            layer.output_start += count;
        } else {
            self.input_start += count;
        }
    }

    fn fill_plain(&mut self, minimum: usize) -> Result<Drive, ArchiveError> {
        if self.plain().len() >= minimum || self.plain_finished() {
            return Ok(Drive::Ready);
        }
        let Some(last) = self.layers.len().checked_sub(1) else {
            return Ok(Drive::NeedInput);
        };
        self.drive_layer(last, minimum)
    }

    fn install_decoder(
        &mut self,
        format: FormatId,
        selection: F::Selection,
    ) -> Result<(), ArchiveError> {
        self.decoder = Some(self.formats.format_decoder(selection, self.limits)?);
        self.format = Some(format);
        Ok(())
    }

    fn detect_decoder(&mut self) -> Result<Drive, ArchiveError> {
        loop {
            if self.plain().is_empty() && !self.plain_finished() {
                if matches!(self.fill_plain(1)?, Drive::NeedInput) {
                    return Ok(Drive::NeedInput);
                }
                continue;
            }

            let filter_probe = self.codecs.probe_codec(self.plain())?;
            if let ProbeResult::Match((filter, selection)) = filter_probe {
                if self.filter_input == FilterInputMode::Predecoded {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_context("outer filter nesting exceeds configured depth"));
                }
                if self.layers.len() >= self.filter_depth {
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_context("outer filter nesting exceeds configured depth"));
                }
                let codec = self.codecs.codec_decoder(selection.clone(), self.limits)?;
                self.layers.push(CodecLayer::new(
                    filter,
                    selection,
                    codec,
                    self.layer_capacity,
                ));
                continue;
            }
            if !self.plain_exhausted() {
                if let ProbeResult::NeedMore { minimum } = filter_probe {
                    if matches!(self.fill_plain(minimum)?, Drive::NeedInput) {
                        return Ok(Drive::NeedInput);
                    }
                    continue;
                }
            }

            match self.formats.probe_format(self.plain())? {
                ProbeResult::Match((format, selection)) => {
                    self.install_decoder(format, selection)?;
                    return Ok(Drive::Ready);
                },
                ProbeResult::NeedMore { minimum } if !self.plain_exhausted() => {
                    if matches!(self.fill_plain(minimum)?, Drive::NeedInput) {
                        return Ok(Drive::NeedInput);
                    }
                },
                _ => {
                    if self.plain_exhausted()
                        && self.plain().len() >= 2 * 512
                        && self.plain()[..2 * 512].iter().all(|byte| *byte == 0)
                    {
                        let selection = self.formats.select_format(FormatId::Tar)?;
                        self.install_decoder(FormatId::Tar, selection)?;
                        return Ok(Drive::Ready);
                    }
                    return Err(ArchiveError::new(ErrorKind::Unsupported)
                        .with_context("no registered sequential archive format matched"));
                },
            }
        }
    }
    fn poll_after_archive(&mut self) -> Result<PipelineEvent<'_>, ArchiveError> {
        loop {
            if !self.plain().is_empty() {
                let invalid = match self.format {
                    Some(FormatId::Tar) => self.plain().iter().any(|byte| *byte != 0),
                    _ => true,
                };
                if invalid {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_context("invalid trailing archive data"));
                }
                let count = self.plain().len();
                self.consume_plain(count);
            }
            if self.plain_finished() {
                self.phase = PipelinePhase::Done;
                return Ok(PipelineEvent::Done);
            }
            if matches!(self.fill_plain(1)?, Drive::NeedInput) {
                return Ok(PipelineEvent::NeedInput);
            }
        }
    }

    /// Polls one structural event without performing I/O.
    #[allow(clippy::too_many_lines)]
    pub fn poll_event(&mut self) -> Result<PipelineEvent<'_>, ArchiveError> {
        if let Some(error) = self.initial_error.take() {
            return Err(error);
        }
        if self.phase == PipelinePhase::Done {
            return Ok(PipelineEvent::Done);
        }
        self.event_data.clear();
        if self.phase == PipelinePhase::ArchiveDone {
            return self.poll_after_archive();
        }

        loop {
            if self.decoder.is_none() && matches!(self.detect_decoder()?, Drive::NeedInput) {
                return Ok(PipelineEvent::NeedInput);
            }
            if self.plain().is_empty()
                && !self.plain_finished()
                && matches!(self.fill_plain(1)?, Drive::NeedInput)
            {
                return Ok(PipelineEvent::NeedInput);
            }

            let input_len = self.plain().len();
            let output_len = self.decoder_scratch.len();
            let end = if self.plain_finished() {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = if let Some(layer) = self.layers.last() {
                self.decoder
                    .as_mut()
                    .ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Protocol)
                            .with_context("archive detection completed without a decoder")
                    })?
                    .step(
                        &layer.output[layer.output_start..layer.output_end],
                        &mut self.decoder_scratch,
                        end,
                    )
            } else {
                self.decoder
                    .as_mut()
                    .ok_or_else(|| {
                        ArchiveError::new(ErrorKind::Protocol)
                            .with_context("archive detection completed without a decoder")
                    })?
                    .step(
                        &self.input[self.input_start..self.input_end],
                        &mut self.decoder_scratch,
                        end,
                    )
            }?
            .validate(input_len, output_len)?;
            let consumed = step.consumed;
            let event = match step.event {
                DecodeEvent::NeedInput => OwnedPipelineEvent::NeedInput,
                DecodeEvent::NeedOutput => {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_context("decoder requested more than the configured output buffer"));
                },
                DecodeEvent::ArchiveMetadata(metadata) => {
                    OwnedPipelineEvent::ArchiveMetadata(metadata)
                },
                DecodeEvent::Entry(metadata) => OwnedPipelineEvent::Entry(metadata),
                DecodeEvent::Data(chunk) => {
                    self.event_data.extend_from_slice(chunk.as_bytes());
                    OwnedPipelineEvent::Data
                },
                DecodeEvent::EndEntry => OwnedPipelineEvent::EndEntry,
                DecodeEvent::Done => OwnedPipelineEvent::Done,
                _ => {
                    return Err(ArchiveError::new(ErrorKind::Protocol)
                        .with_context("unknown archive decoder event"));
                },
            };
            self.consume_plain(consumed);
            if consumed != 0 || !matches!(&event, OwnedPipelineEvent::NeedInput) {
                self.decoder_stalled = false;
            }

            match event {
                OwnedPipelineEvent::NeedInput => {
                    if self.plain_finished() {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_context("archive ended before the decoder reached Done"));
                    }
                    if consumed == 0 && input_len != 0 && !self.decoder_stalled {
                        self.decoder_stalled = true;
                        continue;
                    }
                    if consumed == 0 {
                        let minimum = input_len.checked_add(1).ok_or_else(|| {
                            ArchiveError::new(ErrorKind::Limit)
                                .with_context("archive input lookahead overflow")
                        })?;
                        if matches!(self.fill_plain(minimum)?, Drive::NeedInput) {
                            if self.feed_capacity() == 0 {
                                return Err(ArchiveError::new(ErrorKind::Protocol)
                                    .with_context("archive decoder made a no-progress loop"));
                            }
                            return Ok(PipelineEvent::NeedInput);
                        }
                    }
                },
                OwnedPipelineEvent::ArchiveMetadata(metadata) => {
                    return Ok(PipelineEvent::ArchiveMetadata(metadata));
                },
                OwnedPipelineEvent::Entry(metadata) => {
                    return Ok(PipelineEvent::Entry(metadata));
                },
                OwnedPipelineEvent::Data => {
                    return Ok(PipelineEvent::Data(&self.event_data));
                },
                OwnedPipelineEvent::EndEntry => return Ok(PipelineEvent::EndEntry),
                OwnedPipelineEvent::Done => {
                    self.phase = PipelinePhase::ArchiveDone;
                    return self.poll_after_archive();
                },
            }
        }
    }

    pub(crate) fn into_providers(self) -> ProviderSet<F, C> {
        ProviderSet::from_chains(self.formats, self.codecs)
    }

    /// Resource limits used by this pipeline.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Detected archive format, once enough plaintext has been observed.
    #[must_use]
    pub const fn format(&self) -> Option<FormatId> {
        self.format
    }
}

/// Incremental archive reader over [`Read`].
pub struct ArchiveReader<R: Read, F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    reader: ReaderInput<R>,
    pipeline: Pipeline<F, C>,
    read_buffer: Vec<u8>,
    event_data: Vec<u8>,
}

impl<R, F, C> fmt::Debug for ArchiveReader<R, F, C>
where
    R: Read,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchiveReader")
            .field("limits", &self.pipeline.limits())
            .field("format", &self.pipeline.format())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum ReaderInput<R: Read> {
    Uninitialized(Option<R>),
    Plain(R),
    One(Box<crate::filtered_io::FilterReader<R>>),
    Two(Box<crate::filtered_io::FilterReader<crate::filtered_io::FilterReader<R>>>),
    Three(
        Box<
            crate::filtered_io::FilterReader<
                crate::filtered_io::FilterReader<crate::filtered_io::FilterReader<R>>,
            >,
        >,
    ),
    Four(
        Box<
            crate::filtered_io::FilterReader<
                crate::filtered_io::FilterReader<
                    crate::filtered_io::FilterReader<crate::filtered_io::FilterReader<R>>,
                >,
            >,
        >,
    ),
}

impl<R: Read> ReaderInput<R> {
    fn initialize(input: R, limits: Limits) -> io::Result<Self> {
        let depth = limits.filter_depth().unwrap_or(4).min(4);
        if depth == 0 {
            return Ok(Self::Plain(input));
        }
        let one = crate::filtered_io::FilterReader::with_limits(input, limits)?;
        if depth == 1 {
            return Ok(Self::One(Box::new(one)));
        }
        let two = crate::filtered_io::FilterReader::with_limits(one, limits)?;
        if depth == 2 {
            return Ok(Self::Two(Box::new(two)));
        }
        let three = crate::filtered_io::FilterReader::with_limits(two, limits)?;
        if depth == 3 {
            return Ok(Self::Three(Box::new(three)));
        }
        let four = crate::filtered_io::FilterReader::with_limits(three, limits)?;
        Ok(Self::Four(Box::new(four)))
    }

    fn read(&mut self, output: &mut [u8], limits: Limits) -> io::Result<usize> {
        if let Self::Uninitialized(input) = self {
            let input = input
                .take()
                .ok_or_else(|| io::Error::other("archive input disappeared during detection"))?;
            *self = Self::initialize(input, limits)?;
        }
        match self {
            Self::Plain(input) => input.read(output),
            Self::One(input) => input.read(output),
            Self::Two(input) => input.read(output),
            Self::Three(input) => input.read(output),
            Self::Four(input) => input.read(output),
            Self::Uninitialized(_) => Err(io::Error::other(
                "archive input remained uninitialized after detection",
            )),
        }
    }

    #[allow(clippy::expect_used)]
    fn into_inner(self) -> R {
        match self {
            Self::Uninitialized(input) => {
                input.expect("uninitialized archive reader always owns its input")
            },
            Self::Plain(input) => input,
            Self::One(input) => (*input).into_inner(),
            Self::Two(input) => (*input).into_inner().into_inner(),
            Self::Three(input) => (*input).into_inner().into_inner().into_inner(),
            Self::Four(input) => (*input).into_inner().into_inner().into_inner().into_inner(),
        }
    }
}

impl<R: Read> ArchiveReader<R, BuiltinFormatProviders, BuiltinCodecProviders> {
    /// Builds a bounded reader with the safe default limits.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::default())
    }

    /// Builds a bounded reader with explicit limits.
    #[must_use]
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            reader: ReaderInput::Uninitialized(Some(reader)),
            pipeline: Pipeline::after_filter_adapters(limits),
            read_buffer: vec![0; BUFFER],
            event_data: Vec::with_capacity(BUFFER),
        }
    }
}

impl<R, F, C> ArchiveReader<R, F, C>
where
    R: Read,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Builds a bounded reader that uses one statically registered provider set.
    #[must_use]
    pub fn with_providers(reader: R, limits: Limits, providers: ProviderSet<F, C>) -> Self {
        Self {
            reader: ReaderInput::Plain(reader),
            pipeline: Pipeline::with_providers(limits, providers),
            read_buffer: vec![0; BUFFER],
            event_data: Vec::with_capacity(BUFFER),
        }
    }
    /// Produces the next structural event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        loop {
            let event = match self.pipeline.poll_event().map_err(StreamError::archive)? {
                PipelineEvent::NeedInput => OwnedReaderEvent::NeedInput,
                PipelineEvent::ArchiveMetadata(meta) => OwnedReaderEvent::ArchiveMetadata(meta),
                PipelineEvent::Entry(meta) => OwnedReaderEvent::Entry(meta),
                PipelineEvent::Data(data) => {
                    self.event_data.clear();
                    self.event_data.extend_from_slice(data);
                    OwnedReaderEvent::Data
                },
                PipelineEvent::EndEntry => OwnedReaderEvent::EndEntry,
                PipelineEvent::Done => OwnedReaderEvent::Done,
            };
            match event {
                OwnedReaderEvent::NeedInput => {
                    let capacity = self.pipeline.feed_capacity().min(self.read_buffer.len());
                    if capacity == 0 {
                        return Err(StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_context("pipeline requested input without capacity"),
                        ));
                    }
                    let n = self
                        .reader
                        .read(&mut self.read_buffer[..capacity], self.pipeline.limits())
                        .map_err(StreamError::io)?;
                    if n == 0 {
                        self.pipeline.finish_input().map_err(StreamError::archive)?;
                    } else {
                        let accepted = self
                            .pipeline
                            .feed(&self.read_buffer[..n])
                            .map_err(StreamError::archive)?;
                        if accepted != n {
                            return Err(StreamError::archive(
                                ArchiveError::new(ErrorKind::Protocol)
                                    .with_context("pipeline accepted a partial adapter read"),
                            ));
                        }
                    }
                },
                OwnedReaderEvent::ArchiveMetadata(meta) => {
                    return Ok(ReaderEvent::ArchiveMetadata(meta));
                },
                OwnedReaderEvent::Entry(meta) => return Ok(ReaderEvent::Entry(meta)),
                OwnedReaderEvent::Data => return Ok(ReaderEvent::Data(&self.event_data)),
                OwnedReaderEvent::EndEntry => return Ok(ReaderEvent::EndEntry),
                OwnedReaderEvent::Done => return Ok(ReaderEvent::Done),
            }
        }
    }

    pub(crate) fn into_parts(self) -> (R, ProviderSet<F, C>) {
        (self.reader.into_inner(), self.pipeline.into_providers())
    }

    /// Returns the wrapped input.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Resource budgets used by this reader.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.pipeline.limits()
    }

    /// Detected format, once the first archive event is available.
    #[must_use]
    pub const fn format(&self) -> Option<FormatId> {
        self.pipeline.format()
    }
}

/// Incremental archive writer over a sequential [`Write`] destination.
#[derive(Debug)]
pub struct ArchiveWriter<W: Write> {
    output: SyncFilterWriter<W>,
    encoder: RuntimeEncoder,
    format: FormatId,
    buffer: Vec<u8>,
    failed: bool,
}

impl<W: Write> ArchiveWriter<W> {
    /// Creates a sequential tar writer.
    #[must_use]
    pub fn new(output: W) -> Self {
        Self {
            output: SyncFilterWriter::plain(output),
            encoder: RuntimeEncoder::tar(Limits::default()),
            format: FormatId::Tar,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a sequential writer for an explicit format.
    pub fn with_format(output: W, format: FormatId) -> Result<Self, ArchiveError> {
        Self::with_format_and_limits(output, format, Limits::default())
    }

    /// Creates a sequential writer with explicit format and resource limits.
    pub fn with_format_and_limits(
        output: W,
        format: FormatId,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        Ok(Self {
            output: SyncFilterWriter::plain(output),
            encoder: RuntimeEncoder::sequential(format, limits)?,
            format,
            buffer: vec![0; BUFFER],
            failed: false,
        })
    }

    /// Creates a sequential ZIP writer with an explicit compression method.
    pub fn with_zip_method(output: W, method: ZipMethod, limits: Limits) -> Self {
        Self {
            output: SyncFilterWriter::plain(output),
            encoder: RuntimeEncoder::zip(limits, method),
            format: FormatId::Zip,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a sequential cpio writer for an explicit header dialect.
    pub fn with_cpio_dialect(output: W, dialect: CpioDialect, limits: Limits) -> Self {
        Self {
            output: SyncFilterWriter::plain(output),
            encoder: RuntimeEncoder::cpio(limits, dialect),
            format: FormatId::Cpio,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a streaming `WinZip` AES-256 AE-2 writer.
    #[cfg(feature = "aes")]
    pub fn with_zip_password(
        output: W,
        method: ZipMethod,
        password: SecretBytes,
        limits: Limits,
    ) -> Self {
        Self {
            output: SyncFilterWriter::plain(output),
            encoder: RuntimeEncoder::encrypted_zip(limits, method, password),
            format: FormatId::Zip,
            buffer: vec![0; BUFFER],
            failed: false,
        }
    }

    /// Creates a sequential writer with an optional outer filter.
    pub fn with_filter(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let encoder = RuntimeEncoder::sequential(format, limits)?;
        Ok(Self {
            output: SyncFilterWriter::new(output, filter, limits)?,
            encoder,
            format,
            buffer: vec![0; BUFFER],
            failed: false,
        })
    }

    fn emit(&mut self, produced: usize) -> Result<(), StreamError> {
        if produced == 0 {
            return Ok(());
        }
        if let Err(error) = self.output.write_all(&self.buffer[..produced]) {
            self.failed = true;
            return Err(StreamError::io(error));
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), StreamError> {
        if self.failed {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive writer is poisoned by an earlier I/O error"),
            ));
        }
        Ok(())
    }

    /// Sets archive-level metadata before the first entry.
    pub fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        self.encoder
            .set_archive_metadata(metadata)
            .map_err(StreamError::archive)
    }

    /// Begins an entry. Tar requires `metadata.size()` to be present.
    pub fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        let mut accepted = false;
        while !accepted {
            let step = self
                .encoder
                .step(EncodeCommand::BeginEntry(metadata), &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced)?;
            accepted = step.consumed == 1;
            if !accepted && step.produced == 0 && !matches!(step.status, EncodeStatus::NeedOutput) {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder did not accept begin-entry"),
                ));
            }
        }
        Ok(())
    }

    /// Streams entry body bytes.
    pub fn write_data(&mut self, mut data: &[u8]) -> Result<(), StreamError> {
        self.ensure_live()?;
        while !data.is_empty() {
            let step = self
                .encoder
                .step(EncodeCommand::Data(data), &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced)?;
            data = &data[step.consumed..];
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder made no write progress"),
                ));
            }
        }
        Ok(())
    }

    /// Ends the current entry and verifies its declared size.
    pub fn end_entry(&mut self) -> Result<(), StreamError> {
        self.ensure_live()?;
        let mut accepted = false;
        while !accepted {
            let step = self
                .encoder
                .step(EncodeCommand::EndEntry, &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced)?;
            accepted = step.consumed == 1;
            if !accepted && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder did not accept end-entry"),
                ));
            }
        }
        Ok(())
    }

    /// Finalizes the archive and returns the underlying destination.
    pub fn finish(mut self) -> Result<W, StreamError> {
        self.ensure_live()?;
        loop {
            let step = self
                .encoder
                .step(EncodeCommand::Finish, &mut self.buffer)
                .map_err(StreamError::archive)?;
            self.emit(step.produced)?;
            if matches!(step.status, EncodeStatus::Done) {
                return self.output.finish().map_err(StreamError::io);
            }
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("tar encoder made no finish progress"),
                ));
            }
        }
    }

    /// Abandons the archive without adding a trailer.
    pub fn abort(self) -> Result<W, StreamError> {
        self.output.abort().map_err(StreamError::io)
    }

    /// Output archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }
}

enum ProviderFilterOutput<W, C>
where
    W: Write,
    C: StaticCodecProviders,
{
    Plain {
        output: W,
        _codecs: C,
    },
    Framed {
        output: W,
        codecs: C,
        selection: C::Selection,
        input: Vec<u8>,
        frame_capacity: usize,
        reserved_bytes: usize,
        maximum_bytes: Option<usize>,
        limits: Box<Limits>,
        wrote_frame: bool,
    },
}

impl<W, C> ProviderFilterOutput<W, C>
where
    W: Write,
    C: StaticCodecProviders,
{
    fn write_bytes(&mut self, mut bytes: &[u8]) -> Result<(), StreamError> {
        if let Self::Plain { output, .. } = self {
            return output.write_all(bytes).map_err(StreamError::io);
        }
        while !bytes.is_empty() {
            let full = match self {
                Self::Framed {
                    input,
                    frame_capacity,
                    ..
                } => input.len() == *frame_capacity,
                Self::Plain { .. } => false,
            };
            if full {
                self.emit_frame()?;
                continue;
            }
            let consumed = match self {
                Self::Framed {
                    input,
                    frame_capacity,
                    ..
                } => {
                    let consumed = (*frame_capacity - input.len()).min(bytes.len());
                    input.extend_from_slice(&bytes[..consumed]);
                    consumed
                },
                Self::Plain { .. } => 0,
            };
            bytes = &bytes[consumed..];
        }
        Ok(())
    }
    fn emit_frame(&mut self) -> Result<(), StreamError> {
        let Self::Framed {
            output,
            codecs,
            selection,
            input,
            reserved_bytes,
            maximum_bytes,
            limits,
            wrote_frame,
            ..
        } = self
        else {
            return Ok(());
        };
        let encoded = codecs
            .encode_codec_frame(selection.clone(), input, **limits)
            .map_err(StreamError::archive)?;
        if maximum_bytes.is_some_and(|maximum| {
            reserved_bytes
                .checked_add(input.len())
                .and_then(|used| used.checked_add(encoded.len()))
                .is_none_or(|used| used > maximum)
        }) {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_context("registered codec frame exceeds the writer in-flight budget"),
            ));
        }
        output.write_all(&encoded).map_err(StreamError::io)?;
        input.clear();
        *wrote_frame = true;
        Ok(())
    }

    fn finish(mut self) -> Result<W, StreamError> {
        match &mut self {
            Self::Plain { output, .. } => output.flush().map_err(StreamError::io)?,
            Self::Framed {
                input, wrote_frame, ..
            } => {
                if !input.is_empty() || !*wrote_frame {
                    self.emit_frame()?;
                }
                if let Self::Framed { output, .. } = &mut self {
                    output.flush().map_err(StreamError::io)?;
                }
            },
        }
        Ok(match self {
            Self::Plain { output, .. } | Self::Framed { output, .. } => output,
        })
    }

    fn abort(self) -> W {
        match self {
            Self::Plain { output, .. } | Self::Framed { output, .. } => output,
        }
    }
}

/// Sequential writer backed by one statically registered provider set.
pub struct ProviderArchiveWriter<W, F, C>
where
    W: Write,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    output: ProviderFilterOutput<W, C>,
    encoder: F::Encoder,
    format: FormatId,
    buffer: Vec<u8>,
    failed: bool,
}

impl<W, F, C> fmt::Debug for ProviderArchiveWriter<W, F, C>
where
    W: Write,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderArchiveWriter")
            .field("format", &self.format)
            .field("buffer_capacity", &self.buffer.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<W, F, C> ProviderArchiveWriter<W, F, C>
where
    W: Write,
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Builds a bounded writer from an explicitly registered provider set.
    pub fn with_providers(
        output: W,
        format: FormatId,
        filter: Option<FilterId>,
        limits: Limits,
        providers: ProviderSet<F, C>,
    ) -> Result<Self, ArchiveError> {
        let (formats, codecs) = providers.into_chains();
        let format_selection = formats.select_format(format)?;
        let encoder = formats.format_encoder(format_selection, limits)?;
        let maximum_bytes = limits.in_flight_bytes();
        let configured = maximum_bytes.unwrap_or(BUFFER.saturating_mul(4));
        let capacity = (configured / 4).clamp(1, BUFFER);
        let output = if let Some(filter) = filter {
            let selection = codecs.select_codec(filter)?;
            // Construct once here so a decode-only/disabled provider fails before any output.
            if !matches!(
                codecs.codec_capability(filter),
                crate::provider::ProviderCapability::Available(capability)
                    if capability.can_encode()
            ) {
                return Err(ArchiveError::new(ErrorKind::Capability)
                    .with_format(filter_name(filter))
                    .with_context("registered codec provider cannot encode this filter"));
            }
            ProviderFilterOutput::Framed {
                output,
                codecs,
                selection,
                input: Vec::with_capacity(capacity),
                frame_capacity: capacity,
                reserved_bytes: capacity,
                maximum_bytes,
                limits: Box::new(limits),
                wrote_frame: false,
            }
        } else {
            ProviderFilterOutput::Plain {
                output,
                _codecs: codecs,
            }
        };
        Ok(Self {
            output,
            encoder,
            format,
            buffer: vec![0; capacity],
            failed: false,
        })
    }

    fn encoder_step(
        &mut self,
        command: EncodeCommand<'_>,
    ) -> Result<libarchive_oxide_core::EncodeStep, StreamError> {
        let data_len = match &command {
            EncodeCommand::Data(data) => Some(data.len()),
            _ => None,
        };
        let output_len = self.buffer.len();
        self.encoder
            .step(command, &mut self.buffer)
            .and_then(|step| step.validate(data_len, output_len))
            .map_err(StreamError::archive)
    }

    fn emit(&mut self, produced: usize) -> Result<(), StreamError> {
        if produced == 0 {
            return Ok(());
        }
        if let Err(error) = self.output.write_bytes(&self.buffer[..produced]) {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), StreamError> {
        if self.failed {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive writer is poisoned by an earlier output error"),
            ));
        }
        Ok(())
    }

    /// Sets archive-level metadata before the first entry.
    pub fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        self.encoder
            .set_archive_metadata(metadata)
            .map_err(StreamError::archive)
    }

    /// Begins one entry.
    pub fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.ensure_live()?;
        loop {
            let step = self.encoder_step(EncodeCommand::BeginEntry(metadata))?;
            self.emit(step.produced)?;
            if step.consumed == 1 {
                return Ok(());
            }
            if step.produced == 0 {
                let (kind, context) = if matches!(step.status, EncodeStatus::NeedOutput) {
                    (
                        ErrorKind::Limit,
                        "format provider requires more output than the in-flight budget",
                    )
                } else {
                    (
                        ErrorKind::Protocol,
                        "format provider did not accept begin-entry",
                    )
                };
                return Err(StreamError::archive(
                    ArchiveError::new(kind).with_context(context),
                ));
            }
        }
    }

    /// Streams entry body bytes.
    pub fn write_data(&mut self, mut data: &[u8]) -> Result<(), StreamError> {
        self.ensure_live()?;
        while !data.is_empty() {
            let step = self.encoder_step(EncodeCommand::Data(data))?;
            self.emit(step.produced)?;
            data = &data[step.consumed..];
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("format provider made no write progress"),
                ));
            }
        }
        Ok(())
    }

    /// Ends the current entry.
    pub fn end_entry(&mut self) -> Result<(), StreamError> {
        self.ensure_live()?;
        loop {
            let step = self.encoder_step(EncodeCommand::EndEntry)?;
            self.emit(step.produced)?;
            if step.consumed == 1 {
                return Ok(());
            }
            if step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("format provider did not accept end-entry"),
                ));
            }
        }
    }

    /// Finalizes the archive and returns the underlying destination.
    pub fn finish(mut self) -> Result<W, StreamError> {
        self.ensure_live()?;
        loop {
            let step = self.encoder_step(EncodeCommand::Finish)?;
            self.emit(step.produced)?;
            if matches!(step.status, EncodeStatus::Done) {
                return self.output.finish();
            }
            if step.consumed == 0 && step.produced == 0 {
                return Err(StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("format provider made no finish progress"),
                ));
            }
        }
    }

    /// Abandons the archive without adding a trailer or codec frame.
    pub fn abort(self) -> W {
        self.output.abort()
    }

    /// Output archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }
}
