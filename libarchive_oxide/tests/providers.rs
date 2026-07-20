// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Downstream-style compile-time provider conformance tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use libarchive_oxide::libarchive_oxide_core::{
    ArchiveDecoder, ArchiveEncoder, ArchiveError, ArchivePath, Chunk, Codec, CodecStatus,
    CodecStep, DecodeEvent, DecodeStep, EncodeCommand, EncodeStatus, EncodeStep, EndOfInput,
    EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits, ProbeResult,
};
use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, CodecCapabilities, CodecProvider, CodecProviderNode,
    CreateOptions, FormatCapabilities, FormatProvider, FormatProviderNode, NoCodecProviders,
    NoFormatProviders, Pipeline, PipelineEvent, PlanDisposition, ProviderArchiveEncoder,
    ProviderCapability, ProviderSet,
};

const FORMAT: FormatId = FormatId::Tar;
const FILTER: FilterId = FilterId::Gzip;
const FORMAT_MAGIC: &[u8; 4] = b"XF01";
const FILTER_MAGIC: &[u8; 4] = b"XC01";

type ExampleProviders = ProviderSet<
    FormatProviderNode<ExampleFormat, NoFormatProviders>,
    CodecProviderNode<ExampleCodec, NoCodecProviders>,
>;

fn example_providers() -> ExampleProviders {
    ProviderSet::empty()
        .with_format_provider(ExampleFormat)
        .with_codec_provider(ExampleCodec)
}

fn probe_magic(prefix: &[u8], magic: &[u8]) -> ProbeResult<()> {
    if prefix.len() >= magic.len() {
        if prefix.starts_with(magic) {
            ProbeResult::Match(())
        } else {
            ProbeResult::NoMatch
        }
    } else if magic.starts_with(prefix) {
        ProbeResult::NeedMore {
            minimum: magic.len(),
        }
    } else {
        ProbeResult::NoMatch
    }
}

#[derive(Debug, Clone, Copy)]
struct ExampleFormat;

impl FormatProvider for ExampleFormat {
    type Decoder = ExampleFormatDecoder;
    type Encoder = ExampleFormatEncoder;

    fn format(&self) -> FormatId {
        FORMAT
    }

    fn name(&self) -> &'static str {
        "example-format-v1"
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        probe_magic(prefix, FORMAT_MAGIC)
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::new(true, true, false)
    }

    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleFormatDecoder::default())
    }

    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExampleFormatEncoder::default())
    }
}

#[derive(Debug, Default)]
struct ExampleFormatDecoder {
    state: FormatDecodeState,
}

#[derive(Debug, Default)]
enum FormatDecodeState {
    #[default]
    Header,
    Data {
        remaining: usize,
    },
    EndEntry,
    Done,
}

impl ArchiveDecoder for ExampleFormatDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self.state {
            FormatDecodeState::Header => {
                if input.len() < 8 {
                    if end == EndOfInput::End {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_context("example format header is truncated"));
                    }
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                if &input[..4] != FORMAT_MAGIC {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_context("example format magic is invalid"));
                }
                let length = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
                self.state = FormatDecodeState::Data { remaining: length };
                let metadata =
                    EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("provider.bin"))
                        .size(Some(length as u64))
                        .build();
                Ok(DecodeStep {
                    consumed: 8,
                    produced: 0,
                    event: DecodeEvent::Entry(metadata),
                })
            },
            FormatDecodeState::Data { remaining: 0 } => {
                self.state = FormatDecodeState::EndEntry;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::EndEntry,
                })
            },
            FormatDecodeState::Data { remaining } => {
                if input.is_empty() {
                    if end == EndOfInput::End {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_context("example format payload is truncated"));
                    }
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedInput,
                    });
                }
                if output.is_empty() {
                    return Ok(DecodeStep {
                        consumed: 0,
                        produced: 0,
                        event: DecodeEvent::NeedOutput,
                    });
                }
                let count = remaining.min(input.len()).min(output.len());
                output[..count].copy_from_slice(&input[..count]);
                self.state = FormatDecodeState::Data {
                    remaining: remaining - count,
                };
                Ok(DecodeStep {
                    consumed: count,
                    produced: count,
                    event: DecodeEvent::Data(Chunk::new(&output[..count])),
                })
            },
            FormatDecodeState::EndEntry => {
                self.state = FormatDecodeState::Done;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::Done,
                })
            },
            FormatDecodeState::Done => Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::Done,
            }),
        }
    }
}

#[derive(Debug, Default)]
struct ExampleFormatEncoder {
    state: FormatEncodeState,
}

#[derive(Debug, Default)]
enum FormatEncodeState {
    #[default]
    Ready,
    Entry {
        expected: usize,
        written: usize,
    },
    Finished,
}

impl ArchiveEncoder for ExampleFormatEncoder {
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        match (&mut self.state, command) {
            (FormatEncodeState::Ready, EncodeCommand::BeginEntry(metadata)) => {
                if output.len() < 8 {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: 0,
                        status: EncodeStatus::NeedOutput,
                    });
                }
                let expected = usize::try_from(metadata.size().ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("example format requires a declared size")
                })?)
                .map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_context("example format size does not fit usize")
                })?;
                let encoded = u32::try_from(expected).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_context("example format size exceeds u32")
                })?;
                output[..4].copy_from_slice(FORMAT_MAGIC);
                output[4..8].copy_from_slice(&encoded.to_le_bytes());
                self.state = FormatEncodeState::Entry {
                    expected,
                    written: 0,
                };
                Ok(EncodeStep {
                    consumed: 1,
                    produced: 8,
                    status: EncodeStatus::NeedCommand,
                })
            },
            (FormatEncodeState::Entry { expected, written }, EncodeCommand::Data(data)) => {
                let remaining = expected.saturating_sub(*written);
                let count = remaining.min(data.len()).min(output.len());
                if count == 0 {
                    return Ok(EncodeStep {
                        consumed: 0,
                        produced: 0,
                        status: EncodeStatus::NeedOutput,
                    });
                }
                output[..count].copy_from_slice(&data[..count]);
                *written += count;
                Ok(EncodeStep {
                    consumed: count,
                    produced: count,
                    status: EncodeStatus::NeedCommand,
                })
            },
            (FormatEncodeState::Entry { expected, written }, EncodeCommand::EndEntry) => {
                if expected != written {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_context("example format declared size mismatch"));
                }
                self.state = FormatEncodeState::Ready;
                Ok(EncodeStep {
                    consumed: 1,
                    produced: 0,
                    status: EncodeStatus::NeedCommand,
                })
            },
            (FormatEncodeState::Ready, EncodeCommand::Finish) => {
                self.state = FormatEncodeState::Finished;
                Ok(EncodeStep {
                    consumed: 1,
                    produced: 0,
                    status: EncodeStatus::Done,
                })
            },
            (FormatEncodeState::Finished, EncodeCommand::Finish) => Ok(EncodeStep {
                consumed: 1,
                produced: 0,
                status: EncodeStatus::Done,
            }),
            _ => Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("example format received a command in the wrong state")),
        }
    }
}

impl ProviderArchiveEncoder for ExampleFormatEncoder {}

#[derive(Debug, Clone, Copy)]
struct ExampleCodec;

impl CodecProvider for ExampleCodec {
    type Decoder = ExampleCodecDecoder;

    fn filter(&self) -> FilterId {
        FILTER
    }

    fn name(&self) -> &'static str {
        "example-codec-v1"
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        probe_magic(prefix, FILTER_MAGIC)
    }

    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities::new(true, true)
    }

    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleCodecDecoder::default())
    }

    fn encode_frame(&self, input: &[u8], _limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        let length = u32::try_from(input.len()).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit).with_context("example codec frame exceeds u32")
        })?;
        let mut encoded = Vec::with_capacity(8 + input.len());
        encoded.extend_from_slice(FILTER_MAGIC);
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(input);
        Ok(encoded)
    }
}

#[derive(Debug, Default)]
struct ExampleCodecDecoder {
    state: CodecDecodeState,
}

#[derive(Debug)]
enum CodecDecodeState {
    Header { bytes: [u8; 8], filled: usize },
    Payload { remaining: usize },
    Done,
}

impl Default for CodecDecodeState {
    fn default() -> Self {
        Self::Header {
            bytes: [0; 8],
            filled: 0,
        }
    }
}
impl Codec for ExampleCodecDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            CodecDecodeState::Header {
                mut bytes,
                mut filled,
            } => {
                let consumed = (8 - filled).min(input.len());
                bytes[filled..filled + consumed].copy_from_slice(&input[..consumed]);
                filled += consumed;
                if filled < 8 {
                    if end == EndOfInput::End {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_context("example codec header is truncated"));
                    }
                    self.state = CodecDecodeState::Header { bytes, filled };
                    return Ok(CodecStep {
                        consumed,
                        produced: 0,
                        status: CodecStatus::NeedInput,
                    });
                }
                if &bytes[..4] != FILTER_MAGIC {
                    return Err(ArchiveError::new(ErrorKind::Malformed)
                        .with_context("example codec magic is invalid"));
                }
                let remaining = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
                self.state = if remaining == 0 {
                    CodecDecodeState::Done
                } else {
                    CodecDecodeState::Payload { remaining }
                };
                Ok(CodecStep {
                    consumed,
                    produced: 0,
                    status: if remaining == 0 {
                        CodecStatus::Done
                    } else {
                        CodecStatus::NeedInput
                    },
                })
            },
            CodecDecodeState::Payload { remaining } => {
                if input.is_empty() {
                    if end == EndOfInput::End {
                        return Err(ArchiveError::new(ErrorKind::Malformed)
                            .with_context("example codec payload is truncated"));
                    }
                    return Ok(CodecStep {
                        consumed: 0,
                        produced: 0,
                        status: CodecStatus::NeedInput,
                    });
                }
                if output.is_empty() {
                    return Ok(CodecStep {
                        consumed: 0,
                        produced: 0,
                        status: CodecStatus::NeedOutput,
                    });
                }
                let count = remaining.min(input.len()).min(output.len());
                output[..count].copy_from_slice(&input[..count]);
                let left = remaining - count;
                self.state = if left == 0 {
                    CodecDecodeState::Done
                } else {
                    CodecDecodeState::Payload { remaining: left }
                };
                Ok(CodecStep {
                    consumed: count,
                    produced: count,
                    status: if left == 0 {
                        CodecStatus::Done
                    } else if count == output.len() {
                        CodecStatus::NeedOutput
                    } else {
                        CodecStatus::NeedInput
                    },
                })
            },
            CodecDecodeState::Done => Ok(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            }),
        }
    }
}

fn create_example_archive(payload: &[u8]) -> Vec<u8> {
    let engine = ArchiveEngine::new()
        .with_format_provider(ExampleFormat)
        .with_codec_provider(ExampleCodec);
    let options = CreateOptions::new()
        .with_format(FORMAT)
        .with_filter(Some(FILTER));
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_utf8("ignored-by-example-provider"),
    )
    .size(Some(payload.len() as u64))
    .build();
    let mut writer = engine.create_registered(Vec::new(), options).unwrap();
    writer.start_entry(&metadata).unwrap();
    for chunk in payload.chunks(997) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

#[test]
fn registered_create_event_inspect_plan_and_rewind_share_one_state_model() {
    let payload: Vec<u8> = (0_u8..=250).cycle().take(70_000).collect();
    let encoded = create_example_archive(&payload);
    assert!(encoded.starts_with(FILTER_MAGIC));

    let engine = ArchiveEngine::new()
        .with_format_provider(ExampleFormat)
        .with_codec_provider(ExampleCodec);
    assert!(engine.providers().supports_format(FORMAT));

    let engine = ArchiveEngine::new()
        .with_format_provider(ExampleFormat)
        .with_codec_provider(ExampleCodec);
    let mut session = engine.open(Cursor::new(encoded)).unwrap();
    let digest = session.digest();
    let inspection = session.inspect().unwrap();
    assert_eq!(inspection.format(), FORMAT);
    assert_eq!(inspection.entries().len(), 1);
    assert_eq!(inspection.entries()[0].metadata().size(), Some(70_000));

    session.rewind().unwrap();
    let mut decoded = Vec::new();
    loop {
        match session.next_event().unwrap() {
            libarchive_oxide::ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            libarchive_oxide::ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
    assert_eq!(session.digest(), digest);

    let plan = session.plan(libarchive_oxide::Policy::safe()).unwrap();
    assert_eq!(plan.digest(), digest);
    assert!(matches!(
        plan.entries()[0].disposition(),
        PlanDisposition::Materialize
    ));
}

#[test]
fn caller_driven_pipeline_uses_registered_codec_and_format_at_one_byte_boundaries() {
    let payload: Vec<u8> = (0_u8..=127).cycle().take(4097).collect();
    let encoded = create_example_archive(&payload);
    let mut pipeline = Pipeline::with_providers(Limits::safe(), example_providers());
    let mut offset = 0;
    let mut finished = false;
    let mut decoded = Vec::new();
    loop {
        match pipeline.poll_event().unwrap() {
            PipelineEvent::NeedInput if offset < encoded.len() => {
                assert_eq!(pipeline.feed(&encoded[offset..=offset]).unwrap(), 1);
                offset += 1;
            },
            PipelineEvent::NeedInput if !finished => {
                pipeline.finish_input().unwrap();
                finished = true;
            },
            PipelineEvent::NeedInput => panic!("finished provider pipeline requested more input"),
            PipelineEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            PipelineEvent::Done => break,
            PipelineEvent::ArchiveMetadata(_)
            | PipelineEvent::Entry(_)
            | PipelineEvent::EndEntry => {},
            _ => panic!("unknown provider pipeline event"),
        }
    }
    assert_eq!(pipeline.format(), Some(FORMAT));
    assert_eq!(decoded, payload);
}

#[derive(Debug, Clone, Copy)]
struct DisabledFormat;

impl FormatProvider for DisabledFormat {
    type Decoder = ExampleFormatDecoder;
    type Encoder = ExampleFormatEncoder;

    fn format(&self) -> FormatId {
        FORMAT
    }
    fn name(&self) -> &'static str {
        "disabled-example-format"
    }
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        probe_magic(prefix, FORMAT_MAGIC)
    }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::new(false, false, false)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleFormatDecoder::default())
    }
    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExampleFormatEncoder::default())
    }
}

#[test]
fn capability_queries_distinguish_unknown_disabled_and_available() {
    let empty = ProviderSet::empty();
    assert_eq!(empty.format_capability(FORMAT), ProviderCapability::Unknown);
    assert_eq!(empty.codec_capability(FILTER), ProviderCapability::Unknown);

    let disabled = empty.with_format_provider(DisabledFormat);
    assert_eq!(
        disabled.format_capability(FORMAT),
        ProviderCapability::Disabled
    );

    let options = CreateOptions::new().with_format(FORMAT);
    let error = ArchiveEngine::new()
        .with_format_provider(DisabledFormat)
        .create_registered(Vec::new(), options)
        .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Capability);
}

#[derive(Debug, Clone, Copy)]
struct InvalidProbe;

impl FormatProvider for InvalidProbe {
    type Decoder = ExampleFormatDecoder;
    type Encoder = ExampleFormatEncoder;

    fn format(&self) -> FormatId {
        FormatId::Cpio
    }
    fn name(&self) -> &'static str {
        "invalid-probe"
    }
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        ProbeResult::NeedMore {
            minimum: prefix.len(),
        }
    }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::new(true, true, false)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleFormatDecoder::default())
    }
    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExampleFormatEncoder::default())
    }
}

#[derive(Debug, Clone, Copy)]
struct ConflictFormat {
    id: FormatId,
    name: &'static str,
}

impl FormatProvider for ConflictFormat {
    type Decoder = ExampleFormatDecoder;
    type Encoder = ExampleFormatEncoder;

    fn format(&self) -> FormatId {
        self.id
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        probe_magic(prefix, b"CF01")
    }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::new(true, true, false)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleFormatDecoder::default())
    }
    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExampleFormatEncoder::default())
    }
}

#[test]
fn provider_probe_protocol_and_ambiguity_fail_closed() {
    let mut invalid = Pipeline::with_providers(
        Limits::safe(),
        ProviderSet::empty().with_format_provider(InvalidProbe),
    );
    invalid.feed(b"x").unwrap();
    assert_eq!(
        invalid.poll_event().unwrap_err().kind(),
        ErrorKind::Protocol
    );

    let providers = ProviderSet::empty()
        .with_format_provider(ConflictFormat {
            id: FormatId::Tar,
            name: "conflict-a",
        })
        .with_format_provider(ConflictFormat {
            id: FormatId::Cpio,
            name: "conflict-b",
        });
    let mut ambiguous = Pipeline::with_providers(Limits::safe(), providers);
    ambiguous.feed(b"CF01").unwrap();
    assert_eq!(
        ambiguous.poll_event().unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

#[derive(Debug, Default)]
struct NoProgressDecoder;

impl ArchiveDecoder for NoProgressDecoder {
    fn step<'a>(
        &'a mut self,
        _input: &'a [u8],
        output: &'a mut [u8],
        _end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        Ok(DecodeStep {
            consumed: 0,
            produced: 0,
            event: DecodeEvent::Data(Chunk::new(&output[..0])),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct NoProgressFormat;

impl FormatProvider for NoProgressFormat {
    type Decoder = NoProgressDecoder;
    type Encoder = ExampleFormatEncoder;

    fn format(&self) -> FormatId {
        FormatId::Ar
    }
    fn name(&self) -> &'static str {
        "no-progress"
    }
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        probe_magic(prefix, b"NP01")
    }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::new(true, true, false)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(NoProgressDecoder)
    }
    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExampleFormatEncoder::default())
    }
}

#[test]
fn provider_decoder_steps_are_validated_by_the_shared_pipeline() {
    let mut pipeline = Pipeline::with_providers(
        Limits::safe(),
        ProviderSet::empty().with_format_provider(NoProgressFormat),
    );
    pipeline.feed(b"NP01payload").unwrap();
    assert_eq!(
        pipeline.poll_event().unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

#[derive(Debug, Clone, Copy)]
struct ExpandingCodec;

impl CodecProvider for ExpandingCodec {
    type Decoder = ExampleCodecDecoder;

    fn filter(&self) -> FilterId {
        FilterId::Bzip2
    }

    fn name(&self) -> &'static str {
        "expanding-codec"
    }

    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> {
        ProbeResult::NoMatch
    }

    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities::new(false, true)
    }

    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExampleCodecDecoder::default())
    }

    fn encode_frame(&self, input: &[u8], _limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        Ok(vec![0xa5; input.len().saturating_mul(3).saturating_add(8)])
    }
}

#[test]
fn registered_writer_enforces_combined_in_flight_budget() {
    let limits = Limits::safe().with_in_flight_bytes(Some(256));
    let engine = ArchiveEngine::new()
        .with_limits(limits)
        .with_format_provider(ExampleFormat)
        .with_codec_provider(ExpandingCodec);
    let options = CreateOptions::new()
        .with_format(FORMAT)
        .with_filter(Some(FilterId::Bzip2));
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("bounded.bin"))
        .size(Some(100))
        .build();
    let mut writer = engine.create_registered(Vec::new(), options).unwrap();
    writer.start_entry(&metadata).unwrap();
    let error = writer.write_data(&[0x5a; 100]).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn registered_codec_truncation_remains_a_typed_malformed_error() {
    let mut encoded = create_example_archive(b"truncated-provider-frame");
    encoded.pop();
    let mut reader =
        ArchiveReader::with_providers(Cursor::new(encoded), Limits::safe(), example_providers());
    loop {
        match reader.next_event() {
            Ok(libarchive_oxide::ReaderEvent::Done) => {
                panic!("truncated provider frame unexpectedly completed")
            },
            Ok(_) => {},
            Err(error) => {
                assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
                break;
            },
        }
    }
}
