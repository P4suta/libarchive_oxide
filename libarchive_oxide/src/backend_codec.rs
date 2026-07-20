// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private adapters for codec implementations selected by the build profile.

use std::fmt;
use std::io;

use compression_codecs::Decode;
use compression_codecs::core::util::PartialBuffer;
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind};

pub(crate) struct ExternalDecoder<D> {
    decoder: D,
    filter: FilterId,
    between_members: bool,
    failed: bool,
    done: bool,
}

impl<D> ExternalDecoder<D> {
    pub(crate) const fn new(decoder: D, filter: FilterId) -> Self {
        Self {
            decoder,
            filter,
            between_members: false,
            failed: false,
            done: false,
        }
    }

    fn step(
        source: &PartialBuffer<&[u8]>,
        destination: &PartialBuffer<&mut [u8]>,
        status: CodecStatus,
    ) -> CodecStep {
        CodecStep {
            consumed: source.written_len(),
            produced: destination.written_len(),
            status,
        }
    }

    fn fail(&mut self, error: &io::Error) -> ArchiveError {
        self.failed = true;
        codec_error(self.filter, error)
    }
}

impl<D> fmt::Debug for ExternalDecoder<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalDecoder")
            .field("filter", &filter_name(self.filter))
            .field("between_members", &self.between_members)
            .field("failed", &self.failed)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<D: Decode> Codec for ExternalDecoder<D> {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if self.failed {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(filter_name(self.filter))
                .with_context("decoder cannot continue after a terminal codec error"));
        }
        if self.done {
            if input.is_empty() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(filter_name(self.filter))
                .with_context("data follows the completed codec stream"));
        }

        let mut source = PartialBuffer::new(input);
        let mut destination = PartialBuffer::new(output);
        loop {
            if self.between_members {
                if source.unwritten().is_empty() {
                    let status = if matches!(end, EndOfInput::End) {
                        self.done = true;
                        CodecStatus::Done
                    } else {
                        CodecStatus::NeedInput
                    };
                    return Ok(Self::step(&source, &destination, status));
                }
                if let Err(error) = self.decoder.reinit() {
                    return Err(self.fail(&error));
                }
                self.between_members = false;
            }

            if destination.unwritten().is_empty() {
                return Ok(Self::step(&source, &destination, CodecStatus::NeedOutput));
            }

            let input_before = source.written_len();
            let output_before = destination.written_len();
            let member_done = match self.decoder.decode(&mut source, &mut destination) {
                Ok(done) => done,
                Err(error) => return Err(self.fail(&error)),
            };
            if member_done {
                self.between_members = true;
                continue;
            }
            if destination.unwritten().is_empty() {
                return Ok(Self::step(&source, &destination, CodecStatus::NeedOutput));
            }
            if source.unwritten().is_empty() {
                if matches!(end, EndOfInput::More) {
                    return Ok(Self::step(&source, &destination, CodecStatus::NeedInput));
                }
                let finish_before = destination.written_len();
                let member_done = match self.decoder.finish(&mut destination) {
                    Ok(done) => done,
                    Err(error) => return Err(self.fail(&error)),
                };
                if member_done {
                    self.between_members = true;
                    continue;
                }
                if destination.unwritten().is_empty() {
                    return Ok(Self::step(&source, &destination, CodecStatus::NeedOutput));
                }
                if destination.written_len() == finish_before {
                    let error = io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "codec ended before its terminal record",
                    );
                    return Err(self.fail(&error));
                }
                continue;
            }
            if source.written_len() == input_before && destination.written_len() == output_before {
                let error = io::Error::new(io::ErrorKind::InvalidData, "codec made no progress");
                return Err(self.fail(&error));
            }
        }
    }
}

#[cfg(feature = "native-codecs")]
pub(crate) struct NativeXzDecoder {
    stream: xz_codec::stream::Stream,
    prefix: Vec<u8>,
    memory_limit: Option<usize>,
    prefix_checked: bool,
    failed: bool,
    done: bool,
}

#[cfg(feature = "native-codecs")]
impl NativeXzDecoder {
    pub(crate) fn new(memory_limit: Option<usize>) -> Result<Self, ArchiveError> {
        let native_memory_limit =
            memory_limit.map_or(u64::MAX, |value| u64::try_from(value).unwrap_or(u64::MAX));
        let stream = xz_codec::stream::Stream::new_stream_decoder(
            native_memory_limit,
            xz_codec::stream::CONCATENATED,
        )
        .map_err(|error| xz_error(&error))?;
        Ok(Self {
            stream,
            prefix: Vec::with_capacity(22),
            memory_limit,
            prefix_checked: false,
            failed: false,
            done: false,
        })
    }

    fn preflight_initial_index(&mut self, input: &[u8]) -> Result<(), ArchiveError> {
        if self.prefix_checked {
            return Ok(());
        }
        let stream_offset = usize::try_from(self.stream.total_in()).map_err(|_| {
            ArchiveError::new(ErrorKind::Protocol)
                .with_format("xz")
                .with_context("XZ input position exceeds the platform address space")
        })?;
        let already_staged = self.prefix.len().saturating_sub(stream_offset);
        if already_staged < input.len() && self.prefix.len() < 22 {
            let available = &input[already_staged..];
            let retained = (22 - self.prefix.len()).min(available.len());
            self.prefix.extend_from_slice(&available[..retained]);
        }
        if self.prefix.len() < 13 {
            return Ok(());
        }
        if !self.prefix.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) || self.prefix[12] != 0 {
            self.prefix_checked = true;
            return Ok(());
        }

        let mut records = 0_u64;
        for (position, byte) in self.prefix[13..].iter().copied().enumerate() {
            if position == 9 {
                self.prefix_checked = true;
                return Ok(());
            }
            records |= u64::from(byte & 0x7f) << (position * 7);
            if byte & 0x80 == 0 {
                self.prefix_checked = true;
                let count = usize::try_from(records).map_err(|_| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("xz")
                        .with_context("XZ index record count exceeds the platform address space")
                })?;
                let required = count.checked_mul(2 * size_of::<u64>()).ok_or_else(|| {
                    ArchiveError::new(ErrorKind::Limit)
                        .with_format("xz")
                        .with_context("XZ index allocation size overflow")
                })?;
                if self.memory_limit.is_some_and(|limit| required > limit) {
                    self.failed = true;
                    return Err(ArchiveError::new(ErrorKind::Limit)
                        .with_format("xz")
                        .with_context(format!(
                            "XZ index requires {required} bytes, codec workspace limit was exceeded"
                        )));
                }
                return Ok(());
            }
        }
        Ok(())
    }

    fn fail(&mut self, error: &xz_codec::stream::Error) -> ArchiveError {
        self.failed = true;
        xz_error(error)
    }
}

#[cfg(feature = "native-codecs")]
impl fmt::Debug for NativeXzDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeXzDecoder")
            .field("failed", &self.failed)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "native-codecs")]
impl Codec for NativeXzDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        use xz_codec::stream::{Action, Status};

        if self.failed {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("xz")
                .with_context("XZ decoder cannot continue after a terminal codec error"));
        }
        if self.done {
            if input.is_empty() {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            }
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format("xz")
                .with_context("data follows the completed XZ stream"));
        }

        self.preflight_initial_index(input)?;

        let initial_input = self.stream.total_in();
        let initial_output = self.stream.total_out();
        loop {
            let consumed = usize::try_from(self.stream.total_in() - initial_input)
                .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?;
            let produced = usize::try_from(self.stream.total_out() - initial_output)
                .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?;
            if produced == output.len() {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::NeedOutput,
                });
            }

            let action = if consumed == input.len() && matches!(end, EndOfInput::End) {
                Action::Finish
            } else {
                Action::Run
            };
            let input_before = self.stream.total_in();
            let output_before = self.stream.total_out();
            let status =
                match self
                    .stream
                    .process(&input[consumed..], &mut output[produced..], action)
                {
                    Ok(status) => status,
                    Err(error) => return Err(self.fail(&error)),
                };
            let progressed =
                self.stream.total_in() != input_before || self.stream.total_out() != output_before;
            if matches!(status, Status::StreamEnd) {
                self.done = true;
                return Ok(CodecStep {
                    consumed: usize::try_from(self.stream.total_in() - initial_input)
                        .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?,
                    produced: usize::try_from(self.stream.total_out() - initial_output)
                        .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?,
                    status: CodecStatus::Done,
                });
            }

            let consumed = usize::try_from(self.stream.total_in() - initial_input)
                .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?;
            let produced = usize::try_from(self.stream.total_out() - initial_output)
                .map_err(|_| ArchiveError::new(ErrorKind::Protocol).with_format("xz"))?;
            if produced == output.len() {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::NeedOutput,
                });
            }
            if consumed == input.len() && matches!(end, EndOfInput::More) {
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::NeedInput,
                });
            }
            if !progressed || matches!(status, Status::MemNeeded) {
                self.failed = true;
                return Err(ArchiveError::new(ErrorKind::Malformed)
                    .with_format("xz")
                    .with_context("XZ stream ended before its terminal record"));
            }
        }
    }
}

#[cfg(feature = "native-codecs")]
pub(crate) fn encode_frame(filter: FilterId, input: &[u8]) -> io::Result<Vec<u8>> {
    use compression_codecs::core::Level;

    match filter {
        FilterId::Zstd => encode_external(compression_codecs::ZstdEncoder::new(1), input),
        FilterId::Xz => {
            use std::io::Write;

            let mut encoder = xz_codec::write::XzEncoder::new(Vec::new(), 6);
            encoder.write_all(input)?;
            encoder.finish()
        },
        FilterId::Lz4 => {
            let params = compression_codecs::lz4::params::EncoderParams::default()
                .level(Level::Fastest)
                .block_size(compression_codecs::lz4::params::BlockSize::Max64KB)
                .block_checksum(true)
                .content_checksum(true);
            encode_external(compression_codecs::Lz4Encoder::new(params), input)
        },
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "filter has no native frame encoder",
        )),
    }
}

#[cfg(feature = "native-codecs")]
fn encode_external(
    mut encoder: impl compression_codecs::Encode,
    input: &[u8],
) -> io::Result<Vec<u8>> {
    let mut source = PartialBuffer::new(input);
    let mut output = Vec::new();
    let mut scratch = vec![0_u8; 64 * 1024];
    while !source.unwritten().is_empty() {
        let source_before = source.written_len();
        let written = {
            let mut destination = PartialBuffer::new(scratch.as_mut_slice());
            encoder.encode(&mut source, &mut destination)?;
            destination.written_len()
        };
        output.extend_from_slice(&scratch[..written]);
        if source.written_len() == source_before && written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native encoder made no progress",
            ));
        }
    }
    loop {
        let (done, written) = {
            let mut destination = PartialBuffer::new(scratch.as_mut_slice());
            let done = encoder.finish(&mut destination)?;
            (done, destination.written_len())
        };
        output.extend_from_slice(&scratch[..written]);
        if done {
            return Ok(output);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native encoder made no finish progress",
            ));
        }
    }
}
fn codec_error(filter: FilterId, error: &io::Error) -> ArchiveError {
    let kind = if error.kind() == io::ErrorKind::OutOfMemory {
        ErrorKind::Limit
    } else {
        ErrorKind::Malformed
    };
    ArchiveError::new(kind)
        .with_format(filter_name(filter))
        .with_context(error.to_string())
}

#[cfg(feature = "native-codecs")]
fn xz_error(error: &xz_codec::stream::Error) -> ArchiveError {
    let kind = if matches!(
        error,
        xz_codec::stream::Error::Mem | xz_codec::stream::Error::MemLimit
    ) {
        ErrorKind::Limit
    } else {
        ErrorKind::Malformed
    };
    ArchiveError::new(kind)
        .with_format("xz")
        .with_context(error.to_string())
}

const fn filter_name(filter: FilterId) -> &'static str {
    match filter {
        FilterId::Gzip => "gzip",
        FilterId::Bzip2 => "bzip2",
        FilterId::Zstd => "zstd",
        FilterId::Xz => "xz",
        FilterId::Lz4 => "lz4",
        _ => "unknown",
    }
}
