// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private static dispatch for caller-driven outer codecs.

#[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "lz4"))]
use libarchive_oxide_core::CodecStatus;
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, Codec, CodecStep, EndOfInput, ErrorKind, Limits};

use crate::filter::gzip::GzipDecoder;

#[derive(Debug)]
pub(crate) enum PipelineCodec {
    Gzip(Box<GzipDecoder>),
    #[cfg(feature = "bzip2")]
    Bzip2(compression_codecs::BzDecoder),
    #[cfg(feature = "zstd")]
    Zstd(compression_codecs::ZstdDecoder),
    #[cfg(feature = "xz")]
    Xz(compression_codecs::XzDecoder),
    #[cfg(feature = "lz4")]
    Lz4(compression_codecs::Lz4Decoder),
}

impl PipelineCodec {
    pub(crate) fn new(filter: FilterId, limits: Limits) -> Result<Self, ArchiveError> {
        match filter {
            FilterId::Gzip => Ok(Self::Gzip(Box::new(GzipDecoder::new(limits)))),
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    Ok(Self::Bzip2(compression_codecs::BzDecoder::new()))
                }
                #[cfg(not(feature = "bzip2"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Zstd => {
                #[cfg(feature = "zstd")]
                {
                    Ok(Self::Zstd(compression_codecs::ZstdDecoder::new()))
                }
                #[cfg(not(feature = "zstd"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Xz => {
                #[cfg(feature = "xz")]
                {
                    let memory = limits
                        .codec_memory()
                        .map_or(u64::MAX, |bytes| u64::try_from(bytes).unwrap_or(u64::MAX));
                    Ok(Self::Xz(compression_codecs::XzDecoder::with_memlimit(
                        memory,
                    )))
                }
                #[cfg(not(feature = "xz"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Lz4 => {
                #[cfg(feature = "lz4")]
                {
                    Ok(Self::Lz4(compression_codecs::Lz4Decoder::new()))
                }
                #[cfg(not(feature = "lz4"))]
                {
                    Err(disabled(filter))
                }
            },
            _ => {
                Err(ArchiveError::new(ErrorKind::Unsupported).with_context("unknown outer filter"))
            },
        }
    }

    pub(crate) fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self {
            Self::Gzip(codec) => codec.process(input, output, end),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(codec) => external_process(codec, FilterId::Bzip2, input, output, end),
            #[cfg(feature = "zstd")]
            Self::Zstd(codec) => external_process(codec, FilterId::Zstd, input, output, end),
            #[cfg(feature = "xz")]
            Self::Xz(codec) => external_process(codec, FilterId::Xz, input, output, end),
            #[cfg(feature = "lz4")]
            Self::Lz4(codec) => external_process(codec, FilterId::Lz4, input, output, end),
        }
    }
}

#[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "lz4"))]
fn external_process(
    decoder: &mut impl compression_codecs::Decode,
    filter: FilterId,
    input: &[u8],
    output: &mut [u8],
    end: EndOfInput,
) -> Result<CodecStep, ArchiveError> {
    use compression_codecs::core::util::PartialBuffer;

    let mut source = PartialBuffer::new(input);
    let mut destination = PartialBuffer::new(output);
    let mut done = decoder
        .decode(&mut source, &mut destination)
        .map_err(|error| codec_error(filter, &error))?;
    if !done && source.unwritten().is_empty() && matches!(end, EndOfInput::End) {
        done = decoder
            .finish(&mut destination)
            .map_err(|error| codec_error(filter, &error))?;
        if !done && destination.written_len() == 0 {
            return Err(ArchiveError::new(ErrorKind::Malformed)
                .with_format(filter_name(filter))
                .with_context("codec ended before its terminal record"));
        }
    }
    let status = if done {
        CodecStatus::Done
    } else if destination.unwritten().is_empty() {
        CodecStatus::NeedOutput
    } else {
        CodecStatus::NeedInput
    };
    Ok(CodecStep {
        consumed: source.written_len(),
        produced: destination.written_len(),
        status,
    })
}

#[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "lz4"))]
fn codec_error(filter: FilterId, error: &std::io::Error) -> ArchiveError {
    let kind = if error.kind() == std::io::ErrorKind::OutOfMemory {
        ErrorKind::Limit
    } else {
        ErrorKind::Malformed
    };
    ArchiveError::new(kind)
        .with_format(filter_name(filter))
        .with_context(error.to_string())
}

#[allow(dead_code)]
fn disabled(filter: FilterId) -> ArchiveError {
    ArchiveError::new(ErrorKind::Unsupported)
        .with_format(filter_name(filter))
        .with_context("outer filter support is disabled")
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
