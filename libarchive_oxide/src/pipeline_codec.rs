// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private static dispatch for caller-driven outer codecs.

#[cfg(feature = "async")]
use std::task::Waker;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, Codec, CodecStep, EndOfInput, ErrorKind, Limits};

#[cfg(any(feature = "bzip2", feature = "native-codecs"))]
use crate::backend_codec::ExternalDecoder;
#[cfg(feature = "native-codecs")]
use crate::backend_codec::NativeXzDecoder;
#[cfg(not(feature = "native-codecs"))]
use crate::filter::gzip::GzipDecoder;

#[derive(Debug)]
pub(crate) enum PipelineCodec {
    #[cfg(feature = "native-codecs")]
    Gzip(ExternalDecoder<compression_codecs::GzipDecoder>),
    #[cfg(not(feature = "native-codecs"))]
    Gzip(Box<GzipDecoder>),
    /// Raw DEFLATE (no gzip framing) — the 7z Deflate coder. Backed by the same
    /// `miniz_oxide` raw-inflate core the gzip decoder sits on.
    #[cfg(feature = "sevenz")]
    Deflate(Box<crate::filter::gzip::RawInflateDecoder>),
    #[cfg(feature = "bzip2")]
    Bzip2(ExternalDecoder<compression_codecs::BzDecoder>),
    #[cfg(all(feature = "zstd", feature = "native-codecs"))]
    Zstd(ExternalDecoder<compression_codecs::ZstdDecoder>),
    #[cfg(all(feature = "zstd", not(feature = "native-codecs")))]
    Zstd(Box<crate::filter::zstd::ZstdDecoder>),
    #[cfg(all(feature = "xz", feature = "native-codecs"))]
    Xz(NativeXzDecoder),
    #[cfg(all(feature = "xz", not(feature = "native-codecs")))]
    Xz(Box<crate::filter::xz::XzDecoder>),
    #[cfg(all(feature = "lz4", feature = "native-codecs"))]
    Lz4(ExternalDecoder<compression_codecs::Lz4Decoder>),
    #[cfg(all(feature = "lz4", not(feature = "native-codecs")))]
    Lz4(Box<crate::filter::lz4::Lz4Decoder>),
}

impl PipelineCodec {
    pub(crate) fn new(filter: FilterId, limits: Limits) -> Result<Self, ArchiveError> {
        match filter {
            FilterId::Gzip => {
                #[cfg(feature = "native-codecs")]
                {
                    Ok(Self::Gzip(ExternalDecoder::new(
                        compression_codecs::GzipDecoder::new(),
                        filter,
                    )))
                }
                #[cfg(not(feature = "native-codecs"))]
                {
                    Ok(Self::Gzip(Box::new(GzipDecoder::new(limits))))
                }
            },
            #[cfg(feature = "sevenz")]
            FilterId::Deflate => Ok(Self::Deflate(Box::new(
                crate::filter::gzip::RawInflateDecoder::new(limits),
            ))),
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    Ok(Self::Bzip2(ExternalDecoder::new(
                        compression_codecs::BzDecoder::new(),
                        filter,
                    )))
                }
                #[cfg(not(feature = "bzip2"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Zstd => {
                #[cfg(all(feature = "zstd", feature = "native-codecs"))]
                {
                    let decoder = native_zstd_decoder(limits)?;
                    Ok(Self::Zstd(ExternalDecoder::new(decoder, filter)))
                }
                #[cfg(all(feature = "zstd", not(feature = "native-codecs")))]
                {
                    Ok(Self::Zstd(Box::default()))
                }
                #[cfg(not(feature = "zstd"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Xz => {
                #[cfg(all(feature = "xz", feature = "native-codecs"))]
                {
                    NativeXzDecoder::new(limits.codec_memory()).map(Self::Xz)
                }
                #[cfg(all(feature = "xz", not(feature = "native-codecs")))]
                {
                    crate::filter::xz::XzDecoder::new(limits)
                        .map(Box::new)
                        .map(Self::Xz)
                }
                #[cfg(not(feature = "xz"))]
                {
                    Err(disabled(filter))
                }
            },
            FilterId::Lz4 => {
                #[cfg(all(feature = "lz4", feature = "native-codecs"))]
                {
                    Ok(Self::Lz4(ExternalDecoder::new(
                        compression_codecs::Lz4Decoder::new(),
                        filter,
                    )))
                }
                #[cfg(all(feature = "lz4", not(feature = "native-codecs")))]
                {
                    Ok(Self::Lz4(Box::default()))
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
            #[cfg(feature = "native-codecs")]
            Self::Gzip(codec) => codec.process(input, output, end),
            #[cfg(not(feature = "native-codecs"))]
            Self::Gzip(codec) => codec.process(input, output, end),
            #[cfg(feature = "sevenz")]
            Self::Deflate(codec) => codec.process(input, output, end),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(codec) => codec.process(input, output, end),
            #[cfg(feature = "zstd")]
            Self::Zstd(codec) => codec.process(input, output, end),
            #[cfg(feature = "xz")]
            Self::Xz(codec) => codec.process(input, output, end),
            #[cfg(feature = "lz4")]
            Self::Lz4(codec) => codec.process(input, output, end),
        }
    }

    /// Non-blocking mirror of [`process`](Self::process) for async adapters.
    ///
    /// Every variant inherits the blocking-delegating default except `Xz`,
    /// which overrides [`Codec::poll_process`] to avoid parking the executor
    /// thread on its worker channel.
    #[cfg(feature = "async")]
    pub(crate) fn poll_process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        waker: &Waker,
    ) -> Result<Option<CodecStep>, ArchiveError> {
        match self {
            #[cfg(feature = "native-codecs")]
            Self::Gzip(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(not(feature = "native-codecs"))]
            Self::Gzip(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "sevenz")]
            Self::Deflate(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "zstd")]
            Self::Zstd(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "xz")]
            Self::Xz(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "lz4")]
            Self::Lz4(codec) => codec.poll_process(input, output, end, waker),
        }
    }
}

impl Codec for PipelineCodec {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        // Delegates to the inherent method (inherent resolution wins, so this does not recurse),
        // letting `PipelineCodec` drive the generic `CodecReader<_, PipelineCodec>`.
        PipelineCodec::process(self, input, output, end)
    }
}

#[cfg(all(feature = "zstd", feature = "native-codecs"))]
fn native_zstd_decoder(limits: Limits) -> Result<compression_codecs::ZstdDecoder, ArchiveError> {
    let Some(memory_limit) = limits.codec_memory() else {
        return Ok(compression_codecs::ZstdDecoder::new());
    };
    if memory_limit < 1024 {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_format("zstd")
            .with_context("Zstandard codec memory limit is below the minimum 1 KiB window"));
    }
    let window_log = (usize::BITS - 1 - memory_limit.leading_zeros()).min(31);
    Ok(compression_codecs::ZstdDecoder::new_with_params(&[
        compression_codecs::zstd::params::DParameter::window_log_max(window_log),
    ]))
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
        FilterId::Deflate => "deflate",
        FilterId::Bzip2 => "bzip2",
        FilterId::Zstd => "zstd",
        FilterId::Xz => "xz",
        FilterId::Lz4 => "lz4",
        _ => "unknown",
    }
}
