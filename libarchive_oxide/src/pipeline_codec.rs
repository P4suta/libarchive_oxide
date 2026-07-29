// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private static dispatch for caller-driven outer codecs.

#[cfg(all(
    feature = "async",
    any(
        feature = "zstd",
        feature = "xz",
        feature = "lz4",
        feature = "compress",
        feature = "lzip"
    )
))]
use std::task::Waker;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, Codec, CodecStep, EndOfInput, ErrorKind, Limits};

#[cfg(any(feature = "bzip2", feature = "native-codecs"))]
use crate::backend_codec::ExternalDecoder;
#[cfg(feature = "native-codecs")]
use crate::backend_codec::NativeXzDecoder;
use crate::capability::{Backend, BackendPreference};
use crate::filter::gzip::GzipDecoder;

#[derive(Debug)]
pub(crate) enum PipelineCodec {
    GzipPortable(Box<GzipDecoder>),
    #[cfg(feature = "native-codecs")]
    GzipNative(ExternalDecoder<compression_codecs::GzipDecoder>),
    /// Raw DEFLATE (no gzip framing) — the 7z Deflate coder. Backed by the same
    /// `miniz_oxide` raw-inflate core the gzip decoder sits on.
    #[cfg(feature = "sevenz")]
    Deflate(Box<crate::filter::gzip::RawInflateDecoder>),
    #[cfg(feature = "bzip2")]
    Bzip2(ExternalDecoder<compression_codecs::BzDecoder>),
    #[cfg(feature = "zstd")]
    ZstdPortable(Box<crate::filter::zstd::ZstdDecoder>),
    #[cfg(all(feature = "zstd", feature = "native-codecs"))]
    ZstdNative(ExternalDecoder<compression_codecs::ZstdDecoder>),
    #[cfg(feature = "xz")]
    XzPortable(Box<crate::filter::xz::XzDecoder>),
    #[cfg(all(feature = "xz", feature = "native-codecs"))]
    XzNative(NativeXzDecoder),
    #[cfg(feature = "lz4")]
    Lz4Portable(Box<crate::filter::lz4::Lz4Decoder>),
    #[cfg(all(feature = "lz4", feature = "native-codecs"))]
    Lz4Native(ExternalDecoder<compression_codecs::Lz4Decoder>),
    #[cfg(feature = "compress")]
    Compress(Box<libarchive_oxide_codecs::lzw::CompressDecoder>),
    #[cfg(feature = "lzip")]
    Lzip(Box<crate::filter::lzip::LzipDecoder>),
}

impl PipelineCodec {
    #[cfg(any(feature = "zstd", feature = "sevenz"))]
    pub(crate) fn new(filter: FilterId, limits: Limits) -> Result<Self, ArchiveError> {
        Self::with_backend(filter, limits, BackendPreference::Auto)
    }

    fn with_zstd_backend(
        limits: Limits,
        preference: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        #[cfg(feature = "zstd")]
        {
            match preference.resolve()? {
                Backend::Portable => Ok(Self::ZstdPortable(Box::new(
                    crate::filter::zstd::ZstdDecoder::with_limits(limits),
                ))),
                Backend::Native => {
                    #[cfg(feature = "native-codecs")]
                    return Ok(Self::ZstdNative(ExternalDecoder::new(
                        native_zstd_decoder(limits)?,
                        FilterId::Zstd,
                    )));
                    #[cfg(not(feature = "native-codecs"))]
                    return Err(disabled_backend(FilterId::Zstd, "native"));
                },
            }
        }
        #[cfg(not(feature = "zstd"))]
        {
            let _ = (limits, preference);
            Err(disabled(FilterId::Zstd))
        }
    }

    fn with_xz_backend(
        limits: Limits,
        preference: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        #[cfg(feature = "xz")]
        {
            match preference.resolve()? {
                Backend::Portable => crate::filter::xz::XzDecoder::new(limits)
                    .map(Box::new)
                    .map(Self::XzPortable),
                Backend::Native => {
                    #[cfg(feature = "native-codecs")]
                    return NativeXzDecoder::new(limits.codec_memory()).map(Self::XzNative);
                    #[cfg(not(feature = "native-codecs"))]
                    return Err(disabled_backend(FilterId::Xz, "native"));
                },
            }
        }
        #[cfg(not(feature = "xz"))]
        {
            let _ = (limits, preference);
            Err(disabled(FilterId::Xz))
        }
    }

    fn with_lz4_backend(
        limits: Limits,
        preference: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        #[cfg(feature = "lz4")]
        {
            match preference.resolve()? {
                Backend::Portable => Ok(Self::Lz4Portable(Box::new(
                    crate::filter::lz4::Lz4Decoder::with_limits(limits),
                ))),
                Backend::Native => {
                    #[cfg(feature = "native-codecs")]
                    return Ok(Self::Lz4Native(ExternalDecoder::new(
                        compression_codecs::Lz4Decoder::new(),
                        FilterId::Lz4,
                    )));
                    #[cfg(not(feature = "native-codecs"))]
                    return Err(disabled_backend(FilterId::Lz4, "native"));
                },
            }
        }
        #[cfg(not(feature = "lz4"))]
        {
            let _ = (limits, preference);
            Err(disabled(FilterId::Lz4))
        }
    }

    pub(crate) fn with_backend(
        filter: FilterId,
        limits: Limits,
        preference: BackendPreference,
    ) -> Result<Self, ArchiveError> {
        match filter {
            FilterId::Gzip => match preference.resolve()? {
                Backend::Portable => Ok(Self::GzipPortable(Box::new(GzipDecoder::new(limits)))),
                Backend::Native => {
                    #[cfg(feature = "native-codecs")]
                    return Ok(Self::GzipNative(ExternalDecoder::new(
                        compression_codecs::GzipDecoder::new(),
                        filter,
                    )));
                    #[cfg(not(feature = "native-codecs"))]
                    return Err(disabled_backend(filter, "native"));
                },
            },
            #[cfg(feature = "sevenz")]
            FilterId::Deflate => crate::filter::gzip::RawInflateDecoder::with_limits(limits)
                .map(|decoder| Self::Deflate(Box::new(decoder))),
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    let _ = preference.resolve()?;
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
            FilterId::Zstd => Self::with_zstd_backend(limits, preference),
            FilterId::Xz => Self::with_xz_backend(limits, preference),
            FilterId::Lz4 => Self::with_lz4_backend(limits, preference),
            FilterId::Compress => {
                #[cfg(feature = "compress")]
                {
                    if matches!(preference, BackendPreference::Native) {
                        return Err(ArchiveError::new(ErrorKind::Capability)
                            .with_format("compress")
                            .with_context("the Unix compress/LZW filter has no native backend"));
                    }
                    libarchive_oxide_codecs::lzw::CompressDecoder::with_limits(limits)
                        .map(Box::new)
                        .map(Self::Compress)
                }
                #[cfg(not(feature = "compress"))]
                {
                    let _ = (limits, preference);
                    Err(disabled(filter))
                }
            },
            FilterId::Lzip => {
                #[cfg(feature = "lzip")]
                {
                    if matches!(preference, BackendPreference::Native) {
                        return Err(ArchiveError::new(ErrorKind::Capability)
                            .with_format("lzip")
                            .with_context("the lzip filter has no native backend"));
                    }
                    crate::filter::lzip::LzipDecoder::new(limits)
                        .map(Box::new)
                        .map(Self::Lzip)
                }
                #[cfg(not(feature = "lzip"))]
                {
                    let _ = (limits, preference);
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
            Self::GzipPortable(codec) => codec.process(input, output, end),
            #[cfg(feature = "native-codecs")]
            Self::GzipNative(codec) => codec.process(input, output, end),
            #[cfg(feature = "sevenz")]
            Self::Deflate(codec) => codec.process(input, output, end),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(codec) => codec.process(input, output, end),
            #[cfg(feature = "zstd")]
            Self::ZstdPortable(codec) => codec.process(input, output, end),
            #[cfg(all(feature = "zstd", feature = "native-codecs"))]
            Self::ZstdNative(codec) => codec.process(input, output, end),
            #[cfg(feature = "xz")]
            Self::XzPortable(codec) => codec.process(input, output, end),
            #[cfg(all(feature = "xz", feature = "native-codecs"))]
            Self::XzNative(codec) => codec.process(input, output, end),
            #[cfg(feature = "lz4")]
            Self::Lz4Portable(codec) => codec.process(input, output, end),
            #[cfg(all(feature = "lz4", feature = "native-codecs"))]
            Self::Lz4Native(codec) => codec.process(input, output, end),
            #[cfg(feature = "compress")]
            Self::Compress(codec) => codec.process(input, output, end),
            #[cfg(feature = "lzip")]
            Self::Lzip(codec) => codec.process(input, output, end),
        }
    }

    /// Non-blocking mirror of [`process`](Self::process) for async adapters.
    ///
    /// Every variant inherits the blocking-delegating default except the `Xz`
    /// and lzip worker bridges, which override [`Codec::poll_process`] to avoid
    /// parking the executor thread on a worker channel.
    #[cfg(all(
        feature = "async",
        any(
            feature = "zstd",
            feature = "xz",
            feature = "lz4",
            feature = "compress",
            feature = "lzip"
        )
    ))]
    pub(crate) fn poll_process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        waker: &Waker,
    ) -> Result<Option<CodecStep>, ArchiveError> {
        match self {
            Self::GzipPortable(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "native-codecs")]
            Self::GzipNative(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "sevenz")]
            Self::Deflate(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "zstd")]
            Self::ZstdPortable(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(all(feature = "zstd", feature = "native-codecs"))]
            Self::ZstdNative(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "xz")]
            Self::XzPortable(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(all(feature = "xz", feature = "native-codecs"))]
            Self::XzNative(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "lz4")]
            Self::Lz4Portable(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(all(feature = "lz4", feature = "native-codecs"))]
            Self::Lz4Native(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "compress")]
            Self::Compress(codec) => codec.poll_process(input, output, end, waker),
            #[cfg(feature = "lzip")]
            Self::Lzip(codec) => codec.poll_process(input, output, end, waker),
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

#[cfg(not(feature = "native-codecs"))]
fn disabled_backend(filter: FilterId, backend: &str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Capability)
        .with_format(filter_name(filter))
        .with_context(format!("requested {backend} codec backend is not compiled"))
}

fn filter_name(filter: FilterId) -> &'static str {
    libarchive_oxide_core::capability::filter_capability(filter)
        .map_or("unknown", |record| record.name())
}
