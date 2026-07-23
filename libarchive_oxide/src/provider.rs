// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time archive format and outer-codec provider registration.
//!
//! Providers are composed as generic cons-lists. There is no global registry,
//! trait object, dynamic loading boundary, or plugin ABI.

use std::fmt;
use std::io::Write;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArDecoder, ArEncoder, ArchiveDecoder, ArchiveEncoder, ArchiveError, ArchiveMetadata, Codec,
    CpioDecoder, CpioEncoder, DecodeStep, EncodeCommand, EncodeStep, ErrorKind, FormatId, Limits,
    ProbeResult, TarDecoder, TarEncoder,
};

use crate::pipeline_codec::PipelineCodec;
use crate::zip_stream::{StreamZipMethod, ZipStreamEncoder};

/// Read/write capabilities advertised by one archive format provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatCapabilities {
    decode: bool,
    encode: bool,
    seek: bool,
}

impl FormatCapabilities {
    /// Creates an explicit capability description.
    #[must_use]
    pub const fn new(decode: bool, encode: bool, seek: bool) -> Self {
        Self {
            decode,
            encode,
            seek,
        }
    }

    /// Whether the provider can decode the format.
    #[must_use]
    pub const fn can_decode(self) -> bool {
        self.decode
    }

    /// Whether the provider can encode the format.
    #[must_use]
    pub const fn can_encode(self) -> bool {
        self.encode
    }

    /// Whether this identifier uses the crate's built-in seek-native path.
    /// Downstream sequential providers set this to `false`.
    #[must_use]
    pub const fn requires_seek(self) -> bool {
        self.seek
    }

    const fn available(self) -> bool {
        self.decode || self.encode
    }
}

/// Decode/encode capabilities advertised by one outer codec provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecCapabilities {
    decode: bool,
    encode: bool,
}

impl CodecCapabilities {
    /// Creates an explicit capability description.
    #[must_use]
    pub const fn new(decode: bool, encode: bool) -> Self {
        Self { decode, encode }
    }

    /// Whether the provider can decode the filter.
    #[must_use]
    pub const fn can_decode(self) -> bool {
        self.decode
    }

    /// Whether the provider can encode the filter.
    #[must_use]
    pub const fn can_encode(self) -> bool {
        self.encode
    }

    const fn available(self) -> bool {
        self.decode || self.encode
    }
}

/// Result of querying a registered capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderCapability<T> {
    /// A registered provider implements the capability.
    Available(T),
    /// The identifier is known, but the provider is compiled without support.
    Disabled,
    /// No provider in the static chain recognizes the identifier.
    Unknown,
}

/// Encoder protocol used by format providers.
///
/// It extends the core caller-driven encoder with archive-level metadata while
/// retaining a default that rejects metadata the provider cannot represent.
pub trait ProviderArchiveEncoder: ArchiveEncoder {
    /// Applies archive-level metadata before the first entry.
    fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), ArchiveError> {
        if metadata.volume_name().is_none()
            && metadata.comment().is_none()
            && metadata.extensions().is_empty()
        {
            Ok(())
        } else {
            Err(ArchiveError::new(ErrorKind::Unsupported)
                .with_context("format provider has no archive-level metadata representation"))
        }
    }
}

/// One compile-time archive format provider.
pub trait FormatProvider {
    /// Caller-driven decoder state created after this provider matches.
    type Decoder: ArchiveDecoder;
    /// Caller-driven encoder state created for this provider.
    type Encoder: ProviderArchiveEncoder;

    /// Stable archive format identifier served by this provider.
    fn format(&self) -> FormatId;
    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;
    /// Incrementally probes an immutable prefix.
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()>;
    /// Decode/encode capabilities in this build.
    fn capabilities(&self) -> FormatCapabilities;
    /// Creates fresh decoder state.
    fn decoder(&self, limits: Limits) -> Result<Self::Decoder, ArchiveError>;
    /// Creates fresh encoder state.
    fn encoder(&self, limits: Limits) -> Result<Self::Encoder, ArchiveError>;
}

/// One compile-time outer codec provider.
pub trait CodecProvider {
    /// Caller-driven decoder state created after this provider matches.
    type Decoder: Codec;

    /// Stable outer-filter identifier served by this provider.
    fn filter(&self) -> FilterId;
    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;
    /// Incrementally probes an immutable prefix.
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()>;
    /// Decode/encode capabilities in this build.
    fn capabilities(&self) -> CodecCapabilities;
    /// Creates fresh decoder state.
    fn decoder(&self, limits: Limits) -> Result<Self::Decoder, ArchiveError>;
    /// Encodes one bounded frame/member.
    fn encode_frame(&self, input: &[u8], limits: Limits) -> Result<Vec<u8>, ArchiveError>;
}

/// Empty static-provider selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoProviderSelection {}

/// Recursive selection inside a static provider chain.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSelection<T> {
    /// The head provider matched.
    Head,
    /// A provider in the tail matched.
    Tail(T),
}

/// Empty archive decoder used by an empty provider chain.
#[doc(hidden)]
#[derive(Debug)]
pub struct NoArchiveDecoder;

impl ArchiveDecoder for NoArchiveDecoder {
    fn step<'a>(
        &'a mut self,
        _input: &'a [u8],
        _output: &'a mut [u8],
        _end: libarchive_oxide_core::EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_context("empty format provider chain created a decoder"))
    }
}

/// Empty archive encoder used by an empty provider chain.
#[doc(hidden)]
#[derive(Debug)]
pub struct NoArchiveEncoder;

impl ArchiveEncoder for NoArchiveEncoder {
    fn step(
        &mut self,
        _command: EncodeCommand<'_>,
        _output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_context("empty format provider chain created an encoder"))
    }
}

impl ProviderArchiveEncoder for NoArchiveEncoder {}

/// Empty codec used by an empty provider chain.
#[doc(hidden)]
#[derive(Debug)]
pub struct NoCodecDecoder;

impl Codec for NoCodecDecoder {
    fn process(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
        _end: libarchive_oxide_core::EndOfInput,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_context("empty codec provider chain created a decoder"))
    }
}

/// No registered archive format providers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoFormatProviders;

/// No registered outer codec providers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCodecProviders;

/// One format provider prepended to an existing static chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatProviderNode<P, T> {
    head: P,
    tail: T,
}

/// One codec provider prepended to an existing static chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecProviderNode<P, T> {
    head: P,
    tail: T,
}

/// Decoder state for one node in a format provider chain.
#[doc(hidden)]
pub enum ChainedFormatDecoder<H, T> {
    /// Decoder from the head provider.
    Head(H),
    /// Decoder from the tail chain.
    Tail(T),
}

impl<H, T> fmt::Debug for ChainedFormatDecoder<H, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Head(_) => "ChainedFormatDecoder::Head(..)",
            Self::Tail(_) => "ChainedFormatDecoder::Tail(..)",
        })
    }
}

impl<H: ArchiveDecoder, T: ArchiveDecoder> ArchiveDecoder for ChainedFormatDecoder<H, T> {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self {
            Self::Head(decoder) => decoder.step(input, output, end),
            Self::Tail(decoder) => decoder.step(input, output, end),
        }
    }
}

/// Encoder state for one node in a format provider chain.
#[doc(hidden)]
pub enum ChainedFormatEncoder<H, T> {
    /// Encoder from the head provider.
    Head(H),
    /// Encoder from the tail chain.
    Tail(T),
}

impl<H, T> fmt::Debug for ChainedFormatEncoder<H, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Head(_) => "ChainedFormatEncoder::Head(..)",
            Self::Tail(_) => "ChainedFormatEncoder::Tail(..)",
        })
    }
}

impl<H: ProviderArchiveEncoder, T: ProviderArchiveEncoder> ArchiveEncoder
    for ChainedFormatEncoder<H, T>
{
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        match self {
            Self::Head(encoder) => encoder.step(command, output),
            Self::Tail(encoder) => encoder.step(command, output),
        }
    }
}

impl<H: ProviderArchiveEncoder, T: ProviderArchiveEncoder> ProviderArchiveEncoder
    for ChainedFormatEncoder<H, T>
{
    fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), ArchiveError> {
        match self {
            Self::Head(encoder) => encoder.set_archive_metadata(metadata),
            Self::Tail(encoder) => encoder.set_archive_metadata(metadata),
        }
    }
}

/// Decoder state for one node in a codec provider chain.
#[doc(hidden)]
pub enum ChainedCodecDecoder<H, T> {
    /// Decoder from the head provider.
    Head(H),
    /// Decoder from the tail chain.
    Tail(T),
}

impl<H, T> fmt::Debug for ChainedCodecDecoder<H, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Head(_) => "ChainedCodecDecoder::Head(..)",
            Self::Tail(_) => "ChainedCodecDecoder::Tail(..)",
        })
    }
}

impl<H: Codec, T: Codec> Codec for ChainedCodecDecoder<H, T> {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        match self {
            Self::Head(decoder) => decoder.process(input, output, end),
            Self::Tail(decoder) => decoder.process(input, output, end),
        }
    }
}
/// Internal static dispatch contract implemented by provider-chain nodes.
#[doc(hidden)]
pub trait StaticFormatProviders {
    /// Runtime selection encoded in the chain's type.
    type Selection: Clone;
    /// Union of every decoder state in the chain.
    type Decoder: ArchiveDecoder;
    /// Union of every encoder state in the chain.
    type Encoder: ProviderArchiveEncoder;

    /// Probes all registered providers and rejects conflicting identifiers.
    fn probe_format(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FormatId, Self::Selection)>, ArchiveError>;
    /// Queries one known identifier.
    fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities>;
    /// Selects a provider by identifier.
    fn select_format(&self, format: FormatId) -> Result<Self::Selection, ArchiveError>;
    /// Creates decoder state for a prior selection.
    fn format_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError>;
    /// Creates encoder state for a prior selection.
    fn format_encoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError>;
}

/// Internal static dispatch contract implemented by codec-chain nodes.
#[doc(hidden)]
pub trait StaticCodecProviders {
    /// Runtime selection encoded in the chain's type.
    type Selection: Clone;
    /// Union of every decoder state in the chain.
    type Decoder: Codec;

    /// Probes all registered providers and rejects conflicting identifiers.
    fn probe_codec(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FilterId, Self::Selection)>, ArchiveError>;
    /// Queries one known identifier.
    fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities>;
    /// Selects a provider by identifier.
    fn select_codec(&self, filter: FilterId) -> Result<Self::Selection, ArchiveError>;
    /// Creates decoder state for a prior selection.
    fn codec_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError>;
    /// Encodes one bounded frame/member with a prior selection.
    fn encode_codec_frame(
        &self,
        selection: Self::Selection,
        input: &[u8],
        limits: Limits,
    ) -> Result<Vec<u8>, ArchiveError>;
}

impl StaticFormatProviders for NoFormatProviders {
    type Selection = NoProviderSelection;
    type Decoder = NoArchiveDecoder;
    type Encoder = NoArchiveEncoder;

    fn probe_format(
        &self,
        _prefix: &[u8],
    ) -> Result<ProbeResult<(FormatId, Self::Selection)>, ArchiveError> {
        Ok(ProbeResult::NoMatch)
    }

    fn format_capability(&self, _format: FormatId) -> ProviderCapability<FormatCapabilities> {
        ProviderCapability::Unknown
    }

    fn select_format(&self, format: FormatId) -> Result<Self::Selection, ArchiveError> {
        Err(unknown_format(format))
    }

    fn format_decoder(
        &self,
        selection: Self::Selection,
        _limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        match selection {}
    }

    fn format_encoder(
        &self,
        selection: Self::Selection,
        _limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError> {
        match selection {}
    }
}

impl StaticCodecProviders for NoCodecProviders {
    type Selection = NoProviderSelection;
    type Decoder = NoCodecDecoder;

    fn probe_codec(
        &self,
        _prefix: &[u8],
    ) -> Result<ProbeResult<(FilterId, Self::Selection)>, ArchiveError> {
        Ok(ProbeResult::NoMatch)
    }

    fn codec_capability(&self, _filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        ProviderCapability::Unknown
    }

    fn select_codec(&self, filter: FilterId) -> Result<Self::Selection, ArchiveError> {
        Err(unknown_codec(filter))
    }

    fn codec_decoder(
        &self,
        selection: Self::Selection,
        _limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        match selection {}
    }

    fn encode_codec_frame(
        &self,
        selection: Self::Selection,
        _input: &[u8],
        _limits: Limits,
    ) -> Result<Vec<u8>, ArchiveError> {
        match selection {}
    }
}

impl<P, T> StaticFormatProviders for FormatProviderNode<P, T>
where
    P: FormatProvider,
    T: StaticFormatProviders,
{
    type Selection = ProviderSelection<T::Selection>;
    type Decoder = ChainedFormatDecoder<P::Decoder, T::Decoder>;
    type Encoder = ChainedFormatEncoder<P::Encoder, T::Encoder>;

    fn probe_format(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FormatId, Self::Selection)>, ArchiveError> {
        let head = validate_probe(self.head.probe(prefix), prefix.len(), self.head.name())?;
        let head = match head {
            ProbeResult::Match(()) => {
                ProbeResult::Match((self.head.format(), ProviderSelection::Head))
            },
            ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
            ProbeResult::NoMatch => ProbeResult::NoMatch,
            _ => return Err(unknown_probe_variant(self.head.name())),
        };
        let tail = map_tail_format(self.tail.probe_format(prefix)?)?;
        combine_format_probes(head, tail)
    }

    fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities> {
        if self.head.format() == format {
            let capabilities = self.head.capabilities();
            if capabilities.available() {
                ProviderCapability::Available(capabilities)
            } else {
                ProviderCapability::Disabled
            }
        } else {
            self.tail.format_capability(format)
        }
    }

    fn select_format(&self, format: FormatId) -> Result<Self::Selection, ArchiveError> {
        if self.head.format() == format {
            Ok(ProviderSelection::Head)
        } else {
            self.tail.select_format(format).map(ProviderSelection::Tail)
        }
    }

    fn format_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        match selection {
            ProviderSelection::Head => {
                if !self.head.capabilities().can_decode() {
                    return Err(disabled_format(
                        self.head.format(),
                        self.head.name(),
                        "decode",
                    ));
                }
                self.head.decoder(limits).map(ChainedFormatDecoder::Head)
            },
            ProviderSelection::Tail(selection) => self
                .tail
                .format_decoder(selection, limits)
                .map(ChainedFormatDecoder::Tail),
        }
    }

    fn format_encoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError> {
        match selection {
            ProviderSelection::Head => {
                if !self.head.capabilities().can_encode() {
                    return Err(disabled_format(
                        self.head.format(),
                        self.head.name(),
                        "encode",
                    ));
                }
                self.head.encoder(limits).map(ChainedFormatEncoder::Head)
            },
            ProviderSelection::Tail(selection) => self
                .tail
                .format_encoder(selection, limits)
                .map(ChainedFormatEncoder::Tail),
        }
    }
}

impl<P, T> StaticCodecProviders for CodecProviderNode<P, T>
where
    P: CodecProvider,
    T: StaticCodecProviders,
{
    type Selection = ProviderSelection<T::Selection>;
    type Decoder = ChainedCodecDecoder<P::Decoder, T::Decoder>;

    fn probe_codec(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FilterId, Self::Selection)>, ArchiveError> {
        let head = validate_probe(self.head.probe(prefix), prefix.len(), self.head.name())?;
        let head = match head {
            ProbeResult::Match(()) => {
                ProbeResult::Match((self.head.filter(), ProviderSelection::Head))
            },
            ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
            ProbeResult::NoMatch => ProbeResult::NoMatch,
            _ => return Err(unknown_probe_variant(self.head.name())),
        };
        let tail = map_tail_codec(self.tail.probe_codec(prefix)?)?;
        combine_codec_probes(head, tail)
    }

    fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        if self.head.filter() == filter {
            let capabilities = self.head.capabilities();
            if capabilities.available() {
                ProviderCapability::Available(capabilities)
            } else {
                ProviderCapability::Disabled
            }
        } else {
            self.tail.codec_capability(filter)
        }
    }

    fn select_codec(&self, filter: FilterId) -> Result<Self::Selection, ArchiveError> {
        if self.head.filter() == filter {
            Ok(ProviderSelection::Head)
        } else {
            self.tail.select_codec(filter).map(ProviderSelection::Tail)
        }
    }

    fn codec_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        match selection {
            ProviderSelection::Head => {
                if !self.head.capabilities().can_decode() {
                    return Err(disabled_codec(
                        self.head.filter(),
                        self.head.name(),
                        "decode",
                    ));
                }
                self.head.decoder(limits).map(ChainedCodecDecoder::Head)
            },
            ProviderSelection::Tail(selection) => self
                .tail
                .codec_decoder(selection, limits)
                .map(ChainedCodecDecoder::Tail),
        }
    }

    fn encode_codec_frame(
        &self,
        selection: Self::Selection,
        input: &[u8],
        limits: Limits,
    ) -> Result<Vec<u8>, ArchiveError> {
        let encoded = match selection {
            ProviderSelection::Head => {
                if !self.head.capabilities().can_encode() {
                    return Err(disabled_codec(
                        self.head.filter(),
                        self.head.name(),
                        "encode",
                    ));
                }
                self.head.encode_frame(input, limits)?
            },
            ProviderSelection::Tail(selection) => {
                self.tail.encode_codec_frame(selection, input, limits)?
            },
        };
        validate_encoded_frame(encoded, limits)
    }
}

fn validate_probe<T>(
    result: ProbeResult<T>,
    prefix_len: usize,
    provider: &'static str,
) -> Result<ProbeResult<T>, ArchiveError> {
    if let ProbeResult::NeedMore { minimum } = result {
        if minimum <= prefix_len {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format(provider)
                .with_context("provider probe requested no additional input"));
        }
        Ok(ProbeResult::NeedMore { minimum })
    } else {
        Ok(result)
    }
}

fn map_tail_format<T>(
    result: ProbeResult<(FormatId, T)>,
) -> Result<ProbeResult<(FormatId, ProviderSelection<T>)>, ArchiveError> {
    Ok(match result {
        ProbeResult::Match((format, selection)) => {
            ProbeResult::Match((format, ProviderSelection::Tail(selection)))
        },
        ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
        ProbeResult::NoMatch => ProbeResult::NoMatch,
        _ => return Err(unknown_probe_variant("format-provider-chain")),
    })
}

fn map_tail_codec<T>(
    result: ProbeResult<(FilterId, T)>,
) -> Result<ProbeResult<(FilterId, ProviderSelection<T>)>, ArchiveError> {
    Ok(match result {
        ProbeResult::Match((filter, selection)) => {
            ProbeResult::Match((filter, ProviderSelection::Tail(selection)))
        },
        ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
        ProbeResult::NoMatch => ProbeResult::NoMatch,
        _ => return Err(unknown_probe_variant("codec-provider-chain")),
    })
}

fn combine_format_probes<S>(
    head: ProbeResult<(FormatId, S)>,
    tail: ProbeResult<(FormatId, S)>,
) -> Result<ProbeResult<(FormatId, S)>, ArchiveError> {
    match (head, tail) {
        (ProbeResult::Match((head_id, selection)), ProbeResult::Match((tail_id, _))) => {
            if head_id == tail_id {
                Ok(ProbeResult::Match((head_id, selection)))
            } else {
                Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context("multiple format providers matched the same prefix"))
            }
        },
        // A conclusive head match wins over a still-inconclusive tail: chain order is the
        // compile-time override rule. An inconclusive head must still resolve before a tail match.
        (ProbeResult::Match(value), ProbeResult::NoMatch | ProbeResult::NeedMore { .. })
        | (ProbeResult::NoMatch, ProbeResult::Match(value)) => Ok(ProbeResult::Match(value)),
        (ProbeResult::NeedMore { minimum: left }, ProbeResult::NeedMore { minimum: right }) => {
            Ok(ProbeResult::NeedMore {
                minimum: left.max(right),
            })
        },
        (ProbeResult::NeedMore { minimum }, ProbeResult::Match(_) | ProbeResult::NoMatch)
        | (ProbeResult::NoMatch, ProbeResult::NeedMore { minimum }) => {
            Ok(ProbeResult::NeedMore { minimum })
        },
        (ProbeResult::NoMatch, ProbeResult::NoMatch) => Ok(ProbeResult::NoMatch),
        _ => Err(unknown_probe_variant("format-provider-chain")),
    }
}

fn combine_codec_probes<S>(
    head: ProbeResult<(FilterId, S)>,
    tail: ProbeResult<(FilterId, S)>,
) -> Result<ProbeResult<(FilterId, S)>, ArchiveError> {
    match (head, tail) {
        (ProbeResult::Match((head_id, selection)), ProbeResult::Match((tail_id, _))) => {
            if head_id == tail_id {
                Ok(ProbeResult::Match((head_id, selection)))
            } else {
                Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context("multiple codec providers matched the same prefix"))
            }
        },
        // A conclusive head match wins over a still-inconclusive tail: chain order is the
        // compile-time override rule. An inconclusive head must still resolve before a tail match.
        (ProbeResult::Match(value), ProbeResult::NoMatch | ProbeResult::NeedMore { .. })
        | (ProbeResult::NoMatch, ProbeResult::Match(value)) => Ok(ProbeResult::Match(value)),
        (ProbeResult::NeedMore { minimum: left }, ProbeResult::NeedMore { minimum: right }) => {
            Ok(ProbeResult::NeedMore {
                minimum: left.max(right),
            })
        },
        (ProbeResult::NeedMore { minimum }, ProbeResult::Match(_) | ProbeResult::NoMatch)
        | (ProbeResult::NoMatch, ProbeResult::NeedMore { minimum }) => {
            Ok(ProbeResult::NeedMore { minimum })
        },
        (ProbeResult::NoMatch, ProbeResult::NoMatch) => Ok(ProbeResult::NoMatch),
        _ => Err(unknown_probe_variant("codec-provider-chain")),
    }
}

/// Built-in format provider tail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuiltinFormatProviders;

/// Built-in codec provider tail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuiltinCodecProviders;

/// Statically dispatched built-in sequential decoder.
#[doc(hidden)]
#[derive(Debug)]
pub struct BuiltinFormatDecoder {
    inner: BuiltinFormatDecoderInner,
}

#[derive(Debug)]
enum BuiltinFormatDecoderInner {
    Tar(Box<TarDecoder>),
    Cpio(Box<CpioDecoder>),
    Ar(Box<ArDecoder>),
}

impl BuiltinFormatDecoder {
    pub(crate) fn sequential(format: FormatId, limits: Limits) -> Result<Self, ArchiveError> {
        let inner = match format {
            FormatId::Tar => BuiltinFormatDecoderInner::Tar(Box::new(TarDecoder::new(limits))),
            FormatId::Cpio => BuiltinFormatDecoderInner::Cpio(Box::new(CpioDecoder::new(limits))),
            FormatId::Ar => BuiltinFormatDecoderInner::Ar(Box::new(ArDecoder::new(limits))),
            FormatId::Zip | FormatId::SevenZip | FormatId::Iso9660 => {
                return Err(ArchiveError::new(ErrorKind::Capability)
                    .with_format(format_name(format))
                    .with_context("archive format requires Read + Seek"));
            },
            _ => return Err(unknown_format(format)),
        };
        Ok(Self { inner })
    }
}

impl ArchiveDecoder for BuiltinFormatDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match &mut self.inner {
            BuiltinFormatDecoderInner::Tar(decoder) => decoder.step(input, output, end),
            BuiltinFormatDecoderInner::Cpio(decoder) => decoder.step(input, output, end),
            BuiltinFormatDecoderInner::Ar(decoder) => decoder.step(input, output, end),
        }
    }
}

/// Statically dispatched built-in sequential encoder.
#[doc(hidden)]
#[derive(Debug)]
pub struct BuiltinFormatEncoder {
    inner: BuiltinFormatEncoderInner,
}

#[derive(Debug)]
enum BuiltinFormatEncoderInner {
    Tar(TarEncoder),
    Cpio(CpioEncoder),
    Ar(ArEncoder),
    Zip(Box<ZipStreamEncoder>),
}

impl BuiltinFormatEncoder {
    pub(crate) fn tar(limits: Limits) -> Self {
        Self {
            inner: BuiltinFormatEncoderInner::Tar(TarEncoder::new(limits)),
        }
    }

    pub(crate) fn sequential(format: FormatId, limits: Limits) -> Result<Self, ArchiveError> {
        let inner = match format {
            FormatId::Tar => BuiltinFormatEncoderInner::Tar(TarEncoder::new(limits)),
            FormatId::Cpio => BuiltinFormatEncoderInner::Cpio(CpioEncoder::new(limits)),
            FormatId::Ar => BuiltinFormatEncoderInner::Ar(ArEncoder::new(limits)),
            FormatId::Zip => {
                BuiltinFormatEncoderInner::Zip(Box::new(ZipStreamEncoder::new(limits)))
            },
            FormatId::SevenZip | FormatId::Iso9660 => {
                return Err(ArchiveError::new(ErrorKind::Capability)
                    .with_format(format_name(format))
                    .with_context("format is not available through the sequential writer"));
            },
            _ => return Err(unknown_format(format)),
        };
        Ok(Self { inner })
    }

    pub(crate) fn zip(limits: Limits, method: crate::ZipMethod) -> Self {
        let (method, deferred) = map_zip_method(method);
        let mut encoder = ZipStreamEncoder::with_method(limits, method);
        if let Some(message) = deferred {
            encoder.set_deferred_unsupported(message);
        }
        Self {
            inner: BuiltinFormatEncoderInner::Zip(Box::new(encoder)),
        }
    }

    pub(crate) const fn cpio(limits: Limits, dialect: libarchive_oxide_core::CpioDialect) -> Self {
        Self {
            inner: BuiltinFormatEncoderInner::Cpio(CpioEncoder::with_dialect(limits, dialect)),
        }
    }

    #[cfg(feature = "aes")]
    pub(crate) fn encrypted_zip(
        limits: Limits,
        method: crate::ZipMethod,
        password: crate::SecretBytes,
    ) -> Self {
        let (method, deferred) = map_zip_method(method);
        let mut encoder = ZipStreamEncoder::with_password(limits, method, password);
        if let Some(message) = deferred {
            encoder.set_deferred_unsupported(message);
        }
        Self {
            inner: BuiltinFormatEncoderInner::Zip(Box::new(encoder)),
        }
    }
}

/// Maps the public [`crate::ZipMethod`] to the writer's internal method,
/// returning a deferred structured-Unsupported message when the requested
/// method has no encoder in the current build profile (ZIP Zstandard write
/// requires `native-codecs`; the portable `ruzstd` path is decode-only).
fn map_zip_method(method: crate::ZipMethod) -> (StreamZipMethod, Option<&'static str>) {
    match method {
        crate::ZipMethod::Store => (StreamZipMethod::Store, None),
        crate::ZipMethod::Deflate => (StreamZipMethod::Deflate, None),
        #[cfg(feature = "bzip2")]
        crate::ZipMethod::Bzip2 => (StreamZipMethod::Bzip2, None),
        #[cfg(all(feature = "zstd", feature = "native-codecs"))]
        crate::ZipMethod::Zstd => (StreamZipMethod::Zstd, None),
        #[cfg(all(feature = "zstd", not(feature = "native-codecs")))]
        crate::ZipMethod::Zstd => (
            StreamZipMethod::Deflate,
            Some(
                "ZIP Zstandard write requires the native-codecs profile (no portable zstd encoder)",
            ),
        ),
        #[cfg(feature = "xz")]
        crate::ZipMethod::Lzma => (StreamZipMethod::Lzma, None),
    }
}

impl ArchiveEncoder for BuiltinFormatEncoder {
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        let data_len = match &command {
            EncodeCommand::Data(data) => Some(data.len()),
            _ => None,
        };
        let output_len = output.len();
        match &mut self.inner {
            BuiltinFormatEncoderInner::Tar(encoder) => encoder.step(command, output),
            BuiltinFormatEncoderInner::Cpio(encoder) => encoder.step(command, output),
            BuiltinFormatEncoderInner::Ar(encoder) => encoder.step(command, output),
            BuiltinFormatEncoderInner::Zip(encoder) => encoder.step(command, output),
        }
        .and_then(|step| step.validate(data_len, output_len))
    }
}

impl ProviderArchiveEncoder for BuiltinFormatEncoder {
    fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), ArchiveError> {
        match &mut self.inner {
            BuiltinFormatEncoderInner::Tar(encoder) => encoder.set_archive_metadata(metadata),
            BuiltinFormatEncoderInner::Zip(encoder) => encoder.set_archive_metadata(metadata),
            BuiltinFormatEncoderInner::Cpio(_) | BuiltinFormatEncoderInner::Ar(_) => {
                ProviderArchiveEncoder::set_archive_metadata(&mut NoArchiveEncoder, metadata)
            },
        }
    }
}

/// Statically dispatched built-in outer decoder.
#[doc(hidden)]
#[derive(Debug)]
pub struct BuiltinCodecDecoder {
    inner: PipelineCodec,
}

impl Codec for BuiltinCodecDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        self.inner.process(input, output, end)
    }
}

impl StaticFormatProviders for BuiltinFormatProviders {
    type Selection = FormatId;
    type Decoder = BuiltinFormatDecoder;
    type Encoder = BuiltinFormatEncoder;

    fn probe_format(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FormatId, Self::Selection)>, ArchiveError> {
        Ok(match FormatId::probe(prefix) {
            ProbeResult::Match(format) => ProbeResult::Match((format, format)),
            ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
            ProbeResult::NoMatch => ProbeResult::NoMatch,
            _ => return Err(unknown_probe_variant("built-in-format")),
        })
    }

    fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities> {
        match format {
            FormatId::Tar | FormatId::Cpio | FormatId::Ar | FormatId::Zip | FormatId::Iso9660 => {
                ProviderCapability::Available(FormatCapabilities::new(
                    true,
                    true,
                    matches!(format, FormatId::Zip | FormatId::Iso9660),
                ))
            },
            FormatId::SevenZip if cfg!(feature = "sevenz") => {
                ProviderCapability::Available(FormatCapabilities::new(true, true, true))
            },
            FormatId::SevenZip => ProviderCapability::Disabled,
            // CAB and XAR are seek-native READ-ONLY providers: decode yes, encode no.
            FormatId::Cab | FormatId::Xar => {
                ProviderCapability::Available(FormatCapabilities::new(true, false, true))
            },
            _ => ProviderCapability::Unknown,
        }
    }

    fn select_format(&self, format: FormatId) -> Result<Self::Selection, ArchiveError> {
        match self.format_capability(format) {
            ProviderCapability::Available(_) | ProviderCapability::Disabled => Ok(format),
            ProviderCapability::Unknown => Err(unknown_format(format)),
        }
    }

    fn format_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        if matches!(
            self.format_capability(selection),
            ProviderCapability::Disabled
        ) {
            return Err(disabled_format(selection, format_name(selection), "decode"));
        }
        BuiltinFormatDecoder::sequential(selection, limits)
    }

    fn format_encoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError> {
        if matches!(
            self.format_capability(selection),
            ProviderCapability::Disabled
        ) {
            return Err(disabled_format(selection, format_name(selection), "encode"));
        }
        BuiltinFormatEncoder::sequential(selection, limits)
    }
}

impl StaticCodecProviders for BuiltinCodecProviders {
    type Selection = FilterId;
    type Decoder = BuiltinCodecDecoder;

    fn probe_codec(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FilterId, Self::Selection)>, ArchiveError> {
        Ok(match FilterId::probe(prefix) {
            ProbeResult::Match(filter) => ProbeResult::Match((filter, filter)),
            ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
            ProbeResult::NoMatch => ProbeResult::NoMatch,
            _ => return Err(unknown_probe_variant("built-in-codec")),
        })
    }

    fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        let enabled = match filter {
            FilterId::Gzip => true,
            FilterId::Bzip2 => cfg!(feature = "bzip2"),
            FilterId::Zstd => cfg!(feature = "zstd"),
            FilterId::Xz => cfg!(feature = "xz"),
            FilterId::Lz4 => cfg!(feature = "lz4"),
            _ => return ProviderCapability::Unknown,
        };
        if enabled {
            ProviderCapability::Available(CodecCapabilities::new(true, true))
        } else {
            ProviderCapability::Disabled
        }
    }

    fn select_codec(&self, filter: FilterId) -> Result<Self::Selection, ArchiveError> {
        match self.codec_capability(filter) {
            ProviderCapability::Available(_) | ProviderCapability::Disabled => Ok(filter),
            ProviderCapability::Unknown => Err(unknown_codec(filter)),
        }
    }

    fn codec_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        if matches!(
            self.codec_capability(selection),
            ProviderCapability::Disabled
        ) {
            return Err(disabled_codec(selection, filter_name(selection), "decode"));
        }
        PipelineCodec::new(selection, limits).map(|inner| BuiltinCodecDecoder { inner })
    }

    fn encode_codec_frame(
        &self,
        selection: Self::Selection,
        input: &[u8],
        limits: Limits,
    ) -> Result<Vec<u8>, ArchiveError> {
        if matches!(
            self.codec_capability(selection),
            ProviderCapability::Disabled
        ) {
            return Err(disabled_codec(selection, filter_name(selection), "encode"));
        }
        let encoded = match selection {
            FilterId::Gzip => {
                let mut writer = crate::filtered_io::GzipFilterWrite::new(Vec::new(), limits);
                writer
                    .write_all(input)
                    .and_then(|()| writer.finish())
                    .map_err(|error| codec_io_error("gzip", &error))?
            },
            FilterId::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    let mut writer =
                        bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                    writer
                        .write_all(input)
                        .and_then(|()| writer.finish())
                        .map_err(|error| codec_io_error("bzip2", &error))?
                }
                #[cfg(not(feature = "bzip2"))]
                {
                    return Err(disabled_codec(selection, "bzip2", "encode"));
                }
            },
            FilterId::Zstd | FilterId::Xz | FilterId::Lz4 => {
                #[cfg(any(feature = "zstd", feature = "xz", feature = "lz4"))]
                {
                    crate::filtered_io::encode_profile_frame(selection, input)
                        .map_err(|error| codec_io_error(filter_name(selection), &error))?
                }
                #[cfg(not(any(feature = "zstd", feature = "xz", feature = "lz4")))]
                {
                    return Err(disabled_codec(selection, filter_name(selection), "encode"));
                }
            },
            _ => return Err(unknown_codec(selection)),
        };
        validate_encoded_frame(encoded, limits)
    }
}

/// Registered format and codec provider chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSet<F = BuiltinFormatProviders, C = BuiltinCodecProviders> {
    formats: F,
    codecs: C,
}

impl ProviderSet<BuiltinFormatProviders, BuiltinCodecProviders> {
    /// Built-in providers compiled into this crate.
    #[must_use]
    pub const fn builtins() -> Self {
        Self {
            formats: BuiltinFormatProviders,
            codecs: BuiltinCodecProviders,
        }
    }
}

impl ProviderSet<NoFormatProviders, NoCodecProviders> {
    /// An empty provider set for explicitly closed or provider-only engines.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            formats: NoFormatProviders,
            codecs: NoCodecProviders,
        }
    }
}

impl<F, C> ProviderSet<F, C> {
    pub(crate) const fn from_chains(formats: F, codecs: C) -> Self {
        Self { formats, codecs }
    }

    /// Prepends an archive format provider to the static chain.
    #[must_use]
    pub fn with_format_provider<P>(self, provider: P) -> ProviderSet<FormatProviderNode<P, F>, C>
    where
        P: FormatProvider,
    {
        ProviderSet {
            formats: FormatProviderNode {
                head: provider,
                tail: self.formats,
            },
            codecs: self.codecs,
        }
    }

    /// Prepends an outer codec provider to the static chain.
    #[must_use]
    pub fn with_codec_provider<P>(self, provider: P) -> ProviderSet<F, CodecProviderNode<P, C>>
    where
        P: CodecProvider,
    {
        ProviderSet {
            formats: self.formats,
            codecs: CodecProviderNode {
                head: provider,
                tail: self.codecs,
            },
        }
    }

    /// Splits the set into its statically typed chains.
    #[doc(hidden)]
    #[must_use]
    pub fn into_chains(self) -> (F, C) {
        (self.formats, self.codecs)
    }
}

impl<F: StaticFormatProviders, C: StaticCodecProviders> ProviderSet<F, C> {
    /// Whether a registered format provider is compiled and available.
    #[must_use]
    pub fn supports_format(&self, format: FormatId) -> bool {
        matches!(
            self.formats.format_capability(format),
            ProviderCapability::Available(_)
        )
    }

    /// Whether a registered outer codec provider is compiled and available.
    #[must_use]
    pub fn supports_filter(&self, filter: FilterId) -> bool {
        matches!(
            self.codecs.codec_capability(filter),
            ProviderCapability::Available(_)
        )
    }

    /// Detailed format capability, including disabled and unknown states.
    #[must_use]
    pub fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities> {
        self.formats.format_capability(format)
    }

    /// Detailed codec capability, including disabled and unknown states.
    #[must_use]
    pub fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        self.codecs.codec_capability(filter)
    }
}

impl Default for ProviderSet<BuiltinFormatProviders, BuiltinCodecProviders> {
    fn default() -> Self {
        Self::builtins()
    }
}

fn unknown_probe_variant(provider: &'static str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Protocol)
        .with_format(provider)
        .with_context("provider returned an unknown probe result variant")
}
fn validate_encoded_frame(encoded: Vec<u8>, limits: Limits) -> Result<Vec<u8>, ArchiveError> {
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| encoded.len() > maximum)
    {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_context("codec provider frame exceeds the configured in-flight byte limit"));
    }
    Ok(encoded)
}

fn unknown_format(format: FormatId) -> ArchiveError {
    ArchiveError::new(ErrorKind::Unsupported)
        .with_format(format_name(format))
        .with_context("no registered format provider recognizes the identifier")
}

fn unknown_codec(filter: FilterId) -> ArchiveError {
    ArchiveError::new(ErrorKind::Unsupported)
        .with_format(filter_name(filter))
        .with_context("no registered codec provider recognizes the identifier")
}

fn disabled_format(format: FormatId, provider: &'static str, operation: &str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Capability)
        .with_format(provider)
        .with_context(format!(
            "registered provider for {} is compiled without {operation} capability",
            format_name(format)
        ))
}

fn disabled_codec(filter: FilterId, provider: &'static str, operation: &str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Capability)
        .with_format(provider)
        .with_context(format!(
            "registered provider for {} is compiled without {operation} capability",
            filter_name(filter)
        ))
}

fn codec_io_error(provider: &'static str, error: &std::io::Error) -> ArchiveError {
    let kind = if error.kind() == std::io::ErrorKind::OutOfMemory {
        ErrorKind::Limit
    } else {
        ErrorKind::Protocol
    };
    ArchiveError::new(kind)
        .with_format(provider)
        .with_context(error.to_string())
}

pub(crate) const fn format_name(format: FormatId) -> &'static str {
    match format {
        FormatId::Tar => "tar",
        FormatId::Cpio => "cpio",
        FormatId::Ar => "ar",
        FormatId::Zip => "zip",
        FormatId::SevenZip => "7z",
        FormatId::Iso9660 => "iso9660",
        FormatId::Cab => "cab",
        FormatId::Xar => "xar",
        _ => "unknown",
    }
}

pub(crate) const fn filter_name(filter: FilterId) -> &'static str {
    match filter {
        FilterId::Gzip => "gzip",
        FilterId::Bzip2 => "bzip2",
        FilterId::Zstd => "zstd",
        FilterId::Xz => "xz",
        FilterId::Lz4 => "lz4",
        _ => "unknown",
    }
}
