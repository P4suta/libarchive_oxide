// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Object-safe incremental provider registration.
//!
//! A [`Registry`] owns boxed format and codec providers and exposes them through
//! the same bounded pipeline contract as built-in providers. Registration
//! rejects duplicate identifiers before any archive I/O begins.

use std::fmt;
use std::io::Read;
use std::sync::Arc;

use libarchive_oxide_core::{
    ArchiveDecoder, ArchiveEncoder, ArchiveError, ArchiveMetadata, Codec, EncodeCommand,
    EncodeStep, ErrorKind, FilterId, FormatId, Limits, ProbeResult,
};

use crate::provider::{
    CodecCapabilities, CodecProvider, FormatCapabilities, FormatProvider, ProviderArchiveEncoder,
    ProviderCapability, ProviderSet, StaticCodecProviders, StaticFormatProviders,
};
use crate::range_source::VolumeSet;
use crate::stream::{ArchiveReader, Error as StreamError, Pipeline, ReaderEvent};

/// Object-safe archive-format provider used by [`Registry`].
pub trait IncrementalFormatProvider: Send + Sync {
    /// Stable archive format identifier served by this provider.
    fn format(&self) -> FormatId;
    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;
    /// Incrementally probes an immutable prefix.
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()>;
    /// Decode/encode capabilities in this build.
    fn capabilities(&self) -> FormatCapabilities;
    /// Creates fresh boxed decoder state.
    fn decoder(&self, limits: Limits) -> Result<Box<dyn ArchiveDecoder + Send>, ArchiveError>;
    /// Creates fresh boxed encoder state.
    fn encoder(
        &self,
        limits: Limits,
    ) -> Result<Box<dyn ProviderArchiveEncoder + Send>, ArchiveError>;
}

impl<P> IncrementalFormatProvider for P
where
    P: FormatProvider + Send + Sync,
    P::Decoder: Send + 'static,
    P::Encoder: Send + 'static,
{
    fn format(&self) -> FormatId {
        FormatProvider::format(self)
    }

    fn name(&self) -> &'static str {
        FormatProvider::name(self)
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        FormatProvider::probe(self, prefix)
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatProvider::capabilities(self)
    }

    fn decoder(&self, limits: Limits) -> Result<Box<dyn ArchiveDecoder + Send>, ArchiveError> {
        FormatProvider::decoder(self, limits)
            .map(|decoder| Box::new(decoder) as Box<dyn ArchiveDecoder + Send>)
    }

    fn encoder(
        &self,
        limits: Limits,
    ) -> Result<Box<dyn ProviderArchiveEncoder + Send>, ArchiveError> {
        FormatProvider::encoder(self, limits)
            .map(|encoder| Box::new(encoder) as Box<dyn ProviderArchiveEncoder + Send>)
    }
}

/// Object-safe outer-codec provider used by [`Registry`].
pub trait IncrementalCodecProvider: Send + Sync {
    /// Stable outer-filter identifier served by this provider.
    fn filter(&self) -> FilterId;
    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;
    /// Incrementally probes an immutable prefix.
    fn probe(&self, prefix: &[u8]) -> ProbeResult<()>;
    /// Decode/encode capabilities in this build.
    fn capabilities(&self) -> CodecCapabilities;
    /// Creates fresh boxed decoder state.
    fn decoder(&self, limits: Limits) -> Result<Box<dyn Codec + Send>, ArchiveError>;
    /// Encodes one bounded frame/member.
    fn encode_frame(&self, input: &[u8], limits: Limits) -> Result<Vec<u8>, ArchiveError>;
}

impl<P> IncrementalCodecProvider for P
where
    P: CodecProvider + Send + Sync,
    P::Decoder: Send + 'static,
{
    fn filter(&self) -> FilterId {
        CodecProvider::filter(self)
    }

    fn name(&self) -> &'static str {
        CodecProvider::name(self)
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        CodecProvider::probe(self, prefix)
    }

    fn capabilities(&self) -> CodecCapabilities {
        CodecProvider::capabilities(self)
    }

    fn decoder(&self, limits: Limits) -> Result<Box<dyn Codec + Send>, ArchiveError> {
        CodecProvider::decoder(self, limits)
            .map(|decoder| Box::new(decoder) as Box<dyn Codec + Send>)
    }

    fn encode_frame(&self, input: &[u8], limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        CodecProvider::encode_frame(self, input, limits)
    }
}

/// Object-safe event decoder returned by a random-access format provider.
pub trait RandomAccessArchiveDecoder: Send {
    /// Produces the next archive event.
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError>;

    /// Skips the currently open entry payload.
    fn skip_entry(&mut self) -> Result<(), StreamError>;
}

/// Object-safe seek or multi-volume format provider.
///
/// The provider receives a bounded [`VolumeSet`], not a `Read + Seek` value, so
/// it can request additional immutable volumes without owning naming, network,
/// or filesystem policy.
pub trait RandomAccessFormatProvider: Send + Sync {
    /// Stable archive format identifier served by this provider.
    fn format(&self) -> FormatId;

    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;

    /// Typed capability description. Read access must be seek-native.
    fn capabilities(&self) -> FormatCapabilities;

    /// Probes the primary/additional volumes without consuming source state.
    fn probe(&self, source: &VolumeSet, limits: Limits) -> Result<bool, StreamError>;

    /// Creates a fresh event decoder over the bounded volume set.
    fn open(
        &self,
        source: Arc<VolumeSet>,
        limits: Limits,
    ) -> Result<Box<dyn RandomAccessArchiveDecoder>, StreamError>;
}

/// Fallible builder for an immutable [`Registry`].
#[derive(Default)]
pub struct RegistryBuilder {
    formats: Vec<Box<dyn IncrementalFormatProvider>>,
    random_access_formats: Vec<Box<dyn RandomAccessFormatProvider>>,
    codecs: Vec<Box<dyn IncrementalCodecProvider>>,
}

impl fmt::Debug for RegistryBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryBuilder")
            .field("formats", &self.formats.len())
            .field("random_access_formats", &self.random_access_formats.len())
            .field("codecs", &self.codecs.len())
            .finish()
    }
}

impl RegistryBuilder {
    /// Creates an empty registry builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            formats: Vec::new(),
            random_access_formats: Vec::new(),
            codecs: Vec::new(),
        }
    }

    /// Registers an object-safe format provider.
    pub fn register_format(
        &mut self,
        provider: Box<dyn IncrementalFormatProvider>,
    ) -> Result<&mut Self, ArchiveError> {
        if self.format_registered(provider.format()) {
            return Err(duplicate_provider("format", provider.name()));
        }
        self.formats.push(provider);
        Ok(self)
    }

    /// Registers an object-safe random-access or multi-volume format provider.
    pub fn register_random_access_format(
        &mut self,
        provider: Box<dyn RandomAccessFormatProvider>,
    ) -> Result<&mut Self, ArchiveError> {
        if self.format_registered(provider.format()) {
            return Err(duplicate_provider("format", provider.name()));
        }
        let capabilities = provider.capabilities();
        if !capabilities.can_decode()
            || !capabilities.requires_seek(libarchive_oxide_core::Direction::Read)
        {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format(provider.name())
                .with_context(
                    "random-access format provider must advertise seek-native read capability",
                ));
        }
        self.random_access_formats.push(provider);
        Ok(self)
    }

    /// Registers an object-safe codec provider.
    pub fn register_codec(
        &mut self,
        provider: Box<dyn IncrementalCodecProvider>,
    ) -> Result<&mut Self, ArchiveError> {
        if self
            .codecs
            .iter()
            .any(|registered| registered.filter() == provider.filter())
        {
            return Err(duplicate_provider("codec", provider.name()));
        }
        self.codecs.push(provider);
        Ok(self)
    }

    /// Freezes the provider lists into a cheaply cloneable registry.
    #[must_use]
    pub fn build(self) -> Registry {
        Registry {
            formats: Arc::from(self.formats),
            random_access_formats: Arc::from(self.random_access_formats),
            codecs: Arc::from(self.codecs),
        }
    }

    fn format_registered(&self, format: FormatId) -> bool {
        self.formats
            .iter()
            .any(|registered| registered.format() == format)
            || self
                .random_access_formats
                .iter()
                .any(|registered| registered.format() == format)
    }
}

/// Immutable object-safe provider registry.
#[derive(Clone, Default)]
pub struct Registry {
    formats: Arc<[Box<dyn IncrementalFormatProvider>]>,
    random_access_formats: Arc<[Box<dyn RandomAccessFormatProvider>]>,
    codecs: Arc<[Box<dyn IncrementalCodecProvider>]>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("formats", &self.formats.len())
            .field("random_access_formats", &self.random_access_formats.len())
            .field("codecs", &self.codecs.len())
            .finish()
    }
}

impl Registry {
    /// Creates a builder for downstream or application-selected providers.
    #[must_use]
    pub const fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }

    /// Number of registered format providers.
    #[must_use]
    pub fn format_count(&self) -> usize {
        self.formats.len()
    }

    /// Number of registered codec providers.
    #[must_use]
    pub fn codec_count(&self) -> usize {
        self.codecs.len()
    }

    /// Number of registered random-access format providers.
    #[must_use]
    pub fn random_access_format_count(&self) -> usize {
        self.random_access_formats.len()
    }

    /// Adapts this registry to the common reader/writer pipeline.
    #[doc(hidden)]
    #[must_use]
    pub fn providers(&self) -> ProviderSet<RegistryFormats, RegistryCodecs> {
        ProviderSet::from_chains(
            RegistryFormats(Arc::clone(&self.formats)),
            RegistryCodecs(Arc::clone(&self.codecs)),
        )
    }

    /// Creates a bounded caller-driven pipeline from this registry.
    #[must_use]
    pub fn pipeline(&self, limits: Limits) -> Pipeline<RegistryFormats, RegistryCodecs> {
        Pipeline::with_providers(limits, self.providers())
    }

    /// Creates a streaming reader from this registry.
    #[must_use]
    pub fn reader<R: Read>(
        &self,
        reader: R,
        limits: Limits,
    ) -> ArchiveReader<R, RegistryFormats, RegistryCodecs> {
        ArchiveReader::with_providers(reader, limits, self.providers())
    }

    /// Reports a registered format's typed capability state.
    #[must_use]
    pub fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities> {
        let sequential = RegistryFormats(Arc::clone(&self.formats)).format_capability(format);
        if !matches!(sequential, ProviderCapability::Unknown) {
            return sequential;
        }
        let Some(provider) = self
            .random_access_formats
            .iter()
            .find(|provider| provider.format() == format)
        else {
            return ProviderCapability::Unknown;
        };
        let capabilities = provider.capabilities();
        if capabilities.directions().is_empty() {
            ProviderCapability::Disabled
        } else {
            ProviderCapability::Available(capabilities)
        }
    }

    /// Reports a registered codec's typed capability state.
    #[must_use]
    pub fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        RegistryCodecs(Arc::clone(&self.codecs)).codec_capability(filter)
    }

    /// Detects one registered random-access format.
    ///
    /// Multiple matches fail closed instead of depending on registration order.
    pub fn detect_random_access(
        &self,
        source: &VolumeSet,
        limits: Limits,
    ) -> Result<Option<FormatId>, StreamError> {
        let mut matched = None;
        for provider in self.random_access_formats.iter() {
            if !provider.probe(source, limits)? {
                continue;
            }
            if matched.replace(provider.format()).is_some() {
                return Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context("multiple random-access format providers matched the source")
                    .into());
            }
        }
        Ok(matched)
    }

    /// Opens an explicit registered random-access format over bounded volumes.
    pub fn open_random_access(
        &self,
        format: FormatId,
        source: Arc<VolumeSet>,
        limits: Limits,
    ) -> Result<Box<dyn RandomAccessArchiveDecoder>, StreamError> {
        let provider = self
            .random_access_formats
            .iter()
            .find(|provider| provider.format() == format)
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_context(format!("no random-access provider for format {format:?}"))
            })?;
        let capabilities = provider.capabilities();
        if !capabilities.can_decode()
            || !capabilities.requires_seek(libarchive_oxide_core::Direction::Read)
        {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format(provider.name())
                .with_context("registered random-access provider cannot decode")
                .into());
        }
        provider.open(source, limits)
    }
}

/// Format-provider half of an immutable [`Registry`].
#[doc(hidden)]
#[derive(Clone)]
pub struct RegistryFormats(Arc<[Box<dyn IncrementalFormatProvider>]>);

impl fmt::Debug for RegistryFormats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RegistryFormats")
            .field(&self.0.len())
            .finish()
    }
}

/// Codec-provider half of an immutable [`Registry`].
#[doc(hidden)]
#[derive(Clone)]
pub struct RegistryCodecs(Arc<[Box<dyn IncrementalCodecProvider>]>);

impl fmt::Debug for RegistryCodecs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RegistryCodecs")
            .field(&self.0.len())
            .finish()
    }
}

/// Boxed archive decoder returned by a registry selection.
#[doc(hidden)]
pub struct BoxedArchiveDecoder(Box<dyn ArchiveDecoder + Send>);

impl fmt::Debug for BoxedArchiveDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoxedArchiveDecoder(..)")
    }
}

impl ArchiveDecoder for BoxedArchiveDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<libarchive_oxide_core::DecodeStep<'a>, ArchiveError> {
        self.0.step(input, output, end)
    }
}

/// Boxed archive encoder returned by a registry selection.
#[doc(hidden)]
pub struct BoxedArchiveEncoder(Box<dyn ProviderArchiveEncoder + Send>);

impl fmt::Debug for BoxedArchiveEncoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoxedArchiveEncoder(..)")
    }
}

impl ArchiveEncoder for BoxedArchiveEncoder {
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        self.0.step(command, output)
    }
}

impl ProviderArchiveEncoder for BoxedArchiveEncoder {
    fn set_archive_metadata(&mut self, metadata: &ArchiveMetadata) -> Result<(), ArchiveError> {
        self.0.set_archive_metadata(metadata)
    }
}

/// Boxed codec returned by a registry selection.
#[doc(hidden)]
pub struct BoxedCodec(Box<dyn Codec + Send>);

impl fmt::Debug for BoxedCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoxedCodec(..)")
    }
}

impl Codec for BoxedCodec {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: libarchive_oxide_core::EndOfInput,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        self.0.process(input, output, end)
    }

    fn poll_process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: libarchive_oxide_core::EndOfInput,
        waker: &core::task::Waker,
    ) -> Result<Option<libarchive_oxide_core::CodecStep>, ArchiveError> {
        self.0.poll_process(input, output, end, waker)
    }
}

impl StaticFormatProviders for RegistryFormats {
    type Selection = usize;
    type Decoder = BoxedArchiveDecoder;
    type Encoder = BoxedArchiveEncoder;

    fn probe_format(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FormatId, Self::Selection)>, ArchiveError> {
        let mut combined = ProbeResult::NoMatch;
        for (index, provider) in self.0.iter().enumerate().rev() {
            let result = validate_probe(provider.probe(prefix), prefix.len(), provider.name())?;
            let current = match result {
                ProbeResult::Match(()) => ProbeResult::Match((provider.format(), index)),
                ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
                ProbeResult::NoMatch => ProbeResult::NoMatch,
                _ => return Err(unknown_probe_variant(provider.name())),
            };
            combined = combine_format_probes(current, combined)?;
        }
        Ok(combined)
    }

    fn format_capability(&self, format: FormatId) -> ProviderCapability<FormatCapabilities> {
        let Some(provider) = self.0.iter().find(|provider| provider.format() == format) else {
            return ProviderCapability::Unknown;
        };
        let capabilities = provider.capabilities();
        if capabilities.directions().is_empty() {
            ProviderCapability::Disabled
        } else {
            ProviderCapability::Available(capabilities)
        }
    }

    fn select_format(&self, format: FormatId) -> Result<Self::Selection, ArchiveError> {
        self.0
            .iter()
            .position(|provider| provider.format() == format)
            .ok_or_else(|| unknown_format(format))
    }

    fn format_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        let provider = self.format_provider(selection)?;
        if !provider.capabilities().can_decode() {
            return Err(disabled_provider("format", provider.name(), "decode"));
        }
        provider.decoder(limits).map(BoxedArchiveDecoder)
    }

    fn format_encoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError> {
        let provider = self.format_provider(selection)?;
        if !provider.capabilities().can_encode() {
            return Err(disabled_provider("format", provider.name(), "encode"));
        }
        provider.encoder(limits).map(BoxedArchiveEncoder)
    }
}

impl RegistryFormats {
    fn format_provider(
        &self,
        selection: usize,
    ) -> Result<&dyn IncrementalFormatProvider, ArchiveError> {
        self.0
            .get(selection)
            .map(Box::as_ref)
            .ok_or_else(invalid_selection)
    }
}

impl StaticCodecProviders for RegistryCodecs {
    type Selection = usize;
    type Decoder = BoxedCodec;

    fn probe_codec(
        &self,
        prefix: &[u8],
    ) -> Result<ProbeResult<(FilterId, Self::Selection)>, ArchiveError> {
        let mut combined = ProbeResult::NoMatch;
        for (index, provider) in self.0.iter().enumerate().rev() {
            let result = validate_probe(provider.probe(prefix), prefix.len(), provider.name())?;
            let current = match result {
                ProbeResult::Match(()) => ProbeResult::Match((provider.filter(), index)),
                ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
                ProbeResult::NoMatch => ProbeResult::NoMatch,
                _ => return Err(unknown_probe_variant(provider.name())),
            };
            combined = combine_codec_probes(current, combined)?;
        }
        Ok(combined)
    }

    fn codec_capability(&self, filter: FilterId) -> ProviderCapability<CodecCapabilities> {
        let Some(provider) = self.0.iter().find(|provider| provider.filter() == filter) else {
            return ProviderCapability::Unknown;
        };
        let capabilities = provider.capabilities();
        if capabilities.directions().is_empty() {
            ProviderCapability::Disabled
        } else {
            ProviderCapability::Available(capabilities)
        }
    }

    fn select_codec(&self, filter: FilterId) -> Result<Self::Selection, ArchiveError> {
        self.0
            .iter()
            .position(|provider| provider.filter() == filter)
            .ok_or_else(|| unknown_codec(filter))
    }

    fn codec_decoder(
        &self,
        selection: Self::Selection,
        limits: Limits,
    ) -> Result<Self::Decoder, ArchiveError> {
        let provider = self.codec_provider(selection)?;
        if !provider.capabilities().can_decode() {
            return Err(disabled_provider("codec", provider.name(), "decode"));
        }
        provider.decoder(limits).map(BoxedCodec)
    }

    fn encode_codec_frame(
        &self,
        selection: Self::Selection,
        input: &[u8],
        limits: Limits,
    ) -> Result<Vec<u8>, ArchiveError> {
        let provider = self.codec_provider(selection)?;
        if !provider.capabilities().can_encode() {
            return Err(disabled_provider("codec", provider.name(), "encode"));
        }
        let encoded = provider.encode_frame(input, limits)?;
        validate_encoded_frame(encoded, limits)
    }
}

impl RegistryCodecs {
    fn codec_provider(
        &self,
        selection: usize,
    ) -> Result<&dyn IncrementalCodecProvider, ArchiveError> {
        self.0
            .get(selection)
            .map(Box::as_ref)
            .ok_or_else(invalid_selection)
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

fn combine_format_probes<S>(
    head: ProbeResult<(FormatId, S)>,
    tail: ProbeResult<(FormatId, S)>,
) -> Result<ProbeResult<(FormatId, S)>, ArchiveError> {
    combine_probes(head, tail, "format")
}

fn combine_codec_probes<S>(
    head: ProbeResult<(FilterId, S)>,
    tail: ProbeResult<(FilterId, S)>,
) -> Result<ProbeResult<(FilterId, S)>, ArchiveError> {
    combine_probes(head, tail, "codec")
}

fn combine_probes<I: PartialEq, S>(
    head: ProbeResult<(I, S)>,
    tail: ProbeResult<(I, S)>,
    kind: &'static str,
) -> Result<ProbeResult<(I, S)>, ArchiveError> {
    match (head, tail) {
        (ProbeResult::Match((head_id, selection)), ProbeResult::Match((tail_id, _))) => {
            if head_id == tail_id {
                Ok(ProbeResult::Match((head_id, selection)))
            } else {
                Err(ArchiveError::new(ErrorKind::Protocol)
                    .with_context(format!("multiple {kind} providers matched the same prefix")))
            }
        },
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
        _ => Err(unknown_probe_variant(kind)),
    }
}

fn validate_encoded_frame(encoded: Vec<u8>, limits: Limits) -> Result<Vec<u8>, ArchiveError> {
    if limits
        .in_flight_bytes()
        .is_some_and(|limit| encoded.len() > limit)
    {
        return Err(ArchiveError::new(ErrorKind::Limit)
            .with_context("encoded codec frame exceeds in-flight byte limit"));
    }
    Ok(encoded)
}

fn duplicate_provider(kind: &'static str, name: &'static str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Protocol)
        .with_format(name)
        .with_context(format!("duplicate {kind} provider identifier"))
}

fn disabled_provider(
    kind: &'static str,
    name: &'static str,
    operation: &'static str,
) -> ArchiveError {
    ArchiveError::new(ErrorKind::Capability)
        .with_format(name)
        .with_context(format!("registered {kind} provider cannot {operation}"))
}

fn unknown_format(format: FormatId) -> ArchiveError {
    ArchiveError::new(ErrorKind::Unsupported)
        .with_context(format!("no registered provider for format {format:?}"))
}

fn unknown_codec(filter: FilterId) -> ArchiveError {
    ArchiveError::new(ErrorKind::Unsupported)
        .with_context(format!("no registered provider for filter {filter:?}"))
}

fn invalid_selection() -> ArchiveError {
    ArchiveError::new(ErrorKind::Protocol).with_context("registry selection is out of bounds")
}

fn unknown_probe_variant(provider: &'static str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Protocol)
        .with_format(provider)
        .with_context("provider returned an unknown probe result")
}
