// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Injectable archive-payload codec boundary.
//!
//! Container parsers describe an inner payload without depending on a codec implementation crate.
//! The flagship facade can inject a Safe-Rust decoder,
//! while minimal and downstream builds retain metadata inspection and typed unsupported errors without acquiring codec dependencies.

use core::panic::RefUnwindSafe;

use crate::{ArchiveError, Codec, CodecStep, EndOfInput, ErrorKind, Limits};

/// Stable inner-payload algorithm family requested by a container parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadCodecAlgorithm {
    /// RAR 3.x/4.x LZ77/Huffman payload framing.
    Rar3,
    /// RAR5 LZ77/Huffman payload framing.
    Rar5,
}

/// Bounded payload description passed from a container to a codec provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PayloadCodecRequest {
    algorithm: PayloadCodecAlgorithm,
    method: u64,
    version: u64,
    packed_size: u64,
    unpacked_size: u64,
    dictionary_size: u64,
}

impl PayloadCodecRequest {
    pub(crate) const fn new(
        algorithm: PayloadCodecAlgorithm,
        method: u64,
        version: u64,
        packed_size: u64,
        unpacked_size: u64,
        dictionary_size: u64,
    ) -> Self {
        Self {
            algorithm,
            method,
            version,
            packed_size,
            unpacked_size,
            dictionary_size,
        }
    }

    /// Requested algorithm family.
    #[must_use]
    pub const fn algorithm(self) -> PayloadCodecAlgorithm {
        self.algorithm
    }

    /// Container-native compression method identifier.
    #[must_use]
    pub const fn method(self) -> u64 {
        self.method
    }

    /// Container-native decoder generation/version.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Exact number of encoded bytes belonging to this payload.
    #[must_use]
    pub const fn packed_size(self) -> u64 {
        self.packed_size
    }

    /// Exact expected decoded byte count.
    #[must_use]
    pub const fn unpacked_size(self) -> u64 {
        self.unpacked_size
    }

    /// Required decoder dictionary/window bytes.
    #[must_use]
    pub const fn dictionary_size(self) -> u64 {
        self.dictionary_size
    }
}

/// Supplies optional inner payload codecs without reversing crate dependencies.
pub trait PayloadCodecProvider: Send + Sync + RefUnwindSafe {
    /// Concrete decoder state returned by this provider.
    type Decoder: Codec + Send + Sync + RefUnwindSafe;

    /// Whether this provider can supply any payload decoder.
    ///
    /// The default is appropriate for real providers.
    /// The built-in empty provider overrides it so containers preserve the more specific "provider required" diagnostic.
    fn available(&self) -> bool {
        true
    }

    /// Constructs a fresh decoder for `request`.
    ///
    /// `Ok(None)` means this provider does not implement the requested method;
    /// the container converts that absence into a format-specific typed error.
    fn decoder(
        &self,
        request: PayloadCodecRequest,
        limits: Limits,
    ) -> Result<Option<Self::Decoder>, ArchiveError>;

    /// Reconfigures a completed decoder for a stateful continuation member.
    ///
    /// The concrete decoder is moved across this boundary, so providers can retain algorithm state without allocation, type erasure, or a reverse dependency from the container crate.
    /// The default rejects continuation;
    /// `Ok(None)` means the algorithm/state pair is not supported.
    fn continue_decoder(
        &self,
        _decoder: Self::Decoder,
        _request: PayloadCodecRequest,
        _limits: Limits,
    ) -> Result<Option<Self::Decoder>, ArchiveError> {
        Ok(None)
    }
}

/// Empty provider used by format-only builds and direct core consumers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoPayloadCodecProvider;

/// Unreachable decoder type for [`NoPayloadCodecProvider`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoPayloadCodec;

impl Codec for NoPayloadCodec {
    fn process(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
        _end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_context("empty payload provider created a decoder"))
    }
}

impl PayloadCodecProvider for NoPayloadCodecProvider {
    type Decoder = NoPayloadCodec;

    fn available(&self) -> bool {
        false
    }

    fn decoder(
        &self,
        _request: PayloadCodecRequest,
        _limits: Limits,
    ) -> Result<Option<Self::Decoder>, ArchiveError> {
        Ok(None)
    }
}
