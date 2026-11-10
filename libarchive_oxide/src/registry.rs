// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Statically typed random-access and multi-volume provider contracts.

use std::sync::Arc;

use libarchive_oxide_core::{ArchiveError, ErrorKind, FormatId, Limits};

use crate::provider::FormatCapabilities;
use crate::range_source::VolumeSet;
use crate::stream::{Error as StreamError, ReaderEvent};

/// Event decoder returned by a random-access format provider.
pub trait RandomAccessArchiveDecoder: Send {
    /// Produces the next archive event.
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError>;

    /// Skips the currently open entry payload.
    fn skip_entry(&mut self) -> Result<(), StreamError>;
}

/// Statically typed seek or multi-volume format provider.
///
/// The provider receives a bounded [`VolumeSet`], not a `Read + Seek` value, so it can request additional immutable volumes without owning naming, network,
/// or filesystem policy.
pub trait RandomAccessFormatProvider: Send + Sync {
    /// Concrete event decoder created by this provider.
    type Decoder: RandomAccessArchiveDecoder;

    /// Stable archive format identifier served by this provider.
    fn format(&self) -> FormatId;

    /// Static diagnostic name used in errors and capability reports.
    fn name(&self) -> &'static str;

    /// Typed capability description. Read access must be seek-native.
    fn capabilities(&self) -> FormatCapabilities;

    /// Probes the primary/additional volumes without consuming source state.
    fn probe(&self, source: &VolumeSet, limits: Limits) -> Result<bool, StreamError>;

    /// Creates a fresh event decoder over the bounded volume set.
    fn open(&self, source: Arc<VolumeSet>, limits: Limits) -> Result<Self::Decoder, StreamError>;

    /// Creates an event decoder using the common opening option model.
    ///
    /// Providers that support encrypted headers or payloads override this method and request candidates from `options`.
    /// The default rejects a configured password provider so credentials are never silently ignored.
    fn open_with_options(
        &self,
        source: Arc<VolumeSet>,
        options: &crate::OpenOptions,
    ) -> Result<Self::Decoder, StreamError> {
        if options.has_password_provider() {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_format(self.name())
                .with_context("random-access format provider does not accept passwords")
                .into());
        }
        self.open(source, options.limits())
    }
}
