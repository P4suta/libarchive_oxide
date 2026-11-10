// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared archive-opening options and password callbacks.

use std::fmt;
use std::io;
use std::sync::Arc;

use libarchive_oxide_core::{ArchivePath, FilterId, FormatId, Limits};

use crate::SecretBytes;
use crate::range_source::{SourceLimits, VolumeSet};

/// Why an archive reader is requesting password candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordPurpose {
    /// Decrypt an archive header or index before entries can be listed.
    Header,
    /// Decrypt one entry payload.
    Entry,
}

/// Context supplied to a [`PasswordProvider`].
#[derive(Debug, Clone, Copy)]
pub struct PasswordRequest<'a> {
    format: FormatId,
    entry: Option<&'a ArchivePath>,
    purpose: PasswordPurpose,
}

impl<'a> PasswordRequest<'a> {
    pub(crate) const fn new(
        format: FormatId,
        entry: Option<&'a ArchivePath>,
        purpose: PasswordPurpose,
    ) -> Self {
        Self {
            format,
            entry,
            purpose,
        }
    }

    /// Archive format requesting a password.
    #[must_use]
    pub const fn format(self) -> FormatId {
        self.format
    }

    /// Entry path for a payload request, if one is known.
    #[must_use]
    pub const fn entry(self) -> Option<&'a ArchivePath> {
        self.entry
    }

    /// Header or entry-payload request.
    #[must_use]
    pub const fn purpose(self) -> PasswordPurpose {
        self.purpose
    }
}

/// Application-owned source of zeroizing password candidates.
///
/// Candidate order is significant.
/// Implementations may prompt, consult a key store, or return a fixed list.
/// Providers must not log the request result.
pub trait PasswordProvider: Send + Sync {
    /// Returns ordered candidates for one encrypted archive component.
    fn candidates(&self, request: PasswordRequest<'_>) -> io::Result<Vec<SecretBytes>>;
}

/// A fixed, reusable list implementing [`PasswordProvider`].
#[derive(Clone, Default)]
pub struct PasswordCandidates {
    candidates: Vec<SecretBytes>,
}

impl PasswordCandidates {
    /// Stores candidates in the order in which they should be attempted.
    #[must_use]
    pub fn new(candidates: impl IntoIterator<Item = SecretBytes>) -> Self {
        Self {
            candidates: candidates.into_iter().collect(),
        }
    }

    /// Number of stored candidates.
    /// Secret values are never exposed.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether this provider contains no candidates.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

impl fmt::Debug for PasswordCandidates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordCandidates")
            .field("count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

impl PasswordProvider for PasswordCandidates {
    fn candidates(&self, _request: PasswordRequest<'_>) -> io::Result<Vec<SecretBytes>> {
        Ok(self.candidates.clone())
    }
}

/// Options shared by synchronous, async, Tokio, range, and volume readers.
#[derive(Clone)]
pub struct OpenOptions {
    format: Option<FormatId>,
    filter: Option<FilterId>,
    limits: Limits,
    source_limits: SourceLimits,
    password_provider: Option<Arc<dyn PasswordProvider>>,
    maximum_password_candidates: usize,
    volumes: Option<Arc<VolumeSet>>,
    discover_adjacent_volumes: bool,
}

impl OpenOptions {
    /// Creates finite, safe defaults with automatic format detection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            format: None,
            filter: None,
            limits: Limits::safe(),
            source_limits: SourceLimits::safe(),
            password_provider: None,
            maximum_password_candidates: 16,
            volumes: None,
            discover_adjacent_volumes: false,
        }
    }

    /// Selects an explicit archive format, or `None` for detection.
    #[must_use]
    pub const fn with_format(mut self, format: Option<FormatId>) -> Self {
        self.format = format;
        self
    }

    /// Selects an explicit outer filter, or `None` for signature detection.
    ///
    /// This is required for signatureless filters such as LZMA-alone and Base64.
    /// Remaining nested filter layers are still auto-detected within the configured filter-depth limit.
    #[must_use]
    pub const fn with_filter(mut self, filter: Option<FilterId>) -> Self {
        self.filter = filter;
        self
    }

    /// Replaces parser, decoder, and output limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces encoded source and multi-volume limits.
    #[must_use]
    pub const fn with_source_limits(mut self, limits: SourceLimits) -> Self {
        self.source_limits = limits;
        self
    }

    /// Installs an application-owned password provider.
    #[must_use]
    pub fn with_password_provider(mut self, provider: Arc<dyn PasswordProvider>) -> Self {
        self.password_provider = Some(provider);
        self
    }

    /// Limits candidates returned by a provider for any one request.
    #[must_use]
    pub const fn with_maximum_password_candidates(mut self, maximum: usize) -> Self {
        self.maximum_password_candidates = maximum;
        self
    }

    /// Supplies a caller-owned, bounded multi-volume source set.
    #[must_use]
    pub fn with_volumes(mut self, volumes: Arc<VolumeSet>) -> Self {
        self.source_limits = volumes.limits();
        self.volumes = Some(volumes);
        self
    }

    /// Allows bounded adjacent-volume discovery for path-based open operations.
    ///
    /// Readers opened from handles, streams, or ranges never use this flag.
    #[must_use]
    pub const fn with_adjacent_volume_discovery(mut self, enabled: bool) -> Self {
        self.discover_adjacent_volumes = enabled;
        self
    }

    /// Explicit format, or `None` for detection.
    #[must_use]
    pub const fn format(&self) -> Option<FormatId> {
        self.format
    }

    /// Explicit outer filter, or `None` for signature detection.
    #[must_use]
    pub const fn filter(&self) -> Option<FilterId> {
        self.filter
    }

    /// Parser, decoder, and output limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Encoded source and multi-volume limits.
    #[must_use]
    pub const fn source_limits(&self) -> SourceLimits {
        self.source_limits
    }

    pub(crate) fn without_volumes(&self) -> Self {
        let mut options = self.clone();
        options.volumes = None;
        options
    }

    /// Maximum candidates accepted from one password-provider request.
    #[must_use]
    pub const fn maximum_password_candidates(&self) -> usize {
        self.maximum_password_candidates
    }

    /// Caller-owned volume set, when supplied.
    #[must_use]
    pub fn volumes(&self) -> Option<&Arc<VolumeSet>> {
        self.volumes.as_ref()
    }

    /// Whether path-based adjacent-volume discovery was explicitly enabled.
    #[must_use]
    pub const fn adjacent_volume_discovery(&self) -> bool {
        self.discover_adjacent_volumes
    }

    pub(crate) const fn has_password_provider(&self) -> bool {
        self.password_provider.is_some()
    }

    pub(crate) fn password_candidates(
        &self,
        request: PasswordRequest<'_>,
    ) -> io::Result<Vec<SecretBytes>> {
        let Some(provider) = &self.password_provider else {
            return Ok(Vec::new());
        };
        let candidates = provider.candidates(request)?;
        if candidates.len() > self.maximum_password_candidates {
            return Err(io::Error::other(format!(
                "password provider returned {} candidates; limit is {}",
                candidates.len(),
                self.maximum_password_candidates
            )));
        }
        let bytes = candidates.iter().try_fold(0_usize, |total, candidate| {
            total
                .checked_add(candidate.len())
                .ok_or_else(|| io::Error::other("password candidate byte accounting overflow"))
        })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| bytes > maximum)
        {
            return Err(io::Error::other(
                "password candidates exceed configured metadata limit",
            ));
        }
        Ok(candidates)
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OpenOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenOptions")
            .field("format", &self.format)
            .field("filter", &self.filter)
            .field("limits", &self.limits)
            .field("source_limits", &self.source_limits)
            .field("password_provider", &self.password_provider.is_some())
            .field(
                "maximum_password_candidates",
                &self.maximum_password_candidates,
            )
            .field("volumes", &self.volumes.is_some())
            .field("discover_adjacent_volumes", &self.discover_adjacent_volumes)
            .finish()
    }
}
