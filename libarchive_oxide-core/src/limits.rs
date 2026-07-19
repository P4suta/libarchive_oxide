// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-format resource budgets.

/// Finite-by-default resource budgets shared by codecs, formats, and adapters.
///
/// A zero value is a real zero-byte limit. Use [`Limits::unlimited`] when a
/// trusted caller intentionally wants to remove the configurable budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    decoded_total: Option<u64>,
    entry_bytes: Option<u64>,
    entries: Option<u64>,
    metadata_bytes: Option<usize>,
    codec_memory: Option<usize>,
    path_bytes: Option<usize>,
    nesting: Option<usize>,
    filter_depth: Option<usize>,
    in_flight_bytes: Option<usize>,
}

impl Limits {
    /// Four gibibytes, used by the safe default output budgets.
    pub const FOUR_GIB: u64 = 4 * 1024 * 1024 * 1024;

    /// Builds the finite safe profile.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            decoded_total: Some(Self::FOUR_GIB),
            entry_bytes: Some(Self::FOUR_GIB),
            entries: Some(1_000_000),
            metadata_bytes: Some(64 * 1024 * 1024),
            codec_memory: Some(64 * 1024 * 1024),
            path_bytes: Some(64 * 1024),
            nesting: Some(64),
            filter_depth: Some(4),
            in_flight_bytes: Some(8 * 1024 * 1024),
        }
    }

    /// Removes configurable budgets. Arithmetic and protocol checks remain active.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            decoded_total: None,
            entry_bytes: None,
            entries: None,
            metadata_bytes: None,
            codec_memory: None,
            path_bytes: None,
            nesting: None,
            filter_depth: None,
            in_flight_bytes: None,
        }
    }

    /// Maximum total number of decoded bytes.
    #[must_use]
    pub const fn decoded_total(&self) -> Option<u64> {
        self.decoded_total
    }

    /// Maximum decoded size of one entry.
    #[must_use]
    pub const fn entry_bytes(&self) -> Option<u64> {
        self.entry_bytes
    }

    /// Maximum number of entries.
    #[must_use]
    pub const fn entries(&self) -> Option<u64> {
        self.entries
    }

    /// Maximum metadata allocation.
    #[must_use]
    pub const fn metadata_bytes(&self) -> Option<usize> {
        self.metadata_bytes
    }

    /// Maximum codec dictionary/workspace allocation.
    #[must_use]
    pub const fn codec_memory(&self) -> Option<usize> {
        self.codec_memory
    }

    /// Maximum encoded path length.
    #[must_use]
    pub const fn path_bytes(&self) -> Option<usize> {
        self.path_bytes
    }

    /// Maximum directory/container nesting.
    #[must_use]
    pub const fn nesting(&self) -> Option<usize> {
        self.nesting
    }

    /// Maximum number of nested outer filters.
    #[must_use]
    pub const fn filter_depth(&self) -> Option<usize> {
        self.filter_depth
    }

    /// Maximum bytes buffered between pipeline stages.
    #[must_use]
    pub const fn in_flight_bytes(&self) -> Option<usize> {
        self.in_flight_bytes
    }

    /// Replaces the decoded-total budget.
    #[must_use]
    pub const fn with_decoded_total(mut self, value: Option<u64>) -> Self {
        self.decoded_total = value;
        self
    }

    /// Replaces the per-entry budget.
    #[must_use]
    pub const fn with_entry_bytes(mut self, value: Option<u64>) -> Self {
        self.entry_bytes = value;
        self
    }

    /// Replaces the entry-count budget.
    #[must_use]
    pub const fn with_entries(mut self, value: Option<u64>) -> Self {
        self.entries = value;
        self
    }

    /// Replaces the metadata-allocation budget.
    #[must_use]
    pub const fn with_metadata_bytes(mut self, value: Option<usize>) -> Self {
        self.metadata_bytes = value;
        self
    }

    /// Replaces the codec dictionary/workspace budget.
    #[must_use]
    pub const fn with_codec_memory(mut self, value: Option<usize>) -> Self {
        self.codec_memory = value;
        self
    }

    /// Replaces the archive-native path-length budget.
    #[must_use]
    pub const fn with_path_bytes(mut self, value: Option<usize>) -> Self {
        self.path_bytes = value;
        self
    }

    /// Replaces the directory/container nesting budget.
    #[must_use]
    pub const fn with_nesting(mut self, value: Option<usize>) -> Self {
        self.nesting = value;
        self
    }

    /// Replaces the outer-filter depth budget.
    #[must_use]
    pub const fn with_filter_depth(mut self, value: Option<usize>) -> Self {
        self.filter_depth = value;
        self
    }

    /// Replaces the in-flight pipeline-buffer budget.
    #[must_use]
    pub const fn with_in_flight_bytes(mut self, value: Option<usize>) -> Self {
        self.in_flight_bytes = value;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::safe()
    }
}
