// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated extraction policy and typed application outcomes.

use libarchive_oxide_core::ArchivePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestoreCapabilities(u8);

impl RestoreCapabilities {
    const OVERWRITE: u8 = 1 << 0;
    const SYMLINKS: u8 = 1 << 1;
    const HARDLINKS: u8 = 1 << 2;
    const SPECIAL_FILES: u8 = 1 << 3;

    const fn none() -> Self {
        Self(0)
    }

    const fn with(mut self, capability: u8, enabled: bool) -> Self {
        if enabled {
            self.0 |= capability;
        } else {
            self.0 &= !capability;
        }
        self
    }

    const fn contains(self, capability: u8) -> bool {
        self.0 & capability != 0
    }
}

/// High-level extraction policy.
///
/// This is the only public extraction configuration. A [`crate::ExtractionPlan`]
/// captures its decisions before any filesystem adapter is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    capabilities: RestoreCapabilities,
}

impl Policy {
    /// Conservative policy.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            capabilities: RestoreCapabilities::none(),
        }
    }

    /// Restore-oriented profile.
    ///
    /// High-risk capabilities remain disabled until their builder is called.
    #[must_use]
    pub const fn restore() -> Self {
        Self::safe()
    }

    /// Enables replacing existing regular files.
    #[must_use]
    pub const fn allow_overwrite(mut self, allow: bool) -> Self {
        self.capabilities = self
            .capabilities
            .with(RestoreCapabilities::OVERWRITE, allow);
        self
    }

    /// Enables symbolic-link restoration.
    #[must_use]
    pub const fn allow_symlinks(mut self, allow: bool) -> Self {
        self.capabilities = self.capabilities.with(RestoreCapabilities::SYMLINKS, allow);
        self
    }

    /// Enables links to files created earlier in the same apply session.
    #[must_use]
    pub const fn allow_hardlinks(mut self, allow: bool) -> Self {
        self.capabilities = self
            .capabilities
            .with(RestoreCapabilities::HARDLINKS, allow);
        self
    }

    /// Enables platform-supported special-file restoration.
    #[must_use]
    pub const fn allow_special_files(mut self, allow: bool) -> Self {
        self.capabilities = self
            .capabilities
            .with(RestoreCapabilities::SPECIAL_FILES, allow);
        self
    }

    /// Whether existing regular files may be atomically replaced.
    #[must_use]
    pub const fn overwrite(self) -> bool {
        self.capabilities.contains(RestoreCapabilities::OVERWRITE)
    }

    /// Whether symbolic-link restoration is enabled.
    #[must_use]
    pub const fn symlinks(self) -> bool {
        self.capabilities.contains(RestoreCapabilities::SYMLINKS)
    }

    /// Whether hard-link restoration is enabled.
    #[must_use]
    pub const fn hardlinks(self) -> bool {
        self.capabilities.contains(RestoreCapabilities::HARDLINKS)
    }

    /// Whether special-file restoration is enabled.
    #[must_use]
    pub const fn special_files(self) -> bool {
        self.capabilities
            .contains(RestoreCapabilities::SPECIAL_FILES)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::safe()
    }
}

/// Why one entry was not materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The archive path was absolute, traversing, reserved, or unrepresentable.
    UnsafePath,
    /// Another archive entry already claimed the same host filesystem identity.
    DestinationCollision,
    /// A destination object existed before this extraction session.
    DestinationExists,
    /// Safe policy forbids this entry kind.
    EntryKind,
    /// A link target was absent, unsafe, or not created earlier in this session.
    UnsafeLinkTarget,
    /// The entry refers to data outside the archive (for example a thin-ar member).
    ExternalReference,
    /// The requested restore capability is not implemented on this platform.
    UnsupportedRestore,
    /// The filesystem adapter reported an entry-level operating-system failure.
    FilesystemError,
}

/// Materialization result for one archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryOutcomeKind {
    /// A regular file was atomically committed.
    File,
    /// A directory was created.
    Directory,
    /// A symbolic link was created by an explicitly enabled restore policy.
    Symlink,
    /// A hard link to an earlier session-local file was created.
    Hardlink,
    /// A FIFO, socket inode, or device was created by an explicitly enabled policy.
    Special,
    /// Policy rejected the entry.
    Rejected(RejectionReason),
    /// A structural archive entry required no filesystem object.
    Skipped,
}

/// Per-entry extraction result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryOutcome {
    path: ArchivePath,
    outcome: EntryOutcomeKind,
}

impl EntryOutcome {
    /// Archive-native entry path.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Materialization result.
    #[must_use]
    pub const fn outcome(&self) -> &EntryOutcomeKind {
        &self.outcome
    }

    pub(crate) const fn new(path: ArchivePath, outcome: EntryOutcomeKind) -> Self {
        Self { path, outcome }
    }
}

/// Complete extraction report. Rejections are never silently converted to success.
#[derive(Debug, Default)]
pub struct ExtractionReport {
    outcomes: Vec<EntryOutcome>,
}

impl ExtractionReport {
    /// Per-entry results in archive order.
    #[must_use]
    pub fn outcomes(&self) -> &[EntryOutcome] {
        &self.outcomes
    }

    /// Whether policy rejected at least one entry.
    #[must_use]
    pub fn has_rejections(&self) -> bool {
        self.outcomes
            .iter()
            .any(|item| matches!(item.outcome, EntryOutcomeKind::Rejected(_)))
    }

    pub(crate) fn push(&mut self, outcome: EntryOutcome) {
        self.outcomes.push(outcome);
    }
}
