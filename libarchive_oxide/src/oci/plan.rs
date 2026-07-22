// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit, session-bound plans for applying one OCI image layer.
//!
//! A layer's tar stream mixes ordinary entries with two overlay markers:
//! `.wh.<name>` deletes `<name>` from a lower layer, and `.wh..wh..opq` clears
//! the contents of its parent directory. [`OciLayerPlanner`] interprets those
//! markers, sanitizes every path, maps ownership, and rejects unsafe or
//! conflicting entries, producing an ordered list of [`OciPlanOperation`]s.
//!
//! The resulting [`OciLayerPlan`] is deliberately not serializable: it carries
//! the originating session identity and the expected compressed digest so it
//! can only be applied against the exact layer it was planned from.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Owner};

use super::digest::LayerDigests;
use crate::engine::Policy;
use crate::path::{sanitize, sanitize_archive_path};

/// The whiteout prefix that marks a deletion entry.
const WHITEOUT_PREFIX: &[u8] = b".wh.";
/// The exact basename of an opaque-directory marker.
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";

/// Maps archive ownership onto host ownership during planning.
///
/// Implementations receive the archive [`Owner`] and return the owner that
/// should be materialized. A blanket implementation covers any
/// `Fn(&Owner) -> Owner`, so callers may pass a closure or a table type.
pub trait OwnershipMapper {
    /// Returns the mapped owner for one entry.
    fn map_owner(&self, owner: &Owner) -> Owner;
}

impl<F> OwnershipMapper for F
where
    F: Fn(&Owner) -> Owner,
{
    fn map_owner(&self, owner: &Owner) -> Owner {
        self(owner)
    }
}

/// An [`OwnershipMapper`] that leaves ownership unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityOwnership;

impl OwnershipMapper for IdentityOwnership {
    fn map_owner(&self, owner: &Owner) -> Owner {
        owner.clone()
    }
}

/// A table-driven [`OwnershipMapper`] remapping numeric uids and gids.
///
/// Ids absent from a table pass through unchanged; user and group names are
/// preserved. This models the common OCI case of shifting a container id range
/// into an unprivileged host range.
#[derive(Debug, Clone, Default)]
pub struct OwnershipTable {
    uid: std::collections::BTreeMap<u64, u64>,
    gid: std::collections::BTreeMap<u64, u64>,
}

impl OwnershipTable {
    /// Creates an empty table (an identity mapping until entries are added).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps container uid `from` onto host uid `to`.
    #[must_use]
    pub fn map_uid(mut self, from: u64, to: u64) -> Self {
        self.uid.insert(from, to);
        self
    }

    /// Maps container gid `from` onto host gid `to`.
    #[must_use]
    pub fn map_gid(mut self, from: u64, to: u64) -> Self {
        self.gid.insert(from, to);
        self
    }
}

impl OwnershipMapper for OwnershipTable {
    fn map_owner(&self, owner: &Owner) -> Owner {
        Owner {
            uid: owner.uid.map(|id| self.uid.get(&id).copied().unwrap_or(id)),
            gid: owner.gid.map(|id| self.gid.get(&id).copied().unwrap_or(id)),
            user: owner.user.clone(),
            group: owner.group.clone(),
        }
    }
}

/// Why the planner refused to apply an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OciRejection {
    /// The entry or marker path is unsafe or unrepresentable.
    UnsafePath,
    /// A prior entry in the same layer already claimed this path.
    Duplicate,
    /// A link target is absent, unsafe, or not yet committed in this layer.
    UnsafeLinkTarget,
    /// The entry kind is disabled by policy or unsupported on this platform.
    UnsupportedKind,
    /// The destination is reached through a symbolic link created in this layer.
    SymlinkEscape,
}

impl OciRejection {
    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsafePath => "unsafe or unrepresentable path",
            Self::Duplicate => "duplicate path within the layer",
            Self::UnsafeLinkTarget => "unsafe or uncommitted link target",
            Self::UnsupportedKind => "entry kind disabled by policy or unsupported",
            Self::SymlinkEscape => "destination escapes through a layer symlink",
        }
    }
}

/// A materialization operation carrying its ready-to-apply destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciMaterialize {
    metadata: Box<EntryMetadata>,
    destination: PathBuf,
    link_target: Option<PathBuf>,
    original_owner: Option<Owner>,
}

impl OciMaterialize {
    /// Full entry metadata, with ownership already mapped.
    #[must_use]
    pub fn metadata(&self) -> &EntryMetadata {
        &self.metadata
    }

    /// Normalized relative destination for the entry.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Normalized relative link target for symbolic and hard links.
    #[must_use]
    pub fn link_target(&self) -> Option<&Path> {
        self.link_target.as_deref()
    }

    /// The pre-mapping owner, present only when ownership was remapped.
    #[must_use]
    pub const fn original_owner(&self) -> Option<&Owner> {
        self.original_owner.as_ref()
    }
}

/// A whiteout or opaque removal carrying its ready-to-apply destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRemoval {
    path: ArchivePath,
    destination: PathBuf,
}

impl OciRemoval {
    /// Archive-native path of the marker entry.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Normalized relative destination the removal targets. An empty path
    /// denotes the extraction root.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

/// A refused entry, retained so the caller can audit the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciReject {
    path: ArchivePath,
    reason: OciRejection,
}

impl OciReject {
    /// Archive-native path of the refused entry.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Why the entry was refused.
    #[must_use]
    pub const fn reason(&self) -> OciRejection {
        self.reason
    }
}

/// One planned operation for a single tar entry, in archive order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OciPlanOperation {
    /// Create a file, directory, link, or special entry.
    Materialize(OciMaterialize),
    /// Create an entry whose ownership was remapped from the archive owner.
    MapOwnership(OciMaterialize),
    /// Delete a whiteout target and any subtree it roots.
    Whiteout(OciRemoval),
    /// Clear the contents of an opaque directory in place.
    OpaqueDir(OciRemoval),
    /// Refuse an unsafe or conflicting entry.
    Reject(OciReject),
}

/// A non-serializable, session-bound plan for applying one OCI layer.
#[derive(Debug, Clone)]
pub struct OciLayerPlan {
    pub(crate) session_id: u64,
    pub(crate) expected: LayerDigests,
    pub(crate) policy: Policy,
    pub(crate) operations: Vec<OciPlanOperation>,
}

impl OciLayerPlan {
    /// Expected compressed digest and diffID this plan is bound to.
    #[must_use]
    pub const fn expected(&self) -> LayerDigests {
        self.expected
    }

    /// Planned operations in archive order.
    #[must_use]
    pub fn operations(&self) -> &[OciPlanOperation] {
        &self.operations
    }
}

/// Whether an entry is a structural directory that produces no operation.
///
/// The archive root (`.` or `./`) exists implicitly and is never materialized
/// or rejected; both planning and application skip it identically so their
/// per-entry alignment is preserved.
pub(crate) fn is_structural_skip(metadata: &EntryMetadata) -> bool {
    metadata.kind() == EntryKind::Dir && matches!(metadata.path().as_bytes(), b"." | b"./")
}

/// Splits a raw archive path into its parent bytes and final component bytes.
fn split_last(path: &[u8]) -> (&[u8], &[u8]) {
    // Ignore a single trailing slash so directory markers parse like files.
    let trimmed = path.strip_suffix(b"/").unwrap_or(path);
    match trimmed.iter().rposition(|byte| *byte == b'/') {
        Some(index) => (&trimmed[..index], &trimmed[index + 1..]),
        None => (b"".as_slice(), trimmed),
    }
}

/// Joins a parent path with a child component into raw path bytes.
fn join(parent: &[u8], child: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        child.to_vec()
    } else {
        let mut joined = Vec::with_capacity(parent.len() + 1 + child.len());
        joined.extend_from_slice(parent);
        joined.push(b'/');
        joined.extend_from_slice(child);
        joined
    }
}

/// Interprets the overlay marker, if any, for one entry path.
enum Marker {
    Regular,
    Whiteout(Vec<u8>),
    Opaque(Vec<u8>),
    Unsafe,
}

fn classify(path: &[u8]) -> Marker {
    let (parent, name) = split_last(path);
    if name == OPAQUE_MARKER {
        return Marker::Opaque(parent.to_vec());
    }
    if let Some(target_name) = name.strip_prefix(WHITEOUT_PREFIX) {
        if target_name.is_empty() {
            return Marker::Unsafe;
        }
        return Marker::Whiteout(join(parent, target_name));
    }
    Marker::Regular
}

/// Builds an [`OciLayerPlan`] from the entries of one layer.
pub(crate) struct OciLayerPlanner<'a, M: OwnershipMapper> {
    policy: Policy,
    mapper: &'a M,
    operations: Vec<OciPlanOperation>,
    claimed: BTreeSet<PathBuf>,
    committed_files: BTreeSet<PathBuf>,
    symlinks: BTreeSet<PathBuf>,
}

impl<'a, M: OwnershipMapper> OciLayerPlanner<'a, M> {
    pub(crate) fn new(policy: Policy, mapper: &'a M) -> Self {
        Self {
            policy,
            mapper,
            operations: Vec::new(),
            claimed: BTreeSet::new(),
            committed_files: BTreeSet::new(),
            symlinks: BTreeSet::new(),
        }
    }

    /// Records one tar entry, appending at most one operation.
    pub(crate) fn observe(&mut self, metadata: EntryMetadata) {
        if is_structural_skip(&metadata) {
            return;
        }
        let path = metadata.path().clone();
        let operation = match classify(path.as_bytes()) {
            Marker::Unsafe => reject(path, OciRejection::UnsafePath),
            Marker::Whiteout(target) => self.plan_removal(path, &target, false),
            Marker::Opaque(directory) => self.plan_removal(path, &directory, true),
            Marker::Regular => self.plan_materialize(metadata),
        };
        self.operations.push(operation);
    }

    fn plan_removal(&self, path: ArchivePath, raw: &[u8], opaque: bool) -> OciPlanOperation {
        let destination = if raw.is_empty() {
            // An opaque marker at the archive root clears the whole tree.
            Some(PathBuf::new())
        } else {
            sanitize(raw)
        };
        let Some(destination) = destination else {
            return reject(path, OciRejection::UnsafePath);
        };
        if self.escapes_symlink(&destination) {
            return reject(path, OciRejection::SymlinkEscape);
        }
        let removal = OciRemoval { path, destination };
        if opaque {
            OciPlanOperation::OpaqueDir(removal)
        } else {
            OciPlanOperation::Whiteout(removal)
        }
    }

    fn plan_materialize(&mut self, metadata: EntryMetadata) -> OciPlanOperation {
        let path = metadata.path().clone();
        if metadata.extensions().iter().any(|extension| {
            extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
        }) {
            return reject(path, OciRejection::UnsupportedKind);
        }
        let Some(destination) = sanitize_archive_path(&path) else {
            return reject(path, OciRejection::UnsafePath);
        };
        if self.escapes_symlink(&destination) {
            return reject(path, OciRejection::SymlinkEscape);
        }
        if !self.claimed.insert(destination.clone()) {
            return reject(path, OciRejection::Duplicate);
        }
        let link_target = match self.link_target(&metadata) {
            Ok(target) => target,
            Err(reason) => return reject(path, reason),
        };
        if !self.kind_allowed(&metadata) {
            return reject(path, OciRejection::UnsupportedKind);
        }

        match metadata.kind() {
            EntryKind::File | EntryKind::Hardlink => {
                self.committed_files.insert(destination.clone());
            },
            EntryKind::Symlink => {
                self.symlinks.insert(destination.clone());
            },
            _ => {},
        }

        let original = metadata.owner().clone();
        let mapped = self.mapper.map_owner(&original);
        let remapped = mapped != original;
        let metadata = metadata.into_builder().owner(mapped).build();
        let materialize = OciMaterialize {
            metadata: Box::new(metadata),
            destination,
            link_target,
            original_owner: remapped.then_some(original),
        };
        if remapped {
            OciPlanOperation::MapOwnership(materialize)
        } else {
            OciPlanOperation::Materialize(materialize)
        }
    }

    fn link_target(&self, metadata: &EntryMetadata) -> Result<Option<PathBuf>, OciRejection> {
        match metadata.kind() {
            EntryKind::Symlink => {
                if !self.policy.symlinks() {
                    return Err(OciRejection::UnsupportedKind);
                }
                metadata
                    .link_target()
                    .and_then(sanitize_archive_path)
                    .map(Some)
                    .ok_or(OciRejection::UnsafeLinkTarget)
            },
            EntryKind::Hardlink => {
                if !self.policy.hardlinks() {
                    return Err(OciRejection::UnsupportedKind);
                }
                let target = metadata
                    .link_target()
                    .and_then(sanitize_archive_path)
                    .ok_or(OciRejection::UnsafeLinkTarget)?;
                if self.committed_files.contains(&target) {
                    Ok(Some(target))
                } else {
                    Err(OciRejection::UnsafeLinkTarget)
                }
            },
            _ => Ok(None),
        }
    }

    fn kind_allowed(&self, metadata: &EntryMetadata) -> bool {
        match metadata.kind() {
            EntryKind::File | EntryKind::Dir | EntryKind::Symlink | EntryKind::Hardlink => true,
            EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket => {
                self.policy.special_files() && cfg!(any(target_os = "linux", target_os = "android"))
            },
            _ => false,
        }
    }

    /// Whether any ancestor of `destination` was materialized as a symlink in
    /// this layer, which would let the entry escape through it.
    fn escapes_symlink(&self, destination: &Path) -> bool {
        let mut prefix = PathBuf::new();
        for component in destination.components() {
            prefix.push(component);
            if prefix.as_path() == destination {
                break;
            }
            if self.symlinks.contains(&prefix) {
                return true;
            }
        }
        false
    }

    pub(crate) fn finish(self, session_id: u64, expected: LayerDigests) -> OciLayerPlan {
        OciLayerPlan {
            session_id,
            expected,
            policy: self.policy,
            operations: self.operations,
        }
    }
}

fn reject(path: ArchivePath, reason: OciRejection) -> OciPlanOperation {
    OciPlanOperation::Reject(OciReject { path, reason })
}
