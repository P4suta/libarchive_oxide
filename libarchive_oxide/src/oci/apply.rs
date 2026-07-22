// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, digest-verified application of one OCI image layer.
//!
//! [`OciLayerApplier`] wraps a seekable layer blob and applies it in two passes.
//! The first pass streams the whole layer and verifies the compressed digest and
//! diffID against the expected pair; if either differs the applier returns an
//! error **before touching the destination**. Only once both digests match does
//! the second pass drive a [`FilesystemAdapter`], materializing entries and
//! executing whiteout and opaque-directory operations.
//!
//! Plans are bound to the applier's session identity, and each applier applies
//! at most one plan, mirroring the single-use guard of the core engine.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use libarchive_oxide_core::Limits;

use super::digest::LayerDigests;
use super::layer::{OciLayerEngine, OciLayerError};
use super::plan::{
    OciLayerPlan, OciLayerPlanner, OciMaterialize, OciPlanOperation, OciRemoval, OwnershipMapper,
    is_structural_skip,
};
use crate::engine::Policy;
use crate::filesystem::{
    FilesystemAdapter, FilesystemEntry, FilesystemFinding, FilesystemMaterialization,
    FilesystemOperation, FilesystemRemoval,
};
use crate::filtered_io::FilterReader;
use crate::stream::{ArchiveReader, ReaderEvent};

static NEXT_APPLIER_ID: AtomicU64 = AtomicU64::new(1);

/// A plain tar reader over the decoded (diffID) stream of a layer.
type PlainTar<R> = ArchiveReader<FilterReader<R>>;

/// Opens a bounded tar reader over the decoded layer stream.
fn open_tar<R: Read>(reader: R, limits: Limits) -> Result<PlainTar<R>, OciLayerError> {
    let filter = FilterReader::with_limits(reader, limits).map_err(OciLayerError::Io)?;
    // The decoded bytes are already plain tar; disable further filter detection.
    let tar_limits = limits.with_filter_depth(Some(0));
    Ok(ArchiveReader::with_limits(filter, tar_limits))
}

/// Applies a single OCI image layer with bounded resources and digest binding.
#[derive(Debug)]
pub struct OciLayerApplier<R: Read + Seek> {
    reader: R,
    limits: Limits,
    id: u64,
    applied: bool,
}

impl<R: Read + Seek> OciLayerApplier<R> {
    /// Wraps a seekable layer blob with safe finite resource limits.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, Limits::safe())
    }

    /// Wraps a seekable layer blob with explicit resource limits.
    #[must_use]
    pub fn with_limits(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            id: NEXT_APPLIER_ID.fetch_add(1, Ordering::Relaxed),
            applied: false,
        }
    }

    /// Resource limits used by this applier.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Recovers the wrapped reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    fn rewind(&mut self) -> Result<(), OciLayerError> {
        self.reader
            .seek(SeekFrom::Start(0))
            .map_err(OciLayerError::Io)?;
        Ok(())
    }

    /// Builds a session-bound plan by interpreting the layer's entries.
    ///
    /// Ownership is remapped through `mapper`, overlay markers become explicit
    /// whiteout and opaque operations, and unsafe or conflicting entries become
    /// rejections. The plan is bound to `expected`, the digest pair that
    /// [`Self::apply`] later verifies.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer stream cannot be decoded within limits.
    pub fn plan<M: OwnershipMapper>(
        &mut self,
        expected: LayerDigests,
        policy: Policy,
        mapper: &M,
    ) -> Result<OciLayerPlan, OciLayerError> {
        self.rewind()?;
        let mut reader = open_tar(&mut self.reader, self.limits)?;
        let mut planner = OciLayerPlanner::new(policy, mapper);
        loop {
            match reader.next_event()? {
                ReaderEvent::Entry(metadata) => planner.observe(metadata),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {
                },
            }
        }
        Ok(planner.finish(self.id, expected))
    }

    /// Applies a session-bound plan exactly once.
    ///
    /// The layer is first fully read and its compressed digest and diffID are
    /// verified against the plan's expected pair. On mismatch this returns
    /// [`OciLayerError::DigestMismatch`] and the destination is left completely
    /// unchanged. Only on a match is the adapter driven.
    ///
    /// # Errors
    ///
    /// Returns [`OciLayerError::Session`] if the plan belongs to a different
    /// applier or the applier already applied a plan,
    /// [`OciLayerError::DigestMismatch`] on digest failure, or a stream or
    /// adapter error while applying.
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply<A: FilesystemAdapter>(
        &mut self,
        plan: OciLayerPlan,
        adapter: &mut A,
    ) -> Result<OciApplyReport, OciLayerError> {
        if plan.session_id != self.id {
            return Err(OciLayerError::Session(
                "OCI layer plan belongs to a different applier session",
            ));
        }
        if self.applied {
            return Err(OciLayerError::Session(
                "OCI layer applier has already applied a plan",
            ));
        }
        self.applied = true;

        // Pass one: verify digests without touching the destination.
        self.rewind()?;
        {
            let mut session = OciLayerEngine::with_limits(self.limits).open(&mut self.reader)?;
            session.verify(plan.expected)?;
        }

        // Pass two: drive the adapter now that the layer is trusted.
        self.rewind()?;
        drive_apply(&mut self.reader, self.limits, &plan, adapter)
    }
}

/// Running tallies for an [`OciApplyReport`].
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    materialized: usize,
    removed: usize,
    cleared: usize,
    rejected: usize,
}

/// The in-flight operation for the entry currently being streamed.
#[derive(Clone, Copy)]
enum Active<'plan> {
    Materialize(&'plan OciMaterialize),
    Whiteout(&'plan OciRemoval),
    Opaque(&'plan OciRemoval),
    Reject(&'plan super::plan::OciReject),
    Skip,
}

fn drive_apply<R: Read, A: FilesystemAdapter>(
    reader: &mut R,
    limits: Limits,
    plan: &OciLayerPlan,
    adapter: &mut A,
) -> Result<OciApplyReport, OciLayerError> {
    let mut tar = open_tar(reader, limits)?;
    adapter.begin_session()?;
    let overwrite = plan.policy.overwrite();

    let mut findings: Vec<FilesystemFinding> = Vec::new();
    let mut committed: BTreeSet<PathBuf> = BTreeSet::new();
    let mut counts = Counts::default();
    let mut operations = plan.operations.iter();
    let mut active: Option<Active<'_>> = None;

    loop {
        match tar.next_event()? {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                if active.is_some() {
                    adapter.abort_entry();
                    return Err(OciLayerError::Session(
                        "layer entry began before the previous entry ended",
                    ));
                }
                if is_structural_skip(&metadata) {
                    active = Some(Active::Skip);
                    continue;
                }
                let operation = operations.next().ok_or(OciLayerError::Session(
                    "layer stream produced more entries than the plan",
                ))?;
                active = Some(begin_operation(adapter, operation, overwrite)?);
            },
            ReaderEvent::Data(data) => {
                if matches!(active, Some(Active::Materialize(_))) {
                    adapter.write_data(data)?;
                }
            },
            ReaderEvent::EndEntry => {
                let current = active.take().ok_or(OciLayerError::Session(
                    "layer ended an entry that was not open",
                ))?;
                finish_operation(adapter, current, &mut findings, &mut committed, &mut counts)?;
            },
            ReaderEvent::Done => break,
        }
    }

    if operations.next().is_some() {
        return Err(OciLayerError::Session(
            "plan has more operations than the layer stream",
        ));
    }
    let mut deferred = adapter.finish_session()?;
    findings.append(&mut deferred);

    Ok(OciApplyReport {
        verified: plan.expected,
        findings,
        materialized: counts.materialized,
        removed: counts.removed,
        cleared: counts.cleared,
        rejected: counts.rejected,
    })
}

fn begin_operation<'plan, A: FilesystemAdapter>(
    adapter: &mut A,
    operation: &'plan OciPlanOperation,
    overwrite: bool,
) -> Result<Active<'plan>, OciLayerError> {
    Ok(match operation {
        OciPlanOperation::Materialize(materialize)
        | OciPlanOperation::MapOwnership(materialize) => {
            let entry = FilesystemEntry::new(
                materialize.metadata(),
                materialize.destination(),
                materialize.link_target(),
                overwrite,
            );
            adapter.begin_entry(entry)?;
            Active::Materialize(materialize)
        },
        OciPlanOperation::Whiteout(removal) => Active::Whiteout(removal),
        OciPlanOperation::OpaqueDir(removal) => Active::Opaque(removal),
        OciPlanOperation::Reject(reject) => Active::Reject(reject),
    })
}

fn finish_operation<A: FilesystemAdapter>(
    adapter: &mut A,
    active: Active<'_>,
    findings: &mut Vec<FilesystemFinding>,
    committed: &mut BTreeSet<PathBuf>,
    counts: &mut Counts,
) -> Result<(), OciLayerError> {
    match active {
        Active::Skip => {},
        Active::Materialize(materialize) => {
            let report = adapter.finish_entry()?;
            let (materialization, mut entry_findings) = report.into_parts();
            findings.append(&mut entry_findings);
            match materialization {
                FilesystemMaterialization::File | FilesystemMaterialization::Hardlink => {
                    committed.insert(materialize.destination().to_path_buf());
                    counts.materialized = counts.materialized.saturating_add(1);
                },
                FilesystemMaterialization::Directory
                | FilesystemMaterialization::Symlink
                | FilesystemMaterialization::Special => {
                    counts.materialized = counts.materialized.saturating_add(1);
                },
                FilesystemMaterialization::DestinationExists
                | FilesystemMaterialization::Failed => {
                    counts.rejected = counts.rejected.saturating_add(1);
                },
            }
        },
        Active::Whiteout(removal) => {
            let finding = adapter.remove_path(FilesystemRemoval::new(
                removal.path(),
                removal.destination(),
            ))?;
            findings.push(finding);
            counts.removed = counts.removed.saturating_add(1);
        },
        Active::Opaque(removal) => {
            let finding = adapter.clear_directory(FilesystemRemoval::new(
                removal.path(),
                removal.destination(),
            ))?;
            findings.push(finding);
            counts.cleared = counts.cleared.saturating_add(1);
        },
        Active::Reject(reject) => {
            findings.push(FilesystemFinding::refused(
                reject.path().clone(),
                FilesystemOperation::Entry,
                reject.reason().label(),
            ));
            counts.rejected = counts.rejected.saturating_add(1);
        },
    }
    Ok(())
}

/// The outcome of applying one OCI layer.
#[derive(Debug)]
pub struct OciApplyReport {
    verified: LayerDigests,
    findings: Vec<FilesystemFinding>,
    materialized: usize,
    removed: usize,
    cleared: usize,
    rejected: usize,
}

impl OciApplyReport {
    /// The compressed digest and diffID that were verified before applying.
    #[must_use]
    pub const fn verified(&self) -> LayerDigests {
        self.verified
    }

    /// Typed filesystem findings gathered while applying the layer.
    #[must_use]
    pub fn findings(&self) -> &[FilesystemFinding] {
        &self.findings
    }

    /// Number of entries materialized (files, directories, links, specials).
    #[must_use]
    pub const fn materialized(&self) -> usize {
        self.materialized
    }

    /// Number of whiteout removals executed.
    #[must_use]
    pub const fn removed(&self) -> usize {
        self.removed
    }

    /// Number of opaque directories cleared.
    #[must_use]
    pub const fn cleared(&self) -> usize {
        self.cleared
    }

    /// Number of entries refused by the plan.
    #[must_use]
    pub const fn rejected(&self) -> usize {
        self.rejected
    }

    /// Whether any requested filesystem operation was not fully applied.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.kind() != crate::filesystem::FilesystemFindingKind::Applied)
    }

    /// Consumes the report into its verified digests and findings.
    #[must_use]
    pub fn into_parts(self) -> (LayerDigests, Vec<FilesystemFinding>) {
        (self.verified, self.findings)
    }
}
