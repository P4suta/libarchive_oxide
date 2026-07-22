// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCI image layer engine.
//!
//! This module reads OCI image layers (tar, tar+gzip, or tar+zstd) with bounded
//! resources while computing, in a single pass, both the compressed digest (the
//! outer SHA-256 over the stored blob) and the diffID (the inner SHA-256 over
//! the decoded tar stream).
//!
//! Start from an [`OciLayerEngine`], call [`OciLayerEngine::open`] to obtain an
//! [`OciLayerSession`], stream entry descriptors with
//! [`OciLayerSession::next_entry`], and finish with [`OciLayerSession::digests`]
//! or [`OciLayerSession::verify`].
//!
//! To apply a layer to a filesystem, wrap a seekable blob in an
//! [`OciLayerApplier`], build a session-bound [`OciLayerPlan`] with
//! [`OciLayerApplier::plan`], and commit it with [`OciLayerApplier::apply`].
//! Application verifies the compressed digest and diffID before touching the
//! destination and honors OCI whiteout and opaque-directory markers.

mod apply;
mod digest;
mod layer;
mod plan;

pub use apply::{OciApplyReport, OciLayerApplier};
pub use digest::{LayerDigests, encode_hex};
pub use layer::{
    DigestKind, DigestMismatch, OciLayerEngine, OciLayerEntry, OciLayerError, OciLayerSession,
};
pub use plan::{
    IdentityOwnership, OciLayerPlan, OciMaterialize, OciPlanOperation, OciReject, OciRejection,
    OciRemoval, OwnershipMapper, OwnershipTable,
};
