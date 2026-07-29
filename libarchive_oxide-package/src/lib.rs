// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline software-package inspection and verification.
//!
//! Archive parsing and safe entry delivery belong to `libarchive_oxide`; this
//! crate owns ecosystem-specific structure, integrity, signature-validity, and
//! issuer-trust decisions. No API in this crate performs implicit network I/O.

#![forbid(unsafe_code)]

pub mod alpine;
mod alpine_signature;
mod android_signature;
mod android_v4_signature;
pub mod app_profile;
pub mod deb;
pub mod finding;
mod integrity;
mod jar_signature;
mod msix_blockmap;
mod nuget_signature;
pub mod rpm;
mod verification;
pub mod zip_profile;
mod zip_reader;

pub use alpine::{AlpineApkValidation, AlpineApkValidator};
pub use alpine_signature::{AlpineRsaPublicKey, PackageKeyError};
pub use android_v4_signature::AndroidApkV4Revision;
pub use app_profile::{
    AppPackageProfile, AppPackageValidation, AppPackageValidator, AppSignatureReport,
};
pub use deb::{DebValidation, DebValidator};
pub use finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
pub use rpm::{RpmValidation, RpmValidator};
pub use verification::{
    AndroidApkLineageLevelReport, AndroidApkRotationReport, AndroidApkTargetedSignerReport,
    AndroidApkV4Report, PackageInspector, PackageVerifier, TrustPolicy, VerificationDimension,
    VerificationReport,
};
pub use zip_profile::{ZipPackageProfile, ZipPackageValidation, ZipPackageValidator};
