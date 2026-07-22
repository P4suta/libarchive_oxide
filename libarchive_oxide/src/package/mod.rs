// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded package-verification framework.
//!
//! This module validates untrusted software packages without extracting or
//! whole-buffering them. It ships the Debian `.deb` profile via [`DebValidator`],
//! the RPM profile via [`RpmValidator`], the ZIP-container package profiles
//! (JAR, `NuGet`, wheel, EPUB) via [`ZipPackageValidator`], and the OS/app
//! package profiles (Android APK, iOS IPA, Windows MSIX) via
//! [`AppPackageValidator`]; the shared result vocabulary in [`finding`] is
//! designed to be reused by future package profiles and by CLI or JSON front
//! ends. The two ZIP-container validators share the bounded central-directory
//! reader in the crate-internal `zip_reader` module.

pub mod app_profile;
pub mod deb;
pub mod finding;
pub mod rpm;
pub mod zip_profile;
mod zip_reader;

pub use app_profile::{
    AppPackageProfile, AppPackageValidation, AppPackageValidator, AppSignatureReport,
};
pub use deb::{DebValidation, DebValidator};
pub use finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
pub use rpm::{RpmValidation, RpmValidator};
pub use zip_profile::{ZipPackageProfile, ZipPackageValidation, ZipPackageValidator};
