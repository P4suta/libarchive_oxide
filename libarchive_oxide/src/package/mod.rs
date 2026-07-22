// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded package-verification framework.
//!
//! This module validates untrusted software packages without extracting or
//! whole-buffering them. It ships the Debian `.deb` profile via [`DebValidator`]
//! and the RPM profile via [`RpmValidator`]; the shared result vocabulary in
//! [`finding`] is designed to be reused by future package profiles and by CLI or
//! JSON front ends.

pub mod deb;
pub mod finding;
pub mod rpm;

pub use deb::{DebValidation, DebValidator};
pub use finding::{PackageFinding, PackageFindingCode, Severity, SupportStatus};
pub use rpm::{RpmValidation, RpmValidator};
