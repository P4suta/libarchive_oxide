// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe, allocation-bounded `PPMd` models and range decoders.
//!
//! Archive framing stays in the owning format crate.
//! This crate owns only the compression model and concrete entropy-coder state, keeping dependencies acyclic and avoiding runtime trait objects.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod model;
mod range;

use core::fmt;

pub use model::Ppmd7;
pub use range::RarRangeDecoder;

/// Failure produced by a `PPMd` model or range decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Model order or memory size is outside the supported representation.
    InvalidParameter,
    /// The caller's allocation budget could not be reserved.
    Allocation,
    /// The compressed range stream ended before a complete symbol.
    UnexpectedEnd,
    /// Arithmetic state is inconsistent with the `PPMd` model.
    Corrupt,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidParameter => "invalid PPMd parameter",
            Self::Allocation => "PPMd model allocation failed",
            Self::UnexpectedEnd => "PPMd range stream ended unexpectedly",
            Self::Corrupt => "PPMd range stream is corrupt",
        })
    }
}

impl core::error::Error for Error {}
