// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dependency-free `no_std + alloc` contracts for byte codecs and adapters.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod codec;
mod error;
mod limits;

pub use codec::{Codec, CodecStatus, CodecStep, EndOfInput};
pub use error::{ArchiveError, ErrorKind};
pub use limits::Limits;
