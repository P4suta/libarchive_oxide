// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `no_std` archive traits and uncompressed formats.
//!
//! The crate provides unified [`Codec`], [`ArchiveDecoder`], and
//! [`ArchiveEncoder`] state machines plus typed metadata. It requires `alloc`
//! and has no external dependencies.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
pub mod filter;
mod format;
pub mod limits;
mod meta;
pub mod metadata;
pub mod protocol;

pub use error::{ArchiveError, ErrorKind};
pub use filter::FilterId;
pub use format::FormatId;
pub use format::ar::{ArDecoder, ArEncoder};
pub use format::cpio::{CpioDecoder, CpioDialect, CpioEncoder};
pub use format::tar::{TarDecoder, TarEncoder};
pub use limits::Limits;
pub use meta::{EntryKind, Timestamp};
pub use metadata::{
    ArchiveMetadata, ArchivePath, Device, EntryMetadata, EntryMetadataBuilder, EntryTimes,
    Extension, Owner, PathEncoding, SparseExtent,
};
pub use protocol::{
    ArchiveDecoder, ArchiveEncoder, Chunk, Codec, CodecStatus, CodecStep, DecodeEvent, DecodeStep,
    EncodeCommand, EncodeStatus, EncodeStep, EndOfInput, ProbeResult,
};
