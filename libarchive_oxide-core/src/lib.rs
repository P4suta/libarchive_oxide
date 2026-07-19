// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `no_std` archive traits and uncompressed formats.
//!
//! The crate provides [`Transform`], [`Filter`], [`EntryReader`],
//! [`EntryWriter`], shared metadata, and tar/cpio/ar/ISO 9660 implementations.
//! It requires `alloc`, has no external dependencies, and uses sealed enums for
//! runtime dispatch.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod filter;
pub mod format;
pub mod io;
pub mod meta;
pub mod transform;

pub use error::{Error, Result};
pub use filter::{Decoder, Encoder, Filter};
pub use format::{
    AnyEntryData, AnyReader, ArchiveFormat, Detection, Entry, EntryData, EntryDataSink,
    EntryReader, EntrySink, EntrySource, EntryWriter, OwnedData, SliceData, SourceEvent,
};
pub use io::Sink;
pub use meta::{EntryKind, EntryMeta, PaxMap, Timestamp};
pub use transform::{decode_to_vec, decode_to_vec_capped, Status, Step, Transform};
