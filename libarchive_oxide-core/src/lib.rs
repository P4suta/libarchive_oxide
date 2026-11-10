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

mod blake2sp;
pub mod capability;
mod error;
pub mod filter;
mod format;
pub mod limits;
mod meta;
pub mod metadata;
mod payload;
pub mod protocol;
mod rar_crypto;

pub use capability::{
    AccessMode, AccessProfile, CAPABILITY_LEDGER, CapabilityRecord, CapabilitySubject, Direction,
    DirectionSet, MethodId,
};
pub use error::{ArchiveError, ErrorKind};
pub use filter::FilterId;
pub use format::FormatId;
pub use format::ar::{ArDecoder, ArEncoder, ar_bsd_inline_name_size};
pub use format::cpio::{CpioDecoder, CpioDialect, CpioEncoder, cpio_name_is_trailer};
pub use format::empty::EmptyDecoder;
pub use format::mtree::{MtreeDecoder, MtreeEncoder};
pub use format::rar_legacy::RarLegacyDecoder;
pub use format::rar5::{Rar5CompressionInfo, Rar5Decoder, Rar5SplitVerifier};
pub use format::raw::RawDecoder;
pub use format::tar::{TarDecoder, TarEncoder};
pub use format::warc::{WarcDecoder, WarcEncoder};
pub use limits::Limits;
pub use meta::{EntryKind, Timestamp};
pub use metadata::{
    ArchiveMetadata, ArchivePath, Checksum, ChecksumAlgorithm, Device, EntryMetadata,
    EntryMetadataBuilder, EntryTimes, Extension, Owner, PathEncoding, SparseExtent,
};
pub use payload::{
    NoPayloadCodec, NoPayloadCodecProvider, PayloadCodecAlgorithm, PayloadCodecProvider,
    PayloadCodecRequest,
};
pub use protocol::{
    ArchiveDecoder, ArchiveEncoder, Chunk, Codec, CodecStatus, CodecStep, DecodeEvent, DecodeStep,
    EncodeCommand, EncodeStatus, EncodeStep, EndOfInput, ProbeResult,
};
pub use rar_crypto::{
    NoRar3CryptoProvider, NoRar5CryptoKey, NoRar5CryptoProvider, Rar3CryptoProvider,
    Rar5CryptoParameters, Rar5CryptoProvider,
};
