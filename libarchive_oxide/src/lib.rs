// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive detection, compression, extraction, and creation.
//!
//! This crate adds codecs, zip/7z, filesystem operations, path sanitization, and
//! output limits to [`libarchive_oxide_core`].

#![forbid(unsafe_code)]

// Filter modules use `alloc` paths and also compile under std.
extern crate alloc;

#[cfg(any(feature = "bzip2", feature = "native-codecs"))]
mod backend_codec;

#[cfg(feature = "async")]
mod async_filter;
#[cfg(feature = "async")]
mod async_range;
#[cfg(feature = "async")]
pub mod async_seek;
#[cfg(feature = "async")]
pub mod async_stream;
mod cab;
pub mod capability;
mod codec_read;
#[cfg(not(target_os = "wasi"))]
pub mod create;
#[cfg(feature = "gzip")]
#[allow(
    warnings,
    clippy::all,
    dead_code,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub
)]
#[path = "../vendor/deflate64/src/lib.rs"]
mod deflate64;
#[cfg(not(target_os = "wasi"))]
mod edit;
#[cfg(not(target_os = "wasi"))]
pub mod engine;
#[cfg(not(target_os = "wasi"))]
mod extraction;
pub mod filter;
pub mod filtered_io;

#[cfg(not(target_os = "wasi"))]
pub mod filesystem;
#[cfg(not(target_os = "wasi"))]
mod filesystem_driver;
#[cfg(not(target_os = "wasi"))]
mod filesystem_std;
mod iso_stream;
#[cfg(feature = "lha")]
mod lha;
#[cfg(not(target_os = "wasi"))]
pub mod oci;
mod open;
pub mod path;
mod pipeline_codec;
mod provider;
mod range_source;
mod rar5_volume;
mod rar_legacy_volume;
mod registry;
pub mod secret;
pub mod seek_stream;
#[cfg(feature = "sevenz")]
mod sevenz;
#[cfg(feature = "sevenz")]
mod sevenz_volume;
#[cfg(not(target_os = "wasi"))]
pub mod spool;
mod stream;
#[cfg(all(feature = "tokio", not(target_os = "wasi")))]
pub mod tokio_stream;
#[cfg(not(target_os = "wasi"))]
mod transcode;
mod udf;
mod volume_stream;
mod write_options;
mod xar;
mod zip;
mod zip_read;
mod zip_stream;
mod zip_volume;
#[cfg(feature = "aes")]
mod zipaes;
#[cfg(feature = "aes")]
mod zipcrypto;

#[cfg(feature = "async")]
pub use async_seek::{AsyncSeekArchiveReader, AsyncSeekArchiveWriter};
#[cfg(feature = "async")]
pub use async_stream::{AsyncArchiveReader, AsyncArchiveWriter};
pub use capability::{Backend, BackendPreference, CapabilityState, capability_state};
#[cfg(not(target_os = "wasi"))]
pub use create::{
    CreateStreamError, CreationMetadataProfile, SeekArchiveBuilder, StreamingArchiveBuilder,
};
#[cfg(not(target_os = "wasi"))]
pub use edit::{ArchiveEditor, EditOperation, EditOutcome, EditReport};
#[cfg(not(target_os = "wasi"))]
pub use engine::{
    ApplyReport, ArchiveEngine, ArchiveInspection, ArchiveSession, CreateOptions, EntryDescriptor,
    ExtractionPlan, InputDigest, PlanDisposition, PlannedEntry, PreparedArchive,
};
#[cfg(not(target_os = "wasi"))]
pub use extraction::{EntryOutcome, EntryOutcomeKind, ExtractionReport, Policy, RejectionReason};
#[cfg(not(target_os = "wasi"))]
pub use filesystem::{
    FilesystemAdapter, FilesystemAdapterError, FilesystemCapabilities, FilesystemEntry,
    FilesystemEntryReport, FilesystemFinding, FilesystemFindingKind, FilesystemMaterialization,
    FilesystemOperation, FilesystemRemoval,
};
#[cfg(not(target_os = "wasi"))]
pub use filesystem_std::CapStdFilesystemAdapter;
pub use filtered_io::FilterReader;
pub use libarchive_oxide_core::{
    ArchiveMetadata, ArchivePath, Checksum, ChecksumAlgorithm, CpioDialect, EntryKind,
    EntryMetadata, EntryMetadataBuilder, EntryTimes, ErrorKind, Extension, FilterId, FormatId,
    Limits, Owner, PathEncoding, SparseExtent, Timestamp,
};
#[cfg(not(target_os = "wasi"))]
pub use oci::{
    DigestKind, DigestMismatch, IdentityOwnership, LayerDigests, OciApplyReport, OciLayerApplier,
    OciLayerBlob, OciLayerBuilder, OciLayerEngine, OciLayerEntry, OciLayerError, OciLayerFilter,
    OciLayerPlan, OciLayerSession, OciMaterialize, OciPlanOperation, OciReject, OciRejection,
    OciRemoval, OwnershipMapper, OwnershipTable,
};
pub use open::{
    OpenOptions, PasswordCandidates, PasswordProvider, PasswordPurpose, PasswordRequest,
};
pub use path::{sanitize, sanitize_archive_path};
pub use range_source::{RangeArchiveReader, SourceLimits, VolumeSet};
pub use secret::SecretBytes;
pub use seek_stream::{SeekArchiveReader, SeekArchiveWriter};
#[cfg(not(target_os = "wasi"))]
pub use spool::{SpoolReader, SpoolWriter};
pub(crate) use stream::StreamError;
pub use stream::{ArchiveReader, ArchiveWriter, Entry, EntryWriter, Error, ReaderEvent};
#[cfg(all(feature = "tokio", not(target_os = "wasi")))]
pub use tokio_stream::{
    TokioArchiveReader, TokioArchiveWriter, TokioIo, TokioSeekArchiveReader, TokioSeekArchiveWriter,
};
#[cfg(not(target_os = "wasi"))]
pub use transcode::{
    ArchiveTranscoder, MetadataField, MetadataLoss, MetadataLossPolicy, TranscodeOutcome,
    TranscodeReport,
};
pub use volume_stream::VolumeArchiveReader;
pub use write_options::{
    AesStrength, FormatWriteOptions, SevenZipCompression, SevenZipEncryption, SevenZipFilter,
    SevenZipWriteOptions, XarCompression, XarWriteOptions, ZipCompression, ZipEncryption,
    ZipWriteOptions,
};
pub use zip::ZipMethod;

/// Low-level sans-I/O, provider, registry, and source APIs.
///
/// Most applications only need the types re-exported at the crate root.
pub mod advanced {
    pub use libarchive_oxide_core::capability::{filter_capability, format_capability};
    pub use libarchive_oxide_core::{
        AccessMode, AccessProfile, ArchiveDecoder, ArchiveEncoder, ArchiveError, CAPABILITY_LEDGER,
        CapabilityRecord, CapabilitySubject, Chunk, Codec, CodecStatus, CodecStep, DecodeEvent,
        DecodeStep, Direction, DirectionSet, EncodeCommand, EncodeStatus, EncodeStep, EndOfInput,
        ErrorKind, MethodId, PayloadCodecAlgorithm, PayloadCodecProvider, PayloadCodecRequest,
        ProbeResult, Rar3CryptoProvider,
    };

    #[cfg(feature = "async")]
    pub use crate::async_range::{AsyncRangeArchiveReader, AsyncRangeSource};
    pub use crate::cab::{CabVolumeProvider, CabVolumeReader};
    pub use crate::capability::{CapabilityState, capability_state};
    pub use crate::provider::{
        BuiltinCodecProviders, BuiltinFormatProviders, CodecCapabilities, CodecProvider,
        CodecProviderNode, FormatCapabilities, FormatProvider, FormatProviderNode,
        NoCodecProviders, NoFormatProviders, ProviderArchiveEncoder, ProviderCapability,
        ProviderSet, StaticCodecProviders, StaticFormatProviders,
    };
    pub use crate::range_source::{
        FileReadAt, MemoryReadAt, RangeArchiveReader, RangeMetrics, RangeReadError,
        RangeReadErrorKind, RangeReader, ReadAt, SeekReadAt, SourceIdentity, SourceIdentityError,
        SourceLimits, VolumeId, VolumeResolver, VolumeSet,
    };
    pub use crate::rar_legacy_volume::{RarLegacyVolumeProvider, RarLegacyVolumeReader};
    pub use crate::rar5_volume::{Rar5VolumeProvider, Rar5VolumeReader};
    pub use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
    #[cfg(feature = "sevenz")]
    pub use crate::sevenz_volume::{SevenZipVolumeProvider, SevenZipVolumeReader};
    pub use crate::stream::{Pipeline, PipelineEvent, ProviderArchiveWriter};
    pub use crate::zip_volume::{ZipVolumeProvider, ZipVolumeReader};
}

/// Returns the compression codec implied by a filename.
#[must_use]
pub fn filter_for_name(name: &str) -> Option<FilterId> {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("gz" | "tgz") => Some(FilterId::Gzip),
        Some("bz2" | "tbz" | "tbz2") => Some(FilterId::Bzip2),
        Some("zst") => Some(FilterId::Zstd),
        Some("xz") => Some(FilterId::Xz),
        Some("lz4") => Some(FilterId::Lz4),
        Some("lzo" | "lzop") => Some(FilterId::Lzop),
        Some("z") => Some(FilterId::Compress),
        Some("lz") => Some(FilterId::Lzip),
        Some("lzma") => Some(FilterId::Lzma),
        Some("b64" | "base64") => Some(FilterId::Base64),
        Some("uu" | "uue" | "uuencode") => Some(FilterId::Uuencode),
        Some("rpm") => Some(FilterId::Rpm),
        _ => None,
    }
}
