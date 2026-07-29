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
#[cfg(any(
    feature = "zstd",
    feature = "lz4",
    feature = "compress",
    feature = "lzip",
    feature = "sevenz"
))]
mod codec_read;
#[cfg(not(target_os = "wasi"))]
pub mod create;
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
#[cfg(not(target_os = "wasi"))]
pub mod oci;
pub mod path;
mod pipeline_codec;
mod provider;
mod range_source;
mod registry;
pub mod secret;
pub mod seek_stream;
#[cfg(feature = "sevenz")]
mod sevenz;
#[cfg(not(target_os = "wasi"))]
pub mod spool;
mod stream;
#[cfg(all(feature = "tokio", not(target_os = "wasi")))]
pub mod tokio_stream;
mod udf;
mod xar;
mod zip;
mod zip_stream;

#[cfg(feature = "async")]
pub use async_seek::{AsyncSeekArchiveReader, AsyncSeekArchiveWriter};
#[cfg(feature = "async")]
pub use async_stream::{AsyncArchiveReader, AsyncArchiveWriter};
pub use capability::{Backend, BackendPreference, CapabilityState, capability_state};
#[cfg(not(target_os = "wasi"))]
pub use create::{CreateStreamError, CreationMetadataProfile, StreamingArchiveBuilder};
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
pub use path::{sanitize, sanitize_archive_path};
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
pub use zip::ZipMethod;

/// Low-level sans-I/O, provider, registry, and source APIs.
///
/// Most applications only need the types re-exported at the crate root.
pub mod advanced {
    pub use libarchive_oxide_core::{
        AccessMode, AccessProfile, ArchiveDecoder, ArchiveEncoder, ArchiveError, CAPABILITY_LEDGER,
        CapabilityRecord, CapabilitySubject, Chunk, Codec, CodecStatus, CodecStep, DecodeEvent,
        DecodeStep, Direction, DirectionSet, EncodeCommand, EncodeStatus, EncodeStep, EndOfInput,
        ErrorKind, MethodId, ProbeResult,
    };

    #[cfg(feature = "async")]
    pub use crate::async_range::{AsyncRangeArchiveReader, AsyncRangeSource};
    pub use crate::cab::{CabVolumeProvider, CabVolumeReader};
    pub use crate::capability::{CapabilityState, capability_state};
    pub use crate::provider::{
        CodecCapabilities, FormatCapabilities, ProviderArchiveEncoder, ProviderCapability,
    };
    pub use crate::range_source::{
        FileReadAt, MemoryReadAt, RangeArchiveReader, RangeMetrics, RangeReadError,
        RangeReadErrorKind, RangeReader, ReadAt, SeekReadAt, SourceIdentity, SourceIdentityError,
        SourceLimits, VolumeId, VolumeResolver, VolumeSet,
    };
    pub use crate::registry::{
        IncrementalCodecProvider, IncrementalFormatProvider, RandomAccessArchiveDecoder,
        RandomAccessFormatProvider, Registry, RegistryBuilder,
    };
    pub use crate::stream::{Pipeline, PipelineEvent, ProviderArchiveWriter};

    /// Transitional generic provider chains used by workspace internals.
    ///
    /// New downstream integrations should implement
    /// [`crate::advanced::IncrementalFormatProvider`] or
    /// [`crate::advanced::IncrementalCodecProvider`] and register boxed
    /// providers in a [`crate::advanced::Registry`]. This namespace is not a
    /// second canonical provider API.
    #[doc(hidden)]
    pub mod legacy {
        pub use crate::provider::{
            BuiltinCodecProviders, BuiltinFormatProviders, CodecProvider, CodecProviderNode,
            FormatProvider, FormatProviderNode, NoCodecProviders, NoFormatProviders, ProviderSet,
            StaticCodecProviders, StaticFormatProviders,
        };
    }
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
        Some("z") => Some(FilterId::Compress),
        Some("lz") => Some(FilterId::Lzip),
        _ => None,
    }
}
