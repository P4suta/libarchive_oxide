// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive detection, compression, extraction, and creation.
//!
//! This crate adds codecs, zip/7z, filesystem operations, path sanitization, and
//! output limits to [`libarchive_oxide_core`].

#![forbid(unsafe_code)]

#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
compile_error!(
    "`portable-codecs` and `native-codecs` are mutually exclusive; use \
     `--no-default-features --features native-codecs` for the native profile"
);

// Filter modules use `alloc` paths and also compile under std.
extern crate alloc;

use libarchive_oxide_core::filter::FilterId;

#[cfg(any(feature = "bzip2", feature = "native-codecs"))]
mod backend_codec;

#[cfg(feature = "async")]
mod async_filter;
#[cfg(feature = "async")]
pub mod async_range;
#[cfg(feature = "async")]
pub mod async_seek;
#[cfg(feature = "async")]
pub mod async_stream;
pub mod create;
pub mod engine;
pub mod extractor;
pub mod filter;
pub mod filtered_io;

pub mod filesystem;
mod filesystem_driver;
mod filesystem_std;
mod iso_stream;
pub mod oci;
pub mod package;
pub mod path;
mod pipeline_codec;
pub mod provider;
pub mod range_source;
pub mod secret;
pub mod seek_stream;
#[cfg(feature = "sevenz")]
mod sevenz;
pub mod spool;
pub mod stream;
#[cfg(feature = "tokio")]
pub mod tokio_stream;
mod zip;
mod zip_stream;

#[cfg(feature = "async")]
pub use async_range::{AsyncRangeArchiveReader, AsyncRangeSource};
#[cfg(feature = "async")]
pub use async_seek::{AsyncSeekArchiveReader, AsyncSeekArchiveWriter};
#[cfg(feature = "async")]
pub use async_stream::{AsyncArchiveReader, AsyncArchiveWriter};
pub use create::{CreateStreamError, StreamingArchiveBuilder};
pub use engine::{
    ApplyReport, ArchiveEngine, ArchiveInspection, ArchiveSession, CreateOptions, EntryDescriptor,
    ExtractionPlan, InputDigest, PlanDisposition, PlannedEntry, Policy,
};
pub use extractor::{
    EntryOutcome, EntryOutcomeKind, ExtractionPolicy, ExtractionReport, Extractor, RejectionReason,
};
pub use filesystem::{
    FilesystemAdapter, FilesystemAdapterError, FilesystemCapabilities, FilesystemEntry,
    FilesystemEntryReport, FilesystemFinding, FilesystemFindingKind, FilesystemMaterialization,
    FilesystemOperation, FilesystemRemoval,
};
pub use filesystem_std::CapStdFilesystemAdapter;
pub use filtered_io::FilterReader;
pub use libarchive_oxide_core;
pub use libarchive_oxide_core::CpioDialect;
pub use oci::{
    DigestKind, DigestMismatch, IdentityOwnership, LayerDigests, OciApplyReport, OciLayerApplier,
    OciLayerBlob, OciLayerBuilder, OciLayerEngine, OciLayerEntry, OciLayerError, OciLayerFilter,
    OciLayerPlan, OciLayerSession, OciMaterialize, OciPlanOperation, OciReject, OciRejection,
    OciRemoval, OwnershipMapper, OwnershipTable,
};
pub use package::{
    DebValidation, DebValidator, PackageFinding, PackageFindingCode, RpmValidation, RpmValidator,
    Severity, SupportStatus,
};
pub use path::{sanitize, sanitize_archive_path};
pub use provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, CodecCapabilities, CodecProvider,
    CodecProviderNode, FormatCapabilities, FormatProvider, FormatProviderNode, NoCodecProviders,
    NoFormatProviders, ProviderArchiveEncoder, ProviderCapability, ProviderSet,
};
pub use range_source::{
    RangeArchiveReader, RangeMetrics, RangeReadError, RangeReader, RangeSource, SourceIdentity,
};
pub use secret::SecretBytes;
pub use seek_stream::{SeekArchiveReader, SeekArchiveWriter};
pub use spool::{SpoolReader, SpoolWriter};
pub use stream::{
    ArchiveReader, ArchiveWriter, Pipeline, PipelineEvent, ProviderArchiveWriter, ReaderEvent,
    StreamError,
};
#[cfg(feature = "tokio")]
pub use tokio_stream::{
    TokioArchiveReader, TokioArchiveWriter, TokioExtractor, TokioIo, TokioSeekArchiveReader,
    TokioSeekArchiveWriter,
};
pub use zip::ZipMethod;

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
        _ => None,
    }
}
