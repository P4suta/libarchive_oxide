// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Debian `.deb` validation: happy-path member/filter detection plus a
//! battery of adversarial packages that must be refused without extraction.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Cursor;

use libarchive_oxide::libarchive_oxide_core::{
    ArchiveError, ArchivePath, Codec, CodecStep, EndOfInput, EntryKind, EntryMetadata, ErrorKind,
    FilterId, FormatId, Limits, ProbeResult,
};
use libarchive_oxide::provider::{CodecCapabilities, CodecProvider, ProviderSet};
use libarchive_oxide::{ArchiveEngine, CreateOptions, DebValidator, PackageFindingCode};

/// A single tar entry: archive-native path, kind, and body bytes.
type TarEntry = (&'static [u8], EntryKind, Vec<u8>);

/// Builds an outer `ar` archive from named member bodies.
fn build_ar(members: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Ar))
        .expect("create ar writer");
    for (name, body) in members {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start member");
        if !body.is_empty() {
            writer.write_data(body).expect("write member");
        }
        writer.end_entry().expect("end member");
    }
    writer.finish().expect("finish ar")
}

/// Builds a tar member, optionally wrapped in a single outer filter.
fn build_tar(filter: Option<FilterId>, entries: &[TarEntry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create tar writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish tar")
}

/// The control tarball every well-formed fixture shares.
fn control_entries() -> Vec<TarEntry> {
    vec![
        (
            b"control".as_slice(),
            EntryKind::File,
            b"Package: demo\n".to_vec(),
        ),
        (b"md5sums".as_slice(), EntryKind::File, b"".to_vec()),
    ]
}

/// A small, safe data tarball.
fn data_entries() -> Vec<TarEntry> {
    vec![
        (b"usr/".as_slice(), EntryKind::Dir, Vec::new()),
        (
            b"usr/bin/demo".as_slice(),
            EntryKind::File,
            b"#!/bin/sh\necho hi\n".to_vec(),
        ),
    ]
}

/// A conventional member extension for a data compression filter.
fn data_member_name(filter: Option<FilterId>) -> &'static [u8] {
    match filter {
        Some(FilterId::Gzip) => b"data.tar.gz",
        Some(FilterId::Xz) => b"data.tar.xz",
        Some(FilterId::Zstd) => b"data.tar.zst",
        Some(FilterId::Bzip2) => b"data.tar.bz2",
        Some(FilterId::Lz4) => b"data.tar.lz4",
        None | Some(_) => b"data.tar",
    }
}

/// Builds a well-formed `.deb` whose data tarball uses `data_filter`.
fn build_deb(data_filter: Option<FilterId>) -> Vec<u8> {
    build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            data_member_name(data_filter),
            build_tar(data_filter, &data_entries()),
        ),
    ])
}

fn validate(bytes: &[u8]) -> libarchive_oxide::DebValidation {
    DebValidator::new().validate(Cursor::new(bytes.to_vec()))
}

// --- Happy path -----------------------------------------------------------

#[test]
fn well_formed_deb_is_valid_across_data_filters() {
    for filter in [
        None,
        Some(FilterId::Gzip),
        Some(FilterId::Xz),
        Some(FilterId::Zstd),
        Some(FilterId::Bzip2),
    ] {
        let deb = build_deb(filter);
        let result = validate(&deb);
        assert!(
            result.container_readable(),
            "container should read for {filter:?}"
        );
        assert!(
            result.profile_valid(),
            "profile should be valid for {filter:?}, findings: {:?}",
            result.findings()
        );
        assert!(
            result.findings().is_empty(),
            "no findings expected for {filter:?}: {:?}",
            result.findings()
        );
        assert_eq!(
            result.data_compression(),
            filter,
            "detected data filter for {filter:?}"
        );
        assert_eq!(result.control_compression(), Some(FilterId::Gzip));
    }
}

// --- Adversarial: container structure -------------------------------------

#[test]
fn missing_debian_binary_is_rejected() {
    let deb = build_ar(&[
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingDebianBinary));
}

#[test]
fn out_of_order_members_are_rejected() {
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnexpectedMemberOrder));
}

#[test]
fn invalid_version_stamp_is_rejected() {
    let deb = build_ar(&[
        (b"debian-binary", b"9.9 not a version".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
    ]);
    let result = validate(&deb);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::InvalidVersionStamp));
}

#[test]
fn duplicate_member_is_rejected() {
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
    ]);
    let result = validate(&deb);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DuplicateMember));
}

#[test]
fn traversal_member_name_is_rejected() {
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            b"data.tar.gz",
            build_tar(Some(FilterId::Gzip), &data_entries()),
        ),
        (b"../escape", b"payload".to_vec()),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsafeMemberName));
}

// --- Adversarial: nested tar ----------------------------------------------

#[test]
fn non_archive_member_reports_malformed_nesting() {
    let garbage =
        b"this is plainly not a gzip stream nor a tar archive, just text bytes.".repeat(8);
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (b"data.tar.gz", garbage),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MalformedNesting));
}

#[test]
fn truncated_member_is_rejected() {
    let mut data = build_tar(Some(FilterId::Gzip), &data_entries());
    let keep = data.len().saturating_sub(24);
    data.truncate(keep);
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (b"data.tar.gz", data),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(
        result.has_code(PackageFindingCode::TruncatedMember)
            || result.has_code(PackageFindingCode::MalformedNesting),
        "expected truncation finding, got {:?}",
        result.findings()
    );
}

#[test]
fn traversal_entry_path_is_rejected() {
    let entries: Vec<TarEntry> = vec![(
        b"../../etc/passwd".as_slice(),
        EntryKind::File,
        b"root:x:0:0\n".to_vec(),
    )];
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (b"data.tar.gz", build_tar(Some(FilterId::Gzip), &entries)),
    ]);
    let result = validate(&deb);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsafeEntryPath));
}

#[test]
fn duplicate_entry_path_is_rejected() {
    let entries: Vec<TarEntry> = vec![
        (b"etc/config".as_slice(), EntryKind::File, b"a\n".to_vec()),
        (b"etc/config".as_slice(), EntryKind::File, b"b\n".to_vec()),
    ];
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (b"data.tar.gz", build_tar(Some(FilterId::Gzip), &entries)),
    ]);
    let result = validate(&deb);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DuplicateEntryPath));
}

#[test]
fn decompression_bomb_is_bounded() {
    let entries: Vec<TarEntry> = vec![(
        b"usr/share/blob".as_slice(),
        EntryKind::File,
        vec![0u8; 200_000],
    )];
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (b"data.tar.gz", build_tar(Some(FilterId::Gzip), &entries)),
    ]);
    // Bound each nested tar decode to a fraction of the hostile expansion.
    let limits = Limits::safe().with_decoded_total(Some(8 * 1024));
    let result = DebValidator::new()
        .with_limits(limits)
        .validate(Cursor::new(deb));
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DecompressionBomb));
}

// --- Adversarial: unsupported compression method --------------------------

/// A codec provider that recognizes zstd frames but advertises no capability,
/// mirroring a build compiled without the `zstd` feature.
#[derive(Debug, Clone, Copy)]
struct DisabledZstd;

/// Decoder state for [`DisabledZstd`]; it never actually runs.
struct DisabledDecoder;

impl Codec for DisabledDecoder {
    fn process(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
        _end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Capability).with_context("zstd disabled in this build"))
    }
}

impl CodecProvider for DisabledZstd {
    type Decoder = DisabledDecoder;

    fn filter(&self) -> FilterId {
        FilterId::Zstd
    }

    fn name(&self) -> &'static str {
        "disabled-zstd"
    }

    fn probe(&self, prefix: &[u8]) -> ProbeResult<()> {
        match FilterId::probe(prefix) {
            ProbeResult::Match(FilterId::Zstd) => ProbeResult::Match(()),
            ProbeResult::NeedMore { minimum } => ProbeResult::NeedMore { minimum },
            _ => ProbeResult::NoMatch,
        }
    }

    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities::new(false, false)
    }

    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Capability).with_context("zstd disabled in this build"))
    }

    fn encode_frame(&self, _input: &[u8], _limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Capability).with_context("zstd disabled in this build"))
    }
}

#[test]
fn unsupported_compression_reports_capability_finding() {
    let deb = build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (
            b"control.tar.gz",
            build_tar(Some(FilterId::Gzip), &control_entries()),
        ),
        (
            b"data.tar.zst",
            build_tar(Some(FilterId::Zstd), &data_entries()),
        ),
    ]);
    let providers = ProviderSet::builtins().with_codec_provider(DisabledZstd);
    let result = DebValidator::new()
        .with_codec_providers(providers)
        .validate(Cursor::new(deb));
    // The container reads and the zstd frame is recognized, but it cannot be
    // decoded, so the profile is not confirmed valid.
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert_eq!(result.data_compression(), Some(FilterId::Zstd));
    assert!(result.has_code(PackageFindingCode::UnsupportedCompression));
}
