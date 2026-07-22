// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RPM validation: happy-path lead/header/payload parsing plus a battery
//! of adversarial packages that must be refused without extraction.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Cursor;

use libarchive_oxide::libarchive_oxide_core::{
    ArchiveError, ArchivePath, Codec, CodecStep, EndOfInput, EntryKind, EntryMetadata, ErrorKind,
    FilterId, FormatId, Limits, ProbeResult,
};
use libarchive_oxide::provider::{CodecCapabilities, CodecProvider, ProviderSet};
use libarchive_oxide::{ArchiveEngine, CreateOptions, PackageFindingCode, RpmValidator};

/// A single cpio entry: archive-native path, kind, and body bytes.
type CpioEntry = (&'static [u8], EntryKind, Vec<u8>);

const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TYPE_STRING: u32 = 6;

/// Builds a compressed (or plain) cpio payload from named entries.
fn build_cpio(filter: Option<FilterId>, entries: &[CpioEntry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Cpio)
                .with_filter(filter),
        )
        .expect("create cpio writer");
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
    writer.finish().expect("finish cpio")
}

/// A small, safe set of payload entries.
fn payload_entries() -> Vec<CpioEntry> {
    vec![
        (
            b"usr/bin/demo".as_slice(),
            EntryKind::File,
            b"#!/bin/sh\necho hi\n".to_vec(),
        ),
        (
            b"etc/demo.conf".as_slice(),
            EntryKind::File,
            b"k=v\n".to_vec(),
        ),
    ]
}

/// The 96-byte RPM lead with a valid magic and zeroed remainder.
fn build_lead() -> Vec<u8> {
    let mut lead = vec![0u8; 96];
    lead[..4].copy_from_slice(&LEAD_MAGIC);
    lead[4] = 3; // major
    lead[5] = 0; // minor
    lead
}

/// One 16-byte header index entry.
fn index_entry(tag: u32, kind: u32, offset: u32, count: u32) -> Vec<u8> {
    let mut entry = Vec::with_capacity(16);
    entry.extend_from_slice(&tag.to_be_bytes());
    entry.extend_from_slice(&kind.to_be_bytes());
    entry.extend_from_slice(&offset.to_be_bytes());
    entry.extend_from_slice(&count.to_be_bytes());
    entry
}

/// Assembles one RPM header structure from a raw index and data store.
fn header_bytes(index: &[u8], store: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC);
    out.push(0x01); // version
    out.extend_from_slice(&[0, 0, 0, 0]); // reserved
    let nindex = u32::try_from(index.len() / 16).unwrap();
    out.extend_from_slice(&nindex.to_be_bytes());
    out.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
    out.extend_from_slice(index);
    out.extend_from_slice(store);
    out
}

/// A minimal empty signature header (no index, no store, no padding needed).
fn signature_header() -> Vec<u8> {
    header_bytes(&[], &[])
}

/// A main header carrying the two payload tags.
fn main_header(payload_format: &[u8], payload_compressor: &[u8]) -> Vec<u8> {
    let mut store = Vec::new();
    let format_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(payload_format);
    store.push(0);
    let compressor_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(payload_compressor);
    store.push(0);

    let mut index = Vec::new();
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADFORMAT,
        TYPE_STRING,
        format_offset,
        1,
    ));
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADCOMPRESSOR,
        TYPE_STRING,
        compressor_offset,
        1,
    ));
    header_bytes(&index, &store)
}

/// Assembles a complete RPM from a format tag, compressor tag, and payload.
fn build_rpm(payload_format: &[u8], payload_compressor: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut rpm = build_lead();
    rpm.extend_from_slice(&signature_header());
    rpm.extend_from_slice(&main_header(payload_format, payload_compressor));
    rpm.extend_from_slice(payload);
    rpm
}

/// A conventional `PAYLOADCOMPRESSOR` tag for a filter.
fn compressor_tag(filter: Option<FilterId>) -> &'static [u8] {
    match filter {
        Some(FilterId::Gzip) => b"gzip",
        Some(FilterId::Xz) => b"xz",
        Some(FilterId::Zstd) => b"zstd",
        Some(FilterId::Bzip2) => b"bzip2",
        None | Some(_) => b"none",
    }
}

fn validate(bytes: &[u8]) -> libarchive_oxide::RpmValidation {
    RpmValidator::new().validate(Cursor::new(bytes.to_vec()))
}

// --- Happy path -----------------------------------------------------------

#[test]
fn well_formed_rpm_is_valid_across_payload_filters() {
    for filter in [
        None,
        Some(FilterId::Gzip),
        Some(FilterId::Xz),
        Some(FilterId::Zstd),
        Some(FilterId::Bzip2),
    ] {
        let payload = build_cpio(filter, &payload_entries());
        let rpm = build_rpm(b"cpio", compressor_tag(filter), &payload);
        let result = validate(&rpm);
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
            result.payload_filter(),
            filter,
            "detected payload filter for {filter:?}"
        );
        assert_eq!(result.payload_compressor(), Some(compressor_tag(filter)));
    }
}

// --- Adversarial: container structure -------------------------------------

#[test]
fn invalid_lead_magic_is_rejected() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let mut rpm = build_rpm(b"cpio", b"gzip", &payload);
    rpm[0] = 0x00; // corrupt the lead magic
    let result = validate(&rpm);
    assert!(!result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::InvalidLead));
}

#[test]
fn invalid_header_magic_is_rejected() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let mut rpm = build_rpm(b"cpio", b"gzip", &payload);
    // The signature header intro begins immediately after the 96-byte lead.
    rpm[96] = 0x00; // corrupt the header magic
    let result = validate(&rpm);
    assert!(!result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::InvalidHeader));
}

#[test]
fn oversized_header_is_rejected_as_bomb() {
    // Craft a signature header claiming a huge data store without providing it.
    let mut rpm = build_lead();
    let mut intro = Vec::new();
    intro.extend_from_slice(&HEADER_MAGIC);
    intro.push(0x01);
    intro.extend_from_slice(&[0, 0, 0, 0]);
    intro.extend_from_slice(&0u32.to_be_bytes()); // nindex
    intro.extend_from_slice(&50_000_000u32.to_be_bytes()); // hsize
    rpm.extend_from_slice(&intro);

    let limits = Limits::safe().with_metadata_bytes(Some(64 * 1024));
    let result = RpmValidator::new()
        .with_limits(limits)
        .validate(Cursor::new(rpm));
    assert!(!result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::HeaderTooLarge));
}

#[test]
fn truncated_payload_is_rejected() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let mut rpm = build_rpm(b"cpio", b"gzip", &payload);
    let keep = rpm.len().saturating_sub(24);
    rpm.truncate(keep);
    let result = validate(&rpm);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(
        result.has_code(PackageFindingCode::TruncatedMember)
            || result.has_code(PackageFindingCode::MalformedNesting),
        "expected truncation finding, got {:?}",
        result.findings()
    );
}

// --- Adversarial: payload profile -----------------------------------------

#[test]
fn wrong_payload_format_is_rejected() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let rpm = build_rpm(b"tar", b"gzip", &payload);
    let result = validate(&rpm);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::PayloadFormatMismatch));
}

#[test]
fn compressor_tag_mismatch_is_reported() {
    // Payload is xz, but the tag claims gzip.
    let payload = build_cpio(Some(FilterId::Xz), &payload_entries());
    let rpm = build_rpm(b"cpio", b"gzip", &payload);
    let result = validate(&rpm);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert_eq!(result.payload_filter(), Some(FilterId::Xz));
    assert!(result.has_code(PackageFindingCode::CompressorMismatch));
}

#[test]
fn traversal_entry_path_is_rejected() {
    let entries: Vec<CpioEntry> = vec![(
        b"../../etc/passwd".as_slice(),
        EntryKind::File,
        b"root:x:0:0\n".to_vec(),
    )];
    let payload = build_cpio(Some(FilterId::Gzip), &entries);
    let rpm = build_rpm(b"cpio", b"gzip", &payload);
    let result = validate(&rpm);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsafeEntryPath));
}

#[test]
fn decompression_bomb_is_bounded() {
    let entries: Vec<CpioEntry> = vec![(
        b"usr/share/blob".as_slice(),
        EntryKind::File,
        vec![0u8; 200_000],
    )];
    let payload = build_cpio(Some(FilterId::Gzip), &entries);
    let rpm = build_rpm(b"cpio", b"gzip", &payload);
    let limits = Limits::safe().with_decoded_total(Some(8 * 1024));
    let result = RpmValidator::new()
        .with_limits(limits)
        .validate(Cursor::new(rpm));
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
    let payload = build_cpio(Some(FilterId::Zstd), &payload_entries());
    let rpm = build_rpm(b"cpio", b"zstd", &payload);
    let providers = ProviderSet::builtins().with_codec_provider(DisabledZstd);
    let result = RpmValidator::new()
        .with_codec_providers(providers)
        .validate(Cursor::new(rpm));
    // The container reads and the zstd frame is recognized, but it cannot be
    // decoded, so the profile is not confirmed valid.
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert_eq!(result.payload_filter(), Some(FilterId::Zstd));
    assert!(result.has_code(PackageFindingCode::UnsupportedCompression));
}
