// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RPM validation: happy-path lead/header/payload parsing plus a battery
//! of adversarial packages that must be refused without extraction.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;
use std::io::{Cursor, Read};
use std::rc::Rc;

use base64::Engine as _;
use libarchive_oxide::advanced::CodecCapabilities;
use libarchive_oxide::advanced::legacy::{CodecProvider, ProviderSet};
use libarchive_oxide::{ArchiveEngine, CreateOptions};
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, Codec, CodecStep, DirectionSet, EndOfInput, EntryKind,
    EntryMetadata, ErrorKind, FilterId, FormatId, Limits, ProbeResult,
};
use libarchive_oxide_package::{
    PackageFindingCode, PackageVerifier, RpmValidator, VerificationDimension,
};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

/// A single cpio entry: archive-native path, kind, and body bytes.
type CpioEntry = (&'static [u8], EntryKind, Vec<u8>);

const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TAG_PAYLOADSHA256: u32 = 5092;
const TAG_PAYLOADSHA256ALGO: u32 = 5093;
const TAG_PAYLOADSHA256ALT: u32 = 5097;
const TAG_PAYLOADSHA3_256: u32 = 5123;
const TAG_PAYLOADSHA3_256ALT: u32 = 5124;
const TAG_PAYLOADSHA512: u32 = 5121;
const TAG_PAYLOADSHA512ALT: u32 = 5122;
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;

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

/// One extra raw main-header tag: `(tag, type, count, data-store bytes)`.
type HeaderTag = (u32, u32, u32, Vec<u8>);

/// A main header carrying the payload tags and optional integrity metadata.
fn main_header_with_tags(
    payload_format: &[u8],
    payload_compressor: &[u8],
    extra_tags: &[HeaderTag],
) -> Vec<u8> {
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
    for (tag, kind, count, value) in extra_tags {
        let offset = u32::try_from(store.len()).unwrap();
        store.extend_from_slice(value);
        index.extend_from_slice(&index_entry(*tag, *kind, offset, *count));
    }
    header_bytes(&index, &store)
}

/// Assembles a complete RPM from a format tag, compressor tag, and payload.
fn build_rpm(payload_format: &[u8], payload_compressor: &[u8], payload: &[u8]) -> Vec<u8> {
    build_rpm_with_tags(payload_format, payload_compressor, payload, &[])
}

/// Assembles an RPM whose main header carries additional raw tags.
fn build_rpm_with_tags(
    payload_format: &[u8],
    payload_compressor: &[u8],
    payload: &[u8],
    extra_tags: &[HeaderTag],
) -> Vec<u8> {
    let mut rpm = build_lead();
    rpm.extend_from_slice(&signature_header());
    rpm.extend_from_slice(&main_header_with_tags(
        payload_format,
        payload_compressor,
        extra_tags,
    ));
    rpm.extend_from_slice(payload);
    rpm
}

/// Lowercase hexadecimal encoding used by RPM digest strings.
fn encode_hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(bytes.len() * 2 + 1);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)]);
        encoded.push(DIGITS[usize::from(byte & 0x0F)]);
    }
    encoded.push(0);
    encoded
}

/// A conventional `PAYLOADCOMPRESSOR` tag for a filter.
fn compressor_tag(filter: Option<FilterId>) -> &'static [u8] {
    match filter {
        Some(FilterId::Gzip) => b"gzip",
        Some(FilterId::Xz) => b"xz",
        Some(FilterId::Zstd) => b"zstd",
        Some(FilterId::Bzip2) => b"bzip2",
        Some(FilterId::Lz4) => b"lz4",
        None | Some(_) => b"none",
    }
}

/// Payload filters whose encoders are available in the selected package features.
fn enabled_payload_filters() -> Vec<Option<FilterId>> {
    // Gzip is part of the minimal codec substrate used by the package readers.
    vec![
        None,
        Some(FilterId::Gzip),
        #[cfg(feature = "xz")]
        Some(FilterId::Xz),
        #[cfg(feature = "zstd")]
        Some(FilterId::Zstd),
        #[cfg(feature = "bzip2")]
        Some(FilterId::Bzip2),
        #[cfg(feature = "lz4")]
        Some(FilterId::Lz4),
    ]
}

fn validate(bytes: &[u8]) -> libarchive_oxide_package::RpmValidation {
    RpmValidator::new().validate(Cursor::new(bytes.to_vec()))
}

/// Decodes the deterministic RPM 4.14.2.1 interoperability artifact.
fn rpm_414_fixture() -> Vec<u8> {
    let encoded = include_str!("fixtures/rpm/rpm-4.14.2.1-minimal.rpm.gz.b64")
        .split_whitespace()
        .collect::<String>();
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("decode checked-in RPM fixture");
    let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
    let mut rpm = Vec::new();
    decoder
        .read_to_end(&mut rpm)
        .expect("decompress checked-in RPM fixture");
    rpm
}

/// Finite RPM prefix followed by an endless byte stream.
///
/// Shared accounting lets the resource-limit test prove the verifier stops
/// reading instead of waiting for an EOF an adversarial source never supplies.
struct EndlessSuffix {
    prefix: Cursor<Vec<u8>>,
    observed: Rc<Cell<u64>>,
}

impl EndlessSuffix {
    fn new(prefix: Vec<u8>, observed: Rc<Cell<u64>>) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            observed,
        }
    }
}

impl Read for EndlessSuffix {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let prefix_count = self.prefix.read(buffer)?;
        let count = if prefix_count == 0 {
            buffer.fill(0xA5);
            buffer.len()
        } else {
            prefix_count
        };
        self.observed.set(
            self.observed
                .get()
                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX)),
        );
        Ok(count)
    }
}

// --- Happy path -----------------------------------------------------------

#[test]
fn rpm_414_rpmbuild_fixture_verifies_sha256_and_algorithm_id() {
    let rpm = rpm_414_fixture();
    let artifact_digest = encode_hex(&Sha256::digest(&rpm));
    assert_eq!(
        &artifact_digest[..64],
        b"3784a330734498a37479a57debc86722b73ed50ccc6b7202bfa078aa8d345b82",
        "the fixture must remain bound to its provenance record"
    );

    let report = PackageVerifier::default().rpm(Cursor::new(rpm));
    assert!(
        report.structure().container_readable(),
        "{:?}",
        report.findings()
    );
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);
    assert!(report.findings().is_empty(), "{:?}", report.findings());
}

#[test]
fn well_formed_rpm_is_valid_across_payload_filters() {
    for filter in enabled_payload_filters() {
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
        assert_eq!(result.integrity(), VerificationDimension::NotPresent);
    }
}

#[test]
fn declared_compressed_payload_sha2_and_sha3_digests_are_verified() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let tags = vec![
        (
            TAG_PAYLOADSHA256,
            TYPE_STRING_ARRAY,
            1,
            encode_hex(&Sha256::digest(&payload)),
        ),
        (
            TAG_PAYLOADSHA256ALGO,
            TYPE_INT32,
            1,
            8_u32.to_be_bytes().to_vec(),
        ),
        (
            TAG_PAYLOADSHA512,
            TYPE_STRING,
            1,
            encode_hex(&Sha512::digest(&payload)),
        ),
        (
            TAG_PAYLOADSHA3_256,
            TYPE_STRING,
            1,
            encode_hex(&Sha3_256::digest(&payload)),
        ),
    ];
    let rpm = build_rpm_with_tags(b"cpio", b"gzip", &payload, &tags);

    let validation = validate(&rpm);
    assert!(validation.profile_valid(), "{:?}", validation.findings());
    assert_eq!(validation.integrity(), VerificationDimension::Verified);

    let report = PackageVerifier::default().rpm(Cursor::new(rpm));
    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated,
        "payload integrity must never be promoted to signature validity"
    );
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);
}

#[test]
fn payload_digest_mismatch_does_not_conflate_structure_and_integrity() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let tags = vec![(
        TAG_PAYLOADSHA256,
        TYPE_STRING_ARRAY,
        1,
        encode_hex(&[0xA5; 32]),
    )];
    let rpm = build_rpm_with_tags(b"cpio", b"gzip", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(
        report.structure().profile_valid(),
        "the RPM structure remains valid when its independent digest fails"
    );
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::IntegrityMismatch)
    );
}

#[test]
fn compressed_payload_sha3_256_mismatch_is_invalid() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let tags = vec![(TAG_PAYLOADSHA3_256, TYPE_STRING, 1, encode_hex(&[0x3A; 32]))];
    let rpm = build_rpm_with_tags(b"cpio", b"gzip", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(report.findings().iter().any(|finding| {
        finding.code() == PackageFindingCode::IntegrityMismatch
            && finding.detail().contains("SHA3-256")
    }));
}

#[test]
fn malformed_payload_digest_metadata_is_invalid() {
    let payload = build_cpio(None, &payload_entries());
    let tags = vec![(
        TAG_PAYLOADSHA256,
        TYPE_STRING_ARRAY,
        1,
        b"not-a-sha256-digest\0".to_vec(),
    )];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::InvalidIntegrityMetadata)
    );
}

#[test]
fn unsupported_payload_digest_algorithm_id_is_not_claimed_as_verified() {
    let payload = build_cpio(None, &payload_entries());
    let tags = vec![
        (
            TAG_PAYLOADSHA256,
            TYPE_STRING_ARRAY,
            1,
            encode_hex(&Sha256::digest(&payload)),
        ),
        (
            TAG_PAYLOADSHA256ALGO,
            TYPE_INT32,
            1,
            2_u32.to_be_bytes().to_vec(),
        ),
    ];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Unsupported);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == PackageFindingCode::UnsupportedIntegrityAlgorithm })
    );
}

#[test]
fn uncompressed_payload_alt_digests_are_verified_when_bytes_are_identical() {
    let payload = build_cpio(None, &payload_entries());
    let tags = vec![
        (
            TAG_PAYLOADSHA256ALT,
            TYPE_STRING_ARRAY,
            1,
            encode_hex(&Sha256::digest(&payload)),
        ),
        (
            TAG_PAYLOADSHA512ALT,
            TYPE_STRING,
            1,
            encode_hex(&Sha512::digest(&payload)),
        ),
        (
            TAG_PAYLOADSHA3_256ALT,
            TYPE_STRING,
            1,
            encode_hex(&Sha3_256::digest(&payload)),
        ),
    ];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
}

#[test]
fn compressed_payload_alt_digest_has_precise_unsupported_contract() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let tags = vec![(
        TAG_PAYLOADSHA256ALT,
        TYPE_STRING_ARRAY,
        1,
        encode_hex(&[0x11; 32]),
    )];
    let rpm = build_rpm_with_tags(b"cpio", b"gzip", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Unsupported);
    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.code() == PackageFindingCode::UnsupportedIntegrityScope)
        .expect("compressed ALT finding");
    assert!(
        finding.detail().contains("decoded-stream hook"),
        "{}",
        finding.detail()
    );
}

#[test]
fn alt_digest_requires_declared_and_detected_uncompressed_payload() {
    let payload = build_cpio(Some(FilterId::Gzip), &payload_entries());
    let tags = vec![(
        TAG_PAYLOADSHA256ALT,
        TYPE_STRING_ARRAY,
        1,
        encode_hex(&Sha256::digest(&payload)),
    )];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(!report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Unsupported);
    assert!(report.findings().iter().any(|finding| {
        finding.code() == PackageFindingCode::UnsupportedIntegrityScope
            && finding.detail().contains("not proven uncompressed")
    }));
}

#[test]
fn malformed_alt_digest_is_invalid_not_unsupported() {
    let payload = build_cpio(None, &payload_entries());
    let tags = vec![(TAG_PAYLOADSHA3_256ALT, TYPE_STRING, 1, b"short\0".to_vec())];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let report = PackageVerifier::default().rpm(Cursor::new(rpm));

    assert!(report.structure().profile_valid());
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::InvalidIntegrityMetadata)
    );
}

#[test]
fn payload_digest_read_is_bounded_after_cpio_completion() {
    let payload = build_cpio(None, &payload_entries());
    let tags = vec![(
        TAG_PAYLOADSHA256,
        TYPE_STRING_ARRAY,
        1,
        encode_hex(&[0xA5; 32]),
    )];
    let rpm = build_rpm_with_tags(b"cpio", b"none", &payload, &tags);
    let rpm_len = u64::try_from(rpm.len()).unwrap();
    let observed = Rc::new(Cell::new(0));
    let reader = EndlessSuffix::new(rpm, Rc::clone(&observed));
    let limits = Limits::safe().with_decoded_total(Some(16 * 1024));
    let report = PackageVerifier::default().with_limits(limits).rpm(reader);

    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::IntegrityResourceLimit)
    );
    assert!(
        observed.get() <= rpm_len + 64 * 1024,
        "integrity verifier kept reading an endless suffix: {} bytes",
        observed.get()
    );
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
#[cfg(feature = "xz")]
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
        CodecCapabilities::new(DirectionSet::NONE)
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
    // Only the zstd magic is needed: the injected provider recognizes it but
    // advertises no decode capability, so no zstd encoder feature is required
    // to exercise the feature-off contract.
    let payload = [0x28, 0xB5, 0x2F, 0xFD, 0, 0, 0, 0];
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
