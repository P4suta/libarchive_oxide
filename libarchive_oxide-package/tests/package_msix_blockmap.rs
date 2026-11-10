// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! MSIX/APPX `AppxBlockMap.xml` integrity and resource-boundary tests.

#![allow(clippy::expect_used)]

use std::fmt::Write as _;
use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libarchive_oxide::{ArchivePath, EntryKind, EntryMetadata, Limits};
use libarchive_oxide::{ArchiveWriter, ZipMethod};
use libarchive_oxide_package::{
    AppPackageProfile, PackageFindingCode, PackageVerifier, TrustPolicy, VerificationDimension,
};
use sha2::{Digest, Sha256};

const MICROSOFT_UNSIGNED: &[u8] = include_bytes!("fixtures/msix_blockmap/TestWindows.msix");
const MICROSOFT_SIGNED: &[u8] = include_bytes!("fixtures/msix_blockmap/SignedUntrustedCert.appx");
const BLOCK_SIZE: usize = 64 * 1024;
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

#[derive(Debug)]
struct MapOptions {
    hash_method: &'static str,
    payload_map_name: &'static str,
    mutations: Vec<Mutation>,
    comment_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    OmitPayload,
    OmitManifest,
    IncludeContentTypes,
    DuplicatePayload,
    WrongPayloadHash,
    WrongPayloadSize,
    WrongPayloadLfh,
    OmitLastPayloadBlock,
    IgnorableExtension,
    AttributeFlood,
    DocumentType,
    WrongNamespace,
    NewerKnownNamespace,
}

impl Default for MapOptions {
    fn default() -> Self {
        Self {
            hash_method: SHA256_URI,
            payload_map_name: r"Assets\data.bin",
            mutations: Vec::new(),
            comment_bytes: 0,
        }
    }
}

impl MapOptions {
    fn has(&self, mutation: Mutation) -> bool {
        self.mutations.contains(&mutation)
    }
}

fn package(options: &MapOptions) -> Vec<u8> {
    let payload: Vec<u8> = (0..BLOCK_SIZE + 17)
        .map(|index| u8::try_from(index % 251).expect("bounded byte"))
        .collect();
    let manifest = br#"<?xml version="1.0"?><Package/>"#;
    let content_types = br#"<?xml version="1.0"?><Types/>"#;
    let block_map = build_block_map(options, &payload, manifest, content_types);

    let entries = [
        (b"Assets/data.bin".as_slice(), payload.as_slice()),
        (b"AppxManifest.xml".as_slice(), manifest.as_slice()),
        (b"AppxBlockMap.xml".as_slice(), block_map.as_bytes()),
        (b"[Content_Types].xml".as_slice(), content_types.as_slice()),
    ];
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::safe());
    for (name, body) in entries {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start MSIX entry");
        writer.write_data(body).expect("write MSIX entry");
        writer.end_entry().expect("end MSIX entry");
    }
    writer.finish().expect("finish MSIX ZIP")
}

fn build_block_map(
    options: &MapOptions,
    payload: &[u8],
    manifest: &[u8],
    content_types: &[u8],
) -> String {
    let namespace = if options.has(Mutation::WrongNamespace) {
        "urn:example:not-a-block-map"
    } else if options.has(Mutation::NewerKnownNamespace) {
        "http://schemas.microsoft.com/appx/2017/blockmap"
    } else {
        "http://schemas.microsoft.com/appx/2010/blockmap"
    };
    let mut block_map = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    if options.has(Mutation::DocumentType) {
        block_map.push_str("<!DOCTYPE BlockMap []>");
    }
    write!(
        &mut block_map,
        r#"<BlockMap xmlns="{namespace}" HashMethod="{}""#,
        options.hash_method
    )
    .expect("write BlockMap root");
    if options.has(Mutation::IgnorableExtension) {
        block_map.push_str(
            r#" xmlns:b4="http://schemas.microsoft.com/appx/2021/blockmap" IgnorableNamespaces="b4""#,
        );
    }
    if options.has(Mutation::AttributeFlood) {
        for index in 0..40 {
            write!(&mut block_map, r#" xmlns:x{index}="urn:example:x{index}""#)
                .expect("write excess namespace declaration");
        }
    }
    block_map.push('>');
    if options.comment_bytes != 0 {
        write!(
            &mut block_map,
            "<!--{}-->",
            "x".repeat(options.comment_bytes)
        )
        .expect("write XML comment");
    }
    if !options.has(Mutation::OmitPayload) {
        write_payload_record(&mut block_map, payload, options);
        if options.has(Mutation::DuplicatePayload) {
            block_map.push_str(r#"<File Name="Assets\data.bin" Size="0" LfhSize="45"></File>"#);
        }
    }
    if !options.has(Mutation::OmitManifest) {
        write!(
            &mut block_map,
            r#"<File Name="AppxManifest.xml" Size="{}" LfhSize="46"><Block Hash="{}"/></File>"#,
            manifest.len(),
            STANDARD.encode(Sha256::digest(manifest))
        )
        .expect("write manifest File");
    }
    if options.has(Mutation::IncludeContentTypes) {
        write!(
            &mut block_map,
            r#"<File Name="[Content_Types].xml" Size="{}" LfhSize="49"><Block Hash="{}"/></File>"#,
            content_types.len(),
            STANDARD.encode(Sha256::digest(content_types))
        )
        .expect("write prohibited footprint");
    }
    block_map.push_str("</BlockMap>");
    block_map
}

fn write_payload_record(block_map: &mut String, payload: &[u8], options: &MapOptions) {
    let payload_size = if options.has(Mutation::WrongPayloadSize) {
        payload.len() as u64 + 1
    } else {
        payload.len() as u64
    };
    let local_header_size = if options.has(Mutation::WrongPayloadLfh) {
        31
    } else {
        30 + b"Assets/data.bin".len()
    };
    write!(
        block_map,
        r#"<File Name="{}" Size="{payload_size}" LfhSize="{local_header_size}">"#,
        options.payload_map_name
    )
    .expect("write payload File");
    for (index, block) in payload.chunks(BLOCK_SIZE).enumerate() {
        if options.has(Mutation::OmitLastPayloadBlock) && index == 1 {
            continue;
        }
        let mut hash = Sha256::digest(block).to_vec();
        if options.has(Mutation::WrongPayloadHash) && index == 0 {
            hash[0] ^= 0x80;
        }
        write!(block_map, r#"<Block Hash="{}"/>"#, STANDARD.encode(hash))
            .expect("write payload Block");
    }
    if options.has(Mutation::IgnorableExtension) {
        write!(
            block_map,
            r#"<b4:FileHash Hash="{}"/>"#,
            STANDARD.encode(Sha256::digest(payload))
        )
        .expect("write ignorable FileHash");
    }
    block_map.push_str("</File>");
}

fn verify(bytes: &[u8]) -> libarchive_oxide_package::VerificationReport {
    PackageVerifier::default().app(AppPackageProfile::Msix, Cursor::new(bytes))
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

fn eocd_offset(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("committed fixture has an EOCD")
}

fn central_directory_offset(bytes: &[u8]) -> usize {
    let eocd = eocd_offset(bytes);
    let classic = le_u32(bytes, eocd + 16);
    if classic != u32::MAX {
        return classic as usize;
    }
    let locator = eocd.checked_sub(20).expect("ZIP64 locator precedes EOCD");
    assert_eq!(&bytes[locator..locator + 4], b"PK\x06\x07");
    let zip64 = usize::try_from(le_u64(bytes, locator + 8)).expect("ZIP64 offset fits");
    assert_eq!(&bytes[zip64..zip64 + 4], b"PK\x06\x06");
    usize::try_from(le_u64(bytes, zip64 + 48)).expect("central offset fits")
}

fn central_entry(bytes: &[u8], wanted: &[u8]) -> (usize, usize) {
    let mut central = central_directory_offset(bytes);
    loop {
        assert_eq!(&bytes[central..central + 4], b"PK\x01\x02");
        let name_len = usize::from(le_u16(bytes, central + 28));
        let extra_len = usize::from(le_u16(bytes, central + 30));
        let comment_len = usize::from(le_u16(bytes, central + 32));
        let name = &bytes[central + 46..central + 46 + name_len];
        if name == wanted {
            let local = usize::try_from(le_u32(bytes, central + 42)).expect("local offset fits");
            return (central, local);
        }
        central += 46 + name_len + extra_len + comment_len;
    }
}

#[test]
fn microsoft_msix_sdk_unsigned_fixture_verifies_block_map() {
    let report = verify(MICROSOFT_UNSIGNED);
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotPresent
    );
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);

    let allowed = PackageVerifier::new(TrustPolicy::offline().with_allow_unsigned(true))
        .app(AppPackageProfile::Msix, Cursor::new(MICROSOFT_UNSIGNED));
    assert_eq!(allowed.trust(), VerificationDimension::Verified);
}

#[test]
fn microsoft_multiblock_signed_fixture_verifies_signature_offline() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .app(AppPackageProfile::Msix, Cursor::new(MICROSOFT_SIGNED));
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.trust(), VerificationDimension::Invalid);
    assert_eq!(report.signer_fingerprints().len(), 1);

    let trusted = PackageVerifier::new(
        TrustPolicy::offline().with_trusted_signer_sha256(report.signer_fingerprints()[0]),
    )
    .app(AppPackageProfile::Msix, Cursor::new(MICROSOFT_SIGNED));
    assert_eq!(
        trusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn central_directory_metadata_tamper_invalidates_only_authenticode() {
    let mut tampered = MICROSOFT_SIGNED.to_vec();
    let central = central_directory_offset(&tampered);
    assert_eq!(&tampered[central..central + 4], b"PK\x01\x02");
    tampered[central + 12] ^= 0x01;

    let report = verify(&tampered);
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));
    assert_eq!(report.signer_fingerprints(), &[] as &[[u8; 32]]);
}

#[test]
fn payload_tamper_with_valid_zip_crc_breaks_block_map_and_authenticode() {
    let mut tampered = MICROSOFT_SIGNED.to_vec();
    let (central, local) = central_entry(&tampered, b"Tile.png");
    assert_eq!(
        le_u16(&tampered, central + 10),
        0,
        "fixture payload is stored"
    );
    assert_eq!(&tampered[local..local + 4], b"PK\x03\x04");
    let name_len = usize::from(le_u16(&tampered, local + 26));
    let extra_len = usize::from(le_u16(&tampered, local + 28));
    let body_offset = local + 30 + name_len + extra_len;
    let body_len = usize::try_from(le_u32(&tampered, central + 24)).expect("body length fits");
    tampered[body_offset + body_len / 2] ^= 0x80;
    let crc = crc32fast::hash(&tampered[body_offset..body_offset + body_len]);
    tampered[local + 14..local + 18].copy_from_slice(&crc.to_le_bytes());
    tampered[central + 16..central + 20].copy_from_slice(&crc.to_le_bytes());

    let report = verify(&tampered);
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));
}

#[test]
fn synthetic_two_block_stored_package_verifies_exact_boundaries() {
    let report = verify(&package(&MapOptions::default()));
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
}

#[test]
fn block_hash_tamper_is_invalid() {
    let options = MapOptions {
        mutations: vec![Mutation::WrongPayloadHash],
        ..MapOptions::default()
    };
    let report = verify(&package(&options));
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
}

#[test]
fn declared_size_and_local_header_mismatches_are_invalid() {
    for options in [
        MapOptions {
            mutations: vec![Mutation::WrongPayloadSize],
            ..MapOptions::default()
        },
        MapOptions {
            mutations: vec![Mutation::WrongPayloadLfh],
            ..MapOptions::default()
        },
    ] {
        let report = verify(&package(&options));
        assert_eq!(report.integrity(), VerificationDimension::Invalid);
        assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
    }
}

#[test]
fn every_non_footprint_file_requires_exact_block_map_coverage() {
    let missing = verify(&package(&MapOptions {
        mutations: vec![Mutation::OmitPayload],
        ..MapOptions::default()
    }));
    assert_eq!(missing.integrity(), VerificationDimension::Invalid);
    assert!(missing.has_code(PackageFindingCode::MissingIntegrityRecord));

    let extra = verify(&package(&MapOptions {
        payload_map_name: r"Assets\ghost.bin",
        ..MapOptions::default()
    }));
    assert_eq!(extra.integrity(), VerificationDimension::Invalid);
    assert!(extra.has_code(PackageFindingCode::MissingIntegrityRecord));
}

#[test]
fn manifest_and_content_types_footprint_rules_are_enforced() {
    let missing_manifest = verify(&package(&MapOptions {
        mutations: vec![Mutation::OmitManifest],
        ..MapOptions::default()
    }));
    assert_eq!(missing_manifest.integrity(), VerificationDimension::Invalid);
    assert!(missing_manifest.has_code(PackageFindingCode::InvalidIntegrityMetadata));

    let content_types = verify(&package(&MapOptions {
        mutations: vec![Mutation::IncludeContentTypes],
        ..MapOptions::default()
    }));
    assert_eq!(content_types.integrity(), VerificationDimension::Invalid);
    assert!(content_types.has_code(PackageFindingCode::InvalidIntegrityMetadata));
}

#[test]
fn duplicate_and_traversing_block_map_names_are_rejected() {
    let duplicate = verify(&package(&MapOptions {
        mutations: vec![Mutation::DuplicatePayload],
        ..MapOptions::default()
    }));
    assert_eq!(duplicate.integrity(), VerificationDimension::Invalid);
    assert!(duplicate.has_code(PackageFindingCode::InvalidIntegrityMetadata));

    let traversal = verify(&package(&MapOptions {
        payload_map_name: r"..\escape.bin",
        ..MapOptions::default()
    }));
    assert_eq!(traversal.integrity(), VerificationDimension::Invalid);
    assert!(traversal.has_code(PackageFindingCode::InvalidIntegrityMetadata));
}

#[test]
fn unsupported_hash_method_is_never_approximated() {
    let report = verify(&package(&MapOptions {
        hash_method: "http://www.w3.org/2001/04/xmlenc#sha512",
        ..MapOptions::default()
    }));
    assert_eq!(report.integrity(), VerificationDimension::Unsupported);
    assert!(report.has_code(PackageFindingCode::UnsupportedIntegrityAlgorithm));
}

#[test]
fn declared_ignorable_extension_is_skipped_without_weakening_core_checks() {
    let report = verify(&package(&MapOptions {
        mutations: vec![Mutation::IgnorableExtension],
        ..MapOptions::default()
    }));
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
}

#[test]
fn document_types_and_wrong_namespaces_are_rejected() {
    for mutation in [Mutation::DocumentType, Mutation::WrongNamespace] {
        let report = verify(&package(&MapOptions {
            mutations: vec![mutation],
            ..MapOptions::default()
        }));
        assert_eq!(report.integrity(), VerificationDimension::Invalid);
        assert!(report.has_code(PackageFindingCode::InvalidIntegrityMetadata));
    }
}

#[test]
fn known_encrypted_or_delta_block_map_vocabulary_is_explicitly_unsupported() {
    let report = verify(&package(&MapOptions {
        mutations: vec![Mutation::NewerKnownNamespace],
        ..MapOptions::default()
    }));
    assert_eq!(report.integrity(), VerificationDimension::Unsupported);
    assert!(report.has_code(PackageFindingCode::UnsupportedIntegrityScope));
}

#[test]
fn declared_file_size_requires_the_exact_block_count() {
    let report = verify(&package(&MapOptions {
        mutations: vec![Mutation::OmitLastPayloadBlock],
        ..MapOptions::default()
    }));
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::InvalidIntegrityMetadata));
}

#[test]
fn xml_nesting_and_metadata_budgets_are_enforced() {
    let nesting = PackageVerifier::default()
        .with_limits(Limits::safe().with_nesting(Some(2)))
        .app(
            AppPackageProfile::Msix,
            Cursor::new(package(&MapOptions::default())),
        );
    assert_eq!(nesting.integrity(), VerificationDimension::Invalid);
    assert!(nesting.has_code(PackageFindingCode::IntegrityResourceLimit));

    let attributes = verify(&package(&MapOptions {
        mutations: vec![Mutation::AttributeFlood],
        ..MapOptions::default()
    }));
    assert_eq!(attributes.integrity(), VerificationDimension::Invalid);
    assert!(attributes.has_code(PackageFindingCode::IntegrityResourceLimit));

    let metadata = PackageVerifier::default()
        .with_limits(Limits::safe().with_metadata_bytes(Some(2 * 1024)))
        .app(
            AppPackageProfile::Msix,
            Cursor::new(package(&MapOptions {
                comment_bytes: 4 * 1024,
                ..MapOptions::default()
            })),
        );
    assert!(
        metadata.has_code(PackageFindingCode::IntegrityResourceLimit)
            || metadata.has_code(PackageFindingCode::ContainerUnreadable),
        "{:?}",
        metadata.findings()
    );
}
