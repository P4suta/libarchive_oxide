//! `NuGet` package-signature interoperability and adversarial tests.
//
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Cursor;

use libarchive_oxide_core::Limits;
use libarchive_oxide_package::{
    PackageFindingCode, PackageVerifier, TrustPolicy, VerificationDimension, ZipPackageProfile,
};

const OFFICIAL_SIGNED: &[u8] = include_bytes!("fixtures/nuget_signed/nuget.common.6.0.0.nupkg");
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
const SIGNATURE_NAME: &[u8] = b".signature.p7s";

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn eocd_offset(bytes: &[u8]) -> usize {
    let offset = bytes
        .windows(EOCD_SIGNATURE.len())
        .rposition(|window| window == EOCD_SIGNATURE);
    assert!(offset.is_some(), "committed fixture has a classic EOCD");
    offset.unwrap_or(0)
}

fn tamper_signature_octet() -> Vec<u8> {
    let mut package = OFFICIAL_SIGNED.to_vec();
    let eocd = eocd_offset(&package);
    let mut central = le_u32(&package, eocd + 16) as usize;
    loop {
        assert_eq!(&package[central..central + 4], CENTRAL_SIGNATURE);
        let name_length = le_u16(&package, central + 28) as usize;
        let extra_length = le_u16(&package, central + 30) as usize;
        let comment_length = le_u16(&package, central + 32) as usize;
        let name = &package[central + 46..central + 46 + name_length];
        if name == SIGNATURE_NAME {
            let local = le_u32(&package, central + 42) as usize;
            assert_eq!(&package[local..local + 4], LOCAL_SIGNATURE);
            let local_name_length = le_u16(&package, local + 26) as usize;
            let local_extra_length = le_u16(&package, local + 28) as usize;
            let body_offset = local + 30 + local_name_length + local_extra_length;
            let body_length = le_u32(&package, central + 24) as usize;
            package[body_offset] ^= 0x01;
            let crc = crc32fast::hash(&package[body_offset..body_offset + body_length]);
            package[local + 14..local + 18].copy_from_slice(&crc.to_le_bytes());
            package[central + 16..central + 20].copy_from_slice(&crc.to_le_bytes());
            return package;
        }
        central += 46 + name_length + extra_length + comment_length;
    }
}

fn tamper_authenticated_eocd_comment() -> Vec<u8> {
    let mut package = OFFICIAL_SIGNED.to_vec();
    let eocd = eocd_offset(&package);
    package[eocd + 20..eocd + 22].copy_from_slice(&1_u16.to_le_bytes());
    package.push(b'X');
    package
}

#[test]
fn official_nuget_org_author_and_repository_signature_verifies_offline() {
    let untrusted = PackageVerifier::new(TrustPolicy::offline())
        .zip(ZipPackageProfile::NuGet, Cursor::new(OFFICIAL_SIGNED));
    assert_eq!(untrusted.integrity(), VerificationDimension::Verified);
    assert_eq!(
        untrusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(untrusted.trust(), VerificationDimension::Invalid);
    assert_eq!(untrusted.signer_fingerprints().len(), 2);

    let mut policy = TrustPolicy::offline();
    for fingerprint in untrusted.signer_fingerprints() {
        policy = policy.with_trusted_signer_sha256(*fingerprint);
    }
    let trusted =
        PackageVerifier::new(policy).zip(ZipPackageProfile::NuGet, Cursor::new(OFFICIAL_SIGNED));
    assert_eq!(trusted.integrity(), VerificationDimension::Verified);
    assert_eq!(
        trusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn valid_signature_does_not_imply_issuer_trust() {
    let report =
        PackageVerifier::new(TrustPolicy::offline().with_trusted_signer_sha256([0x5a; 32]))
            .zip(ZipPackageProfile::NuGet, Cursor::new(OFFICIAL_SIGNED));
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(report.signature_validity(), VerificationDimension::Verified);
    assert_eq!(report.trust(), VerificationDimension::Invalid);
}

#[test]
fn authenticated_package_tamper_invalidates_integrity_and_signature() {
    let report = PackageVerifier::new(TrustPolicy::offline()).zip(
        ZipPackageProfile::NuGet,
        Cursor::new(tamper_authenticated_eocd_comment()),
    );
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
}

#[test]
fn malformed_signature_is_rejected_after_zip_crc_remains_valid() {
    let report = PackageVerifier::new(TrustPolicy::offline()).zip(
        ZipPackageProfile::NuGet,
        Cursor::new(tamper_signature_octet()),
    );
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::InvalidSignatureMetadata));
}

#[test]
fn signature_body_obeys_metadata_budget() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .with_limits(Limits::safe().with_metadata_bytes(Some(8 * 1024)))
        .zip(ZipPackageProfile::NuGet, Cursor::new(OFFICIAL_SIGNED));
    assert_ne!(report.signature_validity(), VerificationDimension::Verified);
    assert!(report.has_code(PackageFindingCode::SignatureResourceLimit));
}
