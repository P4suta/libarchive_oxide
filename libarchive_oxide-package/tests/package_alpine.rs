// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Alpine APK v2 interop and adversarial structure tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read, Write};
use std::ops::Range;

use flate2::Compression;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use libarchive_oxide_core::Limits;
use libarchive_oxide_package::{
    AlpineApkValidator, AlpineRsaPublicKey, PackageFindingCode, PackageVerifier, TrustPolicy,
    VerificationDimension,
};

const SIGNATURE: &[u8] = b".SIGN.RSA.alpine-devel@example.invalid.rsa.pub";
const PKGINFO: &[u8] = b"pkgname = demo\npkgver = 1.0-r0\narch = x86_64\nsize = 4\n";
const OFFICIAL_KEY_ID: &[u8] = b"alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub";
const OFFICIAL_APK: &[u8] = include_bytes!("fixtures/alpine_apk_v2/alpine-keys-2.5-r0.apk");
const OFFICIAL_KEY: &[u8] =
    include_bytes!("fixtures/alpine_apk_v2/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub");
const WRONG_KEY: &[u8] =
    include_bytes!("fixtures/alpine_apk_v2/wrong-alpine-devel-61666e3f.rsa.pub");
const OFFICIAL_KEY_FINGERPRINT: [u8; 32] = [
    0x5e, 0x03, 0xbe, 0xe6, 0xb1, 0x20, 0x94, 0xef, 0x8e, 0x01, 0x32, 0x3d, 0x8e, 0xfa, 0x0d, 0x59,
    0x29, 0x48, 0x7c, 0x78, 0x1d, 0xef, 0x11, 0x0f, 0xb2, 0xe8, 0xd0, 0x9f, 0xc4, 0x46, 0xf8, 0x99,
];

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let text = format!("{value:o}");
    let start = field.len().saturating_sub(text.len() + 1);
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
    field[field.len() - 1] = 0;
}

/// Produces one POSIX ustar record independently of the archive crate.
fn tar_record(name: &[u8], body: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 100);
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(
        &mut header[124..136],
        u64::try_from(body.len()).expect("fixture body size"),
    );
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());

    let mut record = header.to_vec();
    record.extend_from_slice(body);
    let padding = (512 - body.len() % 512) % 512;
    record.resize(record.len() + padding, 0);
    record
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("compress fixture segment");
    encoder.finish().expect("finish fixture segment")
}

fn apk_segments(segments: &[Vec<u8>]) -> Vec<u8> {
    let mut apk = Vec::new();
    for segment in segments {
        apk.extend_from_slice(&gzip(segment));
    }
    apk
}

fn gzip_member_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while start < bytes.len() {
        let mut decoder = GzDecoder::new(Cursor::new(&bytes[start..]));
        let mut plain = Vec::new();
        decoder
            .read_to_end(&mut plain)
            .expect("decode independent fixture gzip member");
        let consumed =
            usize::try_from(decoder.into_inner().position()).expect("gzip member length");
        assert!(consumed != 0, "gzip member parser must make progress");
        let end = start.checked_add(consumed).expect("gzip member end");
        assert!(end <= bytes.len(), "gzip member remains in fixture");
        ranges.push(start..end);
        start = end;
    }
    ranges
}

fn mutate_tar_entry_body(tar: &mut [u8], name_prefix: &[u8]) {
    let mut offset = 0_usize;
    while let Some(header) = tar.get(offset..offset.saturating_add(512)) {
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let name = &header[..name_end];
        let size_text = header[124..136]
            .iter()
            .copied()
            .take_while(|byte| *byte != 0 && *byte != b' ')
            .filter(|byte| *byte != b' ')
            .collect::<Vec<_>>();
        let size = usize::from_str_radix(
            std::str::from_utf8(&size_text).expect("fixture tar size is ASCII"),
            8,
        )
        .expect("fixture tar size is octal");
        let body_start = offset.checked_add(512).expect("tar body start");
        let padded = size.checked_add(511).expect("tar padded size") / 512 * 512;
        let next = body_start.checked_add(padded).expect("next tar header");
        assert!(next <= tar.len(), "tar entry remains in decoded member");
        if name.starts_with(name_prefix) {
            assert!(size != 0, "signature entry has a body");
            tar[body_start] ^= 1;
            return;
        }
        offset = next;
    }
    panic!("fixture has no requested tar entry");
}

fn official_key() -> AlpineRsaPublicKey {
    AlpineRsaPublicKey::from_pem(OFFICIAL_KEY_ID.to_vec(), OFFICIAL_KEY)
        .expect("parse official Alpine RSA key")
}

fn signed_apk() -> Vec<u8> {
    let signature = tar_record(SIGNATURE, b"not-a-real-signature");
    let control = tar_record(b".PKGINFO", PKGINFO);
    let mut data = tar_record(b"usr/bin/demo", b"demo");
    data.extend_from_slice(&[0_u8; 1024]);
    apk_segments(&[signature, control, data])
}

fn unsigned_apk() -> Vec<u8> {
    let control = tar_record(b".PKGINFO", PKGINFO);
    let mut data = tar_record(b"usr/bin/demo", b"demo");
    data.extend_from_slice(&[0_u8; 1024]);
    apk_segments(&[control, data])
}

#[test]
fn independent_three_member_gzip_fixture_is_structurally_valid() {
    let result = AlpineApkValidator::new().validate(Cursor::new(signed_apk()));
    assert!(result.container_readable(), "{:?}", result.findings());
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.signature_present());
    assert!(result.has_code(PackageFindingCode::SigningSchemeDetected));
}

#[test]
fn unsigned_package_is_valid_but_signature_is_not_present() {
    let bytes = unsigned_apk();
    let result = AlpineApkValidator::new().validate(Cursor::new(bytes.clone()));
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(!result.signature_present());
    assert!(result.has_code(PackageFindingCode::UnsignedPackage));

    let report = PackageVerifier::default().alpine_apk(Cursor::new(bytes));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotPresent
    );
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);
}

#[test]
fn signature_presence_is_never_reported_as_cryptographic_success() {
    let report = PackageVerifier::default().alpine_apk(Cursor::new(signed_apk()));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert_eq!(report.integrity(), VerificationDimension::NotPresent);
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);
}

#[test]
fn explicit_offline_policy_can_accept_proven_unsigned_packages() {
    let verifier = PackageVerifier::new(TrustPolicy::offline().with_allow_unsigned(true));
    let report = verifier.alpine_apk(Cursor::new(unsigned_apk()));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotPresent
    );
    assert_eq!(report.trust(), VerificationDimension::Verified);
}

#[test]
fn missing_pkginfo_and_invalid_metadata_are_rejected() {
    let mut data = tar_record(b"usr/bin/demo", b"demo");
    data.extend_from_slice(&[0_u8; 1024]);
    let missing = AlpineApkValidator::new().validate(Cursor::new(apk_segments(&[data])));
    assert!(!missing.profile_valid());
    assert!(missing.has_code(PackageFindingCode::MissingRequiredMember));

    let mut malformed = tar_record(
        b".PKGINFO",
        b"pkgname=demo\npkgver = 1.0-r0\narch = x86_64\n",
    );
    malformed.extend_from_slice(&[0_u8; 1024]);
    let invalid = AlpineApkValidator::new().validate(Cursor::new(apk_segments(&[malformed])));
    assert!(!invalid.profile_valid());
    assert!(invalid.has_code(PackageFindingCode::InvalidPackageMetadata));
}

#[test]
fn signature_after_control_and_traversing_paths_are_rejected() {
    let control = tar_record(b".PKGINFO", PKGINFO);
    let signature = tar_record(SIGNATURE, b"signature");
    let mut data = tar_record(b"../escape", b"hostile");
    data.extend_from_slice(&[0_u8; 1024]);
    let result =
        AlpineApkValidator::new().validate(Cursor::new(apk_segments(&[control, signature, data])));
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnexpectedMemberOrder));
    assert!(result.has_code(PackageFindingCode::UnsafeEntryPath));
}

#[test]
fn metadata_and_decoded_output_limits_fail_closed() {
    let mut pkginfo = tar_record(b".PKGINFO", PKGINFO);
    pkginfo.extend_from_slice(&[0_u8; 1024]);
    let metadata_limited = AlpineApkValidator::new()
        .with_limits(Limits::safe().with_metadata_bytes(Some(8)))
        .validate(Cursor::new(apk_segments(&[pkginfo])));
    assert!(!metadata_limited.profile_valid());
    assert!(
        metadata_limited.has_code(PackageFindingCode::MetadataTooLarge),
        "{:?}",
        metadata_limited.findings()
    );

    let decoded_limited = AlpineApkValidator::new()
        .with_limits(Limits::safe().with_decoded_total(Some(512)))
        .validate(Cursor::new(signed_apk()));
    assert!(!decoded_limited.profile_valid());
    assert!(
        decoded_limited.has_code(PackageFindingCode::DecompressionBomb)
            || decoded_limited.has_code(PackageFindingCode::ContainerUnreadable)
    );
}

#[test]
fn non_gzip_and_corrupt_gzip_are_not_misclassified_as_packages() {
    let plain = AlpineApkValidator::new().validate(Cursor::new(b"plain tar".to_vec()));
    assert!(!plain.container_readable());
    assert!(plain.has_code(PackageFindingCode::ContainerFormatMismatch));

    let corrupt = AlpineApkValidator::new().validate(Cursor::new(vec![0x1f, 0x8b, 0, 1, 2, 3]));
    assert!(!corrupt.container_readable());
    assert!(corrupt.has_code(PackageFindingCode::ContainerUnreadable));
}

#[test]
fn official_alpine_keys_package_separates_validity_from_trust() {
    let key = official_key();
    assert_eq!(key.fingerprint_sha256(), OFFICIAL_KEY_FINGERPRINT);

    let without_key = PackageVerifier::default().alpine_apk(Cursor::new(OFFICIAL_APK));
    assert!(
        without_key.structure().profile_valid(),
        "{:?}",
        without_key.findings()
    );
    assert_eq!(without_key.integrity(), VerificationDimension::Verified);
    assert_eq!(
        without_key.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert!(without_key.has_code(PackageFindingCode::MissingVerificationKey));

    let verified = PackageVerifier::default()
        .with_alpine_rsa_public_key(key.clone())
        .alpine_apk(Cursor::new(OFFICIAL_APK));
    assert_eq!(verified.integrity(), VerificationDimension::Verified);
    assert_eq!(
        verified.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(verified.trust(), VerificationDimension::Invalid);
    assert_eq!(verified.signer_fingerprints(), &[key.fingerprint_sha256()]);

    let trusted = PackageVerifier::new(
        TrustPolicy::offline().with_trusted_signer_sha256(key.fingerprint_sha256()),
    )
    .with_alpine_rsa_public_key(key)
    .alpine_apk(Cursor::new(OFFICIAL_APK));
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn official_fixture_control_data_signature_and_wrong_key_tampering_fail_closed() {
    let ranges = gzip_member_ranges(OFFICIAL_APK);
    assert_eq!(ranges.len(), 3);
    let key = official_key();

    let mut control_tampered = OFFICIAL_APK.to_vec();
    control_tampered[ranges[1].start + 4] ^= 1;
    let report = PackageVerifier::default()
        .with_alpine_rsa_public_key(key.clone())
        .alpine_apk(Cursor::new(control_tampered));
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Invalid,
        "{:?}",
        report.findings()
    );
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));

    let mut data_tampered = OFFICIAL_APK.to_vec();
    data_tampered[ranges[2].start + 4] ^= 1;
    let report = PackageVerifier::default()
        .with_alpine_rsa_public_key(key.clone())
        .alpine_apk(Cursor::new(data_tampered));
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert_eq!(report.signature_validity(), VerificationDimension::Verified);
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));

    let mut signature_tar = Vec::new();
    GzDecoder::new(Cursor::new(&OFFICIAL_APK[ranges[0].clone()]))
        .read_to_end(&mut signature_tar)
        .expect("decode official signature member");
    mutate_tar_entry_body(&mut signature_tar, b".SIGN.");
    let mut signature_tampered = gzip(&signature_tar);
    signature_tampered.extend_from_slice(&OFFICIAL_APK[ranges[1].start..]);
    let report = PackageVerifier::default()
        .with_alpine_rsa_public_key(key)
        .alpine_apk(Cursor::new(signature_tampered));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Invalid,
        "{:?}",
        report.findings()
    );
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));

    let wrong_key = AlpineRsaPublicKey::from_pem(OFFICIAL_KEY_ID.to_vec(), WRONG_KEY)
        .expect("parse independent wrong Alpine RSA key");
    let report = PackageVerifier::default()
        .with_alpine_rsa_public_key(wrong_key)
        .alpine_apk(Cursor::new(OFFICIAL_APK));
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));
}

#[test]
fn exact_control_capture_and_legacy_scope_are_explicitly_bounded() {
    let key = official_key();
    let limited = PackageVerifier::default()
        .with_limits(Limits::safe().with_metadata_bytes(Some(1_200)))
        .with_alpine_rsa_public_key(key.clone())
        .alpine_apk(Cursor::new(OFFICIAL_APK));
    assert_ne!(
        limited.signature_validity(),
        VerificationDimension::Verified
    );
    assert!(
        limited.has_code(PackageFindingCode::SignatureResourceLimit),
        "{:?}",
        limited.findings()
    );

    let legacy_key = AlpineRsaPublicKey::from_pem(
        b"alpine-devel@example.invalid.rsa.pub".to_vec(),
        OFFICIAL_KEY,
    )
    .expect("parse key under synthetic legacy key id");
    let legacy = PackageVerifier::default()
        .with_alpine_rsa_public_key(legacy_key)
        .alpine_apk(Cursor::new(signed_apk()));
    assert_eq!(
        legacy.signature_validity(),
        VerificationDimension::Unsupported
    );
    assert!(legacy.has_code(PackageFindingCode::UnsupportedIntegrityScope));
}

#[test]
fn dsa_signature_algorithm_is_explicitly_unsupported() {
    let signature = tar_record(
        b".SIGN.DSA.alpine-devel@example.invalid.dsa.pub",
        b"not-a-real-dsa-signature",
    );
    let control = tar_record(b".PKGINFO", PKGINFO);
    let mut data = tar_record(b"usr/bin/demo", b"demo");
    data.extend_from_slice(&[0_u8; 1024]);
    let report = PackageVerifier::default()
        .alpine_apk(Cursor::new(apk_segments(&[signature, control, data])));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Unsupported
    );
    assert!(report.has_code(PackageFindingCode::UnsupportedSignatureAlgorithm));
}
