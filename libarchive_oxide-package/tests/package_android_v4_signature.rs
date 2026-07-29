// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interoperability and adversarial tests for explicit APK v4/v4.1 sidecars.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::io::{self, Cursor, Read};
use std::ops::Range;

use libarchive_oxide_core::Limits;
use libarchive_oxide_package::{
    AndroidApkV4Revision, AppPackageProfile, PackageFindingCode, PackageVerifier, TrustPolicy,
    VerificationDimension,
};

const CTS_V4_APK: &[u8] = include_bytes!("fixtures/android_apk_v4/v4-digest-v2v3.apk");
const CTS_V4_IDSIG: &[u8] = include_bytes!("fixtures/android_apk_v4/v4-digest-v2v3.apk.idsig");
const AOSP_V41_APK: &[u8] =
    include_bytes!("fixtures/android_apk_v4/v31-rsa-2048_2-tgt-10000-dev-release.apk");
const AOSP_V41_IDSIG: &[u8] =
    include_bytes!("fixtures/android_apk_v4/v31-rsa-2048_2-tgt-10000-dev-release.apk.idsig");
const AOSP_V41_WRONG_DIGEST_APK: &[u8] =
    include_bytes!("fixtures/android_apk_v4/v41-digest-mismatched-with-v31.apk");
const AOSP_V41_WRONG_DIGEST_IDSIG: &[u8] =
    include_bytes!("fixtures/android_apk_v4/v41-digest-mismatched-with-v31.apk.idsig");

fn verify(apk: &[u8], idsig: &[u8]) -> libarchive_oxide_package::VerificationReport {
    PackageVerifier::default().android_apk_with_v4_sidecar(Cursor::new(apk), Cursor::new(idsig))
}

#[derive(Debug)]
struct SigningInfoLayout {
    algorithm: usize,
    signature: Range<usize>,
}

#[derive(Debug)]
struct IdsigLayout {
    hashing_info: Range<usize>,
    primary: SigningInfoLayout,
    extra_block_ids: Vec<usize>,
    extra_signing_infos: Vec<SigningInfoLayout>,
    tree: Option<Range<usize>>,
}

fn read_u32(bytes: &[u8], offset: usize) -> usize {
    let encoded: [u8; 4] = bytes[offset..offset + 4]
        .try_into()
        .expect("fixture u32 is in bounds");
    u32::from_le_bytes(encoded) as usize
}

fn take_sized(bytes: &[u8], cursor: &mut usize) -> Range<usize> {
    let length = read_u32(bytes, *cursor);
    *cursor += 4;
    let range = *cursor..*cursor + length;
    assert!(range.end <= bytes.len(), "fixture sized field is in bounds");
    *cursor = range.end;
    range
}

fn signing_info_layout(bytes: &[u8], cursor: &mut usize) -> SigningInfoLayout {
    let _apk_digest = take_sized(bytes, cursor);
    let _certificate = take_sized(bytes, cursor);
    let _additional_data = take_sized(bytes, cursor);
    let _public_key = take_sized(bytes, cursor);
    let algorithm = *cursor;
    *cursor += 4;
    let signature = take_sized(bytes, cursor);
    SigningInfoLayout {
        algorithm,
        signature,
    }
}

fn idsig_layout(bytes: &[u8]) -> IdsigLayout {
    let mut cursor = 4;
    let hashing_info = take_sized(bytes, &mut cursor);
    let signing_infos = take_sized(bytes, &mut cursor);
    let tree = (cursor < bytes.len()).then(|| take_sized(bytes, &mut cursor));
    assert_eq!(cursor, bytes.len(), "fixture sidecar has no trailing bytes");

    let mut signing_cursor = signing_infos.start;
    let primary = signing_info_layout(bytes, &mut signing_cursor);
    let mut extra_block_ids = Vec::new();
    let mut extra_signing_infos = Vec::new();
    while signing_cursor < signing_infos.end {
        extra_block_ids.push(signing_cursor);
        signing_cursor += 4;
        let nested = take_sized(bytes, &mut signing_cursor);
        let mut nested_cursor = nested.start;
        extra_signing_infos.push(signing_info_layout(bytes, &mut nested_cursor));
        assert_eq!(
            nested_cursor, nested.end,
            "fixture nested signing info has no trailing bytes"
        );
    }
    assert_eq!(
        signing_cursor, signing_infos.end,
        "fixture signing infos end exactly"
    );
    IdsigLayout {
        hashing_info,
        primary,
        extra_block_ids,
        extra_signing_infos,
        tree,
    }
}

fn assert_v4_code(report: &libarchive_oxide_package::VerificationReport, code: PackageFindingCode) {
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert!(
        v4.findings().iter().any(|finding| finding.code() == code),
        "expected {code}, got {:?}",
        v4.findings()
    );
}

#[test]
fn official_cts_v4_sidecar_verifies_signature_binding_root_and_tree() {
    let report = verify(CTS_V4_APK, CTS_V4_IDSIG);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.revision(), Some(AndroidApkV4Revision::V4_0));
    assert_eq!(
        v4.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        v4.findings()
    );
    assert_eq!(
        v4.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        v4.findings()
    );
    assert_eq!(v4.trust(), VerificationDimension::Invalid);
    assert_eq!(v4.signer_fingerprints().len(), 1);
    assert!(v4.findings().is_empty(), "{:?}", v4.findings());
}

#[test]
fn official_apksig_v41_verifies_both_signers_and_v31_specific_digest() {
    let report = verify(AOSP_V41_APK, AOSP_V41_IDSIG);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.revision(), Some(AndroidApkV4Revision::V4_1));
    assert_eq!(
        v4.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        v4.findings()
    );
    assert_eq!(
        v4.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        v4.findings()
    );
    assert_eq!(v4.trust(), VerificationDimension::Invalid);
    assert_eq!(v4.signer_fingerprints().len(), 2);
    assert!(v4.findings().is_empty(), "{:?}", v4.findings());
}

#[test]
fn official_apksig_v41_digest_mismatch_is_rejected_as_sidecar_binding_failure() {
    let report = verify(AOSP_V41_WRONG_DIGEST_APK, AOSP_V41_WRONG_DIGEST_IDSIG);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.revision(), Some(AndroidApkV4Revision::V4_1));
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert!(
        v4.findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::SignatureSidecarMismatch),
        "{:?}",
        v4.findings()
    );
}

#[test]
fn optional_sidecar_absence_is_explicitly_not_evaluated() {
    let report =
        PackageVerifier::default().app(AppPackageProfile::AndroidApk, Cursor::new(CTS_V4_APK));
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries optional v4 result");
    assert_eq!(v4.revision(), None);
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.trust(), VerificationDimension::NotEvaluated);
    assert_v4_code(&report, PackageFindingCode::SignatureSidecarNotProvided);
}

#[test]
fn malformed_or_truncated_sidecars_have_typed_parse_failures() {
    let mut wrong_version = CTS_V4_IDSIG.to_vec();
    wrong_version[..4].copy_from_slice(&99_u32.to_le_bytes());
    for idsig in [&CTS_V4_IDSIG[..3], wrong_version.as_slice()] {
        let report = verify(CTS_V4_APK, idsig);
        let v4 = report
            .android_apk_v4()
            .expect("Android report carries v4 result");
        assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
        assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
        assert_v4_code(&report, PackageFindingCode::InvalidSignatureSidecar);
    }
}

#[test]
fn unsupported_hash_and_signature_algorithms_are_not_downgraded() {
    let layout = idsig_layout(CTS_V4_IDSIG);

    let mut unknown_hash = CTS_V4_IDSIG.to_vec();
    unknown_hash[layout.hashing_info.start..layout.hashing_info.start + 4]
        .copy_from_slice(&2_u32.to_le_bytes());
    let hash_report = verify(CTS_V4_APK, &unknown_hash);
    let hash_v4 = hash_report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(hash_v4.integrity(), VerificationDimension::Unsupported);
    assert_eq!(
        hash_v4.signature_validity(),
        VerificationDimension::Unsupported
    );
    assert_v4_code(
        &hash_report,
        PackageFindingCode::UnsupportedIntegrityAlgorithm,
    );

    let mut unknown_signature = CTS_V4_IDSIG.to_vec();
    unknown_signature[layout.primary.algorithm..layout.primary.algorithm + 4]
        .copy_from_slice(&0xdead_beef_u32.to_le_bytes());
    let signature_report = verify(CTS_V4_APK, &unknown_signature);
    let signature_v4 = signature_report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(
        signature_v4.integrity(),
        VerificationDimension::NotEvaluated
    );
    assert_eq!(
        signature_v4.signature_validity(),
        VerificationDimension::Unsupported
    );
    assert_v4_code(
        &signature_report,
        PackageFindingCode::UnsupportedSignatureAlgorithm,
    );
}

#[test]
fn every_v41_signing_info_signature_is_verified() {
    let layout = idsig_layout(AOSP_V41_IDSIG);
    let secondary = layout
        .extra_signing_infos
        .first()
        .expect("v4.1 fixture has a secondary signer");
    let mut tampered = AOSP_V41_IDSIG.to_vec();
    tampered[secondary.signature.start] ^= 0x80;

    let report = verify(AOSP_V41_APK, &tampered);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert_eq!(
        v4.signer_fingerprints().len(),
        1,
        "the verified primary signer remains independently identified"
    );
    assert_v4_code(&report, PackageFindingCode::SignatureMismatch);
}

#[test]
fn a_sidecar_for_tampered_apk_bytes_is_rejected_by_v2_v3_binding() {
    let mut wrong_apk = CTS_V4_APK.to_vec();
    wrong_apk[0] ^= 0x01;
    let report = verify(&wrong_apk, CTS_V4_IDSIG);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert_v4_code(&report, PackageFindingCode::SignatureSidecarMismatch);
}

#[test]
fn v41_block_id_must_bind_to_the_v31_signer() {
    let layout = idsig_layout(AOSP_V41_IDSIG);
    let block_id = *layout
        .extra_block_ids
        .first()
        .expect("v4.1 fixture has an additional signing-info block");
    let mut wrong_id = AOSP_V41_IDSIG.to_vec();
    wrong_id[block_id..block_id + 4].copy_from_slice(&0x0102_0304_u32.to_le_bytes());

    let report = verify(AOSP_V41_APK, &wrong_id);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert_eq!(v4.signer_fingerprints().len(), 2);
    assert_v4_code(&report, PackageFindingCode::SignatureSidecarMismatch);
}

#[test]
fn serialized_tree_tampering_keeps_signature_and_integrity_separate() {
    let layout = idsig_layout(CTS_V4_IDSIG);
    let tree = layout.tree.expect("CTS sidecar carries a serialized tree");
    let mut tampered = CTS_V4_IDSIG.to_vec();
    tampered[tree.start] ^= 0x40;

    let report = verify(CTS_V4_APK, &tampered);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::Invalid);
    assert_eq!(v4.signature_validity(), VerificationDimension::Verified);
    assert_v4_code(&report, PackageFindingCode::IntegrityMismatch);
}

#[test]
fn sidecar_and_merkle_allocations_obey_metadata_budget() {
    let verifier =
        PackageVerifier::default().with_limits(Limits::safe().with_metadata_bytes(Some(1024)));
    let report =
        verifier.android_apk_with_v4_sidecar(Cursor::new(CTS_V4_APK), Cursor::new(CTS_V4_IDSIG));
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert_v4_code(&report, PackageFindingCode::SignatureResourceLimit);
}

#[test]
fn all_v41_signers_must_be_explicitly_trusted_offline() {
    let untrusted = verify(AOSP_V41_APK, AOSP_V41_IDSIG);
    let signer_fingerprints = untrusted
        .android_apk_v4()
        .expect("Android report carries v4 result")
        .signer_fingerprints()
        .to_vec();
    assert_eq!(signer_fingerprints.len(), 2);

    let one_pin = TrustPolicy::offline().with_trusted_signer_sha256(signer_fingerprints[0]);
    let one_pin_report = PackageVerifier::new(one_pin)
        .android_apk_with_v4_sidecar(Cursor::new(AOSP_V41_APK), Cursor::new(AOSP_V41_IDSIG));
    assert_eq!(
        one_pin_report
            .android_apk_v4()
            .expect("Android report carries v4 result")
            .trust(),
        VerificationDimension::Invalid
    );

    let every_pin = signer_fingerprints
        .iter()
        .copied()
        .fold(TrustPolicy::offline(), |policy, fingerprint| {
            policy.with_trusted_signer_sha256(fingerprint)
        });
    let every_pin_report = PackageVerifier::new(every_pin)
        .android_apk_with_v4_sidecar(Cursor::new(AOSP_V41_APK), Cursor::new(AOSP_V41_IDSIG));
    assert_eq!(
        every_pin_report
            .android_apk_v4()
            .expect("Android report carries v4 result")
            .trust(),
        VerificationDimension::Verified
    );
}

#[derive(Debug)]
struct FailingRead;

impl Read for FailingRead {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic sidecar read failure"))
    }
}

#[test]
fn detached_sidecar_io_failure_is_typed_and_never_panics() {
    let report = PackageVerifier::default()
        .android_apk_with_v4_sidecar(Cursor::new(CTS_V4_APK), FailingRead);
    let v4 = report
        .android_apk_v4()
        .expect("Android report carries v4 result");
    assert_eq!(v4.integrity(), VerificationDimension::NotEvaluated);
    assert_eq!(v4.signature_validity(), VerificationDimension::Invalid);
    assert_v4_code(&report, PackageFindingCode::IntegrityReadFailure);
}
