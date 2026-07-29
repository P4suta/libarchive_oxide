// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interoperability and failure tests for Android APK Signature Schemes v1/v2/v3.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::io::Cursor;

use libarchive_oxide_core::Limits;
use libarchive_oxide_package::{
    AppPackageProfile, AppPackageValidator, PackageFindingCode, PackageVerifier, TrustPolicy,
    VerificationDimension, ZipPackageProfile,
};

const AOSP_V2: &[u8] = include_bytes!("fixtures/android_apk_v2_v3/golden-aligned-v2-out.apk");
const AOSP_V3: &[u8] = include_bytes!("fixtures/android_apk_v2_v3/golden-aligned-v3-out.apk");
const AOSP_ECDSA_V2: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-with-ecdsa-sha256-p256.apk");
const AOSP_BAD_BLOCK_SIZE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-apk-sig-block-size-mismatch.apk");
const AOSP_ALGORITHM_LIST_MISMATCH: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-signatures-and-digests-block-mismatch.apk");
const AOSP_V3_LINEAGE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v1v2v3-with-rsa-2048-lineage-3-signers.apk");
const AOSP_V31: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-rsa-2048_2-tgt-33-1-tgt-28.apk");
const AOSP_V2_STRIPPED: &[u8] = include_bytes!("fixtures/android_apk_v2_v3/v2-stripped.apk");
const AOSP_V2_STRIPPED_WITH_UNKNOWN_SCHEMES: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-stripped-with-ignorable-signing-schemes.apk");
const AOSP_SDK_DEPENDENT_ALGORITHMS: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/golden-rsa-verity-out.apk");
const AOSP_ECDSA_P521: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-with-ecdsa-sha256-p521.apk");
const AOSP_RSA_1024: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-with-rsa-pkcs1-sha256-1024.apk");
const AOSP_RSA_16384: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v2-only-with-rsa-pkcs1-sha256-16384.apk");
const AOSP_V1_TWO_SIGNERS: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v1-only-two-signers.apk");
const AOSP_V1_TWO_SIGNER_INFOS: &[u8] = include_bytes!(
    "fixtures/android_apk_v2_v3/v1-only-with-signed-attrs-signerInfo1-good-signerInfo2-good.apk"
);
const AOSP_V1_BAD_SIGNER_INFO: &[u8] = include_bytes!(
    "fixtures/android_apk_v2_v3/\
     v1-only-with-signed-attrs-signerInfo1-wrong-signature-signerInfo2-good.apk"
);

fn verify(bytes: &[u8]) -> libarchive_oxide_package::VerificationReport {
    PackageVerifier::default().app(AppPackageProfile::AndroidApk, Cursor::new(bytes))
}

#[test]
fn aosp_rsa_v2_signature_and_content_digest_verify() {
    let report = verify(AOSP_V2);
    assert!(report.structure().container_readable());
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.trust(), VerificationDimension::Invalid);
    assert_eq!(report.signer_fingerprints().len(), 1);
}

#[test]
fn aosp_rsa_v3_signature_and_content_digest_verify() {
    let report = verify(AOSP_V3);
    assert!(report.structure().container_readable());
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.signer_fingerprints().len(), 1);
}

#[test]
fn aosp_ecdsa_p256_v2_signature_verifies() {
    let report = verify(AOSP_ECDSA_V2);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.signer_fingerprints().len(), 1);
}

#[test]
fn aosp_apk_v1_two_signers_both_verify_and_both_require_trust_pins() {
    let structure = AppPackageValidator::android_apk().validate(Cursor::new(AOSP_V1_TWO_SIGNERS));
    assert!(structure.signatures().apk_v1());
    assert!(!structure.signatures().apk_signing_block());

    let report = verify(AOSP_V1_TWO_SIGNERS);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.signer_fingerprints().len(), 2);
    assert_eq!(report.trust(), VerificationDimension::Invalid);

    let one_pin = PackageVerifier::new(
        TrustPolicy::offline().with_trusted_signer_sha256(report.signer_fingerprints()[0]),
    )
    .app(
        AppPackageProfile::AndroidApk,
        Cursor::new(AOSP_V1_TWO_SIGNERS),
    );
    assert_eq!(one_pin.trust(), VerificationDimension::Invalid);

    let trust = report
        .signer_fingerprints()
        .iter()
        .copied()
        .fold(TrustPolicy::offline(), |policy, fingerprint| {
            policy.with_trusted_signer_sha256(fingerprint)
        });
    let all_pinned = PackageVerifier::new(trust).app(
        AppPackageProfile::AndroidApk,
        Cursor::new(AOSP_V1_TWO_SIGNERS),
    );
    assert_eq!(all_pinned.trust(), VerificationDimension::Verified);
}

#[test]
fn every_cms_signer_info_must_verify() {
    let good = verify(AOSP_V1_TWO_SIGNER_INFOS);
    assert_eq!(
        good.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        good.findings()
    );
    assert_eq!(good.integrity(), VerificationDimension::Verified);
    assert!(!good.signer_fingerprints().is_empty());

    let wrong = verify(AOSP_V1_BAD_SIGNER_INFO);
    assert_eq!(
        wrong.signature_validity(),
        VerificationDimension::Invalid,
        "{:?}",
        wrong.findings()
    );
    assert!(wrong.has_code(PackageFindingCode::SignatureMismatch));
    assert_eq!(wrong.trust(), VerificationDimension::NotEvaluated);
}

#[test]
fn signer_identity_and_trust_pin_remain_separate() {
    let initial = verify(AOSP_V2);
    let fingerprint = initial.signer_fingerprints()[0];
    let verifier =
        PackageVerifier::new(TrustPolicy::offline().with_trusted_signer_sha256(fingerprint));
    let trusted = verifier.app(AppPackageProfile::AndroidApk, Cursor::new(AOSP_V2));
    assert_eq!(
        trusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(trusted.integrity(), VerificationDimension::Verified);
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn tampered_signed_content_keeps_signature_identity_but_fails_integrity() {
    let mut tampered = AOSP_V2.to_vec();
    let block_start = signing_block_start(&tampered);
    tampered[block_start - 1] ^= 0x01;
    let report = verify(&tampered);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Invalid,
        "{:?}",
        report.findings()
    );
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
}

#[test]
fn malformed_aosp_block_size_fails_closed() {
    let report = verify(AOSP_BAD_BLOCK_SIZE);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert_eq!(report.integrity(), VerificationDimension::NotEvaluated);
    assert!(report.has_code(PackageFindingCode::InvalidSignatureMetadata));
}

#[test]
fn mismatched_signature_and_digest_algorithm_lists_fail_closed() {
    let report = verify(AOSP_ALGORITHM_LIST_MISMATCH);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::InvalidSignatureMetadata));
}

#[test]
fn signing_block_capture_obeys_metadata_budget() {
    let verifier =
        PackageVerifier::default().with_limits(Limits::safe().with_metadata_bytes(Some(2048)));
    let report = verifier.app(AppPackageProfile::AndroidApk, Cursor::new(AOSP_V2));
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureResourceLimit));
}

#[test]
fn v3_proof_of_rotation_lineage_verifies_without_implying_trust() {
    let structure = AppPackageValidator::android_apk().validate(Cursor::new(AOSP_V3_LINEAGE));
    assert!(structure.signatures().apk_v1());
    assert!(structure.signatures().apk_v2());
    assert!(structure.signatures().apk_v3());
    let v1 = PackageVerifier::default().zip(ZipPackageProfile::Jar, Cursor::new(AOSP_V3_LINEAGE));
    assert_eq!(
        v1.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        v1.findings()
    );

    let report = verify(AOSP_V3_LINEAGE);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(report.trust(), VerificationDimension::Invalid);
    let rotation = report
        .android_apk_rotation()
        .expect("official v3 lineage evidence");
    assert!(!rotation.v31_present());
    assert_eq!(rotation.rotation_min_sdk(), None);
    assert!(!rotation.targets_dev_release());
    assert_eq!(rotation.lineage().len(), 3);
    assert_eq!(rotation.signers().len(), 1);
}

#[test]
fn v3_1_targeted_dev_release_rotation_verifies_both_blocks() {
    let structure = AppPackageValidator::android_apk().validate(Cursor::new(AOSP_V31));
    assert!(structure.signatures().apk_v3_1());
    let report = verify(AOSP_V31);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    let rotation = report
        .android_apk_rotation()
        .expect("official v3.1 rotation evidence");
    assert!(rotation.v31_present());
    assert_eq!(rotation.rotation_min_sdk(), Some(32));
    assert!(rotation.targets_dev_release());
    assert_eq!(rotation.signers().len(), 2);
    assert_eq!(rotation.lineage().len(), 2);
}

#[test]
fn authenticated_v1_metadata_rejects_stripped_v2_signatures() {
    for (name, fixture) in [
        ("v2-stripped.apk", AOSP_V2_STRIPPED),
        (
            "v2-stripped-with-ignorable-signing-schemes.apk",
            AOSP_V2_STRIPPED_WITH_UNKNOWN_SCHEMES,
        ),
    ] {
        let structure = AppPackageValidator::android_apk().validate(Cursor::new(fixture));
        assert!(structure.signatures().apk_v1(), "{name}");
        assert!(!structure.signatures().apk_v2(), "{name}");

        let report = verify(fixture);
        assert_eq!(
            report.signature_validity(),
            VerificationDimension::Invalid,
            "{name}: {:?}",
            report.findings()
        );
        assert!(
            report.has_code(PackageFindingCode::SignatureMismatch),
            "{name}: {:?}",
            report.findings()
        );
        assert_eq!(
            report.trust(),
            VerificationDimension::NotEvaluated,
            "{name}"
        );

        let jar_report =
            PackageVerifier::default().zip(ZipPackageProfile::Jar, Cursor::new(fixture));
        assert_eq!(
            jar_report.signature_validity(),
            VerificationDimension::Verified,
            "{name} must remain a valid ordinary signed JAR: {:?}",
            jar_report.findings()
        );
    }
}

#[test]
fn standard_and_fs_verity_signatures_and_content_digests_are_both_verified() {
    const STANDARD_SIGNATURE_OFFSET: usize = 9133;

    let report = verify(AOSP_SDK_DEPENDENT_ALGORITHMS);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );

    let mut tampered = AOSP_SDK_DEPENDENT_ALGORITHMS.to_vec();
    // The immutable AOSP fixture's first v2 record is RSA PKCS#1 SHA-256
    // (0x0103), selected on Android N/O. Its second record is the valid
    // fs-verity RSA variant (0x0421), selected from Android P. Mutate only the
    // standard signature: the later valid record must not hide this failure.
    assert_eq!(
        &tampered[STANDARD_SIGNATURE_OFFSET - 8..STANDARD_SIGNATURE_OFFSET - 4],
        &0x0103_u32.to_le_bytes()
    );
    assert_eq!(
        &tampered[STANDARD_SIGNATURE_OFFSET - 4..STANDARD_SIGNATURE_OFFSET],
        &256_u32.to_le_bytes()
    );
    tampered[STANDARD_SIGNATURE_OFFSET] ^= 1;
    let tampered = verify(&tampered);
    assert_eq!(
        tampered.signature_validity(),
        VerificationDimension::Invalid,
        "{:?}",
        tampered.findings()
    );
    assert_eq!(
        tampered.integrity(),
        VerificationDimension::NotEvaluated,
        "content integrity must not be claimed after an applicable signer signature failed"
    );
    assert_eq!(
        tampered.trust(),
        VerificationDimension::NotEvaluated,
        "invalid signer evidence must never reach trust policy"
    );
    assert!(tampered.has_code(PackageFindingCode::SignatureMismatch));
}

#[test]
fn ecdsa_p521_is_reported_as_unsupported_instead_of_a_signature_mismatch() {
    let report = verify(AOSP_ECDSA_P521);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Unsupported,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::NotEvaluated);
    assert!(report.has_code(PackageFindingCode::UnsupportedSignatureAlgorithm));
}

#[test]
fn rsa_sizes_outside_ring_boundary_are_reported_as_unsupported() {
    for (name, fixture) in [("RSA-1024", AOSP_RSA_1024), ("RSA-16384", AOSP_RSA_16384)] {
        let report = verify(fixture);
        assert_eq!(
            report.signature_validity(),
            VerificationDimension::Unsupported,
            "{name}: {:?}",
            report.findings()
        );
        assert_eq!(
            report.integrity(),
            VerificationDimension::NotEvaluated,
            "{name}"
        );
        assert!(
            report.has_code(PackageFindingCode::UnsupportedSignatureAlgorithm),
            "{name}: {:?}",
            report.findings()
        );
    }
}

fn signing_block_start(apk: &[u8]) -> usize {
    let eocd = apk
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("EOCD");
    let central_offset = u32::from_le_bytes([
        apk[eocd + 16],
        apk[eocd + 17],
        apk[eocd + 18],
        apk[eocd + 19],
    ]) as usize;
    let footer = central_offset - 24;
    let block_size = usize::try_from(u64::from_le_bytes([
        apk[footer],
        apk[footer + 1],
        apk[footer + 2],
        apk[footer + 3],
        apk[footer + 4],
        apk[footer + 5],
        apk[footer + 6],
        apk[footer + 7],
    ]))
    .expect("fixture signing block fits address space");
    central_offset - block_size - 8
}
