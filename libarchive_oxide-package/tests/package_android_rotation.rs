// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AOSP interoperability and fail-closed tests for APK v3 signer rotation.

use std::io::Cursor;

use libarchive_oxide_core::Limits;
use libarchive_oxide_package::{
    AppPackageProfile, PackageFindingCode, PackageVerifier, TrustPolicy, VerificationDimension,
};

const V3_DEV_RELEASE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v3-rsa-2048_2-tgt-dev-release.apk");
const V31_DEV_RELEASE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-rsa-2048_2-tgt-10000-dev-release.apk");
const V31_RELEASE_34: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-rsa-2048_2-tgt-34-1-tgt-28.apk");
const V3_LINEAGE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v1v2v3-with-rsa-2048-lineage-3-signers.apk");
const V3_INVALID_LINEAGE: &[u8] = include_bytes!(
    "fixtures/android_apk_v2_v3/\
     v1v2v3-with-rsa-2048-lineage-3-signers-invalid-lineage-attr.apk"
);
const V31_WRONG_LINEAGE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-2elem-incorrect-lineage.apk");
const V31_TAMPERED_LINEAGE_DIGEST: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-2elem-lineage-incorrect-digest.apk");
const V31_STRIPPED_BLOCK: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-block-stripped-v3-attr-value-33.apk");
const V31_STRIPPED_ATTRIBUTE: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-tgt-33-no-v3-attr.apk");
const V31_WITHOUT_V3: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-tgt-33-no-v3-block.apk");
const V31_WRONG_MINIMUM: &[u8] =
    include_bytes!("fixtures/android_apk_v2_v3/v31-tgt-34-v3-attr-value-33.apk");
const VERITY: &[u8] = include_bytes!("fixtures/android_apk_v2_v3/golden-rsa-verity-out.apk");

fn verify(bytes: &[u8]) -> libarchive_oxide_package::VerificationReport {
    PackageVerifier::default().app(AppPackageProfile::AndroidApk, Cursor::new(bytes))
}

#[test]
fn aosp_release_and_development_targeted_rotation_verify() {
    for (name, fixture, minimum, development) in [
        ("release SDK 34", V31_RELEASE_34, 34, false),
        ("development SDK 10000", V31_DEV_RELEASE, 10_000, true),
    ] {
        let report = verify(fixture);
        assert_eq!(
            report.signature_validity(),
            VerificationDimension::Verified,
            "{name}: {:?}",
            report.findings()
        );
        assert_eq!(
            report.integrity(),
            VerificationDimension::Verified,
            "{name}: {:?}",
            report.findings()
        );
        let rotation = report
            .android_apk_rotation()
            .expect("v3.1 report must carry rotation evidence");
        assert!(rotation.v31_present(), "{name}");
        assert_eq!(rotation.rotation_min_sdk(), Some(minimum), "{name}");
        assert_eq!(rotation.targets_dev_release(), development, "{name}");
        assert_eq!(rotation.signers().len(), 2, "{name}");
        assert_eq!(rotation.lineage().len(), 2, "{name}");
        assert_eq!(rotation.lineage()[0].flags(), 0x17, "{name}");
        assert_eq!(
            rotation.lineage()[0].next_signature_algorithm_id(),
            0x0103,
            "{name}"
        );
        assert_eq!(
            rotation.lineage()[1].signed_signature_algorithm_id(),
            0x0103,
            "{name}"
        );
        assert_eq!(
            rotation.lineage()[1].next_signature_algorithm_id(),
            0,
            "{name}"
        );
    }
}

#[test]
fn v3_development_release_overlap_is_an_authenticated_signer_range() {
    let report = verify(V3_DEV_RELEASE);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    let rotation = report
        .android_apk_rotation()
        .expect("v3 targeted signer lineage");
    assert!(!rotation.v31_present());
    assert_eq!(rotation.rotation_min_sdk(), None);
    assert!(
        rotation
            .signers()
            .iter()
            .any(libarchive_oxide_package::AndroidApkTargetedSignerReport::targets_dev_release)
    );
}

#[test]
fn aosp_lineage_and_targeted_rotation_negatives_fail_closed() {
    for (name, fixture) in [
        ("invalid v3 lineage signature", V3_INVALID_LINEAGE),
        ("v3.1 wrong lineage key", V31_WRONG_LINEAGE),
        ("v3.1 tampered lineage digest", V31_TAMPERED_LINEAGE_DIGEST),
        ("stripped v3.1 block", V31_STRIPPED_BLOCK),
        (
            "stripped rotation-min-sdk attribute",
            V31_STRIPPED_ATTRIBUTE,
        ),
        ("v3.1 without v3 coexistence", V31_WITHOUT_V3),
        ("rotation-min-sdk mismatch", V31_WRONG_MINIMUM),
    ] {
        let report = verify(fixture);
        assert_eq!(
            report.signature_validity(),
            VerificationDimension::Invalid,
            "{name}: {:?}",
            report.findings()
        );
        assert_eq!(
            report.integrity(),
            VerificationDimension::NotEvaluated,
            "{name}"
        );
        assert_eq!(
            report.trust(),
            VerificationDimension::NotEvaluated,
            "{name}"
        );
        assert!(
            report.has_code(PackageFindingCode::SignatureMismatch)
                || report.has_code(PackageFindingCode::InvalidSignatureMetadata),
            "{name}: {:?}",
            report.findings()
        );
    }
}

#[test]
fn valid_lineage_does_not_turn_ancestors_into_implicit_trust_roots() {
    let initial = verify(V3_LINEAGE);
    let rotation = initial
        .android_apk_rotation()
        .expect("three-level lineage evidence");
    assert_eq!(rotation.lineage().len(), 3);
    assert_eq!(initial.trust(), VerificationDimension::Invalid);

    let policy = initial
        .signer_fingerprints()
        .iter()
        .copied()
        .fold(TrustPolicy::offline(), |policy, fingerprint| {
            policy.with_trusted_signer_sha256(fingerprint)
        });
    let trusted =
        PackageVerifier::new(policy).app(AppPackageProfile::AndroidApk, Cursor::new(V3_LINEAGE));
    assert_eq!(
        trusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(trusted.integrity(), VerificationDimension::Verified);
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
    assert!(
        rotation
            .lineage()
            .iter()
            .any(|level| !initial.signer_fingerprints().contains(&level.fingerprint())),
        "at least one verified intermediate lineage certificate is not an active signer pin"
    );
}

#[test]
fn fs_verity_tamper_keeps_signer_validity_separate_from_integrity() {
    let mut tampered = VERITY.to_vec();
    // Change the ID of the first local-header zero-length extra field. The ZIP
    // and v1 entry payloads remain valid, while v2/v3 content authentication
    // (including fs-verity) covers this exact local-header byte.
    tampered[44] ^= 0x01;
    let report = verify(&tampered);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::IntegrityMismatch));
    assert_eq!(report.trust(), VerificationDimension::Invalid);
}

#[test]
fn fs_verity_block_buffer_obeys_the_in_flight_resource_limit() {
    let verifier =
        PackageVerifier::default().with_limits(Limits::safe().with_in_flight_bytes(Some(4095)));
    let report = verifier.app(AppPackageProfile::AndroidApk, Cursor::new(VERITY));
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::NotEvaluated);
    assert!(report.has_code(PackageFindingCode::SignatureResourceLimit));
    assert_eq!(report.trust(), VerificationDimension::Invalid);
}
