// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Streaming JAR-manifest and wheel-RECORD integrity verification.

#![allow(clippy::expect_used)]

use std::fmt::Write as _;
use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use libarchive_oxide::{ArchiveWriter, ReaderEvent, SeekArchiveReader, ZipMethod};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};
use libarchive_oxide_package::{
    AppPackageProfile, PackageFindingCode, PackageVerifier, TrustPolicy, VerificationDimension,
    ZipPackageProfile,
};
use sha2::{Digest, Sha256};

const SIGNED_JAR_APK: &[u8] = include_bytes!("fixtures/jar_apk_v1/jar-apk-v1-signed.apk");
const SIGNER_SHA256: [u8; 32] = [
    0x06, 0xf7, 0x3d, 0xd8, 0x45, 0x50, 0x55, 0x62, 0x14, 0x8c, 0x9b, 0x2d, 0x65, 0x8c, 0xe3, 0x59,
    0xa3, 0xf6, 0xe8, 0x6b, 0xdc, 0x09, 0x69, 0x60, 0x82, 0x6b, 0xa0, 0x4d, 0x0b, 0x2e, 0x41, 0x82,
];

fn build_zip(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Deflate, Limits::safe());
    for (name, body) in entries {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.clone()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).expect("start ZIP entry");
        writer.write_data(body).expect("write ZIP entry");
        writer.end_entry().expect("end ZIP entry");
    }
    writer.finish().expect("finish ZIP")
}

fn fixture_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut archive =
        SeekArchiveReader::new(Cursor::new(SIGNED_JAR_APK)).expect("open signed fixture");
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match archive.next_event().expect("read signed fixture") {
            ReaderEvent::Entry(metadata) => {
                current = (metadata.kind() == EntryKind::File)
                    .then(|| (metadata.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(bytes) => {
                if let Some((_, body)) = &mut current {
                    body.extend_from_slice(bytes);
                }
            },
            ReaderEvent::EndEntry => {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    entries
}

fn jar(digest_override: Option<&str>, signed: bool) -> Vec<u8> {
    let path = b"com/example/Main.class";
    let payload = b"\xca\xfe\xba\xbe demo class";
    let digest =
        digest_override.map_or_else(|| STANDARD.encode(Sha256::digest(payload)), str::to_string);
    let manifest = format!(
        "Manifest-Version: 1.0\r\n\r\nName: {}\r\nSHA-256-Digest: {digest}\r\n\r\n",
        String::from_utf8_lossy(path)
    );
    let mut entries = vec![
        (b"META-INF/MANIFEST.MF".to_vec(), manifest.into_bytes()),
        (path.to_vec(), payload.to_vec()),
    ];
    if signed {
        entries.push((b"META-INF/DEMO.SF".to_vec(), b"signature file".to_vec()));
        entries.push((b"META-INF/DEMO.RSA".to_vec(), b"cms container".to_vec()));
    }
    build_zip(&entries)
}

fn record_line(name: &[u8], body: &[u8]) -> String {
    format!(
        "{},sha256={},{}\n",
        String::from_utf8_lossy(name),
        URL_SAFE_NO_PAD.encode(Sha256::digest(body)),
        body.len()
    )
}

fn wheel(tamper_payload_digest: bool) -> Vec<u8> {
    let metadata_name = b"demo-1.0.dist-info/METADATA";
    let metadata = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";
    let wheel_name = b"demo-1.0.dist-info/WHEEL";
    let wheel = b"Wheel-Version: 1.0\nTag: py3-none-any\n";
    let payload_name = b"demo/__init__.py";
    let payload = b"VALUE = 1\n";
    let record_name = b"demo-1.0.dist-info/RECORD";

    let mut record = String::new();
    record.push_str(&record_line(metadata_name, metadata));
    record.push_str(&record_line(wheel_name, wheel));
    if tamper_payload_digest {
        writeln!(
            &mut record,
            "{},sha256={},{}",
            String::from_utf8_lossy(payload_name),
            URL_SAFE_NO_PAD.encode([0_u8; 32]),
            payload.len()
        )
        .expect("write RECORD row");
    } else {
        record.push_str(&record_line(payload_name, payload));
    }
    writeln!(&mut record, "{},,", String::from_utf8_lossy(record_name))
        .expect("write RECORD self row");

    build_zip(&[
        (metadata_name.to_vec(), metadata.to_vec()),
        (wheel_name.to_vec(), wheel.to_vec()),
        (payload_name.to_vec(), payload.to_vec()),
        (record_name.to_vec(), record.into_bytes()),
    ])
}

#[test]
fn jar_sha256_manifest_digest_is_verified_over_entry_bytes() {
    let bytes = jar(None, false);
    let report = PackageVerifier::default().zip(ZipPackageProfile::Jar, Cursor::new(bytes.clone()));
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotPresent
    );
    assert_eq!(report.trust(), VerificationDimension::NotEvaluated);
    assert!(report.findings().is_empty(), "{:?}", report.findings());

    let allowed = PackageVerifier::new(TrustPolicy::offline().with_allow_unsigned(true))
        .zip(ZipPackageProfile::Jar, Cursor::new(bytes));
    assert_eq!(allowed.trust(), VerificationDimension::Verified);
}

#[test]
fn jar_digest_mismatch_and_malformed_signature_fail_closed() {
    let invalid = PackageVerifier::default().zip(
        ZipPackageProfile::Jar,
        Cursor::new(jar(
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            false,
        )),
    );
    assert_eq!(invalid.integrity(), VerificationDimension::Invalid);
    assert!(
        invalid
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::IntegrityMismatch)
    );

    let signed =
        PackageVerifier::default().zip(ZipPackageProfile::Jar, Cursor::new(jar(None, true)));
    assert_eq!(signed.integrity(), VerificationDimension::Verified);
    assert_eq!(signed.signature_validity(), VerificationDimension::Invalid);
    assert!(
        signed
            .findings()
            .iter()
            .any(|finding| { finding.code() == PackageFindingCode::InvalidSignatureMetadata })
    );
}

#[test]
fn malformed_or_unsupported_jar_digest_fails_closed() {
    let malformed = PackageVerifier::default().zip(
        ZipPackageProfile::Jar,
        Cursor::new(jar(Some("not base64!"), false)),
    );
    assert_eq!(malformed.integrity(), VerificationDimension::Invalid);
    assert!(
        malformed
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::InvalidIntegrityMetadata)
    );

    let payload = b"payload";
    let manifest = format!(
        "Manifest-Version: 1.0\r\n\r\nName: value.bin\r\nSHA1-Digest: {}\r\n\r\n",
        STANDARD.encode([0_u8; 20])
    );
    let unsupported = PackageVerifier::default().zip(
        ZipPackageProfile::Jar,
        Cursor::new(build_zip(&[
            (b"META-INF/MANIFEST.MF".to_vec(), manifest.into_bytes()),
            (b"value.bin".to_vec(), payload.to_vec()),
        ])),
    );
    assert_eq!(unsupported.integrity(), VerificationDimension::Unsupported);
}

#[test]
fn every_non_signature_jar_entry_requires_a_manifest_digest() {
    let covered = b"covered";
    let manifest = format!(
        "Manifest-Version: 1.0\r\n\r\n\
         Name: covered.bin\r\nSHA-256-Digest: {}\r\n\r\n\
         Name: uncovered.bin\r\n\r\n",
        STANDARD.encode(Sha256::digest(covered))
    );
    let report = PackageVerifier::default().zip(
        ZipPackageProfile::Jar,
        Cursor::new(build_zip(&[
            (b"META-INF/MANIFEST.MF".to_vec(), manifest.into_bytes()),
            (b"covered.bin".to_vec(), covered.to_vec()),
            (b"uncovered.bin".to_vec(), b"unsigned".to_vec()),
        ])),
    );
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(report.findings().iter().any(|finding| {
        finding.code() == PackageFindingCode::MissingIntegrityRecord
            && finding.path() == Some(b"uncovered.bin".as_slice())
    }));
}

#[test]
fn openjdk_jarsigner_fixture_verifies_for_jar_and_android_apk_v1() {
    let untrusted =
        PackageVerifier::default().zip(ZipPackageProfile::Jar, Cursor::new(SIGNED_JAR_APK));
    assert!(
        untrusted.structure().profile_valid(),
        "{:?}",
        untrusted.findings()
    );
    assert_eq!(untrusted.integrity(), VerificationDimension::Verified);
    assert_eq!(
        untrusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(untrusted.trust(), VerificationDimension::Invalid);
    assert_eq!(untrusted.signer_fingerprints(), &[SIGNER_SHA256]);

    let verifier =
        PackageVerifier::new(TrustPolicy::offline().with_trusted_signer_sha256(SIGNER_SHA256));
    let trusted = verifier.zip(ZipPackageProfile::Jar, Cursor::new(SIGNED_JAR_APK));
    assert_eq!(trusted.trust(), VerificationDimension::Verified);

    let apk = verifier.app(AppPackageProfile::AndroidApk, Cursor::new(SIGNED_JAR_APK));
    assert!(apk.structure().profile_valid(), "{:?}", apk.findings());
    assert_eq!(apk.integrity(), VerificationDimension::Verified);
    assert_eq!(apk.signature_validity(), VerificationDimension::Verified);
    assert_eq!(apk.trust(), VerificationDimension::Verified);
    assert_eq!(apk.signer_fingerprints(), &[SIGNER_SHA256]);
}

#[test]
fn signed_jar_tampering_and_bad_cms_signature_are_rejected() {
    let mut payload_tampered = fixture_entries();
    let payload = payload_tampered
        .iter_mut()
        .find(|(name, _)| name == b"classes.dex")
        .expect("fixture classes.dex");
    payload.1.push(0);
    let payload_archive = build_zip(&payload_tampered);
    let payload_report = PackageVerifier::default()
        .zip(ZipPackageProfile::Jar, Cursor::new(payload_archive.clone()));
    assert_eq!(payload_report.integrity(), VerificationDimension::Invalid);
    assert_eq!(
        payload_report.signature_validity(),
        VerificationDimension::Invalid
    );
    assert!(payload_report.findings().iter().any(|finding| {
        finding.code() == PackageFindingCode::IntegrityMismatch
            || finding.code() == PackageFindingCode::SignatureMismatch
    }));
    let payload_apk =
        PackageVerifier::default().app(AppPackageProfile::AndroidApk, Cursor::new(payload_archive));
    assert_eq!(
        payload_apk.signature_validity(),
        VerificationDimension::Invalid
    );

    let mut signature_tampered = fixture_entries();
    let signature = signature_tampered
        .iter_mut()
        .find(|(name, _)| name.ends_with(b".RSA"))
        .expect("fixture CMS signature");
    let offset = signature.1.len().saturating_sub(1);
    let byte = signature.1.get_mut(offset).expect("fixture CMS midpoint");
    *byte ^= 0x40;
    let signature_archive = build_zip(&signature_tampered);
    let signature_report = PackageVerifier::default().zip(
        ZipPackageProfile::Jar,
        Cursor::new(signature_archive.clone()),
    );
    assert_eq!(
        signature_report.signature_validity(),
        VerificationDimension::Invalid
    );
    assert!(signature_report.findings().iter().any(|finding| {
        matches!(
            finding.code(),
            PackageFindingCode::InvalidSignatureMetadata | PackageFindingCode::SignatureMismatch
        )
    }));
    let signature_apk = PackageVerifier::default().app(
        AppPackageProfile::AndroidApk,
        Cursor::new(signature_archive),
    );
    assert_eq!(
        signature_apk.signature_validity(),
        VerificationDimension::Invalid
    );
}

#[test]
fn jar_signature_metadata_obeys_the_allocation_budget() {
    let report = PackageVerifier::default()
        .with_limits(Limits::safe().with_metadata_bytes(Some(1_800)))
        .zip(ZipPackageProfile::Jar, Cursor::new(SIGNED_JAR_APK));
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| { finding.code() == PackageFindingCode::SignatureResourceLimit }),
        "{:?}",
        report.findings()
    );
}

#[test]
fn wheel_record_hashes_and_sizes_are_verified() {
    let report =
        PackageVerifier::default().zip(ZipPackageProfile::Wheel, Cursor::new(wheel(false)));
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotPresent
    );
    assert!(report.findings().is_empty(), "{:?}", report.findings());
}

#[test]
fn wheel_record_tampering_is_invalid() {
    let report = PackageVerifier::default().zip(ZipPackageProfile::Wheel, Cursor::new(wheel(true)));
    assert_eq!(report.integrity(), VerificationDimension::Invalid);
    assert!(
        report
            .findings()
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::IntegrityMismatch)
    );
}
