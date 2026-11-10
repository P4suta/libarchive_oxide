// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! iOS IPA Mach-O `CodeDirectory` and CMS verification tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use libarchive_oxide::{ArchiveWriter, ReaderEvent, SeekArchiveReader, ZipMethod};
use libarchive_oxide::{EntryMetadata, Limits};
use libarchive_oxide_package::{
    AppPackageProfile, PackageFindingCode, PackageVerifier, TrustPolicy, VerificationDimension,
};

const SIGNED_IPA: &[u8] = include_bytes!("fixtures/ipa_codesign/rcodesign-signed.ipa");
const DUAL_DIGEST_IPA: &[u8] = include_bytes!("fixtures/ipa_codesign/rcodesign-dual-digest.ipa");

fn rewrite_ipa(source: &[u8], mut mutate: impl FnMut(&[u8], &mut Vec<u8>)) -> Vec<u8> {
    let mut reader = SeekArchiveReader::new(Cursor::new(source)).expect("open IPA fixture");
    let mut entries: Vec<(EntryMetadata, Vec<u8>)> = Vec::new();
    loop {
        match reader.next_event().expect("read IPA fixture") {
            ReaderEvent::Entry(metadata) => entries.push((metadata, Vec::new())),
            ReaderEvent::Data(bytes) => entries.last_mut().expect("current entry").1.extend(bytes),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => break,
            _ => panic!("unexpected future reader event"),
        }
    }

    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::safe());
    for (metadata, mut body) in entries {
        mutate(metadata.path().as_bytes(), &mut body);
        writer.start_entry(&metadata).expect("start IPA member");
        writer.write_data(&body).expect("write IPA member");
        writer.end_entry().expect("end IPA member");
    }
    writer.finish().expect("finish IPA")
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn mutate_alternative_code_directory_flags(body: &mut [u8]) {
    let superblob = body
        .windows(4)
        .position(|window| window == [0xfa, 0xde, 0x0c, 0xc0])
        .expect("embedded-signature SuperBlob");
    let count = be_u32(body, superblob + 8) as usize;
    for index in 0..count {
        let record = superblob + 12 + index * 8;
        if be_u32(body, record) == 0x1000 {
            let code_directory = superblob + be_u32(body, record + 4) as usize;
            body[code_directory + 15] ^= 1;
            return;
        }
    }
    panic!("alternative CodeDirectory slot");
}

fn mutate_cms_signature(body: &mut [u8]) {
    let superblob = body
        .windows(4)
        .position(|window| window == [0xfa, 0xde, 0x0c, 0xc0])
        .expect("embedded-signature SuperBlob");
    let count = be_u32(body, superblob + 8) as usize;
    for index in 0..count {
        let record = superblob + 12 + index * 8;
        if be_u32(body, record) == 0x1_0000 {
            let wrapper = superblob + be_u32(body, record + 4) as usize;
            let wrapper_length = be_u32(body, wrapper + 4) as usize;
            body[wrapper + wrapper_length - 1] ^= 1;
            return;
        }
    }
    panic!("CMS BlobWrapper slot");
}

fn assert_signature_mismatch(bytes: Vec<u8>, expected_integrity: VerificationDimension) {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .app(AppPackageProfile::Ipa, Cursor::new(bytes));
    assert!(
        report.structure().profile_valid(),
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Invalid,
        "{:?}",
        report.findings()
    );
    assert_eq!(
        report.integrity(),
        expected_integrity,
        "{:?}",
        report.findings()
    );
    assert!(
        report.has_code(PackageFindingCode::SignatureMismatch),
        "{:?}",
        report.findings()
    );
}

#[test]
fn rcodesign_signed_ipa_verifies_code_directory_and_cms_offline() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .app(AppPackageProfile::Ipa, Cursor::new(SIGNED_IPA));

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
    .app(AppPackageProfile::Ipa, Cursor::new(SIGNED_IPA));
    assert_eq!(
        trusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn signed_ipa_verification_streams_executable_outside_metadata_budget() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .with_limits(Limits::safe().with_metadata_bytes(Some(16 * 1024)))
        .app(AppPackageProfile::Ipa, Cursor::new(SIGNED_IPA));

    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
}

#[test]
fn signed_ipa_reports_an_embedded_signature_over_the_metadata_budget() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .with_limits(Limits::safe().with_metadata_bytes(Some(4 * 1024)))
        .app(AppPackageProfile::Ipa, Cursor::new(SIGNED_IPA));

    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(
        report.has_code(PackageFindingCode::SignatureResourceLimit),
        "{:?}",
        report.findings()
    );
}

#[test]
fn signed_ipa_rejects_a_modified_mach_o_code_page() {
    let bytes = rewrite_ipa(SIGNED_IPA, |name, body| {
        if name == b"Payload/TestApp.app/TestApp" {
            body[4096] ^= 1;
        }
    });
    assert_signature_mismatch(bytes, VerificationDimension::Invalid);
}

#[test]
fn signed_ipa_rejects_a_modified_sealed_resource() {
    let bytes = rewrite_ipa(SIGNED_IPA, |name, body| {
        if name == b"Payload/TestApp.app/Assets/message.txt" {
            body[0] ^= 1;
        }
    });
    assert_signature_mismatch(bytes, VerificationDimension::Invalid);
}

#[test]
fn rcodesign_dual_digest_ipa_verifies_hash_agility_attributes() {
    let report = PackageVerifier::new(TrustPolicy::offline())
        .app(AppPackageProfile::Ipa, Cursor::new(DUAL_DIGEST_IPA));

    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
}

#[test]
fn signed_ipa_rejects_an_alternative_code_directory_not_bound_by_cms() {
    let bytes = rewrite_ipa(DUAL_DIGEST_IPA, |name, body| {
        if name == b"Payload/TestApp.app/TestApp" {
            mutate_alternative_code_directory_flags(body);
        }
    });
    assert_signature_mismatch(bytes, VerificationDimension::Verified);
}

#[test]
fn signed_ipa_rejects_a_modified_cms_signature() {
    let bytes = rewrite_ipa(SIGNED_IPA, |name, body| {
        if name == b"Payload/TestApp.app/TestApp" {
            mutate_cms_signature(body);
        }
    });
    assert_signature_mismatch(bytes, VerificationDimension::Verified);
}
