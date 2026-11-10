// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RPM `OpenPGP` signature interoperability and adversarial tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::io::{Cursor, Read};
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libarchive_oxide::Limits;
use libarchive_oxide_package::{
    PackageFindingCode, PackageVerifier, RpmOpenPgpPublicKey, TrustPolicy, VerificationDimension,
};

const HEADER_LEN: usize = 16;
const INDEX_LEN: usize = 16;

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"))
}

fn signature_layout(bytes: &[u8]) -> (usize, usize, usize) {
    let start = 96;
    let indexes = usize::try_from(be_u32(&bytes[start + 8..])).expect("index count");
    let store_len = usize::try_from(be_u32(&bytes[start + 12..])).expect("store length");
    let store = start + HEADER_LEN + indexes * INDEX_LEN;
    let main = store + store_len.next_multiple_of(8);
    (start, store, main)
}

fn payload_start(bytes: &[u8]) -> usize {
    let (_, _, main) = signature_layout(bytes);
    let indexes = usize::try_from(be_u32(&bytes[main + 8..])).expect("main index count");
    let store_len = usize::try_from(be_u32(&bytes[main + 12..])).expect("main store length");
    main + HEADER_LEN + indexes * INDEX_LEN + store_len
}

fn signature_record(bytes: &[u8], wanted: u32) -> (usize, usize, usize) {
    let (header, store, _) = signature_layout(bytes);
    let indexes = usize::try_from(be_u32(&bytes[header + 8..])).expect("index count");
    for index in 0..indexes {
        let entry = header + HEADER_LEN + index * INDEX_LEN;
        if be_u32(&bytes[entry..]) == wanted {
            let offset = usize::try_from(be_u32(&bytes[entry + 8..])).expect("record offset");
            let count = usize::try_from(be_u32(&bytes[entry + 12..])).expect("record count");
            return (entry, store + offset, count);
        }
    }
    panic!("signature tag {wanted} is absent")
}

fn as_openpgp_header_array(bytes: &[u8]) -> Vec<u8> {
    let (_, packet_start, packet_len) = signature_record(bytes, 268);
    rebuild_openpgp_header_array(
        bytes,
        &[bytes[packet_start..packet_start + packet_len].to_vec()],
    )
}

fn rebuild_openpgp_header_array(bytes: &[u8], packets: &[Vec<u8>]) -> Vec<u8> {
    let (_, _, main) = signature_layout(bytes);
    let mut encoded = String::new();
    for packet in packets {
        encoded.push_str(&STANDARD.encode(packet));
        encoded.push('\0');
    }

    let mut rebuilt = bytes[..96].to_vec();
    rebuilt.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0]);
    rebuilt.extend_from_slice(&1_u32.to_be_bytes());
    rebuilt.extend_from_slice(
        &u32::try_from(encoded.len())
            .expect("fixture size")
            .to_be_bytes(),
    );
    rebuilt.extend_from_slice(&278_u32.to_be_bytes());
    rebuilt.extend_from_slice(&8_u32.to_be_bytes());
    rebuilt.extend_from_slice(&0_u32.to_be_bytes());
    rebuilt.extend_from_slice(
        &u32::try_from(packets.len())
            .expect("fixture count")
            .to_be_bytes(),
    );
    rebuilt.extend_from_slice(encoded.as_bytes());
    rebuilt.resize(rebuilt.len().next_multiple_of(8), 0);
    rebuilt.extend_from_slice(&bytes[main..]);
    rebuilt
}

struct EndlessSuffix {
    prefix: Cursor<Vec<u8>>,
    observed: Rc<Cell<u64>>,
}

impl Read for EndlessSuffix {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.prefix.read(buffer)?;
        let count = if count == 0 && !buffer.is_empty() {
            buffer.fill(0xa5);
            buffer.len()
        } else {
            count
        };
        self.observed.set(
            self.observed
                .get()
                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX)),
        );
        Ok(count)
    }
}

const PRIMARY_SIGNED: &[u8] =
    include_bytes!("fixtures/rpm_signature/hello-2.0-1.x86_64-signed.rpm");
const PRIMARY_KEY: &[u8] = include_bytes!("fixtures/rpm_signature/rpm.org-rsa-2048-test.pub");
const LEGACY_SIGNED: &[u8] =
    include_bytes!("fixtures/rpm_signature/hello-2.0-1.x86_64-v3-signed.rpm");
const SUBKEY_SIGNED: &[u8] =
    include_bytes!("fixtures/rpm_signature/hello-2.0-1.x86_64-signed-with-subkey.rpm");
const SUBKEY_CERTIFICATE: &[u8] = include_bytes!("fixtures/rpm_signature/alice.asc");

fn verify(bytes: &[u8], key: RpmOpenPgpPublicKey) -> libarchive_oxide_package::VerificationReport {
    PackageVerifier::default()
        .with_rpm_openpgp_public_key(key)
        .rpm(Cursor::new(bytes))
}

#[test]
fn official_rpm_rsa_header_signature_verifies_and_pin_controls_trust() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let fingerprint = key.fingerprint_sha256();

    let missing = PackageVerifier::default().rpm(Cursor::new(PRIMARY_SIGNED));
    assert_eq!(
        missing.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert!(missing.has_code(PackageFindingCode::MissingVerificationKey));

    let untrusted = verify(PRIMARY_SIGNED, key.clone());
    assert_eq!(untrusted.integrity(), VerificationDimension::Verified);
    assert_eq!(
        untrusted.signature_validity(),
        VerificationDimension::Verified
    );
    assert_eq!(untrusted.trust(), VerificationDimension::Invalid);
    assert_eq!(untrusted.signer_fingerprints(), &[fingerprint]);

    let trusted =
        PackageVerifier::new(TrustPolicy::offline().with_trusted_signer_sha256(fingerprint))
            .with_rpm_openpgp_public_key(key)
            .rpm(Cursor::new(PRIMARY_SIGNED));
    assert_eq!(trusted.trust(), VerificationDimension::Verified);
}

#[test]
fn official_rpm_rsa_signing_subkey_verifies_through_its_certificate() {
    let key =
        RpmOpenPgpPublicKey::from_bytes(SUBKEY_CERTIFICATE).expect("official RPM subkey cert");
    let report = verify(SUBKEY_SIGNED, key);

    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(report.signature_validity(), VerificationDimension::Verified);
}

#[test]
fn rpm6_openpgp_header_base64_array_uses_the_same_signed_range() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let report = verify(&as_openpgp_header_array(PRIMARY_SIGNED), key);

    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
}

#[test]
fn signed_header_and_signature_packet_tampering_fail_independently_of_payload_digest() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");

    let mut header_tampered = PRIMARY_SIGNED.to_vec();
    let (_, _, main) = signature_layout(&header_tampered);
    let indexes = usize::try_from(be_u32(&header_tampered[main + 8..])).expect("index count");
    let store_len = usize::try_from(be_u32(&header_tampered[main + 12..])).expect("store length");
    let main_store = main + HEADER_LEN + indexes * INDEX_LEN;
    header_tampered[main_store + store_len - 1] ^= 1;
    let report = verify(&header_tampered, key.clone());
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));

    let mut signature_tampered = PRIMARY_SIGNED.to_vec();
    let (_, packet, length) = signature_record(&signature_tampered, 268);
    signature_tampered[packet + length - 1] ^= 1;
    let report = verify(&signature_tampered, key);
    assert_eq!(report.integrity(), VerificationDimension::Verified);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
}

#[test]
fn malformed_signature_tag_and_unrelated_key_fail_closed() {
    let unrelated =
        RpmOpenPgpPublicKey::from_bytes(SUBKEY_CERTIFICATE).expect("unrelated certificate");
    let report = verify(PRIMARY_SIGNED, unrelated);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::NotEvaluated
    );
    assert!(report.has_code(PackageFindingCode::MissingVerificationKey));

    let mut malformed = PRIMARY_SIGNED.to_vec();
    let (entry, _, _) = signature_record(&malformed, 268);
    malformed[entry + 4..entry + 8].copy_from_slice(&6_u32.to_be_bytes());
    let report = PackageVerifier::default().rpm(Cursor::new(malformed));
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::InvalidSignatureMetadata));
}

#[test]
fn non_binary_openpgp_signature_type_is_not_accepted_for_rpm() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let mut text_signature = PRIMARY_SIGNED.to_vec();
    let (_, packet, _) = signature_record(&text_signature, 268);
    // The fixture uses an old-format two-octet packet length.
    // Its v4 signature body starts at +3 and the following octet is the signature type.
    text_signature[packet + 4] = 1;

    let report = verify(&text_signature, key);
    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Unsupported
    );
    assert!(report.has_code(PackageFindingCode::UnsupportedSignatureAlgorithm));
}

#[test]
fn rpm_openpgp_public_key_input_is_bounded() {
    let oversized = vec![0_u8; 256 * 1024 + 1];
    assert!(RpmOpenPgpPublicKey::from_bytes(oversized).is_err());
}

#[test]
fn official_legacy_header_plus_payload_signature_verifies_without_buffering_payload() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let report = verify(LEGACY_SIGNED, key);

    assert_eq!(
        report.signature_validity(),
        VerificationDimension::Verified,
        "{:?}",
        report.findings()
    );
}

#[test]
fn legacy_payload_tamper_is_not_hidden_by_a_valid_header_signature() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let mut tampered = LEGACY_SIGNED.to_vec();
    let payload = payload_start(&tampered);
    tampered[payload + 32] ^= 1;
    let report = verify(&tampered, key);

    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));
}

#[test]
fn one_bad_openpgp_array_signature_is_not_hidden_by_a_good_one() {
    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let (_, start, length) = signature_record(PRIMARY_SIGNED, 268);
    let good = PRIMARY_SIGNED[start..start + length].to_vec();
    let mut bad = good.clone();
    *bad.last_mut().expect("signature MPI") ^= 1;
    let multisigned = rebuild_openpgp_header_array(PRIMARY_SIGNED, &[good, bad]);
    let report = verify(&multisigned, key);

    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureMismatch));
}

#[test]
fn openpgp_array_count_and_legacy_eof_scan_are_bounded() {
    let (_, start, length) = signature_record(PRIMARY_SIGNED, 268);
    let packet = PRIMARY_SIGNED[start..start + length].to_vec();
    let too_many = rebuild_openpgp_header_array(PRIMARY_SIGNED, &vec![packet; 65]);
    let report = PackageVerifier::default().rpm(Cursor::new(too_many));
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureResourceLimit));

    let key = RpmOpenPgpPublicKey::from_bytes(PRIMARY_KEY).expect("official RPM test key");
    let observed = Rc::new(Cell::new(0));
    let reader = EndlessSuffix {
        prefix: Cursor::new(LEGACY_SIGNED.to_vec()),
        observed: Rc::clone(&observed),
    };
    let report = PackageVerifier::default()
        .with_limits(Limits::safe().with_decoded_total(Some(16 * 1024)))
        .with_rpm_openpgp_public_key(key)
        .rpm(reader);
    assert_eq!(report.signature_validity(), VerificationDimension::Invalid);
    assert!(report.has_code(PackageFindingCode::SignatureResourceLimit));
    assert!(
        observed.get() <= u64::try_from(LEGACY_SIGNED.len()).expect("fixture size") + 64 * 1024,
        "legacy signature verifier kept reading an endless suffix"
    );
}
