// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, offline Android APK Signature Scheme v2/v3 verification.
//!
//! The APK Signing Block is parsed as a length-delimited wire format, signer
//! signatures are checked before their certificate identity is reported, and
//! the APK content digest is streamed in the specification's 1 MiB chunks.
//! The signing block itself is never part of that digest. The ZIP EOCD central
//! directory offset is rewritten to the signing-block start while hashing, as
//! required by the Android scheme. Signature records are selected using the
//! AOSP platform-range policy: every record which can be strongest at an
//! algorithm-introduction SDK in the signer's authenticated range must verify.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::panic::{AssertUnwindSafe, catch_unwind};

use libarchive_oxide_core::Limits;
use ring::signature;
use sha2::{Digest, Sha256, Sha512};
use spki::EncodePublicKey;
use x509_certificate::{CapturedX509Certificate, EcdsaCurve, KeyAlgorithm};

use crate::jar_signature::preflight_der;
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "android-apk";
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
pub(crate) const APK_V2_BLOCK_ID: u32 = 0x7109_871a;
pub(crate) const APK_V3_BLOCK_ID: u32 = 0xf053_68c0;
pub(crate) const APK_V31_BLOCK_ID: u32 = 0x1b93_ad61;
const V2_STRIPPING_PROTECTION_ATTR_ID: u32 = 0xbeef_f00d;
const V3_PROOF_OF_ROTATION_ATTR_ID: u32 = 0x3ba0_6f8c;
const V3_ROTATION_MIN_SDK_ATTR_ID: u32 = 0x559f_8b02;
const V3_ROTATION_DEV_RELEASE_ATTR_ID: u32 = 0xc2a6_b3ba;
const EOCD_MIN: usize = 22;
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;
const CHUNK_SIZE: u64 = 1024 * 1024;
const CHUNK_SIZE_USIZE: usize = 1024 * 1024;
const VERITY_BLOCK_SIZE: usize = 4096;
const VERITY_DIGEST_SIZE: usize = 32;
const VERITY_DIGESTS_PER_BLOCK: usize = VERITY_BLOCK_SIZE / VERITY_DIGEST_SIZE;
const PROOF_OF_ROTATION_VERSION: u32 = 1;
const ANDROID_N_API: u32 = 24;
const ANDROID_P_API: u32 = 28;
const FALLBACK_METADATA_LIMIT: usize = 64 * 1024 * 1024;
const MAX_SIGNERS: usize = 10;
const MAX_CERTIFICATES: usize = 64;
const MAX_LINEAGE_LEVELS: usize = 64;
const MAX_RECORDS: usize = 64;
const MAX_PAIRS: usize = 1024;

#[derive(Debug)]
pub(crate) struct AndroidSignatureVerification {
    pub(crate) integrity: VerificationDimension,
    pub(crate) signature_validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) rotation: Option<AndroidRotationEvidence>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AndroidRotationEvidence {
    pub(crate) v31_present: bool,
    pub(crate) rotation_min_sdk: Option<u32>,
    pub(crate) targets_dev_release: bool,
    pub(crate) signers: Vec<AndroidSignerEvidence>,
    pub(crate) lineage: Vec<AndroidLineageLevelEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AndroidSignerEvidence {
    pub(crate) scheme: &'static str,
    pub(crate) minimum_sdk: u32,
    pub(crate) maximum_sdk: u32,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) lineage_levels: usize,
    pub(crate) targets_dev_release: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AndroidLineageLevelEvidence {
    pub(crate) fingerprint: [u8; 32],
    pub(crate) flags: u32,
    pub(crate) signed_signature_algorithm_id: u32,
    pub(crate) next_signature_algorithm_id: u32,
}

#[derive(Debug)]
pub(crate) enum Failure {
    Invalid(String),
    Mismatch(String),
    Unsupported(String),
    Resource(String),
    Read(String),
}

impl Failure {
    pub(crate) const fn code(&self) -> PackageFindingCode {
        match self {
            Self::Invalid(_) => PackageFindingCode::InvalidSignatureMetadata,
            Self::Mismatch(_) => PackageFindingCode::SignatureMismatch,
            Self::Unsupported(_) => PackageFindingCode::UnsupportedSignatureAlgorithm,
            Self::Resource(_) => PackageFindingCode::SignatureResourceLimit,
            Self::Read(_) => PackageFindingCode::IntegrityReadFailure,
        }
    }

    pub(crate) fn detail(self) -> String {
        match self {
            Self::Invalid(detail)
            | Self::Mismatch(detail)
            | Self::Unsupported(detail)
            | Self::Resource(detail)
            | Self::Read(detail) => detail,
        }
    }
}

#[derive(Debug)]
struct ApkLayout {
    block_start: u64,
    central_offset: u64,
    eocd_offset: u64,
    eocd: Vec<u8>,
    schemes: BTreeMap<u32, Vec<u8>>,
}

#[derive(Debug)]
struct ZipSections {
    central_offset: u64,
    eocd_offset: u64,
    eocd: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContentDigestKind {
    ChunkedSha256,
    VeritySha256,
    ChunkedSha512,
}

impl ContentDigestKind {
    pub(crate) const fn expected_length(self) -> usize {
        match self {
            Self::ChunkedSha256 => 32,
            Self::VeritySha256 => 40,
            Self::ChunkedSha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    V2,
    V3,
    V31,
}

impl Scheme {
    const fn label(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V31 => "v3.1",
        }
    }

    const fn has_sdk_range(self) -> bool {
        matches!(self, Self::V3 | Self::V31)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureAlgorithm {
    RsaPssSha256,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha512,
    EcdsaSha256,
    EcdsaSha512,
    DsaSha256,
    VerityRsaSha256,
    VerityEcdsaSha256,
    VerityDsaSha256,
}

impl SignatureAlgorithm {
    pub(crate) const fn from_id(id: u32) -> Option<Self> {
        match id {
            0x0101 => Some(Self::RsaPssSha256),
            0x0102 => Some(Self::RsaPssSha512),
            0x0103 => Some(Self::RsaPkcs1Sha256),
            0x0104 => Some(Self::RsaPkcs1Sha512),
            0x0201 => Some(Self::EcdsaSha256),
            0x0202 => Some(Self::EcdsaSha512),
            0x0301 => Some(Self::DsaSha256),
            0x0421 => Some(Self::VerityRsaSha256),
            0x0423 => Some(Self::VerityEcdsaSha256),
            0x0425 => Some(Self::VerityDsaSha256),
            _ => None,
        }
    }

    pub(crate) const fn content_digest(self) -> ContentDigestKind {
        match self {
            Self::RsaPssSha256 | Self::RsaPkcs1Sha256 | Self::EcdsaSha256 | Self::DsaSha256 => {
                ContentDigestKind::ChunkedSha256
            },
            Self::RsaPssSha512 | Self::RsaPkcs1Sha512 | Self::EcdsaSha512 => {
                ContentDigestKind::ChunkedSha512
            },
            Self::VerityRsaSha256 | Self::VerityEcdsaSha256 | Self::VerityDsaSha256 => {
                ContentDigestKind::VeritySha256
            },
        }
    }

    /// First Android API level whose APK verifier supports this algorithm.
    ///
    /// APK Signature Scheme v2 and the non-verity algorithms were introduced
    /// in Android N. The fs-verity-compatible algorithms were introduced with
    /// APK Signature Scheme v3 in Android P.
    const fn minimum_sdk(self) -> u32 {
        match self {
            Self::VerityRsaSha256 | Self::VerityEcdsaSha256 | Self::VerityDsaSha256 => {
                ANDROID_P_API
            },
            Self::RsaPssSha256
            | Self::RsaPssSha512
            | Self::RsaPkcs1Sha256
            | Self::RsaPkcs1Sha512
            | Self::EcdsaSha256
            | Self::EcdsaSha512
            | Self::DsaSha256 => ANDROID_N_API,
        }
    }

    const fn uses_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaPssSha256
                | Self::RsaPssSha512
                | Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha512
                | Self::VerityRsaSha256
        )
    }

    pub(crate) fn verifier(
        self,
        key_algorithm: Option<KeyAlgorithm>,
    ) -> Result<&'static dyn signature::VerificationAlgorithm, Failure> {
        match (self, key_algorithm) {
            (Self::RsaPssSha256, Some(KeyAlgorithm::Rsa)) => {
                Ok(&signature::RSA_PSS_2048_8192_SHA256)
            },
            (Self::RsaPssSha512, Some(KeyAlgorithm::Rsa)) => {
                Ok(&signature::RSA_PSS_2048_8192_SHA512)
            },
            (Self::RsaPkcs1Sha256 | Self::VerityRsaSha256, Some(KeyAlgorithm::Rsa)) => {
                Ok(&signature::RSA_PKCS1_2048_8192_SHA256)
            },
            (Self::RsaPkcs1Sha512, Some(KeyAlgorithm::Rsa)) => {
                Ok(&signature::RSA_PKCS1_2048_8192_SHA512)
            },
            (
                Self::EcdsaSha256 | Self::VerityEcdsaSha256,
                Some(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)),
            ) => Ok(&signature::ECDSA_P256_SHA256_ASN1),
            (
                Self::EcdsaSha256 | Self::VerityEcdsaSha256,
                Some(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)),
            ) => Ok(&signature::ECDSA_P384_SHA256_ASN1),
            (Self::EcdsaSha512, Some(KeyAlgorithm::Ecdsa(_))) => Err(Failure::Unsupported(
                "APK ECDSA-with-SHA-512 signatures are not supported by this build".to_string(),
            )),
            (Self::DsaSha256 | Self::VerityDsaSha256, _) => Err(Failure::Unsupported(
                "APK DSA signatures are not supported by this build".to_string(),
            )),
            (_, None) => Err(Failure::Unsupported(
                "APK signer certificate uses an unsupported public-key algorithm".to_string(),
            )),
            (_, Some(actual)) => Err(Failure::Invalid(format!(
                "APK signature algorithm does not match signer public-key type {actual}"
            ))),
        }
    }
}

#[derive(Debug)]
struct SignatureRecord<'a> {
    id: u32,
    bytes: &'a [u8],
}

#[derive(Debug)]
struct DigestRecord<'a> {
    id: u32,
    bytes: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct SignerEvidence {
    pub(crate) fingerprint: [u8; 32],
    sdk_range: Option<(u32, u32)>,
    pub(crate) certificate_der: Vec<u8>,
    content_digests: BTreeMap<ContentDigestKind, Vec<u8>>,
    scheme: Scheme,
    attributes: SignerAttributes,
}

#[derive(Debug, Default)]
struct SignerAttributes {
    lineage: Option<VerifiedLineage>,
    rotation_min_sdk: Option<u32>,
    targets_dev_release: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedLineage {
    levels: Vec<VerifiedLineageLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedLineageLevel {
    certificate_der: Vec<u8>,
    fingerprint: [u8; 32],
    flags: u32,
    signed_signature_algorithm_id: u32,
    next_signature_algorithm_id: u32,
}

impl SignerEvidence {
    pub(crate) fn best_v4_digest(&self) -> Option<&[u8]> {
        self.content_digests
            .last_key_value()
            .map(|(_, digest)| digest.as_slice())
    }
}

/// Verified APK Signing Block identities used to bind an explicitly supplied
/// v4/v4.1 sidecar to the APK that carries the corresponding v2/v3 blocks.
#[derive(Debug)]
pub(crate) struct ApkV4BindingEvidence {
    pub(crate) primary: SignerEvidence,
    pub(crate) v31: Option<SignerEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeMode {
    Strict,
    V4Binding,
}

#[derive(Debug)]
struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize, what: &str) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| Failure::Resource(format!("{what} offset overflow")))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Failure::Invalid(format!("{what} is truncated")))?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self, what: &str) -> Result<u32, Failure> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn length_prefixed(&mut self, what: &str) -> Result<&'a [u8], Failure> {
        let length = self.u32(&format!("{what} length"))?;
        let length = usize::try_from(length)
            .map_err(|_| Failure::Resource(format!("{what} length exceeds address space")))?;
        self.take(length, what)
    }

    fn finish(self, what: &str) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Invalid(format!(
                "{what} has {} trailing bytes",
                self.bytes.len() - self.offset
            )))
        }
    }
}

/// Verifies every detected v2/v3 block. All parsing and hashing remains bounded
/// by `limits`; no certificate or trust information is fetched from a network.
pub(crate) fn verify_android_apk_v2_v3<R: Read + Seek>(
    mut reader: R,
    limits: Limits,
) -> AndroidSignatureVerification {
    let layout = match locate_signing_block(&mut reader, limits) {
        Ok(layout) => layout,
        Err(failure) => return failed_verification(failure),
    };

    let (v2, v3, v31) = match verify_signing_schemes(&layout, limits) {
        Ok(evidence) => evidence,
        Err(failure) => return failed_verification(failure),
    };

    let rotation = build_rotation_evidence(&v3, &v31);
    let evidence = v2
        .iter()
        .chain(v3.iter())
        .chain(v31.iter())
        .collect::<Vec<_>>();
    if evidence.is_empty() {
        return failed_verification(Failure::Invalid(
            "APK signing scheme contains no signer".to_string(),
        ));
    }

    let needs_sha256 = evidence.iter().any(|item| {
        item.content_digests
            .contains_key(&ContentDigestKind::ChunkedSha256)
    });
    let needs_sha512 = evidence.iter().any(|item| {
        item.content_digests
            .contains_key(&ContentDigestKind::ChunkedSha512)
    });
    let needs_verity = evidence.iter().any(|item| {
        item.content_digests
            .contains_key(&ContentDigestKind::VeritySha256)
    });

    let actual = match compute_content_digests(
        &mut reader,
        &layout,
        limits,
        needs_sha256,
        needs_sha512,
        needs_verity,
    ) {
        Ok(actual) => actual,
        Err(failure) => {
            let mut verification = failed_verification(failure);
            verification.signature_validity = VerificationDimension::Verified;
            verification.signer_fingerprints =
                unique_fingerprints(evidence.iter().map(|item| item.fingerprint));
            verification.rotation = rotation;
            return verification;
        },
    };

    let mut findings = Vec::new();
    let mut integrity = VerificationDimension::Verified;
    for signer in &evidence {
        for (kind, expected_digest) in &signer.content_digests {
            let actual_digest = match kind {
                ContentDigestKind::ChunkedSha256 => actual.sha256.as_deref(),
                ContentDigestKind::ChunkedSha512 => actual.sha512.as_deref(),
                ContentDigestKind::VeritySha256 => actual.verity_sha256.as_deref(),
            };
            if actual_digest != Some(expected_digest.as_slice()) {
                integrity = VerificationDimension::Invalid;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::IntegrityMismatch,
                    format!(
                        "APK {} content digest does not match the signed digest",
                        content_digest_label(*kind)
                    ),
                ));
            }
        }
    }

    AndroidSignatureVerification {
        integrity,
        signature_validity: VerificationDimension::Verified,
        signer_fingerprints: unique_fingerprints(evidence.iter().map(|item| item.fingerprint)),
        rotation,
        findings,
    }
}

type SigningSchemeEvidence = (
    Vec<SignerEvidence>,
    Vec<SignerEvidence>,
    Vec<SignerEvidence>,
);

fn verify_signing_schemes(
    layout: &ApkLayout,
    limits: Limits,
) -> Result<SigningSchemeEvidence, Failure> {
    // Android T+ selects v3.1 before v3. The v3.1 minimum SDK is authenticated
    // by the v3 stripping-protection attribute, so both blocks must be parsed
    // before either can be accepted as a targeted-rotation pair.
    let v31 = verify_optional_scheme(
        layout,
        APK_V31_BLOCK_ID,
        Scheme::V31,
        limits,
        AttributeMode::Strict,
    )?;
    let v3 = verify_optional_scheme(
        layout,
        APK_V3_BLOCK_ID,
        Scheme::V3,
        limits,
        AttributeMode::Strict,
    )?;
    let v2 = verify_optional_scheme(
        layout,
        APK_V2_BLOCK_ID,
        Scheme::V2,
        limits,
        AttributeMode::Strict,
    )?;
    if v2.is_empty() && v3.is_empty() && v31.is_empty() {
        return Err(Failure::Unsupported(
            "APK Signing Block contains no supported Signature Scheme v2 or v3 value".to_string(),
        ));
    }
    validate_targeted_rotation(&v3, &v31)?;
    Ok((v2, v3, v31))
}

fn failed_verification(failure: Failure) -> AndroidSignatureVerification {
    let signature_validity = match failure {
        Failure::Unsupported(_) => VerificationDimension::Unsupported,
        Failure::Invalid(_) | Failure::Mismatch(_) | Failure::Resource(_) | Failure::Read(_) => {
            VerificationDimension::Invalid
        },
    };
    let code = failure.code();
    AndroidSignatureVerification {
        integrity: VerificationDimension::NotEvaluated,
        signature_validity,
        signer_fingerprints: Vec::new(),
        rotation: None,
        findings: vec![PackageFinding::new(PROFILE, None, code, failure.detail())],
    }
}

fn content_digest_label(kind: ContentDigestKind) -> &'static str {
    match kind {
        ContentDigestKind::ChunkedSha256 => "1 MiB chunked SHA-256",
        ContentDigestKind::ChunkedSha512 => "1 MiB chunked SHA-512",
        ContentDigestKind::VeritySha256 => "APK fs-verity SHA-256",
    }
}

fn unique_fingerprints(fingerprints: impl IntoIterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
    fingerprints
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Verifies every v2/v3/v3.1 signer block needed by a v4 sidecar, including
/// the selected whole-APK content digest, and returns the exact DER signer
/// identities plus every selected authenticated digest alternative. Rotation attributes
/// remain signed and bounded here, but their lineage semantics are deliberately
/// outside this sidecar-binding pass.
pub(crate) fn verify_android_apk_v4_bindings<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<ApkV4BindingEvidence, Failure> {
    let layout = locate_signing_block(reader, limits)?;
    let mut by_block = BTreeMap::new();
    let mut all_evidence = Vec::new();

    for (id, scheme) in [
        (APK_V2_BLOCK_ID, Scheme::V2),
        (APK_V3_BLOCK_ID, Scheme::V3),
        (APK_V31_BLOCK_ID, Scheme::V31),
    ] {
        let Some(value) = layout.schemes.get(&id) else {
            continue;
        };
        let signers = verify_scheme(
            value,
            scheme,
            &layout.schemes,
            limits,
            AttributeMode::V4Binding,
        )?;
        if signers.is_empty() {
            return Err(Failure::Invalid(format!(
                "APK signing block {id:#010x} has no signer"
            )));
        }
        all_evidence.extend(signers.iter().flat_map(|signer| {
            signer
                .content_digests
                .iter()
                .map(|(kind, digest)| (*kind, digest.clone()))
        }));
        by_block.insert(id, signers);
    }

    if !by_block.contains_key(&APK_V2_BLOCK_ID) && !by_block.contains_key(&APK_V3_BLOCK_ID) {
        return Err(Failure::Unsupported(
            "APK v4 requires a verified Signature Scheme v2 or v3 block".to_string(),
        ));
    }

    let needs_sha256 = all_evidence
        .iter()
        .any(|(kind, _)| *kind == ContentDigestKind::ChunkedSha256);
    let needs_sha512 = all_evidence
        .iter()
        .any(|(kind, _)| *kind == ContentDigestKind::ChunkedSha512);
    let needs_verity = all_evidence
        .iter()
        .any(|(kind, _)| *kind == ContentDigestKind::VeritySha256);
    let actual = compute_content_digests(
        reader,
        &layout,
        limits,
        needs_sha256,
        needs_sha512,
        needs_verity,
    )?;
    for (kind, expected) in &all_evidence {
        let actual = match kind {
            ContentDigestKind::ChunkedSha256 => actual.sha256.as_deref(),
            ContentDigestKind::ChunkedSha512 => actual.sha512.as_deref(),
            ContentDigestKind::VeritySha256 => actual.verity_sha256.as_deref(),
        };
        if actual != Some(expected.as_slice()) {
            return Err(Failure::Mismatch(
                "APK v2/v3 content digest does not match the sidecar binding source".to_string(),
            ));
        }
    }

    let primary_id = if by_block.contains_key(&APK_V3_BLOCK_ID) {
        APK_V3_BLOCK_ID
    } else {
        APK_V2_BLOCK_ID
    };
    let primary_signers = by_block.remove(&primary_id).ok_or_else(|| {
        Failure::Invalid("APK v4 primary signer block disappeared while binding".to_string())
    })?;
    let [primary] = <Vec<SignerEvidence> as TryInto<[SignerEvidence; 1]>>::try_into(
        primary_signers,
    )
    .map_err(|signers| {
        Failure::Mismatch(format!(
            "APK v4 requires exactly one corresponding v2/v3 signer; found {}",
            signers.len()
        ))
    })?;
    let v31 = match by_block.remove(&APK_V31_BLOCK_ID) {
        None => None,
        Some(signers) => {
            let [signer] = <Vec<SignerEvidence> as TryInto<[SignerEvidence; 1]>>::try_into(signers)
                .map_err(|signers| {
                    Failure::Mismatch(format!(
                        "APK v4.1 requires exactly one corresponding v3.1 signer; found {}",
                        signers.len()
                    ))
                })?;
            Some(signer)
        },
    };

    Ok(ApkV4BindingEvidence { primary, v31 })
}

fn locate_signing_block<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<ApkLayout, Failure> {
    let zip = locate_zip_sections(reader)?;
    if zip.central_offset < 24 {
        return Err(Failure::Invalid(
            "APK central directory leaves no room for a signing-block footer".to_string(),
        ));
    }
    let mut footer = [0_u8; 24];
    read_exact_at(reader, zip.central_offset - 24, &mut footer)
        .map_err(|error| Failure::Read(format!("cannot read APK signing-block footer: {error}")))?;
    if &footer[8..] != APK_SIG_BLOCK_MAGIC {
        return Err(Failure::Invalid(
            "APK Signing Block magic is absent".to_string(),
        ));
    }
    let trailing_size = u64_at(&footer, 0)?;
    if trailing_size < 24 {
        return Err(Failure::Invalid(
            "APK Signing Block declared size is smaller than its footer".to_string(),
        ));
    }
    let total_size = trailing_size
        .checked_add(8)
        .ok_or_else(|| Failure::Resource("APK Signing Block size overflow".to_string()))?;
    let block_start = zip.central_offset.checked_sub(total_size).ok_or_else(|| {
        Failure::Invalid("APK Signing Block starts before the archive".to_string())
    })?;
    let mut leading_size = [0_u8; 8];
    read_exact_at(reader, block_start, &mut leading_size)
        .map_err(|error| Failure::Read(format!("cannot read APK signing-block header: {error}")))?;
    if u64_at(&leading_size, 0)? != trailing_size {
        return Err(Failure::Invalid(
            "APK Signing Block leading and trailing sizes differ".to_string(),
        ));
    }
    let region_length = signing_region_length(trailing_size, limits)?;
    let mut region = vec![0_u8; region_length];
    read_exact_at(reader, block_start + 8, &mut region)
        .map_err(|error| Failure::Read(format!("cannot read APK signing-block values: {error}")))?;
    let schemes = parse_id_value_pairs(&region)?;
    Ok(ApkLayout {
        block_start,
        central_offset: zip.central_offset,
        eocd_offset: zip.eocd_offset,
        eocd: zip.eocd,
        schemes,
    })
}

fn locate_zip_sections<R: Read + Seek>(reader: &mut R) -> Result<ZipSections, Failure> {
    let archive_length = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| Failure::Read(format!("cannot measure APK length: {error}")))?;
    let tail_length = archive_length.min(EOCD_SEARCH);
    let tail_start = archive_length - tail_length;
    let tail_length = usize::try_from(tail_length)
        .map_err(|_| Failure::Resource("APK EOCD search exceeds address space".to_string()))?;
    let mut tail = vec![0_u8; tail_length];
    read_exact_at(reader, tail_start, &mut tail)
        .map_err(|error| Failure::Read(format!("cannot read APK tail: {error}")))?;
    let eocd_in_tail = tail
        .windows(4)
        .enumerate()
        .rev()
        .find_map(|(position, magic)| {
            if magic != b"PK\x05\x06" || tail.len().saturating_sub(position) < EOCD_MIN {
                return None;
            }
            let comment_length = usize::from(u16::from_le_bytes([
                tail[position + 20],
                tail[position + 21],
            ]));
            (position
                .checked_add(EOCD_MIN)
                .and_then(|value| value.checked_add(comment_length))
                == Some(tail.len()))
            .then_some(position)
        })
        .ok_or_else(|| Failure::Invalid("APK has no terminal ZIP EOCD record".to_string()))?;
    let eocd = tail[eocd_in_tail..].to_vec();
    if eocd_in_tail >= 20 && tail.get(eocd_in_tail - 20..eocd_in_tail - 16) == Some(b"PK\x06\x07") {
        return Err(Failure::Unsupported(
            "ZIP64 APK Signing Block verification is not supported".to_string(),
        ));
    }
    if u16_at(&eocd, 4)? != 0 || u16_at(&eocd, 6)? != 0 || u16_at(&eocd, 8)? != u16_at(&eocd, 10)? {
        return Err(Failure::Invalid(
            "multi-disk APK ZIP containers are not supported".to_string(),
        ));
    }
    if u16_at(&eocd, 10)? == u16::MAX
        || u32_at(&eocd, 12)? == u32::MAX
        || u32_at(&eocd, 16)? == u32::MAX
    {
        return Err(Failure::Unsupported(
            "ZIP64 APK Signing Block verification is not supported".to_string(),
        ));
    }
    let central_size = u64::from(u32_at(&eocd, 12)?);
    let central_offset = u64::from(u32_at(&eocd, 16)?);
    let eocd_offset = tail_start
        .checked_add(eocd_in_tail as u64)
        .ok_or_else(|| Failure::Resource("APK EOCD offset overflow".to_string()))?;
    if central_offset
        .checked_add(central_size)
        .is_none_or(|end| end != eocd_offset)
    {
        return Err(Failure::Invalid(
            "APK central directory is not immediately followed by EOCD".to_string(),
        ));
    }
    Ok(ZipSections {
        central_offset,
        eocd_offset,
        eocd,
    })
}

fn signing_region_length(trailing_size: u64, limits: Limits) -> Result<usize, Failure> {
    let region_length = trailing_size
        .checked_sub(24)
        .ok_or_else(|| Failure::Invalid("APK Signing Block region underflow".to_string()))?;
    let region_length = usize::try_from(region_length).map_err(|_| {
        Failure::Resource("APK Signing Block does not fit in address space".to_string())
    })?;
    let metadata_limit = limits.metadata_bytes().unwrap_or(FALLBACK_METADATA_LIMIT);
    if region_length > metadata_limit {
        return Err(Failure::Resource(format!(
            "APK Signing Block id-value region is {region_length} bytes; metadata limit is \
             {metadata_limit}"
        )));
    }
    Ok(region_length)
}

fn parse_id_value_pairs(region: &[u8]) -> Result<BTreeMap<u32, Vec<u8>>, Failure> {
    let mut cursor = 0_usize;
    let mut pairs = 0_usize;
    let mut schemes = BTreeMap::new();
    while cursor < region.len() {
        pairs = pairs.saturating_add(1);
        if pairs > MAX_PAIRS {
            return Err(Failure::Resource(format!(
                "APK Signing Block has more than {MAX_PAIRS} id-value pairs"
            )));
        }
        let length_end = cursor
            .checked_add(8)
            .ok_or_else(|| Failure::Resource("APK pair offset overflow".to_string()))?;
        let length_bytes = region
            .get(cursor..length_end)
            .ok_or_else(|| Failure::Invalid("APK id-value pair length is truncated".to_string()))?;
        let pair_length = u64_at(length_bytes, 0)?;
        if pair_length < 4 {
            return Err(Failure::Invalid(
                "APK id-value pair is shorter than its id".to_string(),
            ));
        }
        let pair_length = usize::try_from(pair_length)
            .map_err(|_| Failure::Resource("APK pair length exceeds address space".to_string()))?;
        let pair_end = length_end
            .checked_add(pair_length)
            .ok_or_else(|| Failure::Resource("APK pair end overflow".to_string()))?;
        let pair = region
            .get(length_end..pair_end)
            .ok_or_else(|| Failure::Invalid("APK id-value pair is truncated".to_string()))?;
        let id = u32_at(pair, 0)?;
        if matches!(id, APK_V2_BLOCK_ID | APK_V3_BLOCK_ID | APK_V31_BLOCK_ID)
            && schemes.insert(id, pair[4..].to_vec()).is_some()
        {
            return Err(Failure::Invalid(format!(
                "APK Signing Block repeats scheme id {id:#010x}"
            )));
        }
        cursor = pair_end;
    }
    Ok(schemes)
}

fn verify_scheme(
    value: &[u8],
    scheme: Scheme,
    present_schemes: &BTreeMap<u32, Vec<u8>>,
    limits: Limits,
    attribute_mode: AttributeMode,
) -> Result<Vec<SignerEvidence>, Failure> {
    let mut outer = ByteCursor::new(value);
    let signers = outer.length_prefixed(&format!("APK {} signers", scheme.label()))?;
    outer.finish(&format!("APK {} scheme value", scheme.label()))?;
    if signers.is_empty() {
        return Err(Failure::Invalid(format!(
            "APK {} scheme has no signers",
            scheme.label()
        )));
    }
    let mut cursor = ByteCursor::new(signers);
    let mut evidence = Vec::new();
    while cursor.remaining() != 0 {
        if evidence.len() >= MAX_SIGNERS {
            return Err(Failure::Resource(format!(
                "APK {} scheme exceeds the {MAX_SIGNERS}-signer limit",
                scheme.label()
            )));
        }
        let signer =
            cursor.length_prefixed(&format!("APK {} signer {}", scheme.label(), evidence.len()))?;
        evidence.push(verify_signer(
            signer,
            scheme,
            present_schemes,
            limits,
            attribute_mode,
        )?);
    }
    if scheme.has_sdk_range() {
        validate_v3_ranges(&evidence, scheme)?;
    }
    Ok(evidence)
}

fn verify_optional_scheme(
    layout: &ApkLayout,
    id: u32,
    scheme: Scheme,
    limits: Limits,
    attribute_mode: AttributeMode,
) -> Result<Vec<SignerEvidence>, Failure> {
    let Some(value) = layout.schemes.get(&id) else {
        return Ok(Vec::new());
    };
    verify_scheme(value, scheme, &layout.schemes, limits, attribute_mode)
}

fn verify_signer(
    signer: &[u8],
    scheme: Scheme,
    present_schemes: &BTreeMap<u32, Vec<u8>>,
    limits: Limits,
    attribute_mode: AttributeMode,
) -> Result<SignerEvidence, Failure> {
    let mut signer_cursor = ByteCursor::new(signer);
    let signed_data = signer_cursor.length_prefixed("APK signer signed-data")?;
    let outer_sdk = if scheme.has_sdk_range() {
        let minimum = signer_cursor.u32(&format!("APK {} signer minimum SDK", scheme.label()))?;
        let maximum = signer_cursor.u32(&format!("APK {} signer maximum SDK", scheme.label()))?;
        validate_sdk_range(minimum, maximum, "signer")?;
        Some((minimum, maximum))
    } else {
        None
    };
    let signatures = signer_cursor.length_prefixed("APK signer signatures")?;
    let public_key = signer_cursor.length_prefixed("APK signer public key")?;
    signer_cursor.finish("APK signer")?;

    let signature_records = parse_signature_records(signatures)?;
    let (digest_records, certificate_values, signed_sdk, attributes) =
        parse_signed_data(signed_data, scheme)?;
    if outer_sdk != signed_sdk {
        return Err(Failure::Invalid(
            "APK v3 signer SDK range differs between signer and signed-data".to_string(),
        ));
    }
    let signature_ids = signature_records
        .iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    let digest_ids = digest_records
        .iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    if signature_ids != digest_ids {
        return Err(Failure::Invalid(
            "APK signature and digest algorithm lists differ".to_string(),
        ));
    }

    let (minimum_sdk, maximum_sdk) = outer_sdk.unwrap_or((ANDROID_N_API, i32::MAX as u32));
    let selected_signatures = select_signatures(&signature_records, minimum_sdk, maximum_sdk)?;
    let selected_digest_kinds = selected_signatures
        .iter()
        .filter_map(|record| SignatureAlgorithm::from_id(record.id))
        .map(SignatureAlgorithm::content_digest)
        .collect::<BTreeSet<_>>();
    let (certificate, certificate_der) = parse_first_certificate(certificate_values, limits)?;
    let canonical_public_key = certificate
        .to_public_key_der()
        .map_err(|error| Failure::Invalid(format!("cannot encode APK signer SPKI: {error}")))?;
    if canonical_public_key.as_bytes() != public_key {
        return Err(Failure::Invalid(
            "APK signer public key differs from the first certificate's SPKI".to_string(),
        ));
    }

    for selected in selected_signatures {
        let algorithm = SignatureAlgorithm::from_id(selected.id).ok_or_else(|| {
            Failure::Unsupported(format!(
                "APK signer selected unknown signature algorithm {:#010x}",
                selected.id
            ))
        })?;
        validate_key_support(algorithm, &certificate)?;
        let verifier = algorithm.verifier(certificate.key_algorithm())?;
        certificate
            .verify_signed_data_with_algorithm(signed_data, selected.bytes, verifier)
            .map_err(|_| {
                Failure::Mismatch(format!(
                    "APK {} signature {:#010x} over signed-data did not verify for the \
                     authenticated SDK range {minimum_sdk}..={maximum_sdk}",
                    scheme.label(),
                    selected.id
                ))
            })?;
    }

    let attributes = check_attributes(
        attributes,
        scheme,
        present_schemes,
        attribute_mode,
        &certificate_der,
        limits,
    )?;
    let content_digests = collect_content_digests(&digest_records, &selected_digest_kinds)?;
    let fingerprint = Sha256::digest(&certificate_der).into();
    Ok(SignerEvidence {
        fingerprint,
        sdk_range: outer_sdk,
        certificate_der,
        content_digests,
        scheme,
        attributes,
    })
}

fn collect_content_digests(
    records: &[DigestRecord<'_>],
    selected_kinds: &BTreeSet<ContentDigestKind>,
) -> Result<BTreeMap<ContentDigestKind, Vec<u8>>, Failure> {
    let mut content_digests = BTreeMap::new();
    for record in records {
        let Some(record_algorithm) = SignatureAlgorithm::from_id(record.id) else {
            continue;
        };
        let kind = record_algorithm.content_digest();
        if !selected_kinds.contains(&kind) {
            continue;
        }
        if record.bytes.len() != kind.expected_length() {
            return Err(Failure::Invalid(format!(
                "APK digest for algorithm {:#010x} is {} bytes; expected {}",
                record.id,
                record.bytes.len(),
                kind.expected_length()
            )));
        }
        if let Some(previous) = content_digests.insert(kind, record.bytes.to_vec())
            && previous != record.bytes
        {
            return Err(Failure::Invalid(format!(
                "APK signer provides conflicting authenticated digests for {kind:?}"
            )));
        }
    }
    Ok(content_digests)
}

fn parse_signature_records(bytes: &[u8]) -> Result<Vec<SignatureRecord<'_>>, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let mut records = Vec::new();
    let mut ids = BTreeSet::new();
    while cursor.remaining() != 0 {
        if records.len() >= MAX_RECORDS {
            return Err(Failure::Resource(format!(
                "APK signer exceeds the {MAX_RECORDS}-signature limit"
            )));
        }
        let record_bytes = cursor.length_prefixed("APK signature record")?;
        let mut record = ByteCursor::new(record_bytes);
        let id = record.u32("APK signature algorithm id")?;
        let signature = record.length_prefixed("APK signature bytes")?;
        record.finish("APK signature record")?;
        if !ids.insert(id) {
            return Err(Failure::Invalid(format!(
                "APK signer repeats signature algorithm {id:#010x}"
            )));
        }
        records.push(SignatureRecord {
            id,
            bytes: signature,
        });
    }
    if records.is_empty() {
        return Err(Failure::Invalid(
            "APK signer provides no signatures".to_string(),
        ));
    }
    Ok(records)
}

fn select_signatures<'a>(
    records: &'a [SignatureRecord<'a>],
    minimum_sdk: u32,
    maximum_sdk: u32,
) -> Result<Vec<&'a SignatureRecord<'a>>, Failure> {
    // Mirror AOSP ApkSigningBlockUtilsLite::getSignaturesToVerify. Android
    // chooses one strongest supported signature on a given platform release;
    // verification over an SDK range therefore checks the strongest record at
    // every algorithm-introduction level represented by the signer.
    let mut selected_by_introduction = BTreeMap::new();
    let mut minimum_provided_sdk = None;
    for record in records {
        let Some(algorithm) = SignatureAlgorithm::from_id(record.id) else {
            continue;
        };
        let algorithm_minimum = algorithm.minimum_sdk();
        if algorithm_minimum > maximum_sdk {
            continue;
        }
        minimum_provided_sdk = Some(
            minimum_provided_sdk.map_or(algorithm_minimum, |current: u32| {
                current.min(algorithm_minimum)
            }),
        );
        let replace = selected_by_introduction.get(&algorithm_minimum).is_none_or(
            |current: &&SignatureRecord<'_>| {
                let current_algorithm = SignatureAlgorithm::from_id(current.id);
                current_algorithm
                    .is_none_or(|current| algorithm.content_digest() > current.content_digest())
            },
        );
        if replace {
            selected_by_introduction.insert(algorithm_minimum, record);
        }
    }
    let Some(minimum_provided_sdk) = minimum_provided_sdk else {
        let ids = records
            .iter()
            .map(|record| format!("{:#010x}", record.id))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Failure::Unsupported(format!(
            "APK signer provides only unknown signature algorithms: {ids}"
        )));
    };
    if minimum_sdk < minimum_provided_sdk {
        return Err(Failure::Unsupported(format!(
            "APK signer SDK range starts at {minimum_sdk}, but its earliest supported signature \
             algorithm starts at SDK {minimum_provided_sdk}"
        )));
    }
    let mut selected = selected_by_introduction.into_values().collect::<Vec<_>>();
    selected.sort_by_key(|record| record.id);
    Ok(selected)
}

type ParsedSignedData<'a> = (
    Vec<DigestRecord<'a>>,
    &'a [u8],
    Option<(u32, u32)>,
    &'a [u8],
);

fn parse_signed_data(signed_data: &[u8], scheme: Scheme) -> Result<ParsedSignedData<'_>, Failure> {
    let mut cursor = ByteCursor::new(signed_data);
    let digests = cursor.length_prefixed("APK signed digest sequence")?;
    let certificates = cursor.length_prefixed("APK signer certificate sequence")?;
    let sdk_range = if scheme.has_sdk_range() {
        let minimum = cursor.u32(&format!("APK {} signed minimum SDK", scheme.label()))?;
        let maximum = cursor.u32(&format!("APK {} signed maximum SDK", scheme.label()))?;
        validate_sdk_range(minimum, maximum, "signed-data")?;
        Some((minimum, maximum))
    } else {
        None
    };
    let attributes = cursor.length_prefixed("APK signer attributes")?;
    if scheme == Scheme::V2 && cursor.remaining() == 4 {
        let reserved = cursor.u32("APK v2 signed-data reserved field")?;
        if reserved != 0 {
            return Err(Failure::Invalid(
                "APK v2 signed-data reserved field is nonzero".to_string(),
            ));
        }
    }
    cursor.finish("APK signer signed-data")?;
    Ok((
        parse_digest_records(digests)?,
        certificates,
        sdk_range,
        attributes,
    ))
}

fn parse_digest_records(bytes: &[u8]) -> Result<Vec<DigestRecord<'_>>, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let mut records = Vec::new();
    let mut ids = BTreeSet::new();
    while cursor.remaining() != 0 {
        if records.len() >= MAX_RECORDS {
            return Err(Failure::Resource(format!(
                "APK signer exceeds the {MAX_RECORDS}-digest limit"
            )));
        }
        let record_bytes = cursor.length_prefixed("APK digest record")?;
        let mut record = ByteCursor::new(record_bytes);
        let id = record.u32("APK digest algorithm id")?;
        let digest = record.length_prefixed("APK content digest")?;
        record.finish("APK digest record")?;
        if !ids.insert(id) {
            return Err(Failure::Invalid(format!(
                "APK signer repeats digest algorithm {id:#010x}"
            )));
        }
        records.push(DigestRecord { id, bytes: digest });
    }
    if records.is_empty() {
        return Err(Failure::Invalid(
            "APK signer provides no content digests".to_string(),
        ));
    }
    Ok(records)
}

fn parse_first_certificate(
    bytes: &[u8],
    limits: Limits,
) -> Result<(CapturedX509Certificate, Vec<u8>), Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let mut count = 0_usize;
    let mut first = None;
    while cursor.remaining() != 0 {
        count = count.saturating_add(1);
        if count > MAX_CERTIFICATES {
            return Err(Failure::Resource(format!(
                "APK signer exceeds the {MAX_CERTIFICATES}-certificate limit"
            )));
        }
        let encoded = cursor.length_prefixed("APK signer certificate")?;
        let parsed = parse_certificate(encoded, limits)?;
        if first.is_none() {
            first = Some((parsed, encoded.to_vec()));
        }
    }
    first.ok_or_else(|| Failure::Invalid("APK signer has no certificate".to_string()))
}

pub(crate) fn parse_certificate(
    encoded: &[u8],
    limits: Limits,
) -> Result<CapturedX509Certificate, Failure> {
    preflight_der(encoded, limits).map_err(|error| {
        Failure::Invalid(format!("malformed APK certificate: {}", error.detail()))
    })?;
    catch_unwind(AssertUnwindSafe(|| {
        CapturedX509Certificate::from_der(encoded.to_vec())
    }))
    .map_err(|_| {
        Failure::Invalid(
            "APK certificate parser rejected malformed input without propagating its panic"
                .to_string(),
        )
    })?
    .map_err(|error| Failure::Invalid(format!("malformed APK certificate: {error}")))
}

pub(crate) fn validate_key_support(
    algorithm: SignatureAlgorithm,
    certificate: &CapturedX509Certificate,
) -> Result<(), Failure> {
    if !algorithm.uses_rsa() || certificate.key_algorithm() != Some(KeyAlgorithm::Rsa) {
        return Ok(());
    }
    let public_key = certificate.rsa_public_key_data().map_err(|error| {
        Failure::Invalid(format!("cannot parse APK signer RSA public key: {error}"))
    })?;
    let modulus = public_key
        .modulus
        .as_slice()
        .strip_prefix(&[0])
        .unwrap_or_else(|| public_key.modulus.as_slice());
    if !(256..=1024).contains(&modulus.len()) {
        return Err(Failure::Unsupported(format!(
            "APK RSA keys outside 2048..=8192 bits are not supported by this build ({} bytes)",
            modulus.len()
        )));
    }
    Ok(())
}

fn validate_sdk_range(minimum: u32, maximum: u32, location: &str) -> Result<(), Failure> {
    if minimum > i32::MAX as u32 || maximum > i32::MAX as u32 {
        return Err(Failure::Invalid(format!(
            "APK v3 {location} SDK range exceeds signed 32-bit Android API values: \
             {minimum}..={maximum}"
        )));
    }
    if minimum > maximum || maximum < 28 {
        return Err(Failure::Invalid(format!(
            "APK v3 {location} has invalid SDK range {minimum}..={maximum}"
        )));
    }
    Ok(())
}

fn check_attributes(
    bytes: &[u8],
    scheme: Scheme,
    present_schemes: &BTreeMap<u32, Vec<u8>>,
    _attribute_mode: AttributeMode,
    signer_certificate_der: &[u8],
    limits: Limits,
) -> Result<SignerAttributes, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let mut count = 0_usize;
    let mut ids = BTreeSet::new();
    let mut result = SignerAttributes::default();
    while cursor.remaining() != 0 {
        count = count.saturating_add(1);
        if count > MAX_RECORDS {
            return Err(Failure::Resource(format!(
                "APK signer exceeds the {MAX_RECORDS}-attribute limit"
            )));
        }
        let attribute = cursor.length_prefixed("APK signer attribute")?;
        let mut value = ByteCursor::new(attribute);
        let id = value.u32("APK signer attribute id")?;
        if !ids.insert(id) {
            return Err(Failure::Invalid(format!(
                "APK signer repeats attribute id {id:#010x}"
            )));
        }
        let payload = value.take(value.remaining(), "APK signer attribute value")?;
        match (scheme, id) {
            (Scheme::V2, V2_STRIPPING_PROTECTION_ATTR_ID) => {
                if payload.len() != 4 {
                    return Err(Failure::Invalid(
                        "APK v2 stripping-protection attribute is not four bytes".to_string(),
                    ));
                }
                let referenced = u32_at(payload, 0)?;
                let present = match referenced {
                    2 => present_schemes.contains_key(&APK_V2_BLOCK_ID),
                    3 => present_schemes.contains_key(&APK_V3_BLOCK_ID),
                    31 => present_schemes.contains_key(&APK_V31_BLOCK_ID),
                    _ => true,
                };
                if !present {
                    return Err(Failure::Mismatch(format!(
                        "APK v2 stripping protection references absent scheme v{referenced}"
                    )));
                }
            },
            (Scheme::V3 | Scheme::V31, V3_PROOF_OF_ROTATION_ATTR_ID) => {
                result.lineage = Some(verify_proof_of_rotation(
                    payload,
                    signer_certificate_der,
                    limits,
                )?);
            },
            (Scheme::V3, V3_ROTATION_MIN_SDK_ATTR_ID) => {
                if payload.len() != 4 {
                    return Err(Failure::Invalid(
                        "APK v3 rotation-min-sdk attribute is not four bytes".to_string(),
                    ));
                }
                let minimum = u32_at(payload, 0)?;
                if minimum > i32::MAX as u32 {
                    return Err(Failure::Invalid(format!(
                        "APK v3 rotation-min-sdk value {minimum} exceeds signed Android API values"
                    )));
                }
                result.rotation_min_sdk = Some(minimum);
            },
            (Scheme::V31, V3_ROTATION_MIN_SDK_ATTR_ID) => {
                return Err(Failure::Invalid(
                    "APK v3.1 signer carries the v3-only rotation-min-sdk attribute".to_string(),
                ));
            },
            (Scheme::V3 | Scheme::V31, V3_ROTATION_DEV_RELEASE_ATTR_ID) => {
                if !payload.is_empty() {
                    return Err(Failure::Invalid(
                        "APK targeted-rotation dev-release attribute is not empty".to_string(),
                    ));
                }
                result.targets_dev_release = true;
            },
            _ => {},
        }
    }
    Ok(result)
}

struct ParsedLineageLevel<'a> {
    signed_data: &'a [u8],
    certificate_der: &'a [u8],
    flags: u32,
    signed_signature_algorithm_id: u32,
    next_signature_algorithm_id: u32,
    signature: &'a [u8],
}

fn parse_lineage_level(
    level: &[u8],
    level_index: usize,
) -> Result<ParsedLineageLevel<'_>, Failure> {
    let mut level_cursor = ByteCursor::new(level);
    let signed_data = level_cursor.length_prefixed(&format!(
        "APK proof-of-rotation level {level_index} signed-data"
    ))?;
    let flags = level_cursor.u32("APK proof-of-rotation flags")?;
    let next_signature_algorithm_id =
        level_cursor.u32("APK proof-of-rotation next signature algorithm")?;
    let signature = level_cursor.length_prefixed("APK proof-of-rotation level signature")?;
    level_cursor.finish("APK proof-of-rotation level")?;

    let mut signed_cursor = ByteCursor::new(signed_data);
    let certificate_der = signed_cursor.length_prefixed("APK proof-of-rotation certificate")?;
    let signed_signature_algorithm_id =
        signed_cursor.u32("APK proof-of-rotation signed signature algorithm")?;
    signed_cursor.finish("APK proof-of-rotation signed-data")?;
    Ok(ParsedLineageLevel {
        signed_data,
        certificate_der,
        flags,
        signed_signature_algorithm_id,
        next_signature_algorithm_id,
        signature,
    })
}

fn verify_proof_of_rotation(
    bytes: &[u8],
    signer_certificate_der: &[u8],
    limits: Limits,
) -> Result<VerifiedLineage, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let version = cursor.u32("APK proof-of-rotation version")?;
    if version != PROOF_OF_ROTATION_VERSION {
        return Err(Failure::Invalid(format!(
            "APK proof-of-rotation version {version} is unsupported"
        )));
    }
    preflight_length_prefixed_count(
        cursor.bytes.get(cursor.offset..).ok_or_else(|| {
            Failure::Invalid("APK proof-of-rotation offset is invalid".to_string())
        })?,
        MAX_LINEAGE_LEVELS,
        "APK proof-of-rotation levels",
    )?;

    let mut levels = Vec::new();
    let mut certificates = BTreeSet::new();
    let mut previous: Option<(CapturedX509Certificate, u32)> = None;
    while cursor.remaining() != 0 {
        if levels.len() >= MAX_LINEAGE_LEVELS {
            return Err(Failure::Resource(format!(
                "APK proof-of-rotation exceeds the {MAX_LINEAGE_LEVELS}-level limit"
            )));
        }
        let level_index = levels.len();
        let level =
            cursor.length_prefixed(&format!("APK proof-of-rotation level {level_index}"))?;
        let parsed = parse_lineage_level(level, level_index)?;

        let certificate = parse_certificate(parsed.certificate_der, limits)?;
        if !certificates.insert(parsed.certificate_der.to_vec()) {
            return Err(Failure::Invalid(format!(
                "APK proof-of-rotation repeats a certificate at level {level_index}"
            )));
        }
        if let Some((previous_certificate, previous_algorithm_id)) = &previous {
            if *previous_algorithm_id != parsed.signed_signature_algorithm_id {
                return Err(Failure::Mismatch(format!(
                    "APK proof-of-rotation level {level_index} signature algorithm \
                     {:#010x} differs from its predecessor's \
                     {previous_algorithm_id:#010x}",
                    parsed.signed_signature_algorithm_id
                )));
            }
            let algorithm =
                SignatureAlgorithm::from_id(*previous_algorithm_id).ok_or_else(|| {
                    Failure::Unsupported(format!(
                        "APK proof-of-rotation uses unsupported signature algorithm \
                         {previous_algorithm_id:#010x}"
                    ))
                })?;
            validate_key_support(algorithm, previous_certificate)?;
            let verifier = algorithm.verifier(previous_certificate.key_algorithm())?;
            previous_certificate
                .verify_signed_data_with_algorithm(parsed.signed_data, parsed.signature, verifier)
                .map_err(|_| {
                    Failure::Mismatch(format!(
                        "APK proof-of-rotation signature for level {level_index} did not verify"
                    ))
                })?;
        }
        if parsed.next_signature_algorithm_id != 0
            && SignatureAlgorithm::from_id(parsed.next_signature_algorithm_id).is_none()
        {
            return Err(Failure::Unsupported(format!(
                "APK proof-of-rotation level {level_index} names unsupported next signature \
                 algorithm {:#010x}",
                parsed.next_signature_algorithm_id
            )));
        }
        let fingerprint = Sha256::digest(parsed.certificate_der).into();
        levels.push(VerifiedLineageLevel {
            certificate_der: parsed.certificate_der.to_vec(),
            fingerprint,
            flags: parsed.flags,
            signed_signature_algorithm_id: parsed.signed_signature_algorithm_id,
            next_signature_algorithm_id: parsed.next_signature_algorithm_id,
        });
        previous = Some((certificate, parsed.next_signature_algorithm_id));
    }
    let Some(last) = levels.last() else {
        return Err(Failure::Invalid(
            "APK proof-of-rotation contains no certificate levels".to_string(),
        ));
    };
    if last.certificate_der != signer_certificate_der {
        return Err(Failure::Mismatch(
            "APK signer certificate differs from the terminal proof-of-rotation certificate"
                .to_string(),
        ));
    }
    Ok(VerifiedLineage { levels })
}

fn preflight_length_prefixed_count(
    bytes: &[u8],
    maximum: usize,
    what: &str,
) -> Result<(), Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let mut count = 0_usize;
    while cursor.remaining() != 0 {
        count = count.saturating_add(1);
        if count > maximum {
            return Err(Failure::Resource(format!(
                "{what} exceed the {maximum}-item limit"
            )));
        }
        let _ = cursor.length_prefixed(what)?;
    }
    Ok(())
}

fn validate_v3_ranges(evidence: &[SignerEvidence], scheme: Scheme) -> Result<(), Failure> {
    let mut signers = evidence
        .iter()
        .filter_map(|item| item.sdk_range.map(|range| (range, item)))
        .collect::<Vec<_>>();
    signers.sort_by_key(|(range, _)| *range);
    for pair in signers.windows(2) {
        let (previous_range, previous) = pair[0];
        let (current_range, current) = pair[1];
        let contiguous = previous_range.1.checked_add(1) == Some(current_range.0);
        let development_overlap =
            current.attributes.targets_dev_release && previous_range.1 == current_range.0;
        if !contiguous && !development_overlap {
            return Err(Failure::Invalid(format!(
                "APK {} signer SDK ranges overlap or leave a hole: {}..={} then {}..={}",
                scheme.label(),
                previous_range.0,
                previous_range.1,
                current_range.0,
                current_range.1
            )));
        }
        validate_lineage_extension(previous, current)?;
    }
    Ok(())
}

fn validate_lineage_extension(
    previous: &SignerEvidence,
    current: &SignerEvidence,
) -> Result<(), Failure> {
    let previous_lineage = effective_lineage(previous);
    let current_lineage = effective_lineage(current);
    if previous_lineage.len() > current_lineage.len()
        || !previous_lineage
            .iter()
            .zip(current_lineage.iter())
            .all(|(left, right)| left == right)
    {
        return Err(Failure::Mismatch(
            "APK targeted signers carry inconsistent proof-of-rotation lineages".to_string(),
        ));
    }
    Ok(())
}

fn effective_lineage(signer: &SignerEvidence) -> Vec<&[u8]> {
    signer.attributes.lineage.as_ref().map_or_else(
        || vec![signer.certificate_der.as_slice()],
        |lineage| {
            lineage
                .levels
                .iter()
                .map(|level| level.certificate_der.as_slice())
                .collect()
        },
    )
}

fn validate_targeted_rotation(
    v3: &[SignerEvidence],
    v31: &[SignerEvidence],
) -> Result<(), Failure> {
    if v31.is_empty() {
        if v3
            .iter()
            .any(|signer| signer.attributes.rotation_min_sdk.is_some())
        {
            return Err(Failure::Mismatch(
                "APK v3 rotation-min-sdk stripping protection references an absent v3.1 block"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    if v3.is_empty() {
        return Err(Failure::Mismatch(
            "APK v3.1 block is present without the required v3 block".to_string(),
        ));
    }

    let mut rotated_signers = v31.iter().collect::<Vec<_>>();
    rotated_signers.sort_by_key(|signer| signer.sdk_range);
    let first_v31 = rotated_signers.first().copied().ok_or_else(|| {
        Failure::Invalid("APK v3.1 block contains no targeted signer".to_string())
    })?;
    let (rotation_min_sdk, _) = first_v31
        .sdk_range
        .ok_or_else(|| Failure::Invalid("APK v3.1 signer omits its SDK range".to_string()))?;
    if rotation_min_sdk < 33
        && !(first_v31.attributes.targets_dev_release
            && rotation_min_sdk.checked_add(1).is_some_and(|sdk| sdk >= 33))
    {
        return Err(Failure::Invalid(format!(
            "APK v3.1 signer targets SDK {rotation_min_sdk} without the dev-release marker"
        )));
    }
    for signer in v3 {
        if signer.attributes.rotation_min_sdk != Some(rotation_min_sdk) {
            return Err(Failure::Mismatch(format!(
                "APK v3 rotation-min-sdk stripping protection does not match v3.1 minimum SDK \
                 {rotation_min_sdk}"
            )));
        }
    }

    let mut original_signers = v3.iter().collect::<Vec<_>>();
    original_signers.sort_by_key(|signer| signer.sdk_range);
    let last_v3 = original_signers
        .last()
        .copied()
        .ok_or_else(|| Failure::Invalid("APK v3 block contains no targeted signer".to_string()))?;
    let (_, last_v3_maximum) = last_v3
        .sdk_range
        .ok_or_else(|| Failure::Invalid("APK v3 signer omits its SDK range".to_string()))?;
    let boundary_matches = if first_v31.attributes.targets_dev_release {
        last_v3_maximum == rotation_min_sdk
    } else {
        last_v3_maximum.checked_add(1) == Some(rotation_min_sdk)
    };
    if !boundary_matches {
        return Err(Failure::Mismatch(format!(
            "APK v3/v3.1 targeted-rotation SDK boundary is inconsistent: v3 ends at \
             {last_v3_maximum}, v3.1 starts at {rotation_min_sdk}"
        )));
    }
    validate_lineage_extension(last_v3, first_v31)?;
    if effective_lineage(first_v31).len() < 2 {
        return Err(Failure::Mismatch(
            "APK v3.1 targeted signer has no verifiable certificate rotation".to_string(),
        ));
    }
    Ok(())
}

fn build_rotation_evidence(
    v3: &[SignerEvidence],
    v31: &[SignerEvidence],
) -> Option<AndroidRotationEvidence> {
    let has_lineage = v3
        .iter()
        .chain(v31.iter())
        .any(|signer| signer.attributes.lineage.is_some());
    if !has_lineage && v31.is_empty() {
        return None;
    }
    let longest = v3
        .iter()
        .chain(v31.iter())
        .filter_map(|signer| signer.attributes.lineage.as_ref())
        .max_by_key(|lineage| lineage.levels.len());
    let lineage = longest.map_or_else(Vec::new, |lineage| {
        lineage
            .levels
            .iter()
            .map(|level| AndroidLineageLevelEvidence {
                fingerprint: level.fingerprint,
                flags: level.flags,
                signed_signature_algorithm_id: level.signed_signature_algorithm_id,
                next_signature_algorithm_id: level.next_signature_algorithm_id,
            })
            .collect()
    });
    let mut signers = v3
        .iter()
        .chain(v31.iter())
        .filter_map(|signer| {
            let (minimum_sdk, maximum_sdk) = signer.sdk_range?;
            Some(AndroidSignerEvidence {
                scheme: signer.scheme.label(),
                minimum_sdk,
                maximum_sdk,
                fingerprint: signer.fingerprint,
                lineage_levels: signer
                    .attributes
                    .lineage
                    .as_ref()
                    .map_or(1, |lineage| lineage.levels.len()),
                targets_dev_release: signer.attributes.targets_dev_release,
            })
        })
        .collect::<Vec<_>>();
    signers.sort_by_key(|signer| (signer.minimum_sdk, signer.maximum_sdk, signer.scheme));
    let rotation_boundary = v31
        .iter()
        .filter_map(|signer| signer.sdk_range.map(|range| (range, signer)))
        .min_by_key(|(range, _)| *range);
    Some(AndroidRotationEvidence {
        v31_present: !v31.is_empty(),
        rotation_min_sdk: rotation_boundary.map(|(range, _)| range.0),
        targets_dev_release: rotation_boundary
            .is_some_and(|(_, signer)| signer.attributes.targets_dev_release),
        signers,
        lineage,
    })
}

#[derive(Debug)]
struct ComputedDigests {
    sha256: Option<Vec<u8>>,
    sha512: Option<Vec<u8>>,
    verity_sha256: Option<Vec<u8>>,
}

fn compute_content_digests<R: Read + Seek>(
    reader: &mut R,
    layout: &ApkLayout,
    limits: Limits,
    sha256_requested: bool,
    sha512_requested: bool,
    verity_requested: bool,
) -> Result<ComputedDigests, Failure> {
    let mut digests =
        compute_chunked_digests(reader, layout, limits, sha256_requested, sha512_requested)?;
    if verity_requested {
        digests.verity_sha256 = Some(compute_apk_verity_digest(reader, layout, limits)?);
    }
    Ok(digests)
}

fn compute_chunked_digests<R: Read + Seek>(
    reader: &mut R,
    layout: &ApkLayout,
    limits: Limits,
    sha256_requested: bool,
    sha512_requested: bool,
) -> Result<ComputedDigests, Failure> {
    if !sha256_requested && !sha512_requested {
        return Ok(ComputedDigests {
            sha256: None,
            sha512: None,
            verity_sha256: None,
        });
    }
    let first_length = layout.block_start;
    let central_length = layout
        .eocd_offset
        .checked_sub(layout.central_offset)
        .ok_or_else(|| Failure::Invalid("APK central-directory range underflow".to_string()))?;
    let eocd_length = u64::try_from(layout.eocd.len())
        .map_err(|_| Failure::Resource("APK EOCD length exceeds u64".to_string()))?;
    let signed_length = first_length
        .checked_add(central_length)
        .and_then(|value| value.checked_add(eocd_length))
        .ok_or_else(|| Failure::Resource("APK signed length overflow".to_string()))?;
    if limits
        .decoded_total()
        .is_some_and(|limit| signed_length > limit)
    {
        return Err(Failure::Resource(format!(
            "APK signature covers {signed_length} bytes; decoded-total limit is {}",
            limits.decoded_total().unwrap_or(0)
        )));
    }
    let chunk_count = chunks(first_length)?
        .checked_add(chunks(central_length)?)
        .and_then(|value| value.checked_add(chunks(eocd_length).ok()?))
        .ok_or_else(|| Failure::Resource("APK content chunk count overflow".to_string()))?;
    let chunk_count = u32::try_from(chunk_count)
        .map_err(|_| Failure::Resource("APK has too many 1 MiB content chunks".to_string()))?;
    let prefix = [
        0x5a,
        chunk_count.to_le_bytes()[0],
        chunk_count.to_le_bytes()[1],
        chunk_count.to_le_bytes()[2],
        chunk_count.to_le_bytes()[3],
    ];
    let mut top_sha256 = sha256_requested.then(Sha256::new);
    let mut top_sha512 = sha512_requested.then(Sha512::new);
    if let Some(hasher) = &mut top_sha256 {
        hasher.update(prefix);
    }
    if let Some(hasher) = &mut top_sha512 {
        hasher.update(prefix);
    }

    hash_reader_section(
        reader,
        0,
        first_length,
        limits,
        &mut top_sha256,
        &mut top_sha512,
    )?;
    hash_reader_section(
        reader,
        layout.central_offset,
        central_length,
        limits,
        &mut top_sha256,
        &mut top_sha512,
    )?;

    let mut patched_eocd = layout.eocd.clone();
    let block_start = u32::try_from(layout.block_start).map_err(|_| {
        Failure::Unsupported("APK Signing Block offset exceeds ZIP32 range".to_string())
    })?;
    patched_eocd
        .get_mut(16..20)
        .ok_or_else(|| Failure::Invalid("APK EOCD central offset is truncated".to_string()))?
        .copy_from_slice(&block_start.to_le_bytes());
    hash_memory_section(&patched_eocd, &mut top_sha256, &mut top_sha512)?;

    Ok(ComputedDigests {
        sha256: top_sha256.map(|hasher| hasher.finalize().to_vec()),
        sha512: top_sha512.map(|hasher| hasher.finalize().to_vec()),
        verity_sha256: None,
    })
}

fn compute_apk_verity_digest<R: Read + Seek>(
    reader: &mut R,
    layout: &ApkLayout,
    limits: Limits,
) -> Result<Vec<u8>, Failure> {
    if !layout.block_start.is_multiple_of(VERITY_BLOCK_SIZE as u64) {
        return Err(Failure::Invalid(format!(
            "APK fs-verity signing block starts at {}, which is not 4096-byte aligned",
            layout.block_start
        )));
    }
    let signing_block_size = layout
        .central_offset
        .checked_sub(layout.block_start)
        .ok_or_else(|| Failure::Invalid("APK signing-block range underflow".to_string()))?;
    if !signing_block_size.is_multiple_of(VERITY_BLOCK_SIZE as u64) {
        return Err(Failure::Invalid(format!(
            "APK fs-verity signing block size {signing_block_size} is not a multiple of 4096"
        )));
    }
    if limits
        .in_flight_bytes()
        .is_some_and(|limit| limit < VERITY_BLOCK_SIZE)
    {
        return Err(Failure::Resource(format!(
            "APK fs-verity requires one {VERITY_BLOCK_SIZE}-byte block in flight"
        )));
    }

    let central_length = layout
        .eocd_offset
        .checked_sub(layout.central_offset)
        .ok_or_else(|| Failure::Invalid("APK central-directory range underflow".to_string()))?;
    let eocd_length = u64::try_from(layout.eocd.len())
        .map_err(|_| Failure::Resource("APK EOCD length exceeds u64".to_string()))?;
    let signed_length = layout
        .block_start
        .checked_add(central_length)
        .and_then(|length| length.checked_add(eocd_length))
        .ok_or_else(|| Failure::Resource("APK fs-verity source length overflow".to_string()))?;
    if signed_length == 0 {
        return Err(Failure::Invalid(
            "APK fs-verity source contains no bytes".to_string(),
        ));
    }
    if limits
        .decoded_total()
        .is_some_and(|limit| signed_length > limit)
    {
        return Err(Failure::Resource(format!(
            "APK fs-verity covers {signed_length} bytes; decoded-total limit is {}",
            limits.decoded_total().unwrap_or(0)
        )));
    }

    let leaf_count = signed_length
        .checked_add(VERITY_BLOCK_SIZE as u64 - 1)
        .map(|length| length / VERITY_BLOCK_SIZE as u64)
        .ok_or_else(|| Failure::Resource("APK fs-verity leaf count overflow".to_string()))?;
    let mut tree = StreamingVerityTree::new(leaf_count)?;
    feed_verity_reader(reader, 0, layout.block_start, limits, &mut tree)?;
    feed_verity_reader(
        reader,
        layout.central_offset,
        central_length,
        limits,
        &mut tree,
    )?;

    let mut patched_eocd = layout.eocd.clone();
    let block_start = u32::try_from(layout.block_start).map_err(|_| {
        Failure::Unsupported("APK Signing Block offset exceeds ZIP32 range".to_string())
    })?;
    patched_eocd
        .get_mut(16..20)
        .ok_or_else(|| Failure::Invalid("APK EOCD central offset is truncated".to_string()))?
        .copy_from_slice(&block_start.to_le_bytes());
    tree.update(&patched_eocd)?;
    let root = tree.finish()?;
    let mut encoded = Vec::with_capacity(40);
    encoded.extend_from_slice(&root);
    encoded.extend_from_slice(&signed_length.to_le_bytes());
    Ok(encoded)
}

fn feed_verity_reader<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
    limits: Limits,
    tree: &mut StreamingVerityTree,
) -> Result<(), Failure> {
    reader.seek(SeekFrom::Start(offset)).map_err(|error| {
        Failure::Read(format!("cannot seek while hashing APK fs-verity: {error}"))
    })?;
    let buffer_limit = limits.in_flight_bytes().unwrap_or(64 * 1024);
    let mut buffer = vec![0_u8; buffer_limit.clamp(VERITY_BLOCK_SIZE, 64 * 1024)];
    let mut remaining = length;
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Failure::Resource("APK fs-verity read size overflow".to_string()))?;
        reader.read_exact(&mut buffer[..take]).map_err(|error| {
            Failure::Read(format!(
                "cannot read APK bytes for fs-verity digest: {error}"
            ))
        })?;
        tree.update(&buffer[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

#[derive(Debug)]
struct StreamingVerityTree {
    data_block: Vec<u8>,
    levels: Vec<Vec<u8>>,
    root: Option<[u8; VERITY_DIGEST_SIZE]>,
}

impl StreamingVerityTree {
    fn new(mut leaf_count: u64) -> Result<Self, Failure> {
        if leaf_count == 0 {
            return Err(Failure::Invalid(
                "APK fs-verity tree has no leaves".to_string(),
            ));
        }
        let mut level_count = 1_usize;
        while leaf_count > VERITY_DIGESTS_PER_BLOCK as u64 {
            leaf_count = leaf_count
                .checked_add(VERITY_DIGESTS_PER_BLOCK as u64 - 1)
                .map(|count| count / VERITY_DIGESTS_PER_BLOCK as u64)
                .ok_or_else(|| {
                    Failure::Resource("APK fs-verity level count overflow".to_string())
                })?;
            level_count = level_count.checked_add(1).ok_or_else(|| {
                Failure::Resource("APK fs-verity level count overflow".to_string())
            })?;
        }
        let levels = (0..level_count)
            .map(|_| Vec::with_capacity(VERITY_BLOCK_SIZE))
            .collect();
        Ok(Self {
            data_block: Vec::with_capacity(VERITY_BLOCK_SIZE),
            levels,
            root: None,
        })
    }

    fn update(&mut self, mut bytes: &[u8]) -> Result<(), Failure> {
        while !bytes.is_empty() {
            let available = VERITY_BLOCK_SIZE.saturating_sub(self.data_block.len());
            let take = available.min(bytes.len());
            self.data_block.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.data_block.len() == VERITY_BLOCK_SIZE {
                let digest = verity_hash_block(&self.data_block)?;
                self.data_block.clear();
                self.push_digest(0, digest)?;
            }
        }
        Ok(())
    }

    fn push_digest(
        &mut self,
        mut level: usize,
        mut digest: [u8; VERITY_DIGEST_SIZE],
    ) -> Result<(), Failure> {
        loop {
            let level_count = self.levels.len();
            let buffer = self.levels.get_mut(level).ok_or_else(|| {
                Failure::Resource("APK fs-verity level index overflow".to_string())
            })?;
            buffer.extend_from_slice(&digest);
            if buffer.len() < VERITY_BLOCK_SIZE {
                return Ok(());
            }
            if buffer.len() != VERITY_BLOCK_SIZE {
                return Err(Failure::Resource(
                    "APK fs-verity level exceeded one block".to_string(),
                ));
            }
            digest = verity_hash_block(buffer)?;
            buffer.clear();
            if level + 1 == level_count {
                if self.root.replace(digest).is_some() {
                    return Err(Failure::Invalid(
                        "APK fs-verity tree produced more than one root".to_string(),
                    ));
                }
                return Ok(());
            }
            level = level
                .checked_add(1)
                .ok_or_else(|| Failure::Resource("APK fs-verity level overflow".to_string()))?;
        }
    }

    fn finish(mut self) -> Result<[u8; VERITY_DIGEST_SIZE], Failure> {
        if !self.data_block.is_empty() {
            self.data_block.resize(VERITY_BLOCK_SIZE, 0);
            let digest = verity_hash_block(&self.data_block)?;
            self.data_block.clear();
            self.push_digest(0, digest)?;
        }
        for level in 0..self.levels.len() {
            let Some(buffer) = self.levels.get_mut(level) else {
                return Err(Failure::Resource(
                    "APK fs-verity level disappeared".to_string(),
                ));
            };
            if buffer.is_empty() {
                continue;
            }
            buffer.resize(VERITY_BLOCK_SIZE, 0);
            let digest = verity_hash_block(buffer)?;
            buffer.clear();
            if level + 1 == self.levels.len() {
                if self.root.replace(digest).is_some() {
                    return Err(Failure::Invalid(
                        "APK fs-verity tree produced duplicate roots".to_string(),
                    ));
                }
            } else {
                self.push_digest(level + 1, digest)?;
            }
        }
        self.root.ok_or_else(|| {
            Failure::Invalid("APK fs-verity tree did not produce a root hash".to_string())
        })
    }
}

fn verity_hash_block(bytes: &[u8]) -> Result<[u8; VERITY_DIGEST_SIZE], Failure> {
    if bytes.len() != VERITY_BLOCK_SIZE {
        return Err(Failure::Invalid(format!(
            "APK fs-verity hash input is {} bytes instead of {VERITY_BLOCK_SIZE}",
            bytes.len()
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update([0_u8; 8]);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn chunks(length: u64) -> Result<u64, Failure> {
    if length == 0 {
        return Ok(0);
    }
    length
        .checked_add(CHUNK_SIZE - 1)
        .map(|value| value / CHUNK_SIZE)
        .ok_or_else(|| Failure::Resource("APK chunk-count arithmetic overflow".to_string()))
}

fn hash_reader_section<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
    limits: Limits,
    top_sha256: &mut Option<Sha256>,
    top_sha512: &mut Option<Sha512>,
) -> Result<(), Failure> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| Failure::Read(format!("cannot seek while hashing APK: {error}")))?;
    let buffer_limit = limits.in_flight_bytes().unwrap_or(64 * 1024);
    if buffer_limit == 0 {
        return Err(Failure::Resource(
            "APK digest in-flight byte limit is zero".to_string(),
        ));
    }
    let mut buffer = vec![0_u8; buffer_limit.min(64 * 1024)];
    let mut remaining = length;
    while remaining != 0 {
        let chunk_length = remaining.min(CHUNK_SIZE);
        let chunk_length_u32 = u32::try_from(chunk_length)
            .map_err(|_| Failure::Resource("APK chunk length exceeds u32".to_string()))?;
        let mut chunk_sha256 = top_sha256.is_some().then(Sha256::new);
        let mut chunk_sha512 = top_sha512.is_some().then(Sha512::new);
        update_chunk_header(&mut chunk_sha256, &mut chunk_sha512, chunk_length_u32);
        let mut chunk_remaining = chunk_length;
        while chunk_remaining != 0 {
            let take = usize::try_from(chunk_remaining.min(buffer.len() as u64))
                .map_err(|_| Failure::Resource("APK digest buffer size overflow".to_string()))?;
            reader.read_exact(&mut buffer[..take]).map_err(|error| {
                Failure::Read(format!("cannot read APK bytes for content digest: {error}"))
            })?;
            if let Some(hasher) = &mut chunk_sha256 {
                hasher.update(&buffer[..take]);
            }
            if let Some(hasher) = &mut chunk_sha512 {
                hasher.update(&buffer[..take]);
            }
            chunk_remaining -= take as u64;
        }
        finish_chunk(chunk_sha256, chunk_sha512, top_sha256, top_sha512);
        remaining -= chunk_length;
    }
    Ok(())
}

fn hash_memory_section(
    bytes: &[u8],
    top_sha256: &mut Option<Sha256>,
    top_sha512: &mut Option<Sha512>,
) -> Result<(), Failure> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let end = offset
            .checked_add(CHUNK_SIZE_USIZE)
            .map_or(bytes.len(), |value| value.min(bytes.len()));
        let chunk = &bytes[offset..end];
        let chunk_length = u32::try_from(chunk.len())
            .map_err(|_| Failure::Resource("APK memory chunk length exceeds u32".to_string()))?;
        let mut chunk_sha256 = top_sha256.is_some().then(Sha256::new);
        let mut chunk_sha512 = top_sha512.is_some().then(Sha512::new);
        update_chunk_header(&mut chunk_sha256, &mut chunk_sha512, chunk_length);
        if let Some(hasher) = &mut chunk_sha256 {
            hasher.update(chunk);
        }
        if let Some(hasher) = &mut chunk_sha512 {
            hasher.update(chunk);
        }
        finish_chunk(chunk_sha256, chunk_sha512, top_sha256, top_sha512);
        offset = end;
    }
    Ok(())
}

fn update_chunk_header(sha256: &mut Option<Sha256>, sha512: &mut Option<Sha512>, length: u32) {
    let length = length.to_le_bytes();
    if let Some(hasher) = sha256 {
        hasher.update([0xa5]);
        hasher.update(length);
    }
    if let Some(hasher) = sha512 {
        hasher.update([0xa5]);
        hasher.update(length);
    }
}

fn finish_chunk(
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
    top_sha256: &mut Option<Sha256>,
    top_sha512: &mut Option<Sha512>,
) {
    if let (Some(chunk), Some(top)) = (sha256, top_sha256) {
        top.update(chunk.finalize());
    }
    if let (Some(chunk), Some(top)) = (sha512, top_sha512) {
        top.update(chunk.finalize());
    }
}

fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    output: &mut [u8],
) -> std::io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(output)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Failure> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| Failure::Invalid("little-endian u16 is truncated".to_string()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Failure> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Failure::Invalid("little-endian u32 is truncated".to_string()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Failure> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or_else(|| Failure::Invalid("little-endian u64 is truncated".to_string()))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

    use std::io::Cursor;

    use super::*;

    const AOSP_V2: &[u8] =
        include_bytes!("../tests/fixtures/android_apk_v2_v3/golden-aligned-v2-out.apk");
    const AOSP_V3_LINEAGE: &[u8] = include_bytes!(
        "../tests/fixtures/android_apk_v2_v3/v1v2v3-with-rsa-2048-lineage-3-signers.apk"
    );

    #[test]
    fn equally_ranked_signature_algorithms_keep_the_first_record() {
        let records = [
            SignatureRecord {
                id: 0x0101,
                bytes: &[1],
            },
            SignatureRecord {
                id: 0x0103,
                bytes: &[2],
            },
        ];
        let selected = select_signatures(&records, ANDROID_N_API, i32::MAX as u32)
            .expect("known algorithms select");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, 0x0101);
        assert_eq!(selected[0].bytes, &[1]);
    }

    #[test]
    fn standard_and_verity_algorithms_cover_their_platform_introductions() {
        let records = [
            SignatureRecord {
                id: 0x0103,
                bytes: &[1],
            },
            SignatureRecord {
                id: 0x0421,
                bytes: &[2],
            },
        ];
        let selected = select_signatures(&records, ANDROID_N_API, i32::MAX as u32)
            .expect("known algorithms select");
        assert_eq!(
            selected.iter().map(|record| record.id).collect::<Vec<_>>(),
            [0x0103, 0x0421]
        );
    }

    #[test]
    fn verity_only_cannot_cover_a_pre_p_signer_range() {
        let records = [SignatureRecord {
            id: 0x0421,
            bytes: &[1],
        }];
        assert!(matches!(
            select_signatures(&records, ANDROID_N_API, i32::MAX as u32),
            Err(Failure::Unsupported(detail)) if detail.contains("earliest supported")
        ));
    }

    #[test]
    fn sha512_replaces_sha256_at_the_same_platform_introduction() {
        let records = [
            SignatureRecord {
                id: 0x0103,
                bytes: &[1],
            },
            SignatureRecord {
                id: 0x0104,
                bytes: &[2],
            },
            SignatureRecord {
                id: 0x0421,
                bytes: &[3],
            },
        ];
        let selected = select_signatures(&records, ANDROID_N_API, i32::MAX as u32)
            .expect("known algorithms select");
        assert_eq!(
            selected.iter().map(|record| record.id).collect::<Vec<_>>(),
            [0x0104, 0x0421]
        );
    }

    #[test]
    fn unselected_digest_kind_is_ignored_even_when_malformed() {
        let records = [
            DigestRecord {
                id: 0x0103,
                bytes: &[0xff],
            },
            DigestRecord {
                id: 0x0104,
                bytes: &[0; 64],
            },
        ];
        let selected_kinds = BTreeSet::from([ContentDigestKind::ChunkedSha512]);
        let digests =
            collect_content_digests(&records, &selected_kinds).expect("selected digest is valid");
        assert_eq!(
            digests.keys().copied().collect::<Vec<_>>(),
            [ContentDigestKind::ChunkedSha512]
        );
    }

    #[test]
    fn selected_digest_kind_rejects_malformed_bytes() {
        let records = [DigestRecord {
            id: 0x0104,
            bytes: &[0xff],
        }];
        let selected_kinds = BTreeSet::from([ContentDigestKind::ChunkedSha512]);
        assert!(matches!(
            collect_content_digests(&records, &selected_kinds),
            Err(Failure::Invalid(detail)) if detail.contains("expected 64")
        ));
    }

    #[test]
    fn every_record_sharing_a_selected_digest_kind_must_agree() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let records = [
            DigestRecord {
                id: 0x0101,
                bytes: &first,
            },
            DigestRecord {
                id: 0x0103,
                bytes: &second,
            },
        ];
        let selected_kinds = BTreeSet::from([ContentDigestKind::ChunkedSha256]);
        assert!(matches!(
            collect_content_digests(&records, &selected_kinds),
            Err(Failure::Invalid(detail)) if detail.contains("conflicting authenticated digests")
        ));
    }

    #[test]
    fn every_certificate_in_the_signed_sequence_is_parsed() {
        let mut input = Cursor::new(AOSP_V2);
        let layout =
            locate_signing_block(&mut input, Limits::safe()).expect("official fixture layout");
        let scheme = layout
            .schemes
            .get(&APK_V2_BLOCK_ID)
            .expect("official fixture v2 block");
        let mut outer = ByteCursor::new(scheme);
        let signers = outer
            .length_prefixed("test v2 signers")
            .expect("signer sequence");
        let mut signer_sequence = ByteCursor::new(signers);
        let signer = signer_sequence
            .length_prefixed("test v2 signer")
            .expect("first signer");
        let mut signer = ByteCursor::new(signer);
        let signed_data = signer
            .length_prefixed("test signed-data")
            .expect("signed-data");
        let (_, certificates, _, _) =
            parse_signed_data(signed_data, Scheme::V2).expect("valid signed-data");

        let mut with_malformed_second = certificates.to_vec();
        with_malformed_second.extend_from_slice(&1_u32.to_le_bytes());
        with_malformed_second.push(0);
        assert!(matches!(
            parse_first_certificate(&with_malformed_second, Limits::safe()),
            Err(Failure::Invalid(_))
        ));
    }

    #[test]
    fn zip64_locator_is_rejected_even_without_eocd_sentinels() {
        let mut bytes = vec![0_u8; 20];
        bytes[..4].copy_from_slice(b"PK\x06\x07");
        let mut eocd = vec![0_u8; EOCD_MIN];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&eocd);
        assert!(matches!(
            locate_zip_sections(&mut Cursor::new(bytes)),
            Err(Failure::Unsupported(_))
        ));
    }

    #[test]
    fn v3_sdk_ranges_are_bounded_to_signed_android_api_values() {
        assert!(validate_sdk_range(28, i32::MAX as u32, "test").is_ok());
        assert!(matches!(
            validate_sdk_range(28, i32::MAX as u32 + 1, "test"),
            Err(Failure::Invalid(_))
        ));
    }

    #[test]
    fn rotation_development_marker_belongs_to_the_minimum_v31_boundary() {
        let signer = |sdk_range, targets_dev_release| SignerEvidence {
            fingerprint: [0; 32],
            sdk_range: Some(sdk_range),
            certificate_der: Vec::new(),
            content_digests: BTreeMap::new(),
            scheme: Scheme::V31,
            attributes: SignerAttributes {
                targets_dev_release,
                ..SignerAttributes::default()
            },
        };
        let v31 = [signer((34, 34), false), signer((35, i32::MAX as u32), true)];
        let report = build_rotation_evidence(&[], &v31).expect("v3.1 evidence");
        assert_eq!(report.rotation_min_sdk, Some(34));
        assert!(!report.targets_dev_release);
    }

    #[test]
    fn official_three_level_proof_of_rotation_verifies_directly() {
        let (lineage, signer_certificate) = official_lineage();
        let verified = verify_proof_of_rotation(&lineage, &signer_certificate, Limits::safe())
            .expect("official AOSP proof-of-rotation");
        assert_eq!(verified.levels.len(), 3);
        assert_eq!(verified.levels[0].signed_signature_algorithm_id, 0);
        assert_eq!(verified.levels[0].next_signature_algorithm_id, 0x0103);
        assert_eq!(verified.levels[2].next_signature_algorithm_id, 0);
    }

    #[test]
    fn proof_of_rotation_signature_tamper_fails() {
        let (mut lineage, signer_certificate) = official_lineage();
        let last = lineage.last_mut().expect("lineage signature byte");
        *last ^= 0x01;
        assert!(matches!(
            verify_proof_of_rotation(&lineage, &signer_certificate, Limits::safe()),
            Err(Failure::Mismatch(_))
        ));
    }

    #[test]
    fn duplicate_certificate_rejects_lineage_cycles() {
        let (lineage, signer_certificate) = official_lineage();
        let first = lineage_certificate_range(&lineage, 0);
        let duplicate = lineage[first].to_vec();
        let lineage = replace_lineage_certificate(&lineage, 1, &duplicate);
        assert!(matches!(
            verify_proof_of_rotation(&lineage, &signer_certificate, Limits::safe()),
            Err(Failure::Invalid(detail)) if detail.contains("repeats a certificate")
        ));
    }

    #[test]
    fn oversized_proof_of_rotation_level_count_hits_resource_limit_first() {
        let mut lineage = PROOF_OF_ROTATION_VERSION.to_le_bytes().to_vec();
        for _ in 0..=MAX_LINEAGE_LEVELS {
            lineage.extend_from_slice(&0_u32.to_le_bytes());
        }
        assert!(matches!(
            verify_proof_of_rotation(&lineage, &[], Limits::safe()),
            Err(Failure::Resource(_))
        ));
    }

    fn official_lineage() -> (Vec<u8>, Vec<u8>) {
        let mut input = Cursor::new(AOSP_V3_LINEAGE);
        let layout =
            locate_signing_block(&mut input, Limits::safe()).expect("official fixture layout");
        let scheme = layout
            .schemes
            .get(&APK_V3_BLOCK_ID)
            .expect("official fixture v3 block");
        let mut outer = ByteCursor::new(scheme);
        let signers = outer
            .length_prefixed("test v3 signers")
            .expect("signer sequence");
        let mut signer_sequence = ByteCursor::new(signers);
        let signer = signer_sequence
            .length_prefixed("test v3 signer")
            .expect("first signer");
        let mut signer = ByteCursor::new(signer);
        let signed_data = signer
            .length_prefixed("test signed-data")
            .expect("signed-data");
        let (_, certificates, _, attributes) =
            parse_signed_data(signed_data, Scheme::V3).expect("valid signed-data");
        let mut certificate_sequence = ByteCursor::new(certificates);
        let signer_certificate = certificate_sequence
            .length_prefixed("test signer certificate")
            .expect("signer certificate")
            .to_vec();
        let mut attribute_sequence = ByteCursor::new(attributes);
        while attribute_sequence.remaining() != 0 {
            let attribute = attribute_sequence
                .length_prefixed("test signer attribute")
                .expect("attribute");
            let mut attribute = ByteCursor::new(attribute);
            let id = attribute.u32("test attribute id").expect("attribute id");
            let payload = attribute
                .take(attribute.remaining(), "test attribute payload")
                .expect("attribute payload");
            if id == V3_PROOF_OF_ROTATION_ATTR_ID {
                return (payload.to_vec(), signer_certificate);
            }
        }
        panic!("official fixture proof-of-rotation attribute");
    }

    fn lineage_certificate_range(lineage: &[u8], wanted: usize) -> std::ops::Range<usize> {
        let mut cursor = ByteCursor::new(lineage);
        cursor.u32("test lineage version").expect("version");
        let mut index = 0_usize;
        while cursor.remaining() != 0 {
            let level = cursor.length_prefixed("test lineage level").expect("level");
            if index == wanted {
                let parsed = parse_lineage_level(level, index).expect("parsed level");
                let start = parsed.certificate_der.as_ptr() as usize - lineage.as_ptr() as usize;
                return start..start + parsed.certificate_der.len();
            }
            index += 1;
        }
        panic!("requested lineage certificate");
    }

    fn replace_lineage_certificate(lineage: &[u8], wanted: usize, replacement: &[u8]) -> Vec<u8> {
        let mut cursor = ByteCursor::new(lineage);
        let version = cursor.u32("test lineage version").expect("version");
        let mut rebuilt = version.to_le_bytes().to_vec();
        let mut index = 0_usize;
        while cursor.remaining() != 0 {
            let level = cursor.length_prefixed("test lineage level").expect("level");
            let parsed = parse_lineage_level(level, index).expect("parsed level");
            let certificate = if index == wanted {
                replacement
            } else {
                parsed.certificate_der
            };

            let mut signed_data = Vec::new();
            append_length_prefixed(&mut signed_data, certificate);
            signed_data.extend_from_slice(&parsed.signed_signature_algorithm_id.to_le_bytes());

            let mut rebuilt_level = Vec::new();
            append_length_prefixed(&mut rebuilt_level, &signed_data);
            rebuilt_level.extend_from_slice(&parsed.flags.to_le_bytes());
            rebuilt_level.extend_from_slice(&parsed.next_signature_algorithm_id.to_le_bytes());
            append_length_prefixed(&mut rebuilt_level, parsed.signature);
            append_length_prefixed(&mut rebuilt, &rebuilt_level);
            index += 1;
        }
        assert!(index > wanted, "requested lineage certificate");
        rebuilt
    }

    fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
        let length = u32::try_from(value.len()).expect("test value length");
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(value);
    }
}
