// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded offline verification of RPM `OpenPGP` header signatures.

use std::collections::BTreeSet;
use std::io::{BufReader, Cursor};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::errors::Error as OpenPgpError;
use pgp::packet::{
    Signature, SignatureConfig, SignatureType, SignatureVersion, SignatureVersionSpecific,
    SubpacketData, SubpacketType,
};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, KeyVersion, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::alpine_signature::PackageKeyError;
use crate::rpm::{RpmSignatureMetadata, RpmValidation};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "rpm";
const MAX_PUBLIC_KEY_INPUT: usize = 256 * 1024;

/// A validated transferable `OpenPGP` public-key certificate for RPM signatures.
///
/// Parsing verifies primary-key identity bindings and every retained subkey binding before the certificate can be registered with [`crate::PackageVerifier`].
#[derive(Debug, Clone)]
pub struct RpmOpenPgpPublicKey {
    certificate: SignedPublicKey,
    openpgp_fingerprint: Vec<u8>,
    fingerprint_sha256: [u8; 32],
}

impl RpmOpenPgpPublicKey {
    /// Parses one binary or ASCII-armored transferable `OpenPGP` public key.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds 256 KiB, contains zero or more than one certificate, is malformed, or has an invalid identity/subkey binding signature.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PackageKeyError> {
        let bytes = bytes.as_ref();
        if bytes.len() > MAX_PUBLIC_KEY_INPUT {
            return Err(PackageKeyError::new(format!(
                "RPM OpenPGP public key exceeds the {MAX_PUBLIC_KEY_INPUT}-byte input limit"
            )));
        }
        let (mut parsed, _) =
            SignedPublicKey::from_reader_many(Cursor::new(bytes)).map_err(|error| {
                PackageKeyError::new(format!("RPM OpenPGP public key cannot be parsed: {error}"))
            })?;
        let certificate = parsed
            .next()
            .ok_or_else(|| PackageKeyError::new("RPM OpenPGP input contains no public key"))?
            .map_err(|error| {
                PackageKeyError::new(format!("RPM OpenPGP public key cannot be parsed: {error}"))
            })?;
        if parsed.next().is_some() {
            return Err(PackageKeyError::new(
                "RPM OpenPGP input contains more than one public key",
            ));
        }
        certificate.verify_bindings().map_err(|error| {
            PackageKeyError::new(format!(
                "RPM OpenPGP public-key bindings are invalid: {error}"
            ))
        })?;
        let openpgp_fingerprint = certificate.fingerprint().as_bytes().to_vec();
        let fingerprint_sha256 = Sha256::digest(&openpgp_fingerprint).into();
        Ok(Self {
            certificate,
            openpgp_fingerprint,
            fingerprint_sha256,
        })
    }

    /// Native `OpenPGP` fingerprint of the primary key (20 bytes for v4 keys).
    #[must_use]
    pub fn openpgp_fingerprint(&self) -> &[u8] {
        &self.openpgp_fingerprint
    }

    /// SHA-256 of [`Self::openpgp_fingerprint`] used by [`crate::TrustPolicy`].
    #[must_use]
    pub const fn fingerprint_sha256(&self) -> [u8; 32] {
        self.fingerprint_sha256
    }
}

#[derive(Debug)]
pub(crate) struct RpmSignatureVerification {
    pub(crate) signature_validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

/// Final constant-memory hash result for one legacy header-plus-payload record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RpmLegacyHash {
    Digest(Vec<u8>),
    Invalid(String),
    Unsupported(String),
    ResourceLimit(String),
}

struct LegacyHashState {
    record_index: usize,
    signature: DetachedSignature,
    hasher: RpmHasher,
}

// `sha1_checked` deliberately carries a larger fixed verification state.
// One bounded 832-byte enum per signature avoids heap allocation and virtual dispatch; its size is independent of archive input.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum RpmHasher {
    Md5(md5_010::Md5),
    Sha1(sha1_checked_010::Sha1),
    Ripemd160(ripemd_010::Ripemd160),
    Sha224(sha2_010::Sha224),
    Sha256(sha2_010::Sha256),
    Sha384(sha2_010::Sha384),
    Sha512(sha2_010::Sha512),
    Sha3_256(sha3_010::Sha3_256),
    Sha3_512(sha3_010::Sha3_512),
}

impl RpmHasher {
    fn new(algorithm: HashAlgorithm) -> Result<Self, String> {
        match algorithm {
            HashAlgorithm::Md5 => Ok(Self::Md5(md5_010::Md5::default())),
            HashAlgorithm::Sha1 => Ok(Self::Sha1(sha1_checked_010::Sha1::default())),
            HashAlgorithm::Ripemd160 => Ok(Self::Ripemd160(ripemd_010::Ripemd160::default())),
            HashAlgorithm::Sha224 => Ok(Self::Sha224(sha2_010::Sha224::default())),
            HashAlgorithm::Sha256 => Ok(Self::Sha256(sha2_010::Sha256::default())),
            HashAlgorithm::Sha384 => Ok(Self::Sha384(sha2_010::Sha384::default())),
            HashAlgorithm::Sha512 => Ok(Self::Sha512(sha2_010::Sha512::default())),
            HashAlgorithm::Sha3_256 => Ok(Self::Sha3_256(sha3_010::Sha3_256::default())),
            HashAlgorithm::Sha3_512 => Ok(Self::Sha3_512(sha3_010::Sha3_512::default())),
            _ => Err(format!("unsupported hash algorithm {algorithm:?}")),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md5(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha1(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Ripemd160(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha224(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha256(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha384(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha512(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha3_256(hasher) => digest_010::DynDigest::update(hasher, bytes),
            Self::Sha3_512(hasher) => digest_010::DynDigest::update(hasher, bytes),
        }
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        match self {
            Self::Md5(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha1(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Ripemd160(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha224(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha256(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha384(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha512(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha3_256(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
            Self::Sha3_512(hasher) => digest_010::DynDigest::finalize_reset(hasher).into_vec(),
        }
    }
}

#[derive(Debug)]
enum SignatureHashDataError {
    Unsupported(String),
    Invalid(String),
}

/// Parallel incremental hash states for all legacy RPM signature records.
pub(crate) struct RpmLegacyHashers {
    states: Vec<LegacyHashState>,
    outcomes: Vec<Option<RpmLegacyHash>>,
    payload_bytes: u64,
    payload_limit: Option<u64>,
}

impl RpmLegacyHashers {
    pub(crate) fn needs_eof(&self) -> bool {
        !self.states.is_empty()
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        if self.states.is_empty() {
            return;
        }
        let Some(length) = u64::try_from(bytes.len()).ok() else {
            self.fail_all(&RpmLegacyHash::ResourceLimit(
                "legacy RPM signed payload length does not fit u64".to_string(),
            ));
            return;
        };
        let Some(total) = self.payload_bytes.checked_add(length) else {
            self.fail_all(&RpmLegacyHash::ResourceLimit(
                "legacy RPM signed payload byte count overflowed".to_string(),
            ));
            return;
        };
        if self.payload_limit.is_some_and(|limit| total > limit) {
            self.fail_all(&RpmLegacyHash::ResourceLimit(
                "legacy RPM signed payload exceeds the configured integrity byte budget"
                    .to_string(),
            ));
            return;
        }
        self.payload_bytes = total;
        for state in &mut self.states {
            state.hasher.update(bytes);
        }
    }

    pub(crate) fn read_error(&mut self, error: &std::io::Error) {
        self.fail_all(&RpmLegacyHash::Invalid(format!(
            "cannot read legacy RPM signed payload: {error}"
        )));
    }

    fn fail_all(&mut self, outcome: &RpmLegacyHash) {
        for state in self.states.drain(..) {
            self.outcomes[state.record_index] = Some(outcome.clone());
        }
    }

    pub(crate) fn finish(mut self) -> Vec<Option<RpmLegacyHash>> {
        for mut state in self.states.drain(..) {
            let outcome = finish_legacy_hash(&state.signature, &mut state.hasher);
            self.outcomes[state.record_index] = Some(outcome);
        }
        self.outcomes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateVerdict {
    Missing,
    Verified,
    Invalid,
    Unsupported,
}

fn is_unsupported(error: &OpenPgpError) -> bool {
    matches!(
        error,
        OpenPgpError::Unsupported { .. } | OpenPgpError::Unimplemented { .. }
    )
}

fn key_matches_signature(key: &impl KeyDetails, signature: &Signature) -> bool {
    let fingerprints = signature.issuer_fingerprint();
    let key_ids = signature.issuer_key_id();
    if fingerprints.is_empty() && key_ids.is_empty() {
        return true;
    }
    let fingerprint = key.fingerprint();
    let key_id = key.legacy_key_id();
    fingerprints.iter().any(|issuer| **issuer == fingerprint)
        || key_ids.iter().any(|issuer| **issuer == key_id)
}

fn verify_with_certificate(
    signature: &Signature,
    certificate: &SignedPublicKey,
    signed_header: &[u8],
) -> CandidateVerdict {
    let mut matched = false;
    let mut unsupported = false;
    if key_matches_signature(&certificate.primary_key, signature) {
        matched = true;
        match signature.verify(&certificate.primary_key, Cursor::new(signed_header)) {
            Ok(()) => return CandidateVerdict::Verified,
            Err(error) if is_unsupported(&error) => unsupported = true,
            Err(_) => {},
        }
    }
    for subkey in &certificate.public_subkeys {
        if !key_matches_signature(subkey, signature) {
            continue;
        }
        matched = true;
        match signature.verify(subkey, Cursor::new(signed_header)) {
            Ok(()) => return CandidateVerdict::Verified,
            Err(error) if is_unsupported(&error) => unsupported = true,
            Err(_) => {},
        }
    }
    if !matched {
        CandidateVerdict::Missing
    } else if unsupported {
        CandidateVerdict::Unsupported
    } else {
        CandidateVerdict::Invalid
    }
}

fn verify_prehashed_with_certificate(
    signature: &Signature,
    certificate: &SignedPublicKey,
    digest: &[u8],
) -> CandidateVerdict {
    let (Some(config), Some(raw_signature)) = (signature.config(), signature.signature()) else {
        return CandidateVerdict::Unsupported;
    };
    let mut matched = false;
    let mut unsupported = false;
    if key_matches_signature(&certificate.primary_key, signature) {
        matched = true;
        match certificate
            .primary_key
            .verify(config.hash_alg, digest, raw_signature)
        {
            Ok(()) => return CandidateVerdict::Verified,
            Err(error) if is_unsupported(&error) => unsupported = true,
            Err(_) => {},
        }
    }
    for subkey in &certificate.public_subkeys {
        if !key_matches_signature(subkey, signature) {
            continue;
        }
        matched = true;
        match subkey.verify(config.hash_alg, digest, raw_signature) {
            Ok(()) => return CandidateVerdict::Verified,
            Err(error) if is_unsupported(&error) => unsupported = true,
            Err(_) => {},
        }
    }
    if !matched {
        CandidateVerdict::Missing
    } else if unsupported {
        CandidateVerdict::Unsupported
    } else {
        CandidateVerdict::Invalid
    }
}

fn parse_signature(packet: &[u8]) -> Result<DetachedSignature, OpenPgpError> {
    let mut parsed = DetachedSignature::from_bytes_many(BufReader::new(packet))?;
    let signature = parsed
        .next()
        .ok_or(OpenPgpError::NoMatchingPacket { backtrace: None })??;
    if parsed.next().is_some() {
        return Err(OpenPgpError::TooManyPackets);
    }
    Ok(signature)
}

pub(crate) fn prepare_legacy_hashes(
    metadata: &RpmSignatureMetadata,
    signed_header: &[u8],
    payload_limit: Option<u64>,
) -> RpmLegacyHashers {
    let mut outcomes = vec![None; metadata.records.len()];
    let mut states = Vec::new();
    for (record_index, record) in metadata.records.iter().enumerate() {
        if record.header_only {
            continue;
        }
        let signature = match parse_signature(&record.packet) {
            Ok(signature) => signature,
            Err(error) if is_unsupported(&error) => {
                outcomes[record_index] = Some(RpmLegacyHash::Unsupported(format!(
                    "legacy RPM OpenPGP signature uses unsupported metadata: {error}"
                )));
                continue;
            },
            Err(error) => {
                outcomes[record_index] = Some(RpmLegacyHash::Invalid(format!(
                    "legacy RPM OpenPGP signature packet is malformed: {error}"
                )));
                continue;
            },
        };
        if signature.signature.typ() != Some(SignatureType::Binary) {
            outcomes[record_index] = Some(RpmLegacyHash::Unsupported(
                "legacy RPM signature is not an OpenPGP binary-data signature".to_string(),
            ));
            continue;
        }
        let Some(config) = signature.signature.config() else {
            outcomes[record_index] = Some(RpmLegacyHash::Unsupported(
                "legacy RPM signature version is unsupported".to_string(),
            ));
            continue;
        };
        let mut hasher = match RpmHasher::new(config.hash_alg) {
            Ok(hasher) => hasher,
            Err(error) => {
                outcomes[record_index] = Some(RpmLegacyHash::Unsupported(format!(
                    "legacy RPM signature hash algorithm is unsupported: {error}"
                )));
                continue;
            },
        };
        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt);
        }
        hasher.update(signed_header);
        states.push(LegacyHashState {
            record_index,
            signature,
            hasher,
        });
    }
    RpmLegacyHashers {
        states,
        outcomes,
        payload_bytes: 0,
        payload_limit,
    }
}

fn finish_legacy_hash(signature: &DetachedSignature, hasher: &mut RpmHasher) -> RpmLegacyHash {
    let Some(config) = signature.signature.config() else {
        return RpmLegacyHash::Unsupported(
            "legacy RPM signature version is unsupported".to_string(),
        );
    };
    let hashed_length = match hash_signature_data(config, hasher) {
        Ok(length) => length,
        Err(SignatureHashDataError::Unsupported(error)) => {
            return RpmLegacyHash::Unsupported(format!(
                "legacy RPM signature metadata is unsupported: {error}"
            ));
        },
        Err(SignatureHashDataError::Invalid(error)) => {
            return RpmLegacyHash::Invalid(format!(
                "legacy RPM signature metadata cannot be hashed: {error}"
            ));
        },
    };
    let trailer = match config.trailer(hashed_length) {
        Ok(trailer) => trailer,
        Err(error) if is_unsupported(&error) => {
            return RpmLegacyHash::Unsupported(format!(
                "legacy RPM signature trailer is unsupported: {error}"
            ));
        },
        Err(error) => {
            return RpmLegacyHash::Invalid(format!(
                "legacy RPM signature trailer is invalid: {error}"
            ));
        },
    };
    hasher.update(&trailer);
    let digest = hasher.finalize_reset();
    let Some(signed_prefix) = signature.signature.signed_hash_value() else {
        return RpmLegacyHash::Unsupported(
            "legacy RPM signature has no known signed-hash prefix".to_string(),
        );
    };
    if digest.get(..2) != Some(signed_prefix.as_slice()) {
        return RpmLegacyHash::Invalid(
            "legacy RPM signature signed-hash prefix does not match the package".to_string(),
        );
    }
    RpmLegacyHash::Digest(digest)
}

fn hash_signature_data(
    config: &SignatureConfig,
    hasher: &mut RpmHasher,
) -> Result<usize, SignatureHashDataError> {
    match config.version() {
        SignatureVersion::V2 | SignatureVersion::V3 => {
            let (SignatureVersionSpecific::V2 { created, .. }
            | SignatureVersionSpecific::V3 { created, .. }) = &config.version_specific
            else {
                return Err(SignatureHashDataError::Invalid(
                    "v2/v3 signature is missing version-specific creation time".to_string(),
                ));
            };
            let mut bytes = [0_u8; 5];
            bytes[0] = config.typ.into();
            bytes[1..].copy_from_slice(&created.as_secs().to_be_bytes());
            hasher.update(&bytes);
            Ok(0)
        },
        SignatureVersion::V4 | SignatureVersion::V6 => {
            let mut bytes = vec![
                config.version().into(),
                config.typ.into(),
                config.pub_alg.into(),
                config.hash_alg.into(),
            ];
            let mut hashed_subpackets = Vec::new();
            for packet in &config.hashed_subpackets {
                if packet.is_critical && matches!(packet.typ(), SubpacketType::Other(_)) {
                    return Err(SignatureHashDataError::Invalid(format!(
                        "unknown critical signature subpacket {:?}",
                        packet.typ()
                    )));
                }
                if let SubpacketData::IssuerFingerprint(fingerprint) = &packet.data {
                    let matching_version = matches!(
                        (config.version(), fingerprint.version()),
                        (SignatureVersion::V4, Some(KeyVersion::V4))
                            | (SignatureVersion::V6, Some(KeyVersion::V6))
                    );
                    if !matching_version {
                        return Err(SignatureHashDataError::Invalid(
                            "issuer fingerprint version does not match signature version"
                                .to_string(),
                        ));
                    }
                }
                packet
                    .to_writer(&mut hashed_subpackets)
                    .map_err(|error| SignatureHashDataError::Invalid(error.to_string()))?;
            }
            if config.version() == SignatureVersion::V4 {
                let length = u16::try_from(hashed_subpackets.len()).map_err(|_| {
                    SignatureHashDataError::Invalid(
                        "v4 hashed subpacket area exceeds u16".to_string(),
                    )
                })?;
                bytes.extend_from_slice(&length.to_be_bytes());
            } else {
                let length = u32::try_from(hashed_subpackets.len()).map_err(|_| {
                    SignatureHashDataError::Invalid(
                        "v6 hashed subpacket area exceeds u32".to_string(),
                    )
                })?;
                bytes.extend_from_slice(&length.to_be_bytes());
            }
            bytes.extend_from_slice(&hashed_subpackets);
            hasher.update(&bytes);
            Ok(bytes.len())
        },
        SignatureVersion::V5 => Err(SignatureHashDataError::Unsupported(
            "v5 signature hash data is unsupported".to_string(),
        )),
        SignatureVersion::Other(version) => Err(SignatureHashDataError::Unsupported(format!(
            "signature version {version} is unsupported"
        ))),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn verify_rpm_signatures(
    validation: &RpmValidation,
    keys: &[RpmOpenPgpPublicKey],
) -> RpmSignatureVerification {
    let metadata = validation.signature_metadata();
    let mut findings = Vec::new();
    let mut signer_fingerprints = BTreeSet::new();
    let mut invalid = false;
    let mut unsupported = false;
    let mut missing = false;

    if let Some(detail) = &metadata.invalid {
        invalid = true;
        findings.push(PackageFinding::new(
            PROFILE,
            None,
            PackageFindingCode::InvalidSignatureMetadata,
            detail,
        ));
    }
    if let Some(detail) = &metadata.resource_limit {
        invalid = true;
        findings.push(PackageFinding::new(
            PROFILE,
            None,
            PackageFindingCode::SignatureResourceLimit,
            detail,
        ));
    }

    for (record_index, record) in metadata.records.iter().enumerate() {
        let signature = match parse_signature(&record.packet) {
            Ok(signature) => signature,
            Err(error) if is_unsupported(&error) => {
                unsupported = true;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::UnsupportedSignatureAlgorithm,
                    format!("RPM OpenPGP signature uses unsupported metadata: {error}"),
                ));
                continue;
            },
            Err(error) => {
                invalid = true;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::InvalidSignatureMetadata,
                    format!("RPM OpenPGP signature packet is malformed: {error}"),
                ));
                continue;
            },
        };
        if signature.signature.typ() != Some(SignatureType::Binary) {
            unsupported = true;
            findings.push(PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::UnsupportedSignatureAlgorithm,
                "RPM OpenPGP packet is not a binary-document signature",
            ));
            continue;
        }

        let legacy_digest = if record.header_only {
            None
        } else {
            match validation
                .legacy_hashes()
                .get(record_index)
                .and_then(Option::as_ref)
            {
                Some(RpmLegacyHash::Digest(digest)) => Some(digest.as_slice()),
                Some(RpmLegacyHash::Invalid(detail)) => {
                    invalid = true;
                    findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::SignatureMismatch,
                        detail,
                    ));
                    continue;
                },
                Some(RpmLegacyHash::Unsupported(detail)) => {
                    unsupported = true;
                    findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::UnsupportedSignatureAlgorithm,
                        detail,
                    ));
                    continue;
                },
                Some(RpmLegacyHash::ResourceLimit(detail)) => {
                    invalid = true;
                    findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::SignatureResourceLimit,
                        detail,
                    ));
                    continue;
                },
                None => {
                    invalid = true;
                    findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::InvalidSignatureMetadata,
                        "legacy RPM signature has no streamed hash result",
                    ));
                    continue;
                },
            }
        };
        let mut record_verdict = CandidateVerdict::Missing;
        for key in keys {
            let candidate = if let Some(digest) = legacy_digest {
                verify_prehashed_with_certificate(&signature.signature, &key.certificate, digest)
            } else {
                verify_with_certificate(
                    &signature.signature,
                    &key.certificate,
                    validation.signed_header(),
                )
            };
            match candidate {
                CandidateVerdict::Verified => {
                    record_verdict = CandidateVerdict::Verified;
                    signer_fingerprints.insert(key.fingerprint_sha256);
                    break;
                },
                CandidateVerdict::Invalid => record_verdict = CandidateVerdict::Invalid,
                CandidateVerdict::Unsupported if record_verdict != CandidateVerdict::Invalid => {
                    record_verdict = CandidateVerdict::Unsupported;
                },
                CandidateVerdict::Missing | CandidateVerdict::Unsupported => {},
            }
        }
        match record_verdict {
            CandidateVerdict::Verified => {},
            CandidateVerdict::Missing => {
                missing = true;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::MissingVerificationKey,
                    "RPM OpenPGP signature names a key the caller did not supply",
                ));
            },
            CandidateVerdict::Invalid => {
                invalid = true;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::SignatureMismatch,
                    if record.header_only {
                        "RPM OpenPGP signature does not match the signed main header"
                    } else {
                        "RPM OpenPGP signature does not match the signed main header and payload"
                    },
                ));
            },
            CandidateVerdict::Unsupported => {
                unsupported = true;
                findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::UnsupportedSignatureAlgorithm,
                    "RPM OpenPGP signature requests an unsupported cryptographic algorithm",
                ));
            },
        }
    }

    let signature_validity = if invalid {
        VerificationDimension::Invalid
    } else if unsupported {
        VerificationDimension::Unsupported
    } else if missing || metadata.records.is_empty() {
        VerificationDimension::NotEvaluated
    } else {
        VerificationDimension::Verified
    };
    RpmSignatureVerification {
        signature_validity,
        signer_fingerprints: signer_fingerprints.into_iter().collect(),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_rpm_hashers_match_pgp_for_every_supported_algorithm() {
        let input = b"closed enum RPM digest differential input";
        for algorithm in [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Ripemd160,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
        ] {
            let mut hasher = RpmHasher::new(algorithm).expect("supported concrete RPM hasher");
            for chunk in input.chunks(3) {
                hasher.update(chunk);
            }
            assert_eq!(
                hasher.finalize_reset(),
                algorithm.digest(input).expect("pgp concrete digest"),
                "{algorithm:?}",
            );
        }
        assert!(RpmHasher::new(HashAlgorithm::None).is_err());
    }
}
