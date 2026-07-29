// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, offline Android APK Signature Scheme v4/v4.1 sidecar verification.
//!
//! The caller supplies the `.idsig` byte source explicitly. The verifier never
//! derives a path, opens a sibling file, or performs network I/O. It verifies
//! every `SigningInfo`, binds its exact certificate and authenticated APK digest
//! to verified v2/v3 (and, for v4.1, v3.1) signer blocks, then checks the
//! fs-verity-compatible SHA-256 Merkle root and optional serialized tree over
//! every byte of the APK.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::panic::{AssertUnwindSafe, catch_unwind};

use libarchive_oxide_core::Limits;
use sha2::{Digest, Sha256};
use spki::EncodePublicKey;
use subtle::ConstantTimeEq;

use crate::android_signature::{
    APK_V31_BLOCK_ID, ApkV4BindingEvidence, Failure as BindingFailure, SignatureAlgorithm,
    parse_certificate, validate_key_support, verify_android_apk_v4_bindings,
};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "android-apk";
const FORMAT_VERSION: u32 = 2;
const HASH_ALGORITHM_SHA256: u32 = 1;
const LOG2_BLOCK_SIZE_4096: u8 = 12;
const BLOCK_SIZE: usize = 4096;
const BLOCK_SIZE_U64: u64 = BLOCK_SIZE as u64;
const DIGEST_SIZE: usize = 32;
const DIGEST_SIZE_U64: u64 = DIGEST_SIZE as u64;
const MAX_SALT_SIZE: usize = 32;
const MAX_SIGNING_INFOS_SIZE: usize = 7168;
const INCFS_MAX_SIGNATURE_SIZE: usize = 8096;
const MAX_SIGNING_INFO_BLOCKS: usize = 10;
const FALLBACK_METADATA_LIMIT: usize = 64 * 1024 * 1024;

/// Wire revision represented by a version-2 `.idsig` signing-info payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AndroidApkV4Revision {
    /// One primary signing info bound to APK Signature Scheme v2 or v3.
    V4_0,
    /// A primary signing info plus the v3.1-targeted signing-info block.
    V4_1,
}

impl AndroidApkV4Revision {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V4_0 => "v4.0",
            Self::V4_1 => "v4.1",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AndroidV4Verification {
    pub(crate) revision: Option<AndroidApkV4Revision>,
    pub(crate) integrity: VerificationDimension,
    pub(crate) signature_validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug)]
enum Failure {
    Invalid(String),
    Binding(String),
    Signature(String),
    UnsupportedSignature(String),
    UnsupportedIntegrity(String),
    Integrity(String),
    Resource(String),
    Read(String),
}

impl Failure {
    const fn code(&self) -> PackageFindingCode {
        match self {
            Self::Invalid(_) => PackageFindingCode::InvalidSignatureSidecar,
            Self::Binding(_) => PackageFindingCode::SignatureSidecarMismatch,
            Self::Signature(_) => PackageFindingCode::SignatureMismatch,
            Self::UnsupportedSignature(_) => PackageFindingCode::UnsupportedSignatureAlgorithm,
            Self::UnsupportedIntegrity(_) => PackageFindingCode::UnsupportedIntegrityAlgorithm,
            Self::Integrity(_) => PackageFindingCode::IntegrityMismatch,
            Self::Resource(_) => PackageFindingCode::SignatureResourceLimit,
            Self::Read(_) => PackageFindingCode::IntegrityReadFailure,
        }
    }

    fn detail(self) -> String {
        match self {
            Self::Invalid(detail)
            | Self::Binding(detail)
            | Self::Signature(detail)
            | Self::UnsupportedSignature(detail)
            | Self::UnsupportedIntegrity(detail)
            | Self::Integrity(detail)
            | Self::Resource(detail)
            | Self::Read(detail) => detail,
        }
    }

    const fn signature_dimension(&self) -> VerificationDimension {
        match self {
            Self::UnsupportedSignature(_) | Self::UnsupportedIntegrity(_) => {
                VerificationDimension::Unsupported
            },
            Self::Integrity(_) => VerificationDimension::Verified,
            Self::Invalid(_)
            | Self::Binding(_)
            | Self::Signature(_)
            | Self::Resource(_)
            | Self::Read(_) => VerificationDimension::Invalid,
        }
    }

    const fn integrity_dimension(&self) -> VerificationDimension {
        match self {
            Self::Integrity(_) => VerificationDimension::Invalid,
            Self::UnsupportedIntegrity(_) => VerificationDimension::Unsupported,
            Self::Invalid(_)
            | Self::Binding(_)
            | Self::Signature(_)
            | Self::UnsupportedSignature(_)
            | Self::Resource(_)
            | Self::Read(_) => VerificationDimension::NotEvaluated,
        }
    }
}

#[derive(Debug)]
struct HashingInfo<'a> {
    salt: &'a [u8],
    raw_root_hash: &'a [u8],
}

#[derive(Debug)]
struct SigningInfo<'a> {
    apk_digest: &'a [u8],
    certificate: &'a [u8],
    additional_data: &'a [u8],
    public_key: &'a [u8],
    signature_algorithm_id: u32,
    signature: &'a [u8],
}

#[derive(Debug)]
struct SigningInfoBlock<'a> {
    block_id: u32,
    signing_info: SigningInfo<'a>,
}

#[derive(Debug)]
struct ParsedSidecar<'a> {
    revision: AndroidApkV4Revision,
    hashing_info: HashingInfo<'a>,
    primary: SigningInfo<'a>,
    signing_info_blocks: Vec<SigningInfoBlock<'a>>,
    tree: Option<&'a [u8]>,
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

    fn u8(&mut self, what: &str) -> Result<u8, Failure> {
        self.take(1, what)?
            .first()
            .copied()
            .ok_or_else(|| Failure::Invalid(format!("{what} is truncated")))
    }

    fn u32(&mut self, what: &str) -> Result<u32, Failure> {
        let value = self.take(4, what)?;
        let bytes: [u8; 4] = value
            .try_into()
            .map_err(|_| Failure::Invalid(format!("{what} is truncated")))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn sized(&mut self, what: &str) -> Result<&'a [u8], Failure> {
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

/// Verifies an explicitly supplied v4/v4.1 `.idsig` source against `apk`.
pub(crate) fn verify_android_apk_v4<R: Read + Seek, S: Read>(
    apk: &mut R,
    idsig: S,
    limits: Limits,
) -> AndroidV4Verification {
    let apk_size = match measure_apk(apk, limits) {
        Ok(size) => size,
        Err(failure) => return failed(None, failure, Vec::new()),
    };
    let expected_tree_size = match calculate_level_layout(apk_size) {
        Ok((_, size)) => size,
        Err(failure) => return failed(None, failure, Vec::new()),
    };
    let sidecar_bytes = match read_bounded_sidecar(idsig, expected_tree_size, limits) {
        Ok(bytes) => bytes,
        Err(failure) => return failed(None, failure, Vec::new()),
    };
    let parsed = match parse_sidecar(&sidecar_bytes, expected_tree_size, limits) {
        Ok(parsed) => parsed,
        Err(failure) => return failed(None, failure, Vec::new()),
    };
    let revision = Some(parsed.revision);

    let bindings = match verify_android_apk_v4_bindings(apk, limits) {
        Ok(bindings) => bindings,
        Err(failure) => {
            return failed(revision, map_binding_failure(failure), Vec::new());
        },
    };

    let mut sidecar_fingerprints = Vec::new();
    match verify_signing_info(apk_size, &parsed.hashing_info, &parsed.primary, limits) {
        Ok(fingerprint) => sidecar_fingerprints.push(fingerprint),
        Err(failure) => return failed(revision, failure, Vec::new()),
    }
    for block in &parsed.signing_info_blocks {
        match verify_signing_info(apk_size, &parsed.hashing_info, &block.signing_info, limits) {
            Ok(fingerprint) => sidecar_fingerprints.push(fingerprint),
            Err(failure) => {
                return failed(revision, failure, unique_fingerprints(sidecar_fingerprints));
            },
        }
    }
    sidecar_fingerprints = unique_fingerprints(sidecar_fingerprints);

    if let Err(failure) = bind_signing_infos(&parsed, &bindings) {
        return failed(revision, failure, sidecar_fingerprints);
    }

    let actual_tree = match build_verity_tree(apk, apk_size, parsed.hashing_info.salt, limits) {
        Ok(tree) => tree,
        Err(failure) => return failed(revision, failure, sidecar_fingerprints),
    };
    let actual_root = match root_hash(&actual_tree, parsed.hashing_info.salt) {
        Ok(root) => root,
        Err(failure) => return failed(revision, failure, sidecar_fingerprints),
    };
    if parsed
        .hashing_info
        .raw_root_hash
        .ct_eq(actual_root.as_slice())
        .unwrap_u8()
        != 1
    {
        return failed(
            revision,
            Failure::Integrity(
                "APK v4 Merkle root does not match the signed sidecar root".to_string(),
            ),
            sidecar_fingerprints,
        );
    }
    if let Some(expected_tree) = parsed.tree
        && expected_tree.ct_eq(actual_tree.as_slice()).unwrap_u8() != 1
    {
        return failed(
            revision,
            Failure::Integrity(
                "APK v4 serialized Merkle tree does not match the supplied APK".to_string(),
            ),
            sidecar_fingerprints,
        );
    }

    AndroidV4Verification {
        revision,
        integrity: VerificationDimension::Verified,
        signature_validity: VerificationDimension::Verified,
        signer_fingerprints: sidecar_fingerprints,
        findings: Vec::new(),
    }
}

fn measure_apk<R: Seek>(apk: &mut R, limits: Limits) -> Result<u64, Failure> {
    let size = apk.seek(SeekFrom::End(0)).map_err(|error| {
        Failure::Read(format!("cannot measure APK for v4 verification: {error}"))
    })?;
    if size == 0 {
        return Err(Failure::Invalid(
            "APK v4 cannot verify an empty APK".to_string(),
        ));
    }
    if size > i64::MAX as u64 {
        return Err(Failure::Resource(
            "APK length exceeds the signed 64-bit v4 wire field".to_string(),
        ));
    }
    if limits.decoded_total().is_some_and(|limit| size > limit) {
        return Err(Failure::Resource(format!(
            "APK v4 covers {size} bytes; decoded-total limit is {}",
            limits.decoded_total().unwrap_or(0)
        )));
    }
    Ok(size)
}

fn read_bounded_sidecar<S: Read>(
    mut idsig: S,
    expected_tree_size: usize,
    limits: Limits,
) -> Result<Vec<u8>, Failure> {
    let metadata_limit = limits.metadata_bytes().unwrap_or(FALLBACK_METADATA_LIMIT);
    let readable_tree = expected_tree_size.min(metadata_limit);
    let maximum = INCFS_MAX_SIGNATURE_SIZE
        .checked_add(4)
        .and_then(|value| value.checked_add(readable_tree))
        .ok_or_else(|| Failure::Resource("APK v4 sidecar read limit overflow".to_string()))?;
    let maximum_u64 = u64::try_from(maximum)
        .map_err(|_| Failure::Resource("APK v4 sidecar limit exceeds u64".to_string()))?;
    let mut bytes = Vec::new();
    idsig
        .by_ref()
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::Read(format!("cannot read APK v4 sidecar: {error}")))?;
    if bytes.len() > maximum {
        return Err(Failure::Resource(format!(
            "APK v4 sidecar exceeds the bounded {maximum}-byte allowance"
        )));
    }
    Ok(bytes)
}

fn parse_sidecar(
    bytes: &[u8],
    expected_tree_size: usize,
    limits: Limits,
) -> Result<ParsedSidecar<'_>, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let version = cursor.u32("APK v4 version")?;
    if version != FORMAT_VERSION {
        return Err(Failure::Invalid(format!(
            "APK v4 sidecar version is {version}; only version {FORMAT_VERSION} is supported"
        )));
    }
    let hashing_bytes = cursor.sized("APK v4 hashing info")?;
    let signing_infos_bytes = cursor.sized("APK v4 signing infos")?;
    if signing_infos_bytes.len() > MAX_SIGNING_INFOS_SIZE {
        return Err(Failure::Resource(format!(
            "APK v4 signing infos are {} bytes; maximum is {MAX_SIGNING_INFOS_SIZE}",
            signing_infos_bytes.len()
        )));
    }
    if cursor.offset > INCFS_MAX_SIGNATURE_SIZE {
        return Err(Failure::Resource(format!(
            "APK v4 signature header is {} bytes; incremental-fs maximum is \
             {INCFS_MAX_SIGNATURE_SIZE}",
            cursor.offset
        )));
    }

    let tree = if cursor.remaining() == 0 {
        None
    } else {
        let tree = cursor.sized("APK v4 Merkle tree")?;
        cursor.finish("APK v4 sidecar")?;
        if tree.len() != expected_tree_size {
            return Err(Failure::Invalid(format!(
                "APK v4 Merkle tree is {} bytes; APK size requires {expected_tree_size}",
                tree.len()
            )));
        }
        let metadata_limit = limits.metadata_bytes().unwrap_or(FALLBACK_METADATA_LIMIT);
        if tree.len() > metadata_limit {
            return Err(Failure::Resource(format!(
                "APK v4 Merkle tree is {} bytes; metadata limit is {metadata_limit}",
                tree.len()
            )));
        }
        Some(tree)
    };

    let hashing_info = parse_hashing_info(hashing_bytes)?;
    let (primary, signing_info_blocks) = parse_signing_infos(signing_infos_bytes)?;
    let revision = if signing_info_blocks.is_empty() {
        AndroidApkV4Revision::V4_0
    } else {
        AndroidApkV4Revision::V4_1
    };
    Ok(ParsedSidecar {
        revision,
        hashing_info,
        primary,
        signing_info_blocks,
        tree,
    })
}

fn parse_hashing_info(bytes: &[u8]) -> Result<HashingInfo<'_>, Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let hash_algorithm = cursor.u32("APK v4 hash algorithm")?;
    if hash_algorithm != HASH_ALGORITHM_SHA256 {
        return Err(Failure::UnsupportedIntegrity(format!(
            "APK v4 hash algorithm {hash_algorithm} is unsupported"
        )));
    }
    let log2_block_size = cursor.u8("APK v4 log2 block size")?;
    if log2_block_size != LOG2_BLOCK_SIZE_4096 {
        return Err(Failure::UnsupportedIntegrity(format!(
            "APK v4 log2 block size is {log2_block_size}; only 4096-byte blocks are supported"
        )));
    }
    let salt = cursor.sized("APK v4 hash salt")?;
    if salt.len() > MAX_SALT_SIZE {
        return Err(Failure::Invalid(format!(
            "APK v4 salt is {} bytes; maximum is {MAX_SALT_SIZE}",
            salt.len()
        )));
    }
    let raw_root_hash = cursor.sized("APK v4 raw root hash")?;
    if raw_root_hash.len() != DIGEST_SIZE {
        return Err(Failure::Invalid(format!(
            "APK v4 raw root hash is {} bytes; SHA-256 requires {DIGEST_SIZE}",
            raw_root_hash.len()
        )));
    }
    cursor.finish("APK v4 hashing info")?;
    Ok(HashingInfo {
        salt,
        raw_root_hash,
    })
}

fn parse_signing_infos(
    bytes: &[u8],
) -> Result<(SigningInfo<'_>, Vec<SigningInfoBlock<'_>>), Failure> {
    let mut cursor = ByteCursor::new(bytes);
    let primary = parse_signing_info(&mut cursor, "APK v4 primary signing info")?;
    let mut blocks = Vec::new();
    let mut block_ids = BTreeSet::new();
    while cursor.remaining() != 0 {
        if blocks.len() >= MAX_SIGNING_INFO_BLOCKS {
            return Err(Failure::Resource(format!(
                "APK v4.1 exceeds the {MAX_SIGNING_INFO_BLOCKS}-signing-info-block limit"
            )));
        }
        let block_id = cursor.u32("APK v4.1 signing info block id")?;
        if !block_ids.insert(block_id) {
            return Err(Failure::Invalid(format!(
                "APK v4.1 repeats signing info block id {block_id:#010x}"
            )));
        }
        let nested = cursor.sized("APK v4.1 signing info block")?;
        let mut nested_cursor = ByteCursor::new(nested);
        let signing_info = parse_signing_info(&mut nested_cursor, "APK v4.1 signing info")?;
        nested_cursor.finish("APK v4.1 signing info block")?;
        blocks.push(SigningInfoBlock {
            block_id,
            signing_info,
        });
    }
    Ok((primary, blocks))
}

fn parse_signing_info<'a>(
    cursor: &mut ByteCursor<'a>,
    what: &str,
) -> Result<SigningInfo<'a>, Failure> {
    let apk_digest = cursor.sized(&format!("{what} APK digest"))?;
    if !matches!(apk_digest.len(), 32 | 40 | 64) {
        return Err(Failure::Invalid(format!(
            "{what} APK digest is {} bytes; expected a v2/v3 SHA-256, verity, or SHA-512 digest",
            apk_digest.len()
        )));
    }
    let certificate = cursor.sized(&format!("{what} certificate"))?;
    if certificate.is_empty() {
        return Err(Failure::Invalid(format!("{what} certificate is empty")));
    }
    let additional_data = cursor.sized(&format!("{what} additional data"))?;
    let public_key = cursor.sized(&format!("{what} public key"))?;
    if public_key.is_empty() {
        return Err(Failure::Invalid(format!("{what} public key is empty")));
    }
    let signature_algorithm_id = cursor.u32(&format!("{what} signature algorithm"))?;
    let signature = cursor.sized(&format!("{what} signature"))?;
    if signature.is_empty() {
        return Err(Failure::Invalid(format!("{what} signature is empty")));
    }
    Ok(SigningInfo {
        apk_digest,
        certificate,
        additional_data,
        public_key,
        signature_algorithm_id,
        signature,
    })
}

fn verify_signing_info(
    apk_size: u64,
    hashing_info: &HashingInfo<'_>,
    signing_info: &SigningInfo<'_>,
    limits: Limits,
) -> Result<[u8; 32], Failure> {
    let certificate =
        parse_certificate(signing_info.certificate, limits).map_err(map_certificate_failure)?;
    let canonical_public_key = catch_unwind(AssertUnwindSafe(|| certificate.to_public_key_der()))
        .map_err(|_| {
            Failure::Invalid(
                "APK v4 certificate public-key encoder rejected malformed input".to_string(),
            )
        })?
        .map_err(|error| Failure::Invalid(format!("cannot encode APK v4 signer SPKI: {error}")))?;
    if canonical_public_key.as_bytes() != signing_info.public_key {
        return Err(Failure::Invalid(
            "APK v4 public key differs from the signer certificate's SPKI".to_string(),
        ));
    }
    let algorithm =
        SignatureAlgorithm::from_id(signing_info.signature_algorithm_id).ok_or_else(|| {
            Failure::UnsupportedSignature(format!(
                "APK v4 signature algorithm {:#010x} is unknown",
                signing_info.signature_algorithm_id
            ))
        })?;
    validate_key_support(algorithm, &certificate).map_err(map_certificate_failure)?;
    let verifier = algorithm
        .verifier(certificate.key_algorithm())
        .map_err(map_certificate_failure)?;
    let signed_data = build_signed_data(apk_size, hashing_info, signing_info)?;
    certificate
        .verify_signed_data_with_algorithm(&signed_data, signing_info.signature, verifier)
        .map_err(|_| {
            Failure::Signature(format!(
                "APK v4 signature {:#010x} over signed data did not verify",
                signing_info.signature_algorithm_id
            ))
        })?;
    Ok(Sha256::digest(signing_info.certificate).into())
}

fn build_signed_data(
    apk_size: u64,
    hashing_info: &HashingInfo<'_>,
    signing_info: &SigningInfo<'_>,
) -> Result<Vec<u8>, Failure> {
    let size = 4_usize
        .checked_add(8)
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| checked_sized_add(value, hashing_info.salt))
        .and_then(|value| checked_sized_add(value, hashing_info.raw_root_hash))
        .and_then(|value| checked_sized_add(value, signing_info.apk_digest))
        .and_then(|value| checked_sized_add(value, signing_info.certificate))
        .and_then(|value| checked_sized_add(value, signing_info.additional_data))
        .ok_or_else(|| Failure::Resource("APK v4 signed-data size overflow".to_string()))?;
    let size_u32 = u32::try_from(size)
        .map_err(|_| Failure::Resource("APK v4 signed data exceeds u32".to_string()))?;
    let apk_size_i64 = i64::try_from(apk_size)
        .map_err(|_| Failure::Resource("APK v4 APK size exceeds i64".to_string()))?;
    let mut output = Vec::with_capacity(size);
    output.extend_from_slice(&size_u32.to_le_bytes());
    output.extend_from_slice(&apk_size_i64.to_le_bytes());
    output.extend_from_slice(&HASH_ALGORITHM_SHA256.to_le_bytes());
    output.push(LOG2_BLOCK_SIZE_4096);
    push_sized(&mut output, hashing_info.salt)?;
    push_sized(&mut output, hashing_info.raw_root_hash)?;
    push_sized(&mut output, signing_info.apk_digest)?;
    push_sized(&mut output, signing_info.certificate)?;
    push_sized(&mut output, signing_info.additional_data)?;
    if output.len() != size {
        return Err(Failure::Resource(
            "APK v4 signed-data size accounting mismatch".to_string(),
        ));
    }
    Ok(output)
}

fn checked_sized_add(current: usize, bytes: &[u8]) -> Option<usize> {
    current
        .checked_add(4)
        .and_then(|value| value.checked_add(bytes.len()))
}

fn push_sized(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Failure> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| Failure::Resource("APK v4 sized field exceeds u32".to_string()))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn bind_signing_infos(
    sidecar: &ParsedSidecar<'_>,
    bindings: &ApkV4BindingEvidence,
) -> Result<(), Failure> {
    bind_one(&sidecar.primary, &bindings.primary, "primary v2/v3")?;
    match (&bindings.v31, sidecar.signing_info_blocks.as_slice()) {
        (None, []) => Ok(()),
        (None, blocks) => Err(Failure::Binding(format!(
            "APK v4.1 carries {} additional signing info block(s), but the APK has no v3.1 block",
            blocks.len()
        ))),
        (Some(_), []) => Err(Failure::Binding(
            "APK has a v3.1 signer but the supplied sidecar is legacy v4.0".to_string(),
        )),
        (Some(v31), [block]) if block.block_id == APK_V31_BLOCK_ID => {
            bind_one(&block.signing_info, v31, "v3.1")
        },
        (Some(_), [block]) => Err(Failure::Binding(format!(
            "APK v4.1 block id {:#010x} does not match v3.1 block id {APK_V31_BLOCK_ID:#010x}",
            block.block_id
        ))),
        (Some(_), blocks) => Err(Failure::Binding(format!(
            "APK v4.1 requires exactly one v3.1 signing info block; found {}",
            blocks.len()
        ))),
    }
}

fn bind_one(
    sidecar: &SigningInfo<'_>,
    binding: &crate::android_signature::SignerEvidence,
    label: &str,
) -> Result<(), Failure> {
    if sidecar.certificate != binding.certificate_der {
        return Err(Failure::Binding(format!(
            "APK v4 {label} certificate does not match the corresponding APK Signing Block signer"
        )));
    }
    let expected_digest = binding.best_v4_digest().ok_or_else(|| {
        Failure::Binding(format!(
            "APK v4 {label} signer has no supported authenticated content digest"
        ))
    })?;
    if sidecar.apk_digest.ct_eq(expected_digest).unwrap_u8() != 1 {
        return Err(Failure::Binding(format!(
            "APK v4 {label} digest does not match the corresponding APK Signing Block digest"
        )));
    }
    Ok(())
}

fn calculate_level_layout(apk_size: u64) -> Result<(Vec<(usize, usize)>, usize), Failure> {
    if apk_size == 0 {
        return Err(Failure::Invalid(
            "APK v4 Merkle tree requires a non-empty APK".to_string(),
        ));
    }
    let mut data_size = apk_size;
    let mut bottom_to_top = Vec::new();
    loop {
        let chunk_count = div_ceil(data_size, BLOCK_SIZE_U64)?;
        let digest_bytes = chunk_count
            .checked_mul(DIGEST_SIZE_U64)
            .ok_or_else(|| Failure::Resource("APK v4 digest level size overflow".to_string()))?;
        let level_pages = div_ceil(digest_bytes, BLOCK_SIZE_U64)?;
        let level_size = level_pages
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or_else(|| Failure::Resource("APK v4 padded level size overflow".to_string()))?;
        bottom_to_top.push(level_size);
        if digest_bytes <= BLOCK_SIZE_U64 {
            break;
        }
        data_size = digest_bytes;
    }
    bottom_to_top.reverse();
    let mut offset = 0_usize;
    let mut layout = Vec::with_capacity(bottom_to_top.len());
    for size in bottom_to_top {
        let size = usize::try_from(size).map_err(|_| {
            Failure::Resource("APK v4 tree level exceeds address space".to_string())
        })?;
        layout.push((offset, size));
        offset = offset
            .checked_add(size)
            .ok_or_else(|| Failure::Resource("APK v4 tree size overflow".to_string()))?;
    }
    Ok((layout, offset))
}

fn div_ceil(value: u64, divisor: u64) -> Result<u64, Failure> {
    value
        .checked_add(divisor.saturating_sub(1))
        .map(|adjusted| adjusted / divisor)
        .ok_or_else(|| Failure::Resource("APK v4 division overflow".to_string()))
}

fn build_verity_tree<R: Read + Seek>(
    apk: &mut R,
    apk_size: u64,
    salt: &[u8],
    limits: Limits,
) -> Result<Vec<u8>, Failure> {
    let (layout, total_size) = calculate_level_layout(apk_size)?;
    let metadata_limit = limits.metadata_bytes().unwrap_or(FALLBACK_METADATA_LIMIT);
    if total_size > metadata_limit {
        return Err(Failure::Resource(format!(
            "APK v4 Merkle tree requires {total_size} bytes; metadata limit is {metadata_limit}"
        )));
    }
    let in_flight = limits.in_flight_bytes().unwrap_or(BLOCK_SIZE);
    if in_flight == 0 {
        return Err(Failure::Resource(
            "APK v4 in-flight byte limit is zero".to_string(),
        ));
    }
    let mut tree = vec![0_u8; total_size];
    for index in (0..layout.len()).rev() {
        let (offset, length) = layout
            .get(index)
            .copied()
            .ok_or_else(|| Failure::Resource("APK v4 tree layout index overflow".to_string()))?;
        let output_end = offset
            .checked_add(length)
            .ok_or_else(|| Failure::Resource("APK v4 output level end overflow".to_string()))?;
        if index + 1 == layout.len() {
            let output = tree.get_mut(offset..output_end).ok_or_else(|| {
                Failure::Resource("APK v4 output level is out of bounds".to_string())
            })?;
            hash_apk_pages(apk, apk_size, salt, in_flight, output)?;
        } else {
            let (source_offset, source_length) =
                layout.get(index + 1).copied().ok_or_else(|| {
                    Failure::Resource("APK v4 source level index overflow".to_string())
                })?;
            if source_offset < output_end {
                return Err(Failure::Resource(
                    "APK v4 tree levels overlap unexpectedly".to_string(),
                ));
            }
            let (output_prefix, source_suffix) = tree.split_at_mut(source_offset);
            let output = output_prefix.get_mut(offset..output_end).ok_or_else(|| {
                Failure::Resource("APK v4 output level is out of bounds".to_string())
            })?;
            let source = source_suffix.get(..source_length).ok_or_else(|| {
                Failure::Resource("APK v4 source level is out of bounds".to_string())
            })?;
            hash_memory_pages(source, salt, output)?;
        }
    }
    Ok(tree)
}

fn hash_apk_pages<R: Read + Seek>(
    apk: &mut R,
    apk_size: u64,
    salt: &[u8],
    in_flight: usize,
    output: &mut [u8],
) -> Result<(), Failure> {
    apk.seek(SeekFrom::Start(0))
        .map_err(|error| Failure::Read(format!("cannot seek APK for v4 hashing: {error}")))?;
    let buffer_size = in_flight.min(BLOCK_SIZE);
    let mut buffer = vec![0_u8; buffer_size];
    let zeroes = [0_u8; BLOCK_SIZE];
    let page_count = div_ceil(apk_size, BLOCK_SIZE_U64)?;
    let mut remaining = apk_size;
    for page_index in 0..page_count {
        let page_bytes = remaining.min(BLOCK_SIZE_U64);
        let mut page_remaining = page_bytes;
        let mut hasher = Sha256::new();
        hasher.update(salt);
        while page_remaining != 0 {
            let take = usize::try_from(page_remaining.min(buffer_size as u64)).map_err(|_| {
                Failure::Resource("APK v4 page read size exceeds address space".to_string())
            })?;
            apk.read_exact(
                buffer
                    .get_mut(..take)
                    .ok_or_else(|| Failure::Resource("APK v4 read buffer overflow".to_string()))?,
            )
            .map_err(|error| Failure::Read(format!("cannot read APK for v4 hashing: {error}")))?;
            hasher.update(
                buffer
                    .get(..take)
                    .ok_or_else(|| Failure::Resource("APK v4 read buffer overflow".to_string()))?,
            );
            page_remaining -= take as u64;
        }
        let padding = BLOCK_SIZE_U64
            .checked_sub(page_bytes)
            .ok_or_else(|| Failure::Resource("APK v4 page padding underflow".to_string()))?;
        let padding = usize::try_from(padding)
            .map_err(|_| Failure::Resource("APK v4 page padding overflow".to_string()))?;
        hasher.update(
            zeroes
                .get(..padding)
                .ok_or_else(|| Failure::Resource("APK v4 zero padding overflow".to_string()))?,
        );
        write_digest(output, page_index, hasher.finalize().as_slice())?;
        remaining -= page_bytes;
    }
    Ok(())
}

fn hash_memory_pages(source: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), Failure> {
    if !source.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Failure::Resource(
            "APK v4 source tree level is not page-aligned".to_string(),
        ));
    }
    for (page_index, page) in source.chunks_exact(BLOCK_SIZE).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(page);
        write_digest(output, page_index as u64, hasher.finalize().as_slice())?;
    }
    Ok(())
}

fn write_digest(output: &mut [u8], page_index: u64, digest: &[u8]) -> Result<(), Failure> {
    let page_index = usize::try_from(page_index)
        .map_err(|_| Failure::Resource("APK v4 page index exceeds address space".to_string()))?;
    let offset = page_index
        .checked_mul(DIGEST_SIZE)
        .ok_or_else(|| Failure::Resource("APK v4 digest offset overflow".to_string()))?;
    let end = offset
        .checked_add(DIGEST_SIZE)
        .ok_or_else(|| Failure::Resource("APK v4 digest end overflow".to_string()))?;
    let destination = output
        .get_mut(offset..end)
        .ok_or_else(|| Failure::Resource("APK v4 digest output is too short".to_string()))?;
    if digest.len() != DIGEST_SIZE {
        return Err(Failure::Resource(
            "APK v4 SHA-256 backend returned an unexpected digest length".to_string(),
        ));
    }
    destination.copy_from_slice(digest);
    Ok(())
}

fn root_hash(tree: &[u8], salt: &[u8]) -> Result<[u8; 32], Failure> {
    let first_page = tree
        .get(..BLOCK_SIZE)
        .ok_or_else(|| Failure::Resource("APK v4 tree has no root page".to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(first_page);
    Ok(hasher.finalize().into())
}

fn map_binding_failure(failure: BindingFailure) -> Failure {
    match failure {
        BindingFailure::Invalid(detail) => Failure::Invalid(detail),
        BindingFailure::Mismatch(detail) => Failure::Binding(detail),
        BindingFailure::Unsupported(detail) => Failure::UnsupportedSignature(detail),
        BindingFailure::Resource(detail) => Failure::Resource(detail),
        BindingFailure::Read(detail) => Failure::Read(detail),
    }
}

fn map_certificate_failure(failure: BindingFailure) -> Failure {
    match failure {
        BindingFailure::Invalid(detail) => Failure::Invalid(detail),
        BindingFailure::Mismatch(detail) => Failure::Signature(detail),
        BindingFailure::Unsupported(detail) => Failure::UnsupportedSignature(detail),
        BindingFailure::Resource(detail) => Failure::Resource(detail),
        BindingFailure::Read(detail) => Failure::Read(detail),
    }
}

fn unique_fingerprints(fingerprints: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    fingerprints
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn failed(
    revision: Option<AndroidApkV4Revision>,
    failure: Failure,
    signer_fingerprints: Vec<[u8; 32]>,
) -> AndroidV4Verification {
    let code = failure.code();
    let signature_validity = failure.signature_dimension();
    let integrity = failure.integrity_dimension();
    AndroidV4Verification {
        revision,
        integrity,
        signature_validity,
        signer_fingerprints,
        findings: vec![PackageFinding::new(PROFILE, None, code, failure.detail())],
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use std::io::Cursor;

    use super::*;

    const CTS_APK: &[u8] = include_bytes!("../tests/fixtures/android_apk_v4/v4-digest-v2v3.apk");
    const CTS_IDSIG: &[u8] =
        include_bytes!("../tests/fixtures/android_apk_v4/v4-digest-v2v3.apk.idsig");

    fn append_sized(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(
            &u32::try_from(value.len())
                .expect("test field length fits u32")
                .to_le_bytes(),
        );
        output.extend_from_slice(value);
    }

    fn hashing_info(salt: &[u8], root: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&HASH_ALGORITHM_SHA256.to_le_bytes());
        output.push(LOG2_BLOCK_SIZE_4096);
        append_sized(&mut output, salt);
        append_sized(&mut output, root);
        output
    }

    fn minimal_signing_info() -> Vec<u8> {
        let mut output = Vec::new();
        append_sized(&mut output, &[0_u8; 32]);
        append_sized(&mut output, &[1]);
        append_sized(&mut output, &[]);
        append_sized(&mut output, &[1]);
        output.extend_from_slice(&0x0103_u32.to_le_bytes());
        append_sized(&mut output, &[1]);
        output
    }

    fn sidecar(hashing: &[u8], signing_infos: &[u8]) -> Vec<u8> {
        let mut output = FORMAT_VERSION.to_le_bytes().to_vec();
        append_sized(&mut output, hashing);
        append_sized(&mut output, signing_infos);
        output
    }

    #[test]
    fn cts_tree_layout_and_root_match_the_sidecar() {
        let expected_tree_size = calculate_level_layout(CTS_APK.len() as u64)
            .expect("tree layout")
            .1;
        let parsed =
            parse_sidecar(CTS_IDSIG, expected_tree_size, Limits::safe()).expect("parse idsig");
        let tree = build_verity_tree(
            &mut Cursor::new(CTS_APK),
            CTS_APK.len() as u64,
            parsed.hashing_info.salt,
            Limits::safe(),
        )
        .expect("build tree");
        assert_eq!(parsed.tree, Some(tree.as_slice()));
        assert_eq!(
            parsed.hashing_info.raw_root_hash,
            root_hash(&tree, parsed.hashing_info.salt).expect("root")
        );
    }

    #[test]
    fn parser_rejects_signing_info_bytes_above_incremental_fs_bound() {
        let bytes = sidecar(
            &hashing_info(&[], &[0_u8; DIGEST_SIZE]),
            &vec![0_u8; MAX_SIGNING_INFOS_SIZE + 1],
        );
        assert!(matches!(
            parse_sidecar(&bytes, BLOCK_SIZE, Limits::safe()),
            Err(Failure::Resource(_))
        ));
    }

    #[test]
    fn parser_rejects_oversized_salt_before_certificate_work() {
        let bytes = sidecar(
            &hashing_info(&[0_u8; MAX_SALT_SIZE + 1], &[0_u8; DIGEST_SIZE]),
            &minimal_signing_info(),
        );
        assert!(matches!(
            parse_sidecar(&bytes, BLOCK_SIZE, Limits::safe()),
            Err(Failure::Invalid(_))
        ));
    }

    #[test]
    fn parser_bounds_the_number_of_v41_signing_info_blocks() {
        let mut signing_infos = minimal_signing_info();
        for block_id in 0..=MAX_SIGNING_INFO_BLOCKS {
            signing_infos.extend_from_slice(
                &u32::try_from(block_id)
                    .expect("test block id fits u32")
                    .to_le_bytes(),
            );
            append_sized(&mut signing_infos, &minimal_signing_info());
        }
        let bytes = sidecar(&hashing_info(&[], &[0_u8; DIGEST_SIZE]), &signing_infos);
        assert!(matches!(
            parse_sidecar(&bytes, BLOCK_SIZE, Limits::safe()),
            Err(Failure::Resource(_))
        ));
    }
}
