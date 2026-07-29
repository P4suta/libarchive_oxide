// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline Alpine APK v2 RSA verification building blocks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libarchive_oxide_codecs::gzip::GzipDecoder;
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput, Limits};
use ring::signature;
use sha2::{Digest as _, Sha256};

use crate::alpine::{
    AlpineApkValidation, AlpineDataHash, AlpineSignatureAlgorithm, AlpineSignatureRecord,
};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "alpine-apk";
const BUFFER: usize = 64 * 1024;
const MAX_PUBLIC_KEY_INPUT: usize = 64 * 1024;
const MAX_TRACKED_MEMBERS: usize = 3;
const RSA_ENCRYPTION_ALGORITHM: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

/// A validated Alpine APK v2 RSA verification key.
///
/// APK v2 identifies keys by the suffix of its `.SIGN.*` member. The retained
/// key is canonical PKCS#1 `RSAPublicKey` DER, which is also the exact input
/// expected by `ring`'s RSA verification algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpineRsaPublicKey {
    key_id: Vec<u8>,
    pkcs1_der: Vec<u8>,
    fingerprint: [u8; 32],
}

impl AlpineRsaPublicKey {
    /// Parses either PKCS#1 `RSAPublicKey` DER or an RSA
    /// `SubjectPublicKeyInfo` DER wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe key identifier, malformed/non-canonical
    /// DER, a non-RSA SPKI algorithm, or an RSA modulus outside 2048–8192 bits.
    pub fn from_der(
        key_id: impl Into<Vec<u8>>,
        der: impl AsRef<[u8]>,
    ) -> Result<Self, PackageKeyError> {
        let key_id = validate_key_id(key_id.into())?;
        let der = der.as_ref();
        validate_key_input_size(der)?;
        let pkcs1_der = normalize_public_key_der(der)?;
        let fingerprint = Sha256::digest(&pkcs1_der).into();
        Ok(Self {
            key_id,
            pkcs1_der,
            fingerprint,
        })
    }

    /// Parses a PEM `PUBLIC KEY` (SPKI) or `RSA PUBLIC KEY` (PKCS#1).
    ///
    /// # Errors
    ///
    /// Returns an error for malformed PEM/base64 or any DER/key validation
    /// failure described by [`Self::from_der`].
    pub fn from_pem(
        key_id: impl Into<Vec<u8>>,
        pem: impl AsRef<[u8]>,
    ) -> Result<Self, PackageKeyError> {
        let pem = pem.as_ref();
        validate_key_input_size(pem)?;
        let der = decode_public_key_pem(pem)?;
        Self::from_der(key_id, der)
    }

    /// Parses PEM when a PEM boundary is present, otherwise DER.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected representation or RSA key is invalid.
    pub fn from_bytes(
        key_id: impl Into<Vec<u8>>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self, PackageKeyError> {
        let key_id = key_id.into();
        let bytes = bytes.as_ref();
        if bytes.starts_with(b"-----BEGIN ") {
            Self::from_pem(key_id, bytes)
        } else {
            Self::from_der(key_id, bytes)
        }
    }

    /// Exact APK v2 key identifier, normally a `.rsa.pub` filename.
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// Canonical PKCS#1 `RSAPublicKey` DER used for verification.
    #[must_use]
    pub fn pkcs1_der(&self) -> &[u8] {
        &self.pkcs1_der
    }

    /// SHA-256 fingerprint of [`Self::pkcs1_der`].
    #[must_use]
    pub const fn fingerprint_sha256(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// Validation error for an offline package verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageKeyError {
    detail: String,
}

impl PackageKeyError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for PackageKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for PackageKeyError {}

fn validate_key_input_size(input: &[u8]) -> Result<(), PackageKeyError> {
    if input.len() > MAX_PUBLIC_KEY_INPUT {
        Err(PackageKeyError::new(format!(
            "Alpine RSA public key exceeds the {MAX_PUBLIC_KEY_INPUT}-byte input limit"
        )))
    } else {
        Ok(())
    }
}

fn validate_key_id(key_id: Vec<u8>) -> Result<Vec<u8>, PackageKeyError> {
    if key_id.is_empty() || key_id.len() > 255 {
        return Err(PackageKeyError::new(
            "Alpine RSA key identifier must contain 1 through 255 bytes",
        ));
    }
    if key_id
        .iter()
        .any(|byte| matches!(byte, 0 | b'/' | b'\\' | b'\r' | b'\n' | b':' | b'='))
    {
        return Err(PackageKeyError::new(
            "Alpine RSA key identifier contains an unsafe separator",
        ));
    }
    Ok(key_id)
}

fn decode_public_key_pem(pem: &[u8]) -> Result<Vec<u8>, PackageKeyError> {
    let (label, end) = if pem.starts_with(b"-----BEGIN PUBLIC KEY-----") {
        (
            b"-----BEGIN PUBLIC KEY-----".as_slice(),
            b"-----END PUBLIC KEY-----".as_slice(),
        )
    } else if pem.starts_with(b"-----BEGIN RSA PUBLIC KEY-----") {
        (
            b"-----BEGIN RSA PUBLIC KEY-----".as_slice(),
            b"-----END RSA PUBLIC KEY-----".as_slice(),
        )
    } else {
        return Err(PackageKeyError::new(
            "RSA public key PEM has an unsupported boundary",
        ));
    };
    let after_begin = pem
        .get(label.len()..)
        .ok_or_else(|| PackageKeyError::new("truncated RSA public key PEM"))?;
    let end_offset = find_subslice(after_begin, end)
        .ok_or_else(|| PackageKeyError::new("RSA public key PEM has no matching end boundary"))?;
    let trailing = &after_begin[end_offset + end.len()..];
    if trailing
        .iter()
        .any(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(PackageKeyError::new(
            "RSA public key PEM has trailing non-whitespace data",
        ));
    }
    let mut encoded = Vec::new();
    for byte in &after_begin[..end_offset] {
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'=') {
            return Err(PackageKeyError::new(
                "RSA public key PEM contains a non-base64 byte",
            ));
        }
        encoded.push(*byte);
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| PackageKeyError::new("RSA public key PEM base64 is malformed"))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn normalize_public_key_der(input: &[u8]) -> Result<Vec<u8>, PackageKeyError> {
    if validate_pkcs1_public_key(input).is_ok() {
        return Ok(input.to_vec());
    }

    let mut root = DerReader::new(input);
    let sequence = root.read_tlv(0x30)?;
    root.finish()?;
    let mut spki = DerReader::new(sequence);
    let algorithm = spki.read_tlv(0x30)?;
    if algorithm != RSA_ENCRYPTION_ALGORITHM {
        return Err(PackageKeyError::new(
            "public-key SPKI does not use rsaEncryption with NULL parameters",
        ));
    }
    let bit_string = spki.read_tlv(0x03)?;
    spki.finish()?;
    let Some((&unused_bits, key)) = bit_string.split_first() else {
        return Err(PackageKeyError::new("RSA SPKI bit string is empty"));
    };
    if unused_bits != 0 {
        return Err(PackageKeyError::new(
            "RSA SPKI bit string has non-zero unused bits",
        ));
    }
    validate_pkcs1_public_key(key)?;
    Ok(key.to_vec())
}

fn validate_pkcs1_public_key(input: &[u8]) -> Result<(), PackageKeyError> {
    let mut root = DerReader::new(input);
    let sequence = root.read_tlv(0x30)?;
    root.finish()?;
    let mut key = DerReader::new(sequence);
    let modulus = key.read_positive_integer()?;
    let exponent = key.read_positive_integer()?;
    key.finish()?;

    let modulus = modulus.strip_prefix(&[0]).unwrap_or(modulus);
    if !(256..=1024).contains(&modulus.len())
        || modulus.first().is_none_or(|byte| *byte == 0)
        || (modulus.len() == 256 && modulus[0] & 0x80 == 0)
    {
        return Err(PackageKeyError::new(
            "RSA public modulus must contain 2048 through 8192 significant bits",
        ));
    }
    if exponent.len() > 8 {
        return Err(PackageKeyError::new("RSA public exponent is invalid"));
    }
    let exponent = exponent
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    if exponent < 3 || exponent & 1 == 0 {
        return Err(PackageKeyError::new(
            "RSA public exponent must be an odd integer of at least three",
        ));
    }
    Ok(())
}

struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], PackageKeyError> {
        let tag = *self
            .input
            .get(self.offset)
            .ok_or_else(|| PackageKeyError::new("truncated DER tag"))?;
        if tag != expected_tag {
            return Err(PackageKeyError::new(format!(
                "unexpected DER tag 0x{tag:02x}; expected 0x{expected_tag:02x}"
            )));
        }
        self.offset += 1;
        let length = self.read_length()?;
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| PackageKeyError::new("DER value extends past its input"))?;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_positive_integer(&mut self) -> Result<&'a [u8], PackageKeyError> {
        let integer = self.read_tlv(0x02)?;
        if integer.is_empty() || integer[0] & 0x80 != 0 {
            return Err(PackageKeyError::new("RSA DER integer is empty or negative"));
        }
        if integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0 {
            return Err(PackageKeyError::new(
                "RSA DER integer has a redundant leading zero",
            ));
        }
        Ok(integer)
    }

    fn read_length(&mut self) -> Result<usize, PackageKeyError> {
        let first = *self
            .input
            .get(self.offset)
            .ok_or_else(|| PackageKeyError::new("truncated DER length"))?;
        self.offset += 1;
        if first & 0x80 == 0 {
            return Ok(usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(PackageKeyError::new(
                "DER uses an indefinite or oversized length",
            ));
        }
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| PackageKeyError::new("truncated DER long-form length"))?;
        if self.input[self.offset] == 0 {
            return Err(PackageKeyError::new(
                "DER long-form length has a leading zero",
            ));
        }
        let mut length = 0_usize;
        for byte in &self.input[self.offset..end] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| PackageKeyError::new("DER length overflows usize"))?;
        }
        self.offset = end;
        if length < 128 {
            return Err(PackageKeyError::new(
                "DER length does not use its shortest encoding",
            ));
        }
        Ok(length)
    }

    fn finish(&self) -> Result<(), PackageKeyError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(PackageKeyError::new("DER value has trailing bytes"))
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GzipMemberEvidence {
    pub(crate) encoded: Option<Vec<u8>>,
    pub(crate) sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub(crate) struct GzipEvidence {
    pub(crate) members: Vec<GzipMemberEvidence>,
    pub(crate) member_count: usize,
    pub(crate) capture_exhausted: bool,
}

struct MemberAccumulator {
    encoded: Option<Vec<u8>>,
    sha256: Sha256,
}

impl MemberAccumulator {
    fn new(capture: bool) -> Self {
        Self {
            encoded: capture.then(Vec::new),
            sha256: Sha256::new(),
        }
    }
}

/// Concatenated-gzip reader that retains only the bounded signature/control
/// members and SHA-256 evidence for the first APK v2 members.
pub(crate) struct TrackingGzipReader<R> {
    input: R,
    decoder: GzipDecoder,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    input_eof: bool,
    state: GzipReaderState,
    limits: Limits,
    capture_limit: usize,
    capture_used: usize,
    capture_exhausted: bool,
    decoded_total: u64,
    member_count: usize,
    members: Vec<GzipMemberEvidence>,
    current: MemberAccumulator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GzipReaderState {
    Decoding,
    BetweenMembers,
    Done,
}

impl<R: Read> TrackingGzipReader<R> {
    pub(crate) fn new(input: R, limits: Limits, capture_limit: usize) -> Self {
        Self {
            input,
            decoder: GzipDecoder::new(limits),
            buffer: vec![0; BUFFER],
            start: 0,
            end: 0,
            input_eof: false,
            state: GzipReaderState::Decoding,
            limits,
            capture_limit,
            capture_used: 0,
            capture_exhausted: false,
            decoded_total: 0,
            member_count: 0,
            members: Vec::with_capacity(MAX_TRACKED_MEMBERS),
            current: MemberAccumulator::new(true),
        }
    }

    pub(crate) fn into_evidence(self) -> GzipEvidence {
        GzipEvidence {
            members: self.members,
            member_count: self.member_count,
            capture_exhausted: self.capture_exhausted,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start != 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() || self.input_eof {
            return Ok(());
        }
        let count = self.input.read(&mut self.buffer[self.end..])?;
        if count == 0 {
            self.input_eof = true;
        } else {
            self.end += count;
        }
        Ok(())
    }

    fn account_encoded_range(&mut self, start: usize, end: usize) {
        let bytes = &self.buffer[start..end];
        self.current.sha256.update(bytes);
        let Some(encoded) = &mut self.current.encoded else {
            return;
        };
        let Some(next) = self.capture_used.checked_add(bytes.len()) else {
            self.capture_exhausted = true;
            self.current.encoded = None;
            return;
        };
        if next > self.capture_limit {
            self.capture_exhausted = true;
            self.current.encoded = None;
            return;
        }
        encoded.extend_from_slice(bytes);
        self.capture_used = next;
    }

    fn account_decoded(&mut self, produced: usize) -> io::Result<()> {
        let produced = u64::try_from(produced).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Alpine decoded byte count cannot be represented",
            )
        })?;
        let next = self.decoded_total.checked_add(produced).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Alpine decoded byte count overflow",
            )
        })?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| next > maximum)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Alpine concatenated gzip stream exceeds the decoded-total limit",
            ));
        }
        self.decoded_total = next;
        Ok(())
    }

    fn finish_member(&mut self) {
        let next_index = self.member_count.saturating_add(1);
        let capture_next = next_index < 2;
        let current = core::mem::replace(&mut self.current, MemberAccumulator::new(capture_next));
        if self.members.len() < MAX_TRACKED_MEMBERS {
            self.members.push(GzipMemberEvidence {
                encoded: current.encoded,
                sha256: current.sha256.finalize().into(),
            });
        }
        self.member_count = next_index;
        self.state = GzipReaderState::BetweenMembers;
    }

    fn reset_member(&mut self) {
        self.decoder = GzipDecoder::new(self.limits);
        self.state = GzipReaderState::Decoding;
    }
}

impl<R: Read> Read for TrackingGzipReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.state == GzipReaderState::Done {
            return Ok(0);
        }
        loop {
            if self.state == GzipReaderState::BetweenMembers {
                if self.end - self.start < 2 && !self.input_eof {
                    self.fill()?;
                    if self.end - self.start < 2 && !self.input_eof {
                        continue;
                    }
                }
                let remaining = &self.buffer[self.start..self.end];
                if remaining.is_empty() && self.input_eof {
                    self.state = GzipReaderState::Done;
                    return Ok(0);
                }
                if remaining.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing byte after Alpine gzip member",
                    ));
                }
                if !remaining.starts_with(&[0x1f, 0x8b]) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing data after Alpine gzip member",
                    ));
                }
                self.reset_member();
            }

            if self.start == self.end && !self.input_eof {
                self.fill()?;
            }
            let end = if self.input_eof {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let input_start = self.start;
            let step = self
                .decoder
                .process(&self.buffer[self.start..self.end], output, end)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let consumed_end = input_start + step.consumed;
            self.account_encoded_range(input_start, consumed_end);
            self.account_decoded(step.produced)?;
            self.start = consumed_end;
            if matches!(step.status, CodecStatus::Done) {
                self.finish_member();
            }
            if step.produced != 0 {
                return Ok(step.produced);
            }
            if step.consumed == 0 {
                match step.status {
                    CodecStatus::NeedInput if !self.input_eof => self.fill()?,
                    CodecStatus::Done => {},
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Alpine gzip reader made no progress",
                        ));
                    },
                }
            }
        }
    }
}

pub(crate) struct AlpineVerification {
    pub(crate) integrity: VerificationDimension,
    pub(crate) signature_validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

pub(crate) fn verify_alpine(
    validation: &AlpineApkValidation,
    keys: &BTreeMap<Vec<u8>, AlpineRsaPublicKey>,
) -> AlpineVerification {
    let mut findings = Vec::new();
    let integrity = verify_datahash(validation, &mut findings);
    let (signature_validity, signer_fingerprints) =
        verify_signatures(validation, keys, &mut findings);
    AlpineVerification {
        integrity,
        signature_validity,
        signer_fingerprints,
        findings,
    }
}

fn verify_datahash(
    validation: &AlpineApkValidation,
    findings: &mut Vec<PackageFinding>,
) -> VerificationDimension {
    let expected = match validation.datahash {
        AlpineDataHash::Absent => return VerificationDimension::NotPresent,
        AlpineDataHash::Invalid => return VerificationDimension::Invalid,
        AlpineDataHash::Valid(expected) => expected,
    };
    let Some(evidence) = validation.gzip_evidence.as_ref() else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(b".PKGINFO".to_vec()),
            PackageFindingCode::IntegrityReadFailure,
            "compressed APK member evidence is unavailable",
        ));
        return VerificationDimension::Invalid;
    };
    let data_index = usize::from(validation.signature_present());
    let Some(member) = evidence.members.get(data_index + 1) else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(b".PKGINFO".to_vec()),
            PackageFindingCode::IntegrityReadFailure,
            format!(
                ".PKGINFO datahash names compressed member {}, but only {} complete gzip members were read",
                data_index + 2,
                evidence.member_count
            ),
        ));
        return VerificationDimension::Invalid;
    };
    if member.sha256 == expected {
        VerificationDimension::Verified
    } else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(b".PKGINFO".to_vec()),
            PackageFindingCode::IntegrityMismatch,
            "SHA-256 datahash does not match the exact compressed APK data member",
        ));
        VerificationDimension::Invalid
    }
}

fn verify_signatures(
    validation: &AlpineApkValidation,
    keys: &BTreeMap<Vec<u8>, AlpineRsaPublicKey>,
    findings: &mut Vec<PackageFinding>,
) -> (VerificationDimension, Vec<[u8; 32]>) {
    if !validation.signature_present() {
        return (VerificationDimension::NotPresent, Vec::new());
    }
    if validation.signatures.is_empty() {
        findings.push(PackageFinding::new(
            PROFILE,
            None,
            PackageFindingCode::InvalidSignatureMetadata,
            "signature entries were detected, but none had a valid APK v2 signature name and type",
        ));
        return (VerificationDimension::Invalid, Vec::new());
    }

    let context = SignatureContext {
        control: validation
            .gzip_evidence
            .as_ref()
            .and_then(|evidence| evidence.members.get(1))
            .and_then(|member| member.encoded.as_deref()),
        capture_exhausted: validation
            .gzip_evidence
            .as_ref()
            .is_some_and(|evidence| evidence.capture_exhausted),
        has_datahash: matches!(validation.datahash, AlpineDataHash::Valid(_)),
        keys,
    };
    let mut valid_fingerprints = BTreeSet::new();
    let mut invalid = 0_usize;
    let mut missing_key = 0_usize;
    let mut unsupported = 0_usize;
    let mut resource_limited = 0_usize;
    for record in &validation.signatures {
        match verify_signature_record(record, &context, findings) {
            SignatureOutcome::Valid(fingerprint) => {
                valid_fingerprints.insert(fingerprint);
            },
            SignatureOutcome::Invalid => invalid = invalid.saturating_add(1),
            SignatureOutcome::MissingKey => missing_key = missing_key.saturating_add(1),
            SignatureOutcome::Unsupported => unsupported = unsupported.saturating_add(1),
            SignatureOutcome::ResourceLimited => {
                resource_limited = resource_limited.saturating_add(1);
            },
        }
    }

    let fingerprints: Vec<_> = valid_fingerprints.into_iter().collect();
    let dimension = if !fingerprints.is_empty() {
        VerificationDimension::Verified
    } else if invalid != 0 || resource_limited != 0 {
        VerificationDimension::Invalid
    } else if missing_key != 0 {
        VerificationDimension::NotEvaluated
    } else if unsupported != 0 {
        VerificationDimension::Unsupported
    } else {
        VerificationDimension::NotEvaluated
    };
    (dimension, fingerprints)
}

struct SignatureContext<'a> {
    keys: &'a BTreeMap<Vec<u8>, AlpineRsaPublicKey>,
    control: Option<&'a [u8]>,
    capture_exhausted: bool,
    has_datahash: bool,
}

enum SignatureOutcome {
    Valid([u8; 32]),
    Invalid,
    MissingKey,
    Unsupported,
    ResourceLimited,
}

fn verify_signature_record(
    record: &AlpineSignatureRecord,
    context: &SignatureContext<'_>,
    findings: &mut Vec<PackageFinding>,
) -> SignatureOutcome {
    if record.too_large {
        return SignatureOutcome::ResourceLimited;
    }
    if record.algorithm == AlpineSignatureAlgorithm::Dsa {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(record.name.clone()),
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            "APK v2 DSA signatures are not accepted; supply an RSA-signed package",
        ));
        return SignatureOutcome::Unsupported;
    }
    let Some(key) = context.keys.get(record.key_id.as_slice()) else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(record.name.clone()),
            PackageFindingCode::MissingVerificationKey,
            format!(
                "no offline RSA public key was supplied for {}",
                String::from_utf8_lossy(&record.key_id)
            ),
        ));
        return SignatureOutcome::MissingKey;
    };
    if !context.has_datahash {
        if !findings
            .iter()
            .any(|finding| finding.code() == PackageFindingCode::UnsupportedIntegrityScope)
        {
            findings.push(PackageFinding::new(
                PROFILE,
                Some(b".PKGINFO".to_vec()),
                PackageFindingCode::UnsupportedIntegrityScope,
                "APK v2 RSA verification requires a signed .PKGINFO datahash; the legacy combined control/data scope is not retained",
            ));
        }
        return SignatureOutcome::Unsupported;
    }
    let Some(control) = context.control else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(record.name.clone()),
            PackageFindingCode::SignatureResourceLimit,
            if context.capture_exhausted {
                "exact compressed control member exceeded the configured metadata budget"
            } else {
                "exact compressed control member was unavailable"
            },
        ));
        return SignatureOutcome::ResourceLimited;
    };
    if verify_rsa(record, key, control) {
        SignatureOutcome::Valid(key.fingerprint_sha256())
    } else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(record.name.clone()),
            PackageFindingCode::SignatureMismatch,
            format!(
                "RSA signature did not match the compressed control member using key {}",
                String::from_utf8_lossy(&record.key_id)
            ),
        ));
        SignatureOutcome::Invalid
    }
}

fn verify_rsa(record: &AlpineSignatureRecord, key: &AlpineRsaPublicKey, control: &[u8]) -> bool {
    let algorithm: &'static dyn signature::VerificationAlgorithm = match record.algorithm {
        AlpineSignatureAlgorithm::RsaSha1 => {
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
        },
        AlpineSignatureAlgorithm::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        AlpineSignatureAlgorithm::RsaSha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        AlpineSignatureAlgorithm::Dsa => return false,
    };
    signature::UnparsedPublicKey::new(algorithm, key.pkcs1_der())
        .verify(control, &record.body)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_and_der_lengths_fail_closed() {
        assert!(AlpineRsaPublicKey::from_der(Vec::new(), []).is_err());
        assert!(AlpineRsaPublicKey::from_der(b"../key".to_vec(), []).is_err());
        assert!(AlpineRsaPublicKey::from_der(b"key.rsa.pub".to_vec(), [0x30, 0]).is_err());
        assert!(
            AlpineRsaPublicKey::from_der(
                b"key.rsa.pub".to_vec(),
                vec![0_u8; MAX_PUBLIC_KEY_INPUT + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn pem_parser_rejects_trailing_and_mismatched_boundaries() {
        assert!(
            AlpineRsaPublicKey::from_pem(
                b"key.rsa.pub".to_vec(),
                b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
        assert!(
            AlpineRsaPublicKey::from_pem(
                b"key.rsa.pub".to_vec(),
                b"-----BEGIN RSA PUBLIC KEY-----\nMAA=\n-----END RSA PUBLIC KEY-----\ntrailing"
            )
            .is_err()
        );
    }
}
