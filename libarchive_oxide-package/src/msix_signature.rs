// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded offline verification of MSIX/APPX `AppxSignature.p7x` files.
//!
//! The P7X member starts with `PKCX` followed by CMS `SignedData`.
//! Its Authenticode `SpcIndirectDataContent` carries the `APPX` digest header:
//! hashes of the raw package records, a canonical pre-signature central directory, and the uncompressed package footprint files.
//! All parsing and hashing stays seek-streaming and within the caller's limits.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use bcder::decode::Constructed;
use bcder::{Mode, OctetString};
use libarchive_oxide::Limits;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_certificate::DigestAlgorithm;
use x509_certificate::rfc5280::AlgorithmIdentifier;

use crate::PackageFinding;
use crate::integrity::{EntryDigest, collect_entries};
use crate::jar_signature::{SignatureFailure, preflight_der, verify_cms};
use crate::verification::VerificationDimension;
use crate::zip_reader::{
    ZipEntry, le_u16, le_u32, le_u64, read_central_directory_with_offset, read_exact_at,
};

const PROFILE: &str = "msix";
const SIGNATURE_NAME: &[u8] = b"AppxSignature.p7x";
const BLOCK_MAP_NAME: &[u8] = b"AppxBlockMap.xml";
const CONTENT_TYPES_NAME: &[u8] = b"[Content_Types].xml";
const CODE_INTEGRITY_NAME: &[u8] = b"AppxMetadata/CodeIntegrity.cat";
const P7X_HEADER: &[u8; 4] = b"PKCX";
const APPX_HEADER: &[u8; 4] = b"APPX";
const AXPC: &[u8; 4] = b"AXPC";
const AXCD: &[u8; 4] = b"AXCD";
const AXCT: &[u8; 4] = b"AXCT";
const AXBM: &[u8; 4] = b"AXBM";
const AXCI: &[u8; 4] = b"AXCI";
const DIGEST_RECORD_LEN: usize = 4 + 32;
const REQUIRED_DIGESTS: usize = 4;
const MAX_SPC_CONTENT_BYTES: usize = 4 * 1024;
const MAX_P7X_BYTES: usize = 2 * 1024 * 1024;
const OID_SIGNED_DATA: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
const OID_SPC_INDIRECT_DATA: &[u8] = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04";
const EOCD_MIN: usize = 22;
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;
const ZIP64_LOCATOR_LEN: u64 = 20;
const ZIP64_RECORD_MIN: u64 = 56;
const MAX_ZIP64_RECORD_BYTES: u64 = 1024 * 1024;
const CENTRAL_FIXED: usize = 46;
const LOCAL_FIXED: usize = 30;
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

#[derive(Debug)]
pub(crate) struct MsixSignatureVerification {
    pub(crate) validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug)]
struct AppxDigests {
    file_records: [u8; 32],
    central_directory: [u8; 32],
    content_types: [u8; 32],
    block_map: [u8; 32],
    code_integrity: Option<[u8; 32]>,
}

#[derive(Debug)]
struct NormalizedCms {
    encoded: Vec<u8>,
    spc_der: Vec<u8>,
    signed_content: Vec<u8>,
}

#[derive(Debug)]
enum EndRecords {
    Classic {
        eocd: Vec<u8>,
        eocd_offset: u64,
        central_size: u64,
        count: u64,
    },
    Zip64 {
        record: Vec<u8>,
        locator: Vec<u8>,
        eocd: Vec<u8>,
        record_offset: u64,
        central_size: u64,
        count: u64,
    },
}

impl EndRecords {
    const fn central_size(&self) -> u64 {
        match self {
            Self::Classic { central_size, .. } | Self::Zip64 { central_size, .. } => *central_size,
        }
    }

    const fn count(&self) -> u64 {
        match self {
            Self::Classic { count, .. } | Self::Zip64 { count, .. } => *count,
        }
    }

    const fn central_end(&self) -> u64 {
        match self {
            Self::Classic { eocd_offset, .. } => *eocd_offset,
            Self::Zip64 { record_offset, .. } => *record_offset,
        }
    }
}

pub(crate) fn verify_msix_signature<R: Read + Seek>(
    mut reader: R,
    limits: Limits,
) -> MsixSignatureVerification {
    match verify_msix_signature_inner(&mut reader, limits) {
        Ok((fingerprints, true)) => MsixSignatureVerification {
            validity: VerificationDimension::Verified,
            signer_fingerprints: fingerprints,
            findings: Vec::new(),
        },
        Ok((_, false)) => MsixSignatureVerification {
            validity: VerificationDimension::NotPresent,
            signer_fingerprints: Vec::new(),
            findings: Vec::new(),
        },
        Err(failure) => {
            let validity = if matches!(failure, SignatureFailure::Unsupported(_)) {
                VerificationDimension::Unsupported
            } else {
                VerificationDimension::Invalid
            };
            let code = failure.code();
            MsixSignatureVerification {
                validity,
                signer_fingerprints: Vec::new(),
                findings: vec![PackageFinding::new(
                    PROFILE,
                    Some(SIGNATURE_NAME.to_vec()),
                    code,
                    failure.detail(),
                )],
            }
        },
    }
}

fn verify_msix_signature_inner<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<(Vec<[u8; 32]>, bool), SignatureFailure> {
    let entries =
        collect_entries(&mut *reader, limits, |name| name == SIGNATURE_NAME).map_err(|error| {
            if error.resource_limit {
                SignatureFailure::ResourceLimit(format!(
                    "cannot collect MSIX signature metadata: {}",
                    error.detail
                ))
            } else {
                SignatureFailure::InvalidMetadata(format!(
                    "cannot read MSIX signature metadata: {}",
                    error.detail
                ))
            }
        })?;
    let signatures = entries
        .iter()
        .filter(|entry| entry.name == SIGNATURE_NAME)
        .collect::<Vec<_>>();
    if signatures.is_empty() {
        return Ok((Vec::new(), false));
    }
    if signatures.len() != 1 {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX contains more than one AppxSignature.p7x member".to_string(),
        ));
    }
    let signature = signatures[0];
    let body = signature.metadata_body.as_deref().ok_or_else(|| {
        SignatureFailure::ResourceLimit(
            "AppxSignature.p7x was not retained inside the metadata budget".to_string(),
        )
    })?;
    if body.len() > MAX_P7X_BYTES {
        return Err(SignatureFailure::ResourceLimit(format!(
            "AppxSignature.p7x size {} exceeds the Microsoft profile limit {MAX_P7X_BYTES}",
            body.len()
        )));
    }
    let cms = body.strip_prefix(P7X_HEADER).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "AppxSignature.p7x does not begin with the PKCX file identifier".to_string(),
        )
    })?;
    let normalized = normalize_authenticode_cms(cms, limits)?;
    let digests = parse_spc_indirect_data(&normalized.spc_der)?;
    let fingerprints = verify_cms(&normalized.encoded, &normalized.signed_content, limits)?;

    verify_footprint_digests(&entries, &digests)?;
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "cannot seek to the start of the MSIX package: {error}"
        ))
    })?;
    let (file_records, central_directory) = raw_package_digests(reader, limits)?;
    compare_digest("AXPC file-record", digests.file_records, &file_records)?;
    compare_digest(
        "AXCD central-directory",
        digests.central_directory,
        &central_directory,
    )?;
    Ok((fingerprints, true))
}

#[derive(Debug, Clone, Copy)]
struct DerTlv {
    start: usize,
    content: usize,
    end: usize,
    tag: u8,
}

/// Authenticode predates RFC 5652 and places its content SEQUENCE directly inside `EncapsulatedContentInfo.[0]`.
/// The CMS dependency intentionally accepts the RFC 5652 OCTET STRING form only.
/// Rebuilding just the unsigned outer containers around an OCTET STRING containing the original SEQUENCE lets the existing verifier see the exact same signed content bytes; signer attributes, certificates, and signatures remain byte-for-byte untouched.
fn normalize_authenticode_cms(
    cms: &[u8],
    limits: Limits,
) -> Result<NormalizedCms, SignatureFailure> {
    preflight_der(cms, limits)?;
    let outer = expected_tlv(cms, 0, 0x30, "CMS ContentInfo")?;
    if outer.end != cms.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX CMS ContentInfo has trailing bytes".to_string(),
        ));
    }
    let signed_data_oid = expected_tlv(cms, outer.content, 0x06, "CMS content-type OID")?;
    if &cms[signed_data_oid.start..signed_data_oid.end] != OID_SIGNED_DATA {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX P7X CMS content type is not SignedData".to_string(),
        ));
    }
    let outer_explicit = expected_tlv(cms, signed_data_oid.end, 0xa0, "CMS SignedData wrapper")?;
    if outer_explicit.end != outer.end {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX CMS ContentInfo contains unexpected fields".to_string(),
        ));
    }
    let signed_data = expected_tlv(cms, outer_explicit.content, 0x30, "CMS SignedData")?;
    if signed_data.end != outer_explicit.end {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX CMS SignedData wrapper contains trailing fields".to_string(),
        ));
    }
    let version = expected_tlv(cms, signed_data.content, 0x02, "CMS SignedData version")?;
    let algorithms = expected_tlv(cms, version.end, 0x31, "CMS digest-algorithm set")?;
    let encapsulated = expected_tlv(cms, algorithms.end, 0x30, "CMS encapsulated content")?;
    let spc_oid = expected_tlv(
        cms,
        encapsulated.content,
        0x06,
        "CMS encapsulated content-type OID",
    )?;
    if &cms[spc_oid.start..spc_oid.end] != OID_SPC_INDIRECT_DATA {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX P7X does not carry SpcIndirectDataContent".to_string(),
        ));
    }
    let content_wrapper = expected_tlv(cms, spc_oid.end, 0xa0, "CMS content wrapper")?;
    if content_wrapper.end != encapsulated.end {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX encapsulated content has trailing fields".to_string(),
        ));
    }
    let original = expected_tlv(cms, content_wrapper.content, 0x30, "SpcIndirectDataContent")?;
    if original.end != content_wrapper.end {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX SpcIndirectDataContent wrapper has trailing fields".to_string(),
        ));
    }
    let original_bytes = cms[original.start..original.end].to_vec();
    if original_bytes.len() > MAX_SPC_CONTENT_BYTES {
        return Err(SignatureFailure::ResourceLimit(format!(
            "MSIX SpcIndirectDataContent size {} exceeds the format limit {MAX_SPC_CONTENT_BYTES}",
            original_bytes.len()
        )));
    }

    // Authenticode's PKCS#7 profile digests the SEQUENCE content octets rather than the outer SEQUENCE tag and length.
    // This is also the byte range the Microsoft SDK supplies to PKCS7_verify.
    let signed_content = cms[original.content..original.end].to_vec();
    let octet = encode_tlv(0x04, &signed_content)?;
    let new_content_wrapper = encode_tlv(0xa0, &octet)?;
    let mut encapsulated_content =
        Vec::with_capacity(spc_oid.end - spc_oid.start + new_content_wrapper.len());
    encapsulated_content.extend_from_slice(&cms[spc_oid.start..spc_oid.end]);
    encapsulated_content.extend_from_slice(&new_content_wrapper);
    let new_encapsulated = encode_tlv(0x30, &encapsulated_content)?;

    let mut signed_data_content = Vec::with_capacity(
        encapsulated.start - signed_data.content + new_encapsulated.len() + signed_data.end
            - encapsulated.end,
    );
    signed_data_content.extend_from_slice(&cms[signed_data.content..encapsulated.start]);
    signed_data_content.extend_from_slice(&new_encapsulated);
    signed_data_content.extend_from_slice(&cms[encapsulated.end..signed_data.end]);
    let new_signed_data = encode_tlv(0x30, &signed_data_content)?;
    let new_outer_explicit = encode_tlv(0xa0, &new_signed_data)?;

    let mut outer_content =
        Vec::with_capacity(signed_data_oid.end - signed_data_oid.start + new_outer_explicit.len());
    outer_content.extend_from_slice(&cms[signed_data_oid.start..signed_data_oid.end]);
    outer_content.extend_from_slice(&new_outer_explicit);
    let normalized = encode_tlv(0x30, &outer_content)?;
    Ok(NormalizedCms {
        encoded: normalized,
        spc_der: original_bytes,
        signed_content,
    })
}

fn expected_tlv(
    data: &[u8],
    offset: usize,
    tag: u8,
    label: &str,
) -> Result<DerTlv, SignatureFailure> {
    let value = der_tlv(data, offset)?;
    if value.tag != tag {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "{label} has DER tag 0x{:02x}, expected 0x{tag:02x}",
            value.tag
        )));
    }
    Ok(value)
}

fn der_tlv(data: &[u8], start: usize) -> Result<DerTlv, SignatureFailure> {
    let tag = *data.get(start).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("MSIX CMS DER tag is truncated".to_string())
    })?;
    if tag & 0x1f == 0x1f {
        return Err(SignatureFailure::Unsupported(
            "MSIX CMS high-tag-number form is unsupported".to_string(),
        ));
    }
    let length_offset = start.checked_add(1).ok_or_else(|| {
        SignatureFailure::ResourceLimit("MSIX CMS DER offset overflows".to_string())
    })?;
    let first = *data.get(length_offset).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("MSIX CMS DER length is truncated".to_string())
    })?;
    let (length, content) = if first & 0x80 == 0 {
        (usize::from(first), length_offset + 1)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(SignatureFailure::Unsupported(
                "indefinite-length MSIX CMS is unsupported".to_string(),
            ));
        }
        if count > core::mem::size_of::<usize>() {
            return Err(SignatureFailure::ResourceLimit(
                "MSIX CMS DER length exceeds address space".to_string(),
            ));
        }
        let length_start = length_offset + 1;
        let content = length_start.checked_add(count).ok_or_else(|| {
            SignatureFailure::ResourceLimit("MSIX CMS DER length offset overflows".to_string())
        })?;
        let encoded = data.get(length_start..content).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "MSIX CMS DER long-form length is truncated".to_string(),
            )
        })?;
        if encoded.first() == Some(&0) {
            return Err(SignatureFailure::InvalidMetadata(
                "MSIX CMS DER length has a leading zero".to_string(),
            ));
        }
        let length = encoded.iter().try_fold(0_usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
        });
        let length = length.ok_or_else(|| {
            SignatureFailure::ResourceLimit("MSIX CMS DER length overflows".to_string())
        })?;
        (length, content)
    };
    let end = content.checked_add(length).ok_or_else(|| {
        SignatureFailure::ResourceLimit("MSIX CMS DER extent overflows".to_string())
    })?;
    if end > data.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX CMS DER value is truncated".to_string(),
        ));
    }
    Ok(DerTlv {
        start,
        content,
        end,
        tag,
    })
}

fn encode_tlv(tag: u8, content: &[u8]) -> Result<Vec<u8>, SignatureFailure> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve(content.len().saturating_add(10))
        .map_err(|error| {
            SignatureFailure::ResourceLimit(format!(
                "cannot allocate normalized MSIX CMS container: {error}"
            ))
        })?;
    encoded.push(tag);
    encode_der_length(content.len(), &mut encoded);
    encoded.extend_from_slice(content);
    Ok(encoded)
}

fn encode_der_length(length: usize, target: &mut Vec<u8>) {
    if length < 0x80 {
        target.push(u8::try_from(length).unwrap_or(0));
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let significant = &bytes[first..];
    target.push(0x80 | u8::try_from(significant.len()).unwrap_or(u8::MAX));
    target.extend_from_slice(significant);
}

fn parse_spc_indirect_data(content: &[u8]) -> Result<AppxDigests, SignatureFailure> {
    let (algorithm, header) = Constructed::decode(content, Mode::Der, |cons| {
        cons.take_sequence(|cons| {
            #[allow(
                clippy::redundant_closure_for_method_calls,
                reason = "the generic method reference is not lifetime-general enough"
            )]
            let _attribute = cons.take_sequence(|cons| cons.capture_all())?;
            cons.take_sequence(|cons| {
                let algorithm = AlgorithmIdentifier::take_from(cons)?;
                let digest = OctetString::take_from(cons)?;
                Ok((algorithm, digest.to_bytes().to_vec()))
            })
        })
    })
    .map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "MSIX Authenticode SpcIndirectDataContent is malformed: {error}"
        ))
    })?;
    let algorithm = DigestAlgorithm::try_from(&algorithm).map_err(|error| {
        SignatureFailure::Unsupported(format!(
            "MSIX Authenticode package digest algorithm is unsupported: {error}"
        ))
    })?;
    if algorithm != DigestAlgorithm::Sha256 {
        return Err(SignatureFailure::Unsupported(format!(
            "MSIX Authenticode APPX digest header requires SHA-256, found {algorithm:?}"
        )));
    }
    parse_appx_digest_header(&header)
}

fn parse_appx_digest_header(header: &[u8]) -> Result<AppxDigests, SignatureFailure> {
    if !header.starts_with(APPX_HEADER) {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX Authenticode digest bytes do not begin with APPX".to_string(),
        ));
    }
    let records = header
        .len()
        .checked_sub(APPX_HEADER.len())
        .filter(|length| length % DIGEST_RECORD_LEN == 0)
        .map(|length| length / DIGEST_RECORD_LEN)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "MSIX APPX digest header has a partial record".to_string(),
            )
        })?;
    if records != REQUIRED_DIGESTS && records != REQUIRED_DIGESTS + 1 {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "MSIX APPX digest header has {records} records; expected four or five"
        )));
    }

    let mut values = BTreeMap::<[u8; 4], [u8; 32]>::new();
    for record in header[APPX_HEADER.len()..]
        .as_chunks::<DIGEST_RECORD_LEN>()
        .0
    {
        let name: [u8; 4] = record[..4].try_into().map_err(|_| {
            SignatureFailure::InvalidMetadata("MSIX APPX digest name is truncated".to_string())
        })?;
        if !matches!(&name, AXPC | AXCD | AXCT | AXBM | AXCI) {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "MSIX APPX digest header contains unknown record {}",
                String::from_utf8_lossy(&name)
            )));
        }
        let value: [u8; 32] = record[4..].try_into().map_err(|_| {
            SignatureFailure::InvalidMetadata("MSIX APPX digest value is truncated".to_string())
        })?;
        if values.insert(name, value).is_some() {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "MSIX APPX digest header repeats record {}",
                String::from_utf8_lossy(&name)
            )));
        }
    }
    let required = |name: &[u8; 4]| {
        values.get(name).copied().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(format!(
                "MSIX APPX digest header is missing {}",
                String::from_utf8_lossy(name)
            ))
        })
    };
    Ok(AppxDigests {
        file_records: required(AXPC)?,
        central_directory: required(AXCD)?,
        content_types: required(AXCT)?,
        block_map: required(AXBM)?,
        code_integrity: values.get(AXCI).copied(),
    })
}

fn verify_footprint_digests(
    entries: &[EntryDigest],
    digests: &AppxDigests,
) -> Result<(), SignatureFailure> {
    compare_entry_digest(entries, CONTENT_TYPES_NAME, digests.content_types)?;
    compare_entry_digest(entries, BLOCK_MAP_NAME, digests.block_map)?;
    let code_integrity = entries
        .iter()
        .filter(|entry| entry.name == CODE_INTEGRITY_NAME)
        .collect::<Vec<_>>();
    match (digests.code_integrity.as_ref(), code_integrity.as_slice()) {
        (None, []) => Ok(()),
        (Some(expected), [entry]) => compare_digest(
            "AXCI code-integrity",
            *expected,
            entry.sha256.as_slice(),
        ),
        (None, [_]) => Err(SignatureFailure::Mismatch(
            "MSIX contains AppxMetadata/CodeIntegrity.cat but the signed APPX header has no AXCI digest"
                .to_string(),
        )),
        (Some(_), []) => Err(SignatureFailure::Mismatch(
            "MSIX signed APPX header has an AXCI digest but CodeIntegrity.cat is absent".to_string(),
        )),
        _ => Err(SignatureFailure::InvalidMetadata(
            "MSIX repeats AppxMetadata/CodeIntegrity.cat".to_string(),
        )),
    }
}

fn compare_entry_digest(
    entries: &[EntryDigest],
    name: &[u8],
    expected: [u8; 32],
) -> Result<(), SignatureFailure> {
    let matching = entries
        .iter()
        .filter(|entry| entry.name == name)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [entry] => compare_digest(
            &format!("{} footprint", String::from_utf8_lossy(name)),
            expected,
            entry.sha256.as_slice(),
        ),
        [] => Err(SignatureFailure::Mismatch(format!(
            "signed MSIX footprint {} is absent",
            String::from_utf8_lossy(name)
        ))),
        _ => Err(SignatureFailure::InvalidMetadata(format!(
            "MSIX repeats signed footprint {}",
            String::from_utf8_lossy(name)
        ))),
    }
}

fn compare_digest(label: &str, expected: [u8; 32], actual: &[u8]) -> Result<(), SignatureFailure> {
    if bool::from(expected.as_slice().ct_eq(actual)) {
        Ok(())
    } else {
        Err(SignatureFailure::Mismatch(format!(
            "MSIX signed {label} SHA-256 digest does not match the package"
        )))
    }
}

fn raw_package_digests<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<([u8; 32], [u8; 32]), SignatureFailure> {
    let (entries, central_offset) =
        read_central_directory_with_offset(reader, limits).map_err(|detail| {
            SignatureFailure::InvalidMetadata(format!(
                "cannot parse MSIX central directory for Authenticode: {detail}"
            ))
        })?;
    let signatures = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.name == SIGNATURE_NAME)
        .collect::<Vec<_>>();
    let [(signature_index, signature)] = signatures.as_slice() else {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX central directory must contain exactly one AppxSignature.p7x".to_string(),
        ));
    };
    if *signature_index + 1 != entries.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "AppxSignature.p7x must be the last MSIX central-directory member".to_string(),
        ));
    }
    validate_signature_local_extent(reader, signature, central_offset)?;

    let end_records = read_end_records(reader, limits)?;
    if end_records.count() != entries.len() as u64 {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX end record count disagrees with its central directory".to_string(),
        ));
    }
    let (signature_central_offset, signature_central_length, central_end) =
        central_signature_extent(reader, &entries, central_offset)?;
    if central_end != end_records.central_end()
        || central_end.checked_sub(central_offset) != Some(end_records.central_size())
    {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX central-directory extent disagrees with its end records".to_string(),
        ));
    }

    let file_records = hash_range(reader, 0, signature.local_offset)?;
    let unsigned_central_size = end_records
        .central_size()
        .checked_sub(signature_central_length)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "MSIX signature central record exceeds the directory size".to_string(),
            )
        })?;
    let mut central_hasher = Sha256::new();
    hash_range_into(
        reader,
        central_offset,
        signature_central_offset
            .checked_sub(central_offset)
            .ok_or_else(|| {
                SignatureFailure::InvalidMetadata(
                    "MSIX signature central record precedes the directory".to_string(),
                )
            })?,
        &mut central_hasher,
    )?;
    hash_canonical_end_records(
        end_records,
        entries.len() as u64 - 1,
        unsigned_central_size,
        signature.local_offset,
        &mut central_hasher,
    )?;
    Ok((file_records, central_hasher.finalize().into()))
}

fn validate_signature_local_extent<R: Read + Seek>(
    reader: &mut R,
    signature: &ZipEntry,
    central_offset: u64,
) -> Result<(), SignatureFailure> {
    if signature.is_encrypted() {
        return Err(SignatureFailure::InvalidMetadata(
            "AppxSignature.p7x may not be encrypted".to_string(),
        ));
    }
    let mut fixed = [0_u8; LOCAL_FIXED];
    read_exact_at(reader, signature.local_offset, &mut fixed).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "cannot read AppxSignature.p7x local header: {error}"
        ))
    })?;
    if &fixed[..4] != b"PK\x03\x04" {
        return Err(SignatureFailure::InvalidMetadata(
            "AppxSignature.p7x local header signature is invalid".to_string(),
        ));
    }
    let name_len = usize::from(le_u16(&fixed, 26));
    let extra_len = usize::from(le_u16(&fixed, 28));
    let mut name = vec![0_u8; name_len];
    read_exact_at(
        reader,
        signature.local_offset + LOCAL_FIXED as u64,
        &mut name,
    )
    .map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "cannot read AppxSignature.p7x local name: {error}"
        ))
    })?;
    if name != SIGNATURE_NAME {
        return Err(SignatureFailure::InvalidMetadata(
            "AppxSignature.p7x local and central names disagree".to_string(),
        ));
    }
    let body_end = signature
        .local_offset
        .checked_add(LOCAL_FIXED as u64)
        .and_then(|value| value.checked_add(name_len as u64))
        .and_then(|value| value.checked_add(extra_len as u64))
        .and_then(|value| value.checked_add(signature.compressed_size))
        .ok_or_else(|| {
            SignatureFailure::ResourceLimit("AppxSignature.p7x local extent overflows".to_string())
        })?;
    let local_end = if signature.flags & FLAG_DATA_DESCRIPTOR == 0 {
        body_end
    } else {
        let mut prefix = [0_u8; 4];
        read_exact_at(reader, body_end, &mut prefix).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "cannot read AppxSignature.p7x data descriptor: {error}"
            ))
        })?;
        let marker = u64::from(u8::from(&prefix == b"PK\x07\x08")) * 4;
        let sizes = if signature.compressed_size > u64::from(u32::MAX)
            || signature.uncompressed_size > u64::from(u32::MAX)
        {
            20
        } else {
            12
        };
        body_end
            .checked_add(marker)
            .and_then(|value| value.checked_add(sizes))
            .ok_or_else(|| {
                SignatureFailure::ResourceLimit(
                    "AppxSignature.p7x descriptor extent overflows".to_string(),
                )
            })?
    };
    if local_end != central_offset {
        return Err(SignatureFailure::Mismatch(
            "AppxSignature.p7x is not the final local file record".to_string(),
        ));
    }
    Ok(())
}

fn central_signature_extent<R: Read + Seek>(
    reader: &mut R,
    entries: &[ZipEntry],
    central_offset: u64,
) -> Result<(u64, u64, u64), SignatureFailure> {
    let mut position = central_offset;
    let mut signature_extent = None;
    for entry in entries {
        let mut fixed = [0_u8; CENTRAL_FIXED];
        read_exact_at(reader, position, &mut fixed).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!("cannot read MSIX central record: {error}"))
        })?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(SignatureFailure::InvalidMetadata(
                "MSIX central record signature is invalid".to_string(),
            ));
        }
        let name_len = usize::from(le_u16(&fixed, 28));
        let variable_len = name_len
            .checked_add(usize::from(le_u16(&fixed, 30)))
            .and_then(|value| value.checked_add(usize::from(le_u16(&fixed, 32))))
            .ok_or_else(|| {
                SignatureFailure::ResourceLimit("MSIX central record length overflows".to_string())
            })?;
        let length = (CENTRAL_FIXED + variable_len) as u64;
        let mut name = vec![0_u8; name_len];
        read_exact_at(reader, position + CENTRAL_FIXED as u64, &mut name).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "cannot read MSIX central member name: {error}"
            ))
        })?;
        if name != entry.name {
            return Err(SignatureFailure::InvalidMetadata(
                "MSIX central parser order or name disagrees".to_string(),
            ));
        }
        if name == SIGNATURE_NAME {
            signature_extent = Some((position, length));
        }
        position = position.checked_add(length).ok_or_else(|| {
            SignatureFailure::ResourceLimit("MSIX central offset overflows".to_string())
        })?;
    }
    let (offset, length) = signature_extent.ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "MSIX central directory has no AppxSignature.p7x record".to_string(),
        )
    })?;
    Ok((offset, length, position))
}

#[allow(
    clippy::too_many_lines,
    reason = "classic and ZIP64 terminal validation remains one auditable transaction"
)]
fn read_end_records<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<EndRecords, SignatureFailure> {
    let file_len = reader.seek(SeekFrom::End(0)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot measure MSIX ZIP: {error}"))
    })?;
    let tail_len_u64 = file_len.min(EOCD_SEARCH);
    let tail_len = usize::try_from(tail_len_u64).map_err(|_| {
        SignatureFailure::ResourceLimit("MSIX EOCD search exceeds address space".to_string())
    })?;
    if limits
        .metadata_bytes()
        .is_some_and(|limit| tail_len > limit)
    {
        return Err(SignatureFailure::ResourceLimit(
            "MSIX EOCD search exceeds the metadata budget".to_string(),
        ));
    }
    let tail_start = file_len - tail_len_u64;
    let mut tail = vec![0_u8; tail_len];
    read_exact_at(reader, tail_start, &mut tail).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot read MSIX ZIP tail: {error}"))
    })?;
    let eocd_in_tail = tail
        .windows(4)
        .enumerate()
        .rev()
        .find_map(|(offset, signature)| {
            if signature != b"PK\x05\x06" || tail.len().saturating_sub(offset) < EOCD_MIN {
                return None;
            }
            let comment = usize::from(le_u16(&tail, offset + 20));
            (offset + EOCD_MIN + comment == tail.len()).then_some(offset)
        })
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "MSIX ZIP has no terminal end-of-central-directory record".to_string(),
            )
        })?;
    let eocd_offset = tail_start + eocd_in_tail as u64;
    let eocd = tail[eocd_in_tail..].to_vec();
    if le_u16(&eocd, 4) != 0 || le_u16(&eocd, 6) != 0 {
        return Err(SignatureFailure::Unsupported(
            "multi-disk MSIX Authenticode is unsupported".to_string(),
        ));
    }
    let count16 = le_u16(&eocd, 10);
    let central_size32 = le_u32(&eocd, 12);
    let central_offset32 = le_u32(&eocd, 16);
    let zip64 = count16 == u16::MAX || central_size32 == u32::MAX || central_offset32 == u32::MAX;
    if !zip64 {
        if le_u16(&eocd, 8) != count16 {
            return Err(SignatureFailure::InvalidMetadata(
                "MSIX EOCD entry counts disagree".to_string(),
            ));
        }
        return Ok(EndRecords::Classic {
            eocd,
            eocd_offset,
            central_size: u64::from(central_size32),
            count: u64::from(count16),
        });
    }
    if eocd_offset < ZIP64_LOCATOR_LEN {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX ZIP64 locator is missing".to_string(),
        ));
    }
    let mut locator = [0_u8; 20];
    read_exact_at(reader, eocd_offset - ZIP64_LOCATOR_LEN, &mut locator).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot read MSIX ZIP64 locator: {error}"))
    })?;
    if &locator[..4] != b"PK\x06\x07" || le_u32(&locator, 4) != 0 || le_u32(&locator, 16) != 1 {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX ZIP64 locator is invalid or multi-disk".to_string(),
        ));
    }
    let record_offset = le_u64(&locator, 8);
    let mut header = [0_u8; 12];
    read_exact_at(reader, record_offset, &mut header).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot read MSIX ZIP64 end record: {error}"))
    })?;
    if &header[..4] != b"PK\x06\x06" {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX ZIP64 end-record signature is invalid".to_string(),
        ));
    }
    let record_len = le_u64(&header, 4).checked_add(12).ok_or_else(|| {
        SignatureFailure::ResourceLimit("MSIX ZIP64 end-record length overflows".to_string())
    })?;
    if !(ZIP64_RECORD_MIN..=MAX_ZIP64_RECORD_BYTES).contains(&record_len)
        || record_offset.checked_add(record_len) != Some(eocd_offset - ZIP64_LOCATOR_LEN)
    {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX ZIP64 end-record extent is invalid".to_string(),
        ));
    }
    let record_len_usize = usize::try_from(record_len).map_err(|_| {
        SignatureFailure::ResourceLimit("MSIX ZIP64 end record exceeds address space".to_string())
    })?;
    if limits
        .metadata_bytes()
        .is_some_and(|limit| record_len_usize > limit)
    {
        return Err(SignatureFailure::ResourceLimit(
            "MSIX ZIP64 end record exceeds the metadata budget".to_string(),
        ));
    }
    let mut record = vec![0_u8; record_len_usize];
    read_exact_at(reader, record_offset, &mut record).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot read MSIX ZIP64 end record: {error}"))
    })?;
    if le_u32(&record, 16) != 0
        || le_u32(&record, 20) != 0
        || le_u64(&record, 24) != le_u64(&record, 32)
    {
        return Err(SignatureFailure::InvalidMetadata(
            "MSIX ZIP64 end record is multi-disk or has inconsistent counts".to_string(),
        ));
    }
    Ok(EndRecords::Zip64 {
        central_size: le_u64(&record, 40),
        count: le_u64(&record, 32),
        record,
        locator: locator.to_vec(),
        eocd,
        record_offset,
    })
}

fn hash_canonical_end_records(
    records: EndRecords,
    count: u64,
    central_size: u64,
    central_offset: u64,
    hasher: &mut Sha256,
) -> Result<(), SignatureFailure> {
    match records {
        EndRecords::Classic { mut eocd, .. } => {
            let count = u16::try_from(count).map_err(|_| {
                SignatureFailure::ResourceLimit(
                    "canonical MSIX entry count does not fit classic EOCD".to_string(),
                )
            })?;
            let central_size = u32::try_from(central_size).map_err(|_| {
                SignatureFailure::ResourceLimit(
                    "canonical MSIX directory size does not fit classic EOCD".to_string(),
                )
            })?;
            let central_offset = u32::try_from(central_offset).map_err(|_| {
                SignatureFailure::ResourceLimit(
                    "canonical MSIX directory offset does not fit classic EOCD".to_string(),
                )
            })?;
            eocd[8..10].copy_from_slice(&count.to_le_bytes());
            eocd[10..12].copy_from_slice(&count.to_le_bytes());
            eocd[12..16].copy_from_slice(&central_size.to_le_bytes());
            eocd[16..20].copy_from_slice(&central_offset.to_le_bytes());
            hasher.update(eocd);
        },
        EndRecords::Zip64 {
            mut record,
            mut locator,
            mut eocd,
            ..
        } => {
            record[24..32].copy_from_slice(&count.to_le_bytes());
            record[32..40].copy_from_slice(&count.to_le_bytes());
            record[40..48].copy_from_slice(&central_size.to_le_bytes());
            record[48..56].copy_from_slice(&central_offset.to_le_bytes());
            let canonical_record_offset =
                central_offset.checked_add(central_size).ok_or_else(|| {
                    SignatureFailure::ResourceLimit(
                        "canonical MSIX ZIP64 end-record offset overflows".to_string(),
                    )
                })?;
            locator[8..16].copy_from_slice(&canonical_record_offset.to_le_bytes());
            patch_eocd_sentinel_u16(&mut eocd[8..10], count)?;
            patch_eocd_sentinel_u16(&mut eocd[10..12], count)?;
            patch_eocd_sentinel_u32(&mut eocd[12..16], central_size)?;
            patch_eocd_sentinel_u32(&mut eocd[16..20], central_offset)?;
            hasher.update(record);
            hasher.update(locator);
            hasher.update(eocd);
        },
    }
    Ok(())
}

fn patch_eocd_sentinel_u16(field: &mut [u8], value: u64) -> Result<(), SignatureFailure> {
    if le_u16(field, 0) == u16::MAX {
        return Ok(());
    }
    let value = u16::try_from(value).map_err(|_| {
        SignatureFailure::ResourceLimit("MSIX EOCD count truncation would overflow".to_string())
    })?;
    field.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_eocd_sentinel_u32(field: &mut [u8], value: u64) -> Result<(), SignatureFailure> {
    if le_u32(field, 0) == u32::MAX {
        return Ok(());
    }
    let value = u32::try_from(value).map_err(|_| {
        SignatureFailure::ResourceLimit("MSIX EOCD value truncation would overflow".to_string())
    })?;
    field.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn hash_range<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    length: u64,
) -> Result<[u8; 32], SignatureFailure> {
    let mut hasher = Sha256::new();
    hash_range_into(reader, start, length, &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn hash_range_into<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    mut length: u64,
    hasher: &mut Sha256,
) -> Result<(), SignatureFailure> {
    reader.seek(SeekFrom::Start(start)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!("cannot seek in MSIX signed view: {error}"))
    })?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while length != 0 {
        let take = usize::try_from(length.min(buffer.len() as u64)).unwrap_or(buffer.len());
        reader.read_exact(&mut buffer[..take]).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "cannot read the complete MSIX signed view: {error}"
            ))
        })?;
        hasher.update(&buffer[..take]);
        length -= take as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        APPX_HEADER, AXBM, AXCD, AXCT, AXPC, DIGEST_RECORD_LEN, P7X_HEADER, SIGNATURE_NAME,
        normalize_authenticode_cms, parse_appx_digest_header, parse_spc_indirect_data,
    };
    use crate::integrity::collect_entries;
    use crate::jar_signature::{SignatureFailure, verify_cms};
    use libarchive_oxide::Limits;

    const SIGNED_MSIX: &[u8] =
        include_bytes!("../tests/fixtures/msix_blockmap/SignedUntrustedCert.appx");

    fn signature_body() -> Vec<u8> {
        let entries = collect_entries(Cursor::new(SIGNED_MSIX), Limits::safe(), |name| {
            name == SIGNATURE_NAME
        })
        .expect("fixture entries collect");
        entries
            .into_iter()
            .find(|entry| entry.name == SIGNATURE_NAME)
            .and_then(|entry| entry.metadata_body)
            .expect("fixture P7X retained")
    }

    #[test]
    fn normalized_authenticode_content_and_signature_verify() {
        let body = signature_body();
        let cms = body.strip_prefix(P7X_HEADER).expect("PKCX header");
        let normalized = normalize_authenticode_cms(cms, Limits::safe()).expect("normalize CMS");
        parse_spc_indirect_data(&normalized.spc_der).expect("parse APPX digest header");
        let fingerprints = verify_cms(
            &normalized.encoded,
            &normalized.signed_content,
            Limits::safe(),
        )
        .expect("verify fixture signature");
        assert_eq!(fingerprints.len(), 1);
    }

    #[test]
    fn cms_signature_octet_tamper_is_rejected() {
        let body = signature_body();
        let cms = body.strip_prefix(P7X_HEADER).expect("PKCX header");
        let mut normalized =
            normalize_authenticode_cms(cms, Limits::safe()).expect("normalize CMS");
        let last = normalized.encoded.last_mut().expect("nonempty CMS");
        *last ^= 0x01;
        let failure = verify_cms(
            &normalized.encoded,
            &normalized.signed_content,
            Limits::safe(),
        )
        .expect_err("tampered signature fails");
        assert!(matches!(failure, SignatureFailure::Mismatch(_)));
    }

    #[test]
    fn truncated_spc_content_and_excess_nesting_are_typed_failures() {
        let body = signature_body();
        let cms = body.strip_prefix(P7X_HEADER).expect("PKCX header");
        let normalized = normalize_authenticode_cms(cms, Limits::safe()).expect("normalize CMS");
        let truncated = &normalized.spc_der[..normalized.spc_der.len() - 1];
        assert!(matches!(
            parse_spc_indirect_data(truncated),
            Err(SignatureFailure::InvalidMetadata(_))
        ));
        assert!(matches!(
            normalize_authenticode_cms(cms, Limits::safe().with_nesting(Some(1))),
            Err(SignatureFailure::ResourceLimit(_))
        ));
    }

    #[test]
    fn appx_digest_header_rejects_duplicate_records() {
        let mut header = APPX_HEADER.to_vec();
        for (index, name) in [AXPC, AXPC, AXCT, AXBM].into_iter().enumerate() {
            header.extend_from_slice(name);
            header.extend_from_slice(&[u8::try_from(index).expect("small index"); 32]);
        }
        assert_eq!(header.len(), APPX_HEADER.len() + 4 * DIGEST_RECORD_LEN);
        let failure = parse_appx_digest_header(&header).expect_err("duplicate AXPC fails");
        assert!(matches!(failure, SignatureFailure::InvalidMetadata(_)));

        header[APPX_HEADER.len() + DIGEST_RECORD_LEN..][..4].copy_from_slice(AXCD);
        parse_appx_digest_header(&header).expect("all four required digests");
    }
}
