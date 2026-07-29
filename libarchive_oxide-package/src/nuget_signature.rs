// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline `NuGet` package structure, integrity, and CMS signature verification.
//!
//! `NuGet` signs a canonical byte stream obtained by removing the final stored
//! `.signature.p7s` ZIP member and patching the classic EOCD counts, central
//! directory size, and central directory offset. ZIP64 packages are not
//! signable under `NuGet` signature format v1 and are rejected explicitly.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::ops::Deref as _;
use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bcder::decode::{Constructed, DecodeError, Source};
use bcder::{Ia5String, Mode, OctetString, Oid, Tag, Utf8String};
use cryptographic_message_syntax::asn1::rfc5652::{
    CertificateChoices, CertificateSet, CmsVersion, DigestAlgorithmIdentifiers,
    EncapsulatedContentInfo, IssuerAndSerialNumber, OID_CONTENT_TYPE, OID_COUNTER_SIGNATURE,
    OID_ID_DATA, OID_ID_SIGNED_DATA, OID_MESSAGE_DIGEST, SignedAttributes, UnsignedAttributes,
};
use libarchive_oxide_core::Limits;
use quick_xml::Reader;
use quick_xml::events::Event;
use ring::signature;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use x509_certificate::certificate::certificate_is_subset_of;
use x509_certificate::rfc5280::AlgorithmIdentifier;
use x509_certificate::rfc5652::Attribute;
use x509_certificate::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, X509Certificate};

use crate::integrity::{ZipVerification, collect_entries};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "nuget";
const SIGNATURE_NAME: &[u8] = b".signature.p7s";
const EOCD_MIN: usize = 22;
const EOCD_SEARCH: u64 = 65_535 + EOCD_MIN as u64;
const CENTRAL_FIXED: usize = 46;
const LOCAL_FIXED: usize = 30;
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const FLAG_UTF8: u16 = 0x0800;
const METHOD_STORE: u16 = 0;
const MAX_CMS_CERTIFICATES: usize = 64;
const MAX_COUNTERSIGNATURES: usize = 1;
const METADATA_FALLBACK: usize = 64 * 1024 * 1024;

const OID_COMMITMENT_TYPE: &str = "1.2.840.113549.1.9.16.2.16";
const OID_PROOF_OF_ORIGIN: &str = "1.2.840.113549.1.9.16.6.1";
const OID_PROOF_OF_RECEIPT: &str = "1.2.840.113549.1.9.16.6.2";
const OID_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
const OID_SERVICE_INDEX: &str = "1.3.6.1.4.1.311.84.2.1.1.1";
const OID_PACKAGE_OWNERS: &str = "1.3.6.1.4.1.311.84.2.1.1.2";
const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

#[derive(Debug)]
struct Failure {
    code: PackageFindingCode,
    detail: String,
    unsupported: bool,
}

impl Failure {
    fn invalid(code: PackageFindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            unsupported: false,
        }
    }

    fn mismatch(code: PackageFindingCode, detail: impl Into<String>) -> Self {
        Self::invalid(code, detail)
    }

    fn unsupported(code: PackageFindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            unsupported: true,
        }
    }

    fn resource(code: PackageFindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            unsupported: false,
        }
    }

    fn finding(self, path: Option<Vec<u8>>) -> PackageFinding {
        PackageFinding::new(PROFILE, path, self.code, self.detail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NuGetSignatureType {
    Author,
    Repository,
}

#[derive(Debug)]
struct SignatureEnvelope {
    hash_algorithm: DigestAlgorithm,
    expected_package_hash: Vec<u8>,
    signer_fingerprints: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
enum NuGetSignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(Vec<u8>),
}

#[derive(Clone, Debug)]
struct NuGetSignerInfo {
    sid: NuGetSignerIdentifier,
    digest_algorithm: AlgorithmIdentifier,
    signed_attributes: Option<SignedAttributes>,
    signature_algorithm: AlgorithmIdentifier,
    signature: OctetString,
    unsigned_attributes: Option<UnsignedAttributes>,
    signed_attributes_data: Option<Vec<u8>>,
}

impl NuGetSignerInfo {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(Self::from_sequence)
    }

    fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let version = CmsVersion::take_from(cons)?;
        #[allow(
            clippy::redundant_closure_for_method_calls,
            reason = "the generic method reference is not lifetime-general enough"
        )]
        let sid = match cons.take_opt_primitive_if(Tag::CTX_0, |primitive| primitive.take_all())? {
            Some(identifier) => {
                NuGetSignerIdentifier::SubjectKeyIdentifier(identifier.as_ref().to_vec())
            },
            None => NuGetSignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::take_from(
                cons,
            )?),
        };
        match (&sid, version) {
            (NuGetSignerIdentifier::SubjectKeyIdentifier(_), CmsVersion::V3)
            | (NuGetSignerIdentifier::IssuerAndSerialNumber(_), CmsVersion::V1) => {},
            _ => return Err(cons.content_err("CMS signer identifier/version mismatch")),
        }
        let digest_algorithm = AlgorithmIdentifier::take_from(cons)?;
        let signed_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
            let captured = cons.capture_all()?;
            let encoded = captured.as_slice().to_vec();
            let attributes = Constructed::decode(captured.as_slice(), Mode::Der, |cons| {
                SignedAttributes::take_from_set(cons)
            })
            .map_err(DecodeError::convert)?;
            Ok((attributes, encoded))
        })?;
        let (signed_attributes, signed_attributes_data) = signed_attributes
            .map_or((None, None), |(attributes, encoded)| {
                (Some(attributes), Some(encoded))
            });
        let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
        let signature = OctetString::take_from(cons)?;
        let unsigned_attributes =
            cons.take_opt_constructed_if(Tag::CTX_1, UnsignedAttributes::take_from_set)?;
        Ok(Self {
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
            unsigned_attributes,
            signed_attributes_data,
        })
    }

    fn signed_attributes_digested_content(&self) -> Option<Vec<u8>> {
        let content = self.signed_attributes_data.as_ref()?;
        let mut encoded = Vec::with_capacity(content.len().saturating_add(8));
        encoded.push(0x31);
        encode_der_length(content.len(), &mut encoded);
        encoded.extend_from_slice(content);
        Some(encoded)
    }
}

#[derive(Debug)]
struct NuGetSignedData {
    content_info: EncapsulatedContentInfo,
    certificates: Option<CertificateSet>,
    signer_infos: Vec<NuGetSignerInfo>,
}

impl NuGetSignedData {
    fn decode_der(data: &[u8]) -> Result<Self, DecodeError<std::convert::Infallible>> {
        Constructed::decode(data, Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                let content_type = Oid::take_from(cons)?;
                if content_type != OID_ID_SIGNED_DATA {
                    return Err(cons.content_err("expected signed-data content type"));
                }
                cons.take_constructed_if(Tag::CTX_0, |cons| {
                    cons.take_sequence(|cons| {
                        let _version = CmsVersion::take_from(cons)?;
                        let _digest_algorithms = DigestAlgorithmIdentifiers::take_from(cons)?;
                        let content_info = EncapsulatedContentInfo::take_from(cons)?;
                        let certificates =
                            cons.take_opt_constructed_if(Tag::CTX_0, CertificateSet::take_from)?;
                        #[allow(
                            clippy::redundant_closure_for_method_calls,
                            reason = "the generic method reference is not lifetime-general enough"
                        )]
                        let revocations =
                            cons.take_opt_constructed_if(Tag::CTX_1, |cons| cons.capture_all())?;
                        if revocations.is_some() {
                            return Err(cons.content_err(
                                "NuGet SignedData must not contain revocation-info choices",
                            ));
                        }
                        let signer_infos = cons.take_set(|cons| {
                            let mut signers = Vec::new();
                            while let Some(signer) = NuGetSignerInfo::take_opt_from(cons)? {
                                signers.push(signer);
                            }
                            Ok(signers)
                        })?;
                        Ok(Self {
                            content_info,
                            certificates,
                            signer_infos,
                        })
                    })
                })
            })
        })
    }
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

#[derive(Debug)]
struct RawZip {
    file_len: u64,
    central_offset: u64,
    central_size: u64,
    eocd_offset: u64,
    entries: Vec<RawEntry>,
}

#[derive(Debug)]
struct RawEntry {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    local_end: u64,
    central_position: u64,
    central_length: u64,
}

impl RawZip {
    fn signature(&self) -> Option<&RawEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name == SIGNATURE_NAME)
    }
}

/// Adds bounded `.nuspec` XML checks to the structure-only `NuGet` inspector.
pub(crate) fn inspect_nuspec<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
    findings: &mut Vec<PackageFinding>,
) -> bool {
    let entries = match collect_entries(reader, limits, is_root_nuspec) {
        Ok(entries) => entries,
        Err(error) => {
            findings.push(PackageFinding::new(
                PROFILE,
                None,
                if error.resource_limit {
                    PackageFindingCode::MetadataTooLarge
                } else {
                    PackageFindingCode::InvalidPackageMetadata
                },
                error.detail,
            ));
            return false;
        },
    };
    let mut manifests = entries.iter().filter(|entry| is_root_nuspec(&entry.name));
    let Some(manifest) = manifests.next() else {
        return false;
    };
    if manifests.next().is_some() {
        return false;
    }
    let Some(body) = manifest.metadata_body.as_deref() else {
        findings.push(PackageFinding::new(
            PROFILE,
            Some(manifest.name.clone()),
            PackageFindingCode::MetadataTooLarge,
            "NuGet .nuspec body was not retained inside the metadata budget",
        ));
        return false;
    };
    match validate_nuspec_xml(body, limits) {
        Ok(()) => true,
        Err(failure) => {
            findings.push(failure.finding(Some(manifest.name.clone())));
            false
        },
    }
}

/// Verifies a `NuGet` signature completely offline.
pub(crate) fn verify_nuget<R: Read + Seek>(mut reader: R, limits: Limits) -> ZipVerification {
    let raw = match parse_raw_zip(&mut reader, limits) {
        Ok(raw) => raw,
        Err(failure) => {
            let signature_validity = if failure.unsupported {
                VerificationDimension::Unsupported
            } else {
                VerificationDimension::Invalid
            };
            return ZipVerification {
                integrity: if failure.unsupported {
                    VerificationDimension::Unsupported
                } else {
                    VerificationDimension::Invalid
                },
                signature_validity,
                signer_fingerprints: Vec::new(),
                findings: vec![failure.finding(None)],
            };
        },
    };
    let Some(signature_entry) = raw.signature() else {
        return ZipVerification {
            integrity: VerificationDimension::NotPresent,
            signature_validity: VerificationDimension::NotPresent,
            signer_fingerprints: Vec::new(),
            findings: Vec::new(),
        };
    };
    let signature_body = match read_signature_body(&mut reader, signature_entry, limits) {
        Ok(body) => body,
        Err(failure) => {
            return failed_signature(failure, VerificationDimension::NotEvaluated);
        },
    };
    let envelope = match verify_signature_envelope(&signature_body, limits) {
        Ok(envelope) => envelope,
        Err(failure) => {
            return failed_signature(failure, VerificationDimension::NotEvaluated);
        },
    };
    let actual_hash =
        match canonical_package_hash(&mut reader, &raw, signature_entry, envelope.hash_algorithm) {
            Ok(hash) => hash,
            Err(failure) => {
                return ZipVerification {
                    integrity: if failure.unsupported {
                        VerificationDimension::Unsupported
                    } else {
                        VerificationDimension::Invalid
                    },
                    signature_validity: VerificationDimension::Invalid,
                    signer_fingerprints: envelope.signer_fingerprints,
                    findings: vec![failure.finding(None)],
                };
            },
        };
    if !bool::from(
        actual_hash
            .as_slice()
            .ct_eq(envelope.expected_package_hash.as_slice()),
    ) {
        return ZipVerification {
            integrity: VerificationDimension::Invalid,
            signature_validity: VerificationDimension::Invalid,
            signer_fingerprints: envelope.signer_fingerprints,
            findings: vec![PackageFinding::new(
                PROFILE,
                None,
                PackageFindingCode::IntegrityMismatch,
                "NuGet canonical package hash does not match authenticated SignatureContent",
            )],
        };
    }
    ZipVerification {
        integrity: VerificationDimension::Verified,
        signature_validity: VerificationDimension::Verified,
        signer_fingerprints: envelope.signer_fingerprints,
        findings: Vec::new(),
    }
}

fn failed_signature(failure: Failure, integrity: VerificationDimension) -> ZipVerification {
    ZipVerification {
        integrity,
        signature_validity: if failure.unsupported {
            VerificationDimension::Unsupported
        } else {
            VerificationDimension::Invalid
        },
        signer_fingerprints: Vec::new(),
        findings: vec![failure.finding(Some(SIGNATURE_NAME.to_vec()))],
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the XML state machine is kept contiguous so every event updates the same budgets"
)]
fn validate_nuspec_xml(body: &[u8], limits: Limits) -> Result<(), Failure> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Required {
        Id,
        Version,
        Authors,
        Description,
    }

    let mut xml = Reader::from_reader(body);
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut metadata_seen = false;
    let mut active: Option<(Required, usize, bool)> = None;
    let mut seen = BTreeSet::new();
    loop {
        match xml.read_event_into(&mut buffer).map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidPackageMetadata,
                format!("NuGet .nuspec XML is malformed: {error}"),
            )
        })? {
            Event::Decl(_) | Event::Comment(_) => {},
            Event::Start(element) => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    Failure::resource(
                        PackageFindingCode::MetadataTooLarge,
                        "NuGet .nuspec nesting depth overflow",
                    )
                })?;
                if limits.nesting().is_some_and(|limit| depth > limit) {
                    return Err(Failure::resource(
                        PackageFindingCode::MetadataTooLarge,
                        "NuGet .nuspec nesting exceeds configured limit",
                    ));
                }
                let name = element.name();
                let name = name.as_ref();
                match depth {
                    1 if name == b"package" && !root_seen && !root_closed => root_seen = true,
                    2 if root_seen && name == b"metadata" && !metadata_seen => metadata_seen = true,
                    3 if metadata_seen => {
                        let required = match name {
                            b"id" => Some(Required::Id),
                            b"version" => Some(Required::Version),
                            b"authors" => Some(Required::Authors),
                            b"description" => Some(Required::Description),
                            _ => None,
                        };
                        if let Some(required) = required {
                            if !seen.insert(required) {
                                return Err(Failure::invalid(
                                    PackageFindingCode::InvalidPackageMetadata,
                                    format!(
                                        "NuGet .nuspec repeats required <{}> metadata",
                                        String::from_utf8_lossy(name)
                                    ),
                                ));
                            }
                            active = Some((required, depth, false));
                        }
                    },
                    _ if depth == 1 => {
                        return Err(Failure::invalid(
                            PackageFindingCode::InvalidPackageMetadata,
                            "NuGet .nuspec root element must be <package>",
                        ));
                    },
                    _ => {},
                }
            },
            Event::Empty(element) => {
                let name = element.name();
                if matches!(
                    name.as_ref(),
                    b"id" | b"version" | b"authors" | b"description"
                ) {
                    return Err(Failure::invalid(
                        PackageFindingCode::InvalidPackageMetadata,
                        format!(
                            "NuGet .nuspec required <{}> metadata is empty",
                            String::from_utf8_lossy(name.as_ref())
                        ),
                    ));
                }
            },
            Event::Text(text) => {
                if let Some((required, required_depth, nonempty)) = active {
                    active = Some((
                        required,
                        required_depth,
                        nonempty || text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace()),
                    ));
                } else if (depth == 0 || root_closed)
                    && text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace())
                {
                    return Err(Failure::invalid(
                        PackageFindingCode::InvalidPackageMetadata,
                        "NuGet .nuspec has text outside its root element",
                    ));
                }
            },
            Event::CData(text) => {
                if let Some((required, required_depth, nonempty)) = active {
                    active = Some((
                        required,
                        required_depth,
                        nonempty || text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace()),
                    ));
                } else if (depth == 0 || root_closed)
                    && text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace())
                {
                    return Err(Failure::invalid(
                        PackageFindingCode::InvalidPackageMetadata,
                        "NuGet .nuspec has CDATA outside its root element",
                    ));
                }
            },
            Event::End(element) => {
                if let Some((_, required_depth, nonempty)) = active
                    && required_depth == depth
                {
                    if !nonempty {
                        return Err(Failure::invalid(
                            PackageFindingCode::InvalidPackageMetadata,
                            format!(
                                "NuGet .nuspec required <{}> metadata is empty",
                                String::from_utf8_lossy(element.name().as_ref())
                            ),
                        ));
                    }
                    active = None;
                }
                if depth == 1 {
                    root_closed = true;
                }
                depth = depth.checked_sub(1).ok_or_else(|| {
                    Failure::invalid(
                        PackageFindingCode::InvalidPackageMetadata,
                        "NuGet .nuspec closes more elements than it opens",
                    )
                })?;
            },
            Event::Eof => break,
            Event::PI(_) | Event::DocType(_) | Event::GeneralRef(_) => {
                return Err(Failure::invalid(
                    PackageFindingCode::InvalidPackageMetadata,
                    "NuGet .nuspec contains a processing instruction, DTD, or entity reference",
                ));
            },
        }
        buffer.clear();
    }
    if depth != 0 || !root_seen || !root_closed || !metadata_seen {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidPackageMetadata,
            "NuGet .nuspec must contain one closed <package><metadata> document",
        ));
    }
    for required in [
        Required::Id,
        Required::Version,
        Required::Authors,
        Required::Description,
    ] {
        if !seen.contains(&required) {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidPackageMetadata,
                format!("NuGet .nuspec is missing required {required:?} metadata"),
            ));
        }
    }
    Ok(())
}

fn is_root_nuspec(name: &[u8]) -> bool {
    !name.contains(&b'/') && name.ends_with(b".nuspec")
}

#[allow(
    clippy::too_many_lines,
    reason = "the classic ZIP signing view is one ordered validation transaction"
)]
fn parse_raw_zip<R: Read + Seek>(reader: &mut R, limits: Limits) -> Result<RawZip, Failure> {
    let file_len = reader.seek(SeekFrom::End(0)).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!("cannot measure NuGet ZIP length: {error}"),
        )
    })?;
    let tail_len_u64 = file_len.min(EOCD_SEARCH);
    let tail_len = usize::try_from(tail_len_u64).map_err(|_| {
        Failure::resource(
            PackageFindingCode::IntegrityResourceLimit,
            "NuGet EOCD search range exceeds address space",
        )
    })?;
    let mut tail = vec![0_u8; tail_len];
    read_exact_at(reader, file_len - tail_len_u64, &mut tail).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!("cannot read NuGet ZIP tail: {error}"),
        )
    })?;
    let eocd_in_tail = tail
        .windows(4)
        .enumerate()
        .rev()
        .find_map(|(offset, signature)| {
            if signature != b"PK\x05\x06" || tail.len().saturating_sub(offset) < EOCD_MIN {
                return None;
            }
            let comment_len = usize::from(le_u16(&tail, offset + 20));
            (offset + EOCD_MIN + comment_len == tail.len()).then_some(offset)
        })
        .ok_or_else(|| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet ZIP has no terminal end-of-central-directory record",
            )
        })?;
    let eocd_offset = file_len - tail_len_u64 + eocd_in_tail as u64;
    let eocd = &tail[eocd_in_tail..];
    if le_u16(eocd, 4) != 0 || le_u16(eocd, 6) != 0 {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            "multi-disk NuGet packages are outside signature format v1",
        ));
    }
    let on_disk = le_u16(eocd, 8);
    let count = le_u16(eocd, 10);
    let central_size32 = le_u32(eocd, 12);
    let central_offset32 = le_u32(eocd, 16);
    if on_disk != count {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet ZIP EOCD entry counts disagree",
        ));
    }
    if count == u16::MAX || central_size32 == u32::MAX || central_offset32 == u32::MAX {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            "ZIP64 is not supported by NuGet signature format v1",
        ));
    }
    if limits
        .entries()
        .is_some_and(|limit| u64::from(count) > limit)
    {
        return Err(Failure::resource(
            PackageFindingCode::IntegrityResourceLimit,
            "NuGet ZIP entry count exceeds configured limit",
        ));
    }
    let central_size = u64::from(central_size32);
    let central_offset = u64::from(central_offset32);
    if central_offset
        .checked_add(central_size)
        .is_none_or(|end| end != eocd_offset)
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet ZIP central directory does not end at the EOCD",
        ));
    }

    let metadata_limit = limits.metadata_bytes().unwrap_or(METADATA_FALLBACK);
    let mut metadata_used = 0_usize;
    let mut entries = Vec::with_capacity(usize::from(count.min(4096)));
    let mut central_position = central_offset;
    for _ in 0..count {
        let mut fixed = [0_u8; CENTRAL_FIXED];
        read_exact_at(reader, central_position, &mut fixed).map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                format!("cannot read NuGet central-directory header: {error}"),
            )
        })?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet ZIP central-directory signature is invalid",
            ));
        }
        let name_len = usize::from(le_u16(&fixed, 28));
        let extra_len = usize::from(le_u16(&fixed, 30));
        let comment_len = usize::from(le_u16(&fixed, 32));
        let variable_len = name_len
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| {
                Failure::resource(
                    PackageFindingCode::IntegrityResourceLimit,
                    "NuGet central-directory variable fields overflow",
                )
            })?;
        metadata_used = metadata_used
            .checked_add(variable_len)
            .and_then(|value| value.checked_add(std::mem::size_of::<RawEntry>()))
            .ok_or_else(|| {
                Failure::resource(
                    PackageFindingCode::IntegrityResourceLimit,
                    "NuGet central-directory metadata accounting overflow",
                )
            })?;
        if metadata_used > metadata_limit {
            return Err(Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet central-directory metadata exceeds configured limit",
            ));
        }
        let mut variable = vec![0_u8; variable_len];
        read_exact_at(
            reader,
            central_position + CENTRAL_FIXED as u64,
            &mut variable,
        )
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                format!("cannot read NuGet central-directory fields: {error}"),
            )
        })?;
        let name = variable[..name_len].to_vec();
        if limits.path_bytes().is_some_and(|limit| name.len() > limit) {
            return Err(Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet ZIP pathname exceeds configured limit",
            ));
        }
        let compressed32 = le_u32(&fixed, 20);
        let uncompressed32 = le_u32(&fixed, 24);
        let local32 = le_u32(&fixed, 42);
        if compressed32 == u32::MAX || uncompressed32 == u32::MAX || local32 == u32::MAX {
            return Err(Failure::unsupported(
                PackageFindingCode::UnsupportedIntegrityScope,
                "ZIP64 entry metadata is not supported by NuGet signature format v1",
            ));
        }
        let central_length = (CENTRAL_FIXED + variable_len) as u64;
        let mut entry = RawEntry {
            name,
            flags: le_u16(&fixed, 8),
            method: le_u16(&fixed, 10),
            crc32: le_u32(&fixed, 16),
            compressed_size: u64::from(compressed32),
            uncompressed_size: u64::from(uncompressed32),
            local_offset: u64::from(local32),
            local_end: 0,
            central_position,
            central_length,
        };
        entry.local_end = validate_local_entry(reader, &entry, central_offset)?;
        entries.push(entry);
        central_position = central_position
            .checked_add(central_length)
            .ok_or_else(|| {
                Failure::resource(
                    PackageFindingCode::IntegrityResourceLimit,
                    "NuGet central-directory offset overflow",
                )
            })?;
    }
    if central_position != eocd_offset {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet central-directory size does not match its records",
        ));
    }
    validate_raw_entries(&entries, central_offset)?;
    Ok(RawZip {
        file_len,
        central_offset,
        central_size,
        eocd_offset,
        entries,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "local/central equality checks intentionally remain adjacent and auditable"
)]
fn validate_local_entry<R: Read + Seek>(
    reader: &mut R,
    entry: &RawEntry,
    central_offset: u64,
) -> Result<u64, Failure> {
    let mut fixed = [0_u8; LOCAL_FIXED];
    read_exact_at(reader, entry.local_offset, &mut fixed).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!(
                "cannot read local header for {}: {error}",
                String::from_utf8_lossy(&entry.name)
            ),
        )
    })?;
    if &fixed[..4] != b"PK\x03\x04"
        || le_u16(&fixed, 6) != entry.flags
        || le_u16(&fixed, 8) != entry.method
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!(
                "local and central headers disagree for {}",
                String::from_utf8_lossy(&entry.name)
            ),
        ));
    }
    let name_len = usize::from(le_u16(&fixed, 26));
    let extra_len = usize::from(le_u16(&fixed, 28));
    let mut local_name = vec![0_u8; name_len];
    read_exact_at(
        reader,
        entry.local_offset + LOCAL_FIXED as u64,
        &mut local_name,
    )
    .map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!("cannot read NuGet local filename: {error}"),
        )
    })?;
    if local_name != entry.name {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet local and central filenames disagree",
        ));
    }
    if entry.flags & FLAG_DATA_DESCRIPTOR == 0
        && (le_u32(&fixed, 14) != entry.crc32
            || u64::from(le_u32(&fixed, 18)) != entry.compressed_size
            || u64::from(le_u32(&fixed, 22)) != entry.uncompressed_size)
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!(
                "local and central CRC/size fields disagree for {}",
                String::from_utf8_lossy(&entry.name)
            ),
        ));
    }
    let data_offset = entry
        .local_offset
        .checked_add(LOCAL_FIXED as u64)
        .and_then(|value| value.checked_add(name_len as u64))
        .and_then(|value| value.checked_add(extra_len as u64))
        .ok_or_else(|| {
            Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet local data offset overflow",
            )
        })?;
    let mut end = data_offset
        .checked_add(entry.compressed_size)
        .ok_or_else(|| {
            Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet local entry extent overflow",
            )
        })?;
    if entry.flags & FLAG_DATA_DESCRIPTOR != 0 {
        let mut descriptor = [0_u8; 16];
        read_exact_at(reader, end, &mut descriptor).map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                format!("cannot read NuGet data descriptor: {error}"),
            )
        })?;
        let (offset, length) = if &descriptor[..4] == b"PK\x07\x08" {
            (4, 16_u64)
        } else {
            (0, 12_u64)
        };
        if le_u32(&descriptor, offset) != entry.crc32
            || u64::from(le_u32(&descriptor, offset + 4)) != entry.compressed_size
            || u64::from(le_u32(&descriptor, offset + 8)) != entry.uncompressed_size
        {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet data descriptor disagrees with the central directory",
            ));
        }
        end = end.checked_add(length).ok_or_else(|| {
            Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet data descriptor extent overflow",
            )
        })?;
    }
    if end > central_offset {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet local entry overlaps the central directory",
        ));
    }
    Ok(end)
}

fn validate_raw_entries(entries: &[RawEntry], central_offset: u64) -> Result<(), Failure> {
    let mut names = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.clone()) {
            return Err(Failure::invalid(
                PackageFindingCode::DuplicateEntryPath,
                "NuGet ZIP repeats an exact member name",
            ));
        }
        let key = entry
            .name
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();
        if !folded.insert(key) {
            return Err(Failure::invalid(
                PackageFindingCode::DuplicateEntryPath,
                "NuGet ZIP has a case-insensitive member collision",
            ));
        }
    }
    let mut by_offset = entries.iter().collect::<Vec<_>>();
    by_offset.sort_by_key(|entry| entry.local_offset);
    for pair in by_offset.windows(2) {
        if pair[0].local_end > pair[1].local_offset {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet local entries overlap",
            ));
        }
    }
    let signature_like = entries
        .iter()
        .filter(|entry| entry.name.eq_ignore_ascii_case(SIGNATURE_NAME))
        .collect::<Vec<_>>();
    if signature_like.is_empty() {
        return Ok(());
    }
    if signature_like.len() != 1 || signature_like[0].name != SIGNATURE_NAME {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMember,
            "NuGet signature member must occur once with exact lowercase spelling",
        ));
    }
    let signature = signature_like[0];
    if signature.method != METHOD_STORE
        || signature.flags & (FLAG_UTF8 | FLAG_DATA_DESCRIPTOR) != 0
        || signature.compressed_size != signature.uncompressed_size
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMember,
            "NuGet signature member must be a classic stored, non-UTF-8 ZIP entry",
        ));
    }
    if entries
        .last()
        .is_none_or(|entry| entry.name != SIGNATURE_NAME)
        || by_offset
            .last()
            .is_none_or(|entry| entry.name != SIGNATURE_NAME)
        || signature.local_end != central_offset
        || signature
            .central_position
            .checked_add(signature.central_length)
            != Some(entries.last().map_or(signature.central_position, |entry| {
                entry.central_position + entry.central_length
            }))
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMember,
            "NuGet signature member must be the final contiguous local and central entry",
        ));
    }
    Ok(())
}

fn read_signature_body<R: Read + Seek>(
    reader: &mut R,
    entry: &RawEntry,
    limits: Limits,
) -> Result<Vec<u8>, Failure> {
    let size = usize::try_from(entry.uncompressed_size).map_err(|_| {
        Failure::resource(
            PackageFindingCode::SignatureResourceLimit,
            "NuGet signature size exceeds address space",
        )
    })?;
    let maximum = limits
        .metadata_bytes()
        .unwrap_or(METADATA_FALLBACK)
        .min(limits.in_flight_bytes().unwrap_or(usize::MAX));
    if size > maximum {
        return Err(Failure::resource(
            PackageFindingCode::SignatureResourceLimit,
            "NuGet signature exceeds configured metadata/in-flight limit",
        ));
    }
    let mut fixed = [0_u8; LOCAL_FIXED];
    read_exact_at(reader, entry.local_offset, &mut fixed).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMember,
            format!("cannot reread NuGet signature local header: {error}"),
        )
    })?;
    let data_offset = entry.local_offset
        + LOCAL_FIXED as u64
        + u64::from(le_u16(&fixed, 26))
        + u64::from(le_u16(&fixed, 28));
    let mut body = vec![0_u8; size];
    read_exact_at(reader, data_offset, &mut body).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("cannot read NuGet signature body: {error}"),
        )
    })?;
    Ok(body)
}

#[allow(
    clippy::too_many_lines,
    reason = "primary and repository countersignature constraints form one CMS envelope check"
)]
fn verify_signature_envelope(
    signature_body: &[u8],
    limits: Limits,
) -> Result<SignatureEnvelope, Failure> {
    crate::jar_signature::preflight_der(signature_body, limits).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("NuGet CMS preflight failed: {}", error.detail()),
        )
    })?;
    let raw = catch_unwind(AssertUnwindSafe(|| {
        NuGetSignedData::decode_der(signature_body)
    }))
    .map_err(|_| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS parser rejected malformed input without propagating its panic",
        )
    })?
    .map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("cannot parse NuGet CMS SignedData: {error}"),
        )
    })?;
    if raw.signer_infos.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS must contain exactly one primary signer",
        ));
    }
    let certificates = raw.certificates.as_ref().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS contains no certificates",
        )
    })?;
    if certificates.len() > MAX_CMS_CERTIFICATES {
        return Err(Failure::resource(
            PackageFindingCode::SignatureResourceLimit,
            format!(
                "NuGet CMS certificate count {} exceeds fixed limit {MAX_CMS_CERTIFICATES}",
                certificates.len()
            ),
        ));
    }
    let content = raw
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                "NuGet primary signature has no encapsulated SignatureContent",
            )
        })?
        .clone()
        .to_bytes()
        .to_vec();
    if raw.content_info.content_type != OID_ID_DATA {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            "NuGet CMS encapsulates a content type other than id-data",
        ));
    }
    let primary = raw.signer_infos.first().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS primary signer is absent",
        )
    })?;
    let primary_type = signature_type(primary)?;
    let primary_fingerprint = verify_signer(primary, &content, certificates)?;
    validate_repository_attributes(primary, primary_type)?;

    let countersignatures = countersignatures(primary)?;
    if countersignatures.len() > MAX_COUNTERSIGNATURES {
        return Err(Failure::resource(
            PackageFindingCode::SignatureResourceLimit,
            "NuGet CMS has more than one repository countersignature",
        ));
    }
    if primary_type == NuGetSignatureType::Repository && !countersignatures.is_empty() {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet repository primary signature must not have a repository countersignature",
        ));
    }
    let mut fingerprints = vec![primary_fingerprint];
    for counter in countersignatures {
        let counter_type = signature_type(&counter)?;
        if counter_type != NuGetSignatureType::Repository {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                "NuGet countersignature must be a repository signature",
            ));
        }
        validate_repository_attributes(&counter, counter_type)?;
        fingerprints.push(verify_signer(
            &counter,
            primary.signature.clone().to_bytes().as_ref(),
            certificates,
        )?);
    }
    fingerprints.sort_unstable();
    fingerprints.dedup();
    let (hash_algorithm, expected_package_hash) = parse_signature_content(&content)?;
    Ok(SignatureEnvelope {
        hash_algorithm,
        expected_package_hash,
        signer_fingerprints: fingerprints,
    })
}

fn countersignatures(primary: &NuGetSignerInfo) -> Result<Vec<NuGetSignerInfo>, Failure> {
    let mut counters = Vec::new();
    let Some(attributes) = primary.unsigned_attributes.as_ref() else {
        return Ok(counters);
    };
    for attribute in attributes.iter() {
        if attribute.typ != OID_COUNTER_SIGNATURE {
            continue;
        }
        for value in &attribute.values {
            let signer = value
                .deref()
                .clone()
                .decode(|cons| cons.take_sequence(NuGetSignerInfo::from_sequence))
                .map_err(|error| {
                    Failure::invalid(
                        PackageFindingCode::InvalidSignatureMetadata,
                        format!("NuGet repository countersignature is malformed: {error}"),
                    )
                })?;
            counters.push(signer);
        }
    }
    Ok(counters)
}

fn verify_signer(
    signer: &NuGetSignerInfo,
    content: &[u8],
    certificates: &CertificateSet,
) -> Result<[u8; 32], Failure> {
    let digest = DigestAlgorithm::try_from(&signer.digest_algorithm).map_err(|error| {
        Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            format!("NuGet CMS digest algorithm is unsupported: {error}"),
        )
    })?;
    if digest == DigestAlgorithm::Sha1 {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            "NuGet signature format v1 accepts only SHA-256, SHA-384, or SHA-512",
        ));
    }
    let signature_algorithm = SignatureAlgorithm::from_oid_and_digest_algorithm(
        &signer.signature_algorithm.algorithm,
        digest,
    )
    .map_err(|error| {
        Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            format!("NuGet CMS signature algorithm is unsupported: {error}"),
        )
    })?;
    if !matches!(
        signature_algorithm,
        SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512
    ) {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            "NuGet signature format v1 accepts only RSA with SHA-2",
        ));
    }
    let (certificate, certificate_der) = find_signer_certificate(signer, certificates)?;
    if certificate.key_algorithm() != Some(KeyAlgorithm::Rsa) {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            "NuGet signer certificate does not contain an RSA public key",
        ));
    }
    let rsa = certificate.rsa_public_key_data().map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("cannot parse NuGet signer RSA key: {error}"),
        )
    })?;
    let modulus = rsa
        .modulus
        .as_slice()
        .strip_prefix(&[0])
        .unwrap_or_else(|| rsa.modulus.as_slice());
    if !(256..=1024).contains(&modulus.len()) {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            format!(
                "NuGet signer RSA key is outside the supported 2048..=8192-bit range ({} bytes)",
                modulus.len()
            ),
        ));
    }
    let signed_attributes = signer.signed_attributes.as_ref().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS signer has no signed attributes",
        )
    })?;
    validate_content_type(signed_attributes)?;
    validate_message_digest(signed_attributes, digest, content)?;
    validate_signing_certificate_v2(signed_attributes, &certificate_der)?;

    let signed_bytes = signer.signed_attributes_digested_content().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS signer has no signed-attribute bytes",
        )
    })?;
    let verification_algorithm = signature_algorithm
        .resolve_verification_algorithm(KeyAlgorithm::Rsa)
        .map_err(|error| {
            Failure::unsupported(
                PackageFindingCode::UnsupportedSignatureAlgorithm,
                format!("cannot resolve NuGet RSA verification algorithm: {error}"),
            )
        })?;
    signature::UnparsedPublicKey::new(verification_algorithm, certificate.public_key_data())
        .verify(&signed_bytes, signer.signature.clone().to_bytes().as_ref())
        .map_err(|_| {
            Failure::mismatch(
                PackageFindingCode::SignatureMismatch,
                "NuGet CMS RSA signature verification failed",
            )
        })?;
    Ok(Sha256::digest(&certificate_der).into())
}

fn find_signer_certificate(
    signer: &NuGetSignerInfo,
    certificates: &CertificateSet,
) -> Result<(X509Certificate, Vec<u8>), Failure> {
    let mut matching_certificates = BTreeSet::<Vec<u8>>::new();
    for choice in certificates.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            return Err(Failure::unsupported(
                PackageFindingCode::UnsupportedSignatureAlgorithm,
                "NuGet CMS contains a non-X.509 certificate choice",
            ));
        };
        let certificate = X509Certificate::from((**certificate).clone());
        let identifier_matches = match &signer.sid {
            NuGetSignerIdentifier::IssuerAndSerialNumber(identifier) => certificate_is_subset_of(
                &identifier.serial_number,
                &identifier.issuer,
                certificate.serial_number_asn1(),
                certificate.issuer_name(),
            ),
            NuGetSignerIdentifier::SubjectKeyIdentifier(identifier) => {
                certificate.iter_extensions().any(|extension| {
                    if extension.id.to_string() != OID_SUBJECT_KEY_IDENTIFIER {
                        return false;
                    }
                    let encoded = extension.value.clone().into_bytes();
                    Constructed::decode(encoded.as_ref(), Mode::Der, OctetString::take_from)
                        .ok()
                        .is_some_and(|actual| actual.to_bytes().as_ref() == identifier)
                })
            },
        };
        if identifier_matches {
            let der = certificate.encode_der().map_err(|error| {
                Failure::invalid(
                    PackageFindingCode::InvalidSignatureMetadata,
                    format!("cannot DER-encode NuGet signer certificate: {error}"),
                )
            })?;
            matching_certificates.insert(der);
        }
    }
    if matching_certificates.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!(
                "NuGet CMS signer identifier resolves to {} distinct certificates",
                matching_certificates.len()
            ),
        ));
    }
    let der = matching_certificates.into_iter().next().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS signer certificate is absent",
        )
    })?;
    let certificate = X509Certificate::from_der(&der).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("cannot parse matched NuGet signer certificate: {error}"),
        )
    })?;
    Ok((certificate, der))
}

fn validate_content_type(attributes: &SignedAttributes) -> Result<(), Failure> {
    let attribute = single_attribute(attributes, OID_CONTENT_TYPE.to_string().as_str())?;
    if attribute.values.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS content-type signed attribute must have exactly one value",
        ));
    }
    let oid = attribute.values[0]
        .deref()
        .clone()
        .decode(Oid::take_from)
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                format!("NuGet CMS content-type attribute is malformed: {error}"),
            )
        })?;
    if oid != OID_ID_DATA {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            "NuGet CMS signer authenticates a content type other than id-data",
        ));
    }
    Ok(())
}

fn validate_message_digest(
    attributes: &SignedAttributes,
    digest: DigestAlgorithm,
    content: &[u8],
) -> Result<(), Failure> {
    let attribute = single_attribute(attributes, OID_MESSAGE_DIGEST.to_string().as_str())?;
    if attribute.values.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS message-digest signed attribute must have exactly one value",
        ));
    }
    let wanted = attribute.values[0]
        .deref()
        .clone()
        .decode(OctetString::take_from)
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                format!("NuGet CMS message-digest attribute is malformed: {error}"),
            )
        })?
        .to_bytes();
    let mut hasher = digest.digester();
    hasher.update(content);
    let actual = hasher.finish();
    if bool::from(wanted.as_ref().ct_eq(actual.as_ref())) {
        Ok(())
    } else {
        Err(Failure::mismatch(
            PackageFindingCode::SignatureMismatch,
            "NuGet CMS signed message-digest does not match its content",
        ))
    }
}

fn validate_signing_certificate_v2(
    attributes: &SignedAttributes,
    certificate_der: &[u8],
) -> Result<(), Failure> {
    let attribute = single_attribute(attributes, OID_SIGNING_CERTIFICATE_V2)?;
    if attribute.values.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet signing-certificate-v2 attribute must have exactly one value",
        ));
    }
    let (algorithm, wanted) = attribute.values[0]
        .deref()
        .clone()
        .decode(|cons| {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    cons.take_sequence(|cons| {
                        let algorithm = AlgorithmIdentifier::take_opt_from(cons)?;
                        let hash = OctetString::take_from(cons)?;
                        let _issuer_serial = cons.capture_all()?;
                        Ok((algorithm, hash.to_bytes().to_vec()))
                    })
                })
            })
        })
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                format!("NuGet signing-certificate-v2 attribute is malformed: {error}"),
            )
        })?;
    let digest = match algorithm {
        None => DigestAlgorithm::Sha256,
        Some(algorithm) => DigestAlgorithm::try_from(&algorithm).map_err(|error| {
            Failure::unsupported(
                PackageFindingCode::UnsupportedSignatureAlgorithm,
                format!("NuGet signing-certificate-v2 digest is unsupported: {error}"),
            )
        })?,
    };
    if digest == DigestAlgorithm::Sha1 {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedSignatureAlgorithm,
            "NuGet signing-certificate-v2 may not use SHA-1",
        ));
    }
    let mut hasher = digest.digester();
    hasher.update(certificate_der);
    let actual = hasher.finish();
    if bool::from(wanted.as_slice().ct_eq(actual.as_ref())) {
        Ok(())
    } else {
        Err(Failure::mismatch(
            PackageFindingCode::SignatureMismatch,
            "NuGet signing-certificate-v2 hash does not match the signer certificate",
        ))
    }
}

fn signature_type(signer: &NuGetSignerInfo) -> Result<NuGetSignatureType, Failure> {
    let attributes = signer.signed_attributes.as_ref().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS signer has no signed attributes",
        )
    })?;
    let attribute = single_attribute(attributes, OID_COMMITMENT_TYPE)?;
    if attribute.values.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet commitment-type-indication must have exactly one value",
        ));
    }
    let oid = attribute.values[0]
        .deref()
        .clone()
        .decode(|cons| cons.take_sequence(Oid::take_from))
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                format!("NuGet commitment-type-indication is malformed: {error}"),
            )
        })?
        .to_string();
    match oid.as_str() {
        OID_PROOF_OF_ORIGIN => Ok(NuGetSignatureType::Author),
        OID_PROOF_OF_RECEIPT => Ok(NuGetSignatureType::Repository),
        _ => Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            format!("NuGet signature has unknown commitment type {oid}"),
        )),
    }
}

fn validate_repository_attributes(
    signer: &NuGetSignerInfo,
    signature_type: NuGetSignatureType,
) -> Result<(), Failure> {
    let attributes = signer.signed_attributes.as_ref().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet CMS signer has no signed attributes",
        )
    })?;
    let service = attributes
        .iter()
        .filter(|attribute| attribute.typ.to_string() == OID_SERVICE_INDEX)
        .collect::<Vec<_>>();
    let owners = attributes
        .iter()
        .filter(|attribute| attribute.typ.to_string() == OID_PACKAGE_OWNERS)
        .collect::<Vec<_>>();
    if signature_type == NuGetSignatureType::Author {
        if !service.is_empty() || !owners.is_empty() {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                "NuGet author signature carries repository-only attributes",
            ));
        }
        return Ok(());
    }
    if service.len() != 1 || service[0].values.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet repository signature requires exactly one service-index URL",
        ));
    }
    let service_url = service[0].values[0]
        .deref()
        .clone()
        .decode(Ia5String::take_from)
        .map_err(|error| {
            Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                format!("NuGet repository service-index URL is malformed: {error}"),
            )
        })?
        .to_string();
    if !service_url.starts_with("https://")
        || service_url.len() <= "https://".len()
        || service_url.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet repository service-index URL must be an absolute HTTPS URL",
        ));
    }
    if owners.len() > 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            "NuGet repository signature repeats package-owners metadata",
        ));
    }
    if let Some(owners) = owners.first() {
        if owners.values.len() != 1 {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                "NuGet package-owners attribute must have exactly one value",
            ));
        }
        let owner_names = owners.values[0]
            .deref()
            .clone()
            .decode(|cons| {
                cons.take_sequence(|cons| {
                    let mut names = Vec::new();
                    while let Some(name) = Utf8String::take_opt_from(cons)? {
                        names.push(name.to_string());
                    }
                    Ok(names)
                })
            })
            .map_err(|error| {
                Failure::invalid(
                    PackageFindingCode::InvalidSignatureMetadata,
                    format!("NuGet package-owners metadata is malformed: {error}"),
                )
            })?;
        if owner_names.is_empty() || owner_names.iter().any(|name| name.trim().is_empty()) {
            return Err(Failure::invalid(
                PackageFindingCode::InvalidSignatureMetadata,
                "NuGet package-owners metadata must contain non-empty UTF-8 names",
            ));
        }
    }
    Ok(())
}

fn single_attribute<'a>(
    attributes: &'a SignedAttributes,
    oid: &str,
) -> Result<&'a Attribute, Failure> {
    let matches = attributes
        .iter()
        .filter(|attribute| attribute.typ.to_string() == oid)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidSignatureMetadata,
            format!("NuGet CMS requires exactly one signed attribute {oid}"),
        ));
    }
    Ok(matches[0])
}

fn parse_signature_content(content: &[u8]) -> Result<(DigestAlgorithm, Vec<u8>), Failure> {
    let text = std::str::from_utf8(content).map_err(|_| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet SignatureContent is not UTF-8",
        )
    })?;
    let mut sections = text.split("\n\n");
    if sections.next() != Some("Version:1") {
        return Err(Failure::unsupported(
            PackageFindingCode::UnsupportedIntegrityScope,
            "NuGet SignatureContent version is absent or not version 1",
        ));
    }
    let hash_line = sections.next().ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet SignatureContent has no package hash section",
        )
    })?;
    if sections.next() != Some("") || sections.next().is_some() || hash_line.contains('\n') {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet SignatureContent has trailing or malformed sections",
        ));
    }
    let (oid, encoded) = hash_line.split_once("-Hash:").ok_or_else(|| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet SignatureContent package hash property is malformed",
        )
    })?;
    let algorithm = match oid {
        "2.16.840.1.101.3.4.2.1" => DigestAlgorithm::Sha256,
        "2.16.840.1.101.3.4.2.2" => DigestAlgorithm::Sha384,
        "2.16.840.1.101.3.4.2.3" => DigestAlgorithm::Sha512,
        _ => {
            return Err(Failure::unsupported(
                PackageFindingCode::UnsupportedIntegrityAlgorithm,
                format!("NuGet SignatureContent requests unsupported hash OID {oid}"),
            ));
        },
    };
    let expected = STANDARD.decode(encoded).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            format!("NuGet SignatureContent hash is not canonical base64: {error}"),
        )
    })?;
    let expected_len = match algorithm {
        DigestAlgorithm::Sha256 => 32,
        DigestAlgorithm::Sha384 => 48,
        DigestAlgorithm::Sha512 => 64,
        DigestAlgorithm::Sha1 => 20,
    };
    if expected.len() != expected_len || STANDARD.encode(&expected) != encoded {
        return Err(Failure::invalid(
            PackageFindingCode::InvalidIntegrityMetadata,
            "NuGet SignatureContent hash has the wrong length or non-canonical base64",
        ));
    }
    Ok((algorithm, expected))
}

fn canonical_package_hash<R: Read + Seek>(
    reader: &mut R,
    raw: &RawZip,
    signature: &RawEntry,
    algorithm: DigestAlgorithm,
) -> Result<Vec<u8>, Failure> {
    let mut digest = DynamicDigest::new(algorithm)?;
    hash_range(reader, &mut digest, 0, signature.local_offset)?;
    for entry in &raw.entries {
        if entry.name != SIGNATURE_NAME {
            hash_range(
                reader,
                &mut digest,
                entry.central_position,
                entry.central_length,
            )?;
        }
    }
    hash_range(reader, &mut digest, raw.eocd_offset, 8)?;
    let count = u16::try_from(raw.entries.len().saturating_sub(1)).map_err(|_| {
        Failure::resource(
            PackageFindingCode::IntegrityResourceLimit,
            "NuGet canonical EOCD entry count does not fit u16",
        )
    })?;
    digest.update(&count.to_le_bytes());
    digest.update(&count.to_le_bytes());
    let central_size = raw
        .central_size
        .checked_sub(signature.central_length)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet canonical central-directory size underflows",
            )
        })?;
    digest.update(&central_size.to_le_bytes());
    let signature_extent = raw
        .central_offset
        .checked_sub(signature.local_offset)
        .ok_or_else(|| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet signature local extent underflows",
            )
        })?;
    let central_offset = raw
        .central_offset
        .checked_sub(signature_extent)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            Failure::invalid(
                PackageFindingCode::InvalidIntegrityMetadata,
                "NuGet canonical central-directory offset underflows",
            )
        })?;
    digest.update(&central_offset.to_le_bytes());
    let suffix_offset = raw.eocd_offset + 20;
    hash_range(
        reader,
        &mut digest,
        suffix_offset,
        raw.file_len - suffix_offset,
    )?;
    Ok(digest.finish())
}

enum DynamicDigest {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl DynamicDigest {
    fn new(algorithm: DigestAlgorithm) -> Result<Self, Failure> {
        match algorithm {
            DigestAlgorithm::Sha256 => Ok(Self::Sha256(Sha256::new())),
            DigestAlgorithm::Sha384 => Ok(Self::Sha384(Sha384::new())),
            DigestAlgorithm::Sha512 => Ok(Self::Sha512(Sha512::new())),
            DigestAlgorithm::Sha1 => Err(Failure::unsupported(
                PackageFindingCode::UnsupportedIntegrityAlgorithm,
                "SHA-1 NuGet package hashes are outside verifier policy",
            )),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(digest) => digest.update(bytes),
            Self::Sha384(digest) => digest.update(bytes),
            Self::Sha512(digest) => digest.update(bytes),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(digest) => digest.finalize().to_vec(),
            Self::Sha384(digest) => digest.finalize().to_vec(),
            Self::Sha512(digest) => digest.finalize().to_vec(),
        }
    }
}

fn hash_range<R: Read + Seek>(
    reader: &mut R,
    digest: &mut DynamicDigest,
    offset: u64,
    length: u64,
) -> Result<(), Failure> {
    reader.seek(SeekFrom::Start(offset)).map_err(|error| {
        Failure::invalid(
            PackageFindingCode::IntegrityReadFailure,
            format!("cannot seek while hashing NuGet package: {error}"),
        )
    })?;
    let mut remaining = length;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            Failure::resource(
                PackageFindingCode::IntegrityResourceLimit,
                "NuGet package hash chunk exceeds address space",
            )
        })?;
        reader.read_exact(&mut buffer[..chunk]).map_err(|error| {
            Failure::invalid(
                PackageFindingCode::IntegrityReadFailure,
                format!("cannot read while hashing NuGet package: {error}"),
            )
        })?;
        digest.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(())
}

fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> std::io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer)
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
