// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded offline verification for JAR and Android APK v1 signatures.
//!
//! Signature blocks are retained inside [`Limits::metadata_bytes`], preflighted
//! as definite-length DER with finite node/depth caps, and only then handed to
//! the CMS/X.509 parser behind a panic boundary. The dependency's optional HTTP
//! feature is disabled, and trust is decided separately by the caller's pinned
//! certificate fingerprints.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cryptographic_message_syntax::{CmsError, SignedData};
use libarchive_oxide_core::Limits;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use x509_certificate::certificate::certificate_is_subset_of;
use x509_certificate::{DigestAlgorithm, SignatureAlgorithm};

use crate::integrity::{
    EntryDigest, ManifestSection, RawManifestSection, manifest_sections, manifest_sections_with_raw,
};
use crate::verification::VerificationDimension;
use crate::{PackageFinding, PackageFindingCode};

const JAR_MANIFEST: &[u8] = b"META-INF/MANIFEST.MF";
const MAX_CMS_CERTIFICATES: usize = 64;
const MAX_CMS_DER_NODES: usize = 16_384;
const MAX_CMS_NESTING: usize = 64;
const MAX_CMS_SIGNERS: usize = 16;
const MAX_SIGNATURE_BLOCKS: usize = 16;
const MAX_SIGNATURE_MEMBERS: usize = 128;
const APK_SIGNED_HEADER: &[u8] = b"X-Android-APK-Signed";
const APK_SIGNATURE_SCHEME_V2: u32 = 2;
const APK_SIGNATURE_SCHEME_V3: u32 = 3;
const MAX_ANDROID_SIGNATURE_SCHEME_ID: u32 = 2_147_483_647;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AndroidApkSchemePresence {
    v2: bool,
    v3: bool,
}

impl AndroidApkSchemePresence {
    pub(crate) const fn new(v2: bool, v3: bool) -> Self {
        Self { v2, v3 }
    }

    const fn contains(self, scheme: u32) -> bool {
        match scheme {
            APK_SIGNATURE_SCHEME_V2 => self.v2,
            APK_SIGNATURE_SCHEME_V3 => self.v3,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct JarSignatureVerification {
    pub(crate) validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureMemberKind {
    SignatureFile,
    SignatureBlock,
}

#[derive(Debug, Default)]
struct SignatureMembers<'a> {
    signature_files: Vec<&'a EntryDigest>,
    signature_blocks: Vec<&'a EntryDigest>,
}

#[derive(Debug)]
pub(crate) enum SignatureFailure {
    InvalidMetadata(String),
    Mismatch(String),
    Unsupported(String),
    ResourceLimit(String),
}

impl SignatureFailure {
    const fn code(&self) -> PackageFindingCode {
        match self {
            Self::InvalidMetadata(_) => PackageFindingCode::InvalidSignatureMetadata,
            Self::Mismatch(_) => PackageFindingCode::SignatureMismatch,
            Self::Unsupported(_) => PackageFindingCode::UnsupportedSignatureAlgorithm,
            Self::ResourceLimit(_) => PackageFindingCode::SignatureResourceLimit,
        }
    }

    pub(crate) fn detail(self) -> String {
        match self {
            Self::InvalidMetadata(detail)
            | Self::Mismatch(detail)
            | Self::Unsupported(detail)
            | Self::ResourceLimit(detail) => detail,
        }
    }
}

#[derive(Debug, Default)]
struct FailureState {
    invalid: bool,
    unsupported: bool,
}

impl FailureState {
    fn record(
        &mut self,
        profile: &'static str,
        path: Option<Vec<u8>>,
        failure: SignatureFailure,
        findings: &mut Vec<PackageFinding>,
    ) {
        match failure {
            SignatureFailure::Unsupported(_) => self.unsupported = true,
            SignatureFailure::InvalidMetadata(_)
            | SignatureFailure::Mismatch(_)
            | SignatureFailure::ResourceLimit(_) => self.invalid = true,
        }
        let code = failure.code();
        findings.push(PackageFinding::new(profile, path, code, failure.detail()));
    }
}

#[derive(Debug, Default)]
struct SignatureProgress {
    failures: FailureState,
    findings: Vec<PackageFinding>,
    fingerprints: BTreeSet<[u8; 32]>,
    authenticated_groups: Vec<AuthenticatedSignatureGroup>,
    verified_blocks: usize,
}

#[derive(Debug)]
struct AuthenticatedSignatureGroup {
    signer_base: Vec<u8>,
    whole_manifest: bool,
    covered_entries: BTreeSet<Vec<u8>>,
}

impl SignatureProgress {
    fn record(&mut self, profile: &'static str, path: Option<Vec<u8>>, failure: SignatureFailure) {
        self.failures
            .record(profile, path, failure, &mut self.findings);
    }
}

/// Whether `name` must be retained for JAR/APK v1 verification.
pub(crate) fn is_jar_signature_metadata(name: &[u8]) -> bool {
    name == JAR_MANIFEST || signature_member(name).is_some()
}

/// Whether `name` is exempt from payload coverage because it is signature metadata.
pub(crate) fn is_jar_signature_related(name: &[u8]) -> bool {
    if name == JAR_MANIFEST || signature_member(name).is_some() {
        return true;
    }
    direct_meta_inf_name(name).is_some_and(|rest| ascii_starts_with(rest, b"SIG-"))
}

pub(crate) fn verify_jar_signatures(
    entries: &[EntryDigest],
    integrity: VerificationDimension,
    profile: &'static str,
    limits: Limits,
    apk_schemes: Option<AndroidApkSchemePresence>,
) -> JarSignatureVerification {
    let (grouped, signature_member_count, signature_block_count) = group_signature_members(entries);
    if grouped.is_empty() {
        return JarSignatureVerification {
            validity: VerificationDimension::NotPresent,
            signer_fingerprints: Vec::new(),
            findings: Vec::new(),
        };
    }

    if signature_member_count > MAX_SIGNATURE_MEMBERS
        || signature_block_count > MAX_SIGNATURE_BLOCKS
    {
        return JarSignatureVerification {
            validity: VerificationDimension::Invalid,
            signer_fingerprints: Vec::new(),
            findings: vec![PackageFinding::new(
                profile,
                None,
                PackageFindingCode::SignatureResourceLimit,
                format!(
                    "JAR has {signature_member_count} signature members and \
                     {signature_block_count} CMS blocks; limits are {MAX_SIGNATURE_MEMBERS} \
                     members and {MAX_SIGNATURE_BLOCKS} blocks"
                ),
            )],
        };
    }

    let manifest = entries
        .iter()
        .find(|entry| entry.name == JAR_MANIFEST)
        .and_then(|entry| entry.metadata_body.as_deref());
    let mut progress = SignatureProgress::default();
    if manifest.is_none() {
        progress.record(
            profile,
            Some(JAR_MANIFEST.to_vec()),
            SignatureFailure::InvalidMetadata(
                "signed JAR has no retained META-INF/MANIFEST.MF body".to_string(),
            ),
        );
    }

    for (base, members) in grouped {
        verify_signature_group(
            &base,
            members,
            manifest,
            profile,
            limits,
            apk_schemes,
            &mut progress,
        );
    }
    apply_signature_coverage(entries, profile, apk_schemes.is_some(), &mut progress);
    apply_integrity_verdict(integrity, profile, &mut progress);
    let validity = if progress.failures.invalid {
        VerificationDimension::Invalid
    } else if progress.failures.unsupported {
        VerificationDimension::Unsupported
    } else if progress.verified_blocks == 0 {
        VerificationDimension::Invalid
    } else {
        VerificationDimension::Verified
    };
    JarSignatureVerification {
        validity,
        signer_fingerprints: progress.fingerprints.into_iter().collect(),
        findings: progress.findings,
    }
}

fn group_signature_members(
    entries: &[EntryDigest],
) -> (BTreeMap<Vec<u8>, SignatureMembers<'_>>, usize, usize) {
    let mut grouped = BTreeMap::<Vec<u8>, SignatureMembers<'_>>::new();
    let mut count = 0_usize;
    let mut block_count = 0_usize;
    for entry in entries {
        let Some((base, kind)) = signature_member(&entry.name) else {
            continue;
        };
        count = count.saturating_add(1);
        let members = grouped.entry(base).or_default();
        match kind {
            SignatureMemberKind::SignatureFile => members.signature_files.push(entry),
            SignatureMemberKind::SignatureBlock => {
                block_count = block_count.saturating_add(1);
                members.signature_blocks.push(entry);
            },
        }
    }
    (grouped, count, block_count)
}

fn verify_signature_group(
    base: &[u8],
    members: SignatureMembers<'_>,
    manifest: Option<&[u8]>,
    profile: &'static str,
    limits: Limits,
    apk_schemes: Option<AndroidApkSchemePresence>,
    progress: &mut SignatureProgress,
) {
    let member_label = String::from_utf8_lossy(base);
    if !valid_signer_base(base) {
        progress.record(
            profile,
            None,
            SignatureFailure::InvalidMetadata(
                "JAR signature member base name must contain 1..=8 ASCII letters, digits, \
                 hyphens, or underscores"
                    .to_string(),
            ),
        );
        return;
    }
    if members.signature_files.len() != 1 {
        progress.record(
            profile,
            None,
            SignatureFailure::InvalidMetadata(format!(
                "JAR signer {member_label} has {} .SF members; exactly one is required",
                members.signature_files.len()
            )),
        );
        return;
    }
    if members.signature_blocks.is_empty() {
        progress.record(
            profile,
            None,
            SignatureFailure::InvalidMetadata(format!(
                "JAR signer {member_label} has no matching CMS signature block"
            )),
        );
        return;
    }
    let Some(signature_file) = members.signature_files.first().copied() else {
        return;
    };
    let Some(signature_file_body) = signature_file.metadata_body.as_deref() else {
        progress.record(
            profile,
            Some(signature_file.name.clone()),
            SignatureFailure::InvalidMetadata(
                "JAR .SF body was not retained inside the metadata budget".to_string(),
            ),
        );
        return;
    };
    let signature_file_verification =
        manifest.and_then(
            |manifest| match verify_signature_file(signature_file_body, manifest) {
                Ok(verification) => Some(verification),
                Err(failure) => {
                    progress.record(profile, Some(signature_file.name.clone()), failure);
                    None
                },
            },
        );
    let mut signature_file_authenticated = false;
    for block in members.signature_blocks {
        signature_file_authenticated |=
            verify_signature_block(block, signature_file_body, profile, limits, progress);
    }
    let signature_file_valid = signature_file_verification.is_some();
    if signature_file_authenticated && let Some(verification) = signature_file_verification {
        progress
            .authenticated_groups
            .push(AuthenticatedSignatureGroup {
                signer_base: base.to_vec(),
                whole_manifest: verification.whole_manifest,
                covered_entries: verification.covered_entries,
            });
    }
    if signature_file_authenticated
        && signature_file_valid
        && let Some(apk_schemes) = apk_schemes
        && let Err(failure) = verify_apk_signature_references(signature_file_body, apk_schemes)
    {
        progress.record(profile, Some(signature_file.name.clone()), failure);
    }
}

fn apply_signature_coverage(
    entries: &[EntryDigest],
    profile: &'static str,
    require_uniform_signers: bool,
    progress: &mut SignatureProgress,
) {
    if progress.verified_blocks == 0 || progress.authenticated_groups.is_empty() {
        return;
    }
    let payload_entries = entries
        .iter()
        .filter(|entry| !entry.name.ends_with(b"/") && !is_jar_signature_related(&entry.name))
        .collect::<Vec<_>>();
    if require_uniform_signers {
        let mut missing = Vec::new();
        for group in &progress.authenticated_groups {
            for entry in &payload_entries {
                if !group.whole_manifest && !group.covered_entries.contains(&entry.name) {
                    missing.push((entry.name.clone(), group.signer_base.clone()));
                }
            }
        }
        for (name, signer_base) in missing {
            progress.record(
                profile,
                Some(name),
                SignatureFailure::Mismatch(format!(
                    "APK v1 entry is not authenticated by signer {}",
                    String::from_utf8_lossy(&signer_base)
                )),
            );
        }
        return;
    }

    if progress
        .authenticated_groups
        .iter()
        .any(|group| group.whole_manifest)
    {
        return;
    }
    let authenticated_entries = progress
        .authenticated_groups
        .iter()
        .flat_map(|group| group.covered_entries.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    for entry in payload_entries {
        if !authenticated_entries.contains(&entry.name) {
            progress.record(
                profile,
                Some(entry.name.clone()),
                SignatureFailure::Mismatch(
                    "JAR entry manifest section is not authenticated by any valid signature file"
                        .to_string(),
                ),
            );
        }
    }
}

fn verify_signature_block(
    block: &EntryDigest,
    signature_file: &[u8],
    profile: &'static str,
    limits: Limits,
    progress: &mut SignatureProgress,
) -> bool {
    let Some(block_body) = block.metadata_body.as_deref() else {
        progress.record(
            profile,
            Some(block.name.clone()),
            SignatureFailure::InvalidMetadata(
                "JAR CMS signature block was not retained inside the metadata budget".to_string(),
            ),
        );
        return false;
    };
    match verify_cms(block_body, signature_file, limits) {
        Ok(block_fingerprints) => {
            progress.verified_blocks = progress.verified_blocks.saturating_add(1);
            progress.fingerprints.extend(block_fingerprints);
            true
        },
        Err(failure) => {
            progress.record(profile, Some(block.name.clone()), failure);
            false
        },
    }
}

fn apply_integrity_verdict(
    integrity: VerificationDimension,
    profile: &'static str,
    progress: &mut SignatureProgress,
) {
    match integrity {
        VerificationDimension::Verified => {},
        VerificationDimension::Unsupported => {
            progress.failures.unsupported = true;
        },
        VerificationDimension::Invalid => progress.record(
            profile,
            None,
            SignatureFailure::Mismatch(
                "signed JAR payload or manifest integrity is invalid".to_string(),
            ),
        ),
        VerificationDimension::NotPresent | VerificationDimension::NotEvaluated => progress.record(
            profile,
            None,
            SignatureFailure::InvalidMetadata(
                "signed JAR does not provide verifiable manifest coverage".to_string(),
            ),
        ),
    }
}

#[derive(Debug)]
struct SignatureFileVerification {
    whole_manifest: bool,
    covered_entries: BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
enum SignatureDigestScope {
    WholeManifest,
    MainAttributes,
    IndividualSection,
}

impl SignatureDigestScope {
    const fn suffix(self) -> &'static [u8] {
        match self {
            Self::WholeManifest => b"-Digest-Manifest",
            Self::MainAttributes => b"-Digest-Manifest-Main-Attributes",
            Self::IndividualSection => b"-Digest",
        }
    }
}

#[derive(Debug, Default)]
struct DigestCheck {
    supported: usize,
    mismatched: bool,
    unsupported: bool,
}

fn verify_signature_file(
    signature_file: &[u8],
    manifest: &[u8],
) -> Result<SignatureFileVerification, SignatureFailure> {
    let signature_sections = manifest_sections_with_raw(signature_file).map_err(|detail| {
        SignatureFailure::InvalidMetadata(format!("JAR .SF metadata is malformed: {detail}"))
    })?;
    let manifest_sections = manifest_sections_with_raw(manifest).map_err(|detail| {
        SignatureFailure::InvalidMetadata(format!("JAR manifest metadata is malformed: {detail}"))
    })?;
    validate_signature_file_layout(&signature_sections)?;
    validate_manifest_section_layout(&manifest_sections)?;

    let whole = verify_signature_main(&signature_sections, &manifest_sections, manifest)?;
    let manifest_by_name = manifest_sections_by_name(&manifest_sections)?;
    let covered_entries =
        verify_signature_sections(&signature_sections, &manifest_by_name, manifest)?;
    let whole_manifest = whole.supported != 0 && !whole.mismatched;
    if !whole_manifest && covered_entries.is_empty() {
        return Err(if whole.supported != 0 {
            SignatureFailure::Mismatch(
                "JAR .SF whole-manifest digest does not match and no section fallback exists"
                    .to_string(),
            )
        } else {
            SignatureFailure::Unsupported(
                "JAR .SF has no supported whole-manifest or individual-section digest".to_string(),
            )
        });
    }
    Ok(SignatureFileVerification {
        whole_manifest,
        covered_entries,
    })
}

fn verify_signature_main(
    signature_sections: &[RawManifestSection],
    manifest_sections: &[RawManifestSection],
    manifest: &[u8],
) -> Result<DigestCheck, SignatureFailure> {
    let signature_main = &signature_sections
        .first()
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata("JAR .SF file has no main section".to_string())
        })?
        .attributes;
    let manifest_main_section = manifest_sections.first().ok_or_else(|| {
        SignatureFailure::InvalidMetadata("JAR manifest has no main section".to_string())
    })?;
    let manifest_main = manifest
        .get(manifest_main_section.raw.clone())
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "JAR manifest main-section byte range is invalid".to_string(),
            )
        })?;
    let whole = verify_digest_attributes(
        signature_main,
        SignatureDigestScope::WholeManifest,
        manifest,
    )?;
    let main = verify_digest_attributes(
        signature_main,
        SignatureDigestScope::MainAttributes,
        manifest_main,
    )?;
    if main.mismatched {
        return Err(SignatureFailure::Mismatch(
            "JAR .SF manifest-main-attributes digest does not match".to_string(),
        ));
    }
    if main.supported == 0 && main.unsupported {
        return Err(SignatureFailure::Unsupported(
            "JAR .SF uses only unsupported manifest-main-attributes digests".to_string(),
        ));
    }
    Ok(whole)
}

fn manifest_sections_by_name(
    manifest_sections: &[RawManifestSection],
) -> Result<BTreeMap<Vec<u8>, &RawManifestSection>, SignatureFailure> {
    let mut manifest_by_name = BTreeMap::<Vec<u8>, &RawManifestSection>::new();
    for section in &manifest_sections[1..] {
        let name = section
            .attributes
            .first()
            .ok_or_else(|| {
                SignatureFailure::InvalidMetadata(
                    "JAR manifest contains an empty individual section".to_string(),
                )
            })?
            .1
            .clone();
        if manifest_by_name.insert(name.clone(), section).is_some() {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "JAR manifest repeats section {}",
                String::from_utf8_lossy(&name)
            )));
        }
    }
    Ok(manifest_by_name)
}

fn verify_signature_sections(
    signature_sections: &[RawManifestSection],
    manifest_by_name: &BTreeMap<Vec<u8>, &RawManifestSection>,
    manifest: &[u8],
) -> Result<BTreeSet<Vec<u8>>, SignatureFailure> {
    let mut covered_entries = BTreeSet::new();
    for section in &signature_sections[1..] {
        let name = section
            .attributes
            .first()
            .ok_or_else(|| {
                SignatureFailure::InvalidMetadata(
                    "JAR .SF contains an empty individual section".to_string(),
                )
            })?
            .1
            .clone();
        if !covered_entries.insert(name.clone()) {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "JAR .SF repeats section {}",
                String::from_utf8_lossy(&name)
            )));
        }
        let manifest_section = manifest_by_name.get(&name).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(format!(
                "JAR .SF names a section absent from the manifest: {}",
                String::from_utf8_lossy(&name)
            ))
        })?;
        let raw = manifest.get(manifest_section.raw.clone()).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(format!(
                "JAR manifest section range is invalid for {}",
                String::from_utf8_lossy(&name)
            ))
        })?;
        let check = verify_digest_attributes(
            &section.attributes,
            SignatureDigestScope::IndividualSection,
            raw,
        )?;
        if check.mismatched {
            return Err(SignatureFailure::Mismatch(format!(
                "JAR .SF digest does not match manifest section {}",
                String::from_utf8_lossy(&name)
            )));
        }
        if check.supported == 0 {
            return Err(if check.unsupported {
                SignatureFailure::Unsupported(format!(
                    "JAR .SF section {} uses only unsupported digest algorithms",
                    String::from_utf8_lossy(&name)
                ))
            } else {
                SignatureFailure::InvalidMetadata(format!(
                    "JAR .SF section {} contains no digest",
                    String::from_utf8_lossy(&name)
                ))
            });
        }
    }
    Ok(covered_entries)
}

fn validate_signature_file_layout(sections: &[RawManifestSection]) -> Result<(), SignatureFailure> {
    let main = sections.first().ok_or_else(|| {
        SignatureFailure::InvalidMetadata("JAR .SF file has no main section".to_string())
    })?;
    let Some((name, value)) = main.attributes.first() else {
        return Err(SignatureFailure::InvalidMetadata(
            "JAR .SF main section is empty".to_string(),
        ));
    };
    if name.as_slice() != b"Signature-Version" || !valid_version(value) {
        return Err(SignatureFailure::InvalidMetadata(
            "JAR .SF must begin with an exact `Signature-Version: number` header".to_string(),
        ));
    }
    if main
        .attributes
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"Name"))
    {
        return Err(SignatureFailure::InvalidMetadata(
            "JAR .SF main section contains a forbidden Name header".to_string(),
        ));
    }
    for section in &sections[1..] {
        let Some((name, value)) = section.attributes.first() else {
            return Err(SignatureFailure::InvalidMetadata(
                "JAR .SF contains an empty individual section".to_string(),
            ));
        };
        if name.as_slice() != b"Name" || value.is_empty() {
            return Err(SignatureFailure::InvalidMetadata(
                "JAR .SF individual section must begin with an exact non-empty Name header"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_manifest_section_layout(
    sections: &[RawManifestSection],
) -> Result<(), SignatureFailure> {
    let main = sections.first().ok_or_else(|| {
        SignatureFailure::InvalidMetadata("JAR manifest has no main section".to_string())
    })?;
    let Some((name, value)) = main.attributes.first() else {
        return Err(SignatureFailure::InvalidMetadata(
            "JAR manifest main section is empty".to_string(),
        ));
    };
    if name.as_slice() != b"Manifest-Version" || !valid_version(value) {
        return Err(SignatureFailure::InvalidMetadata(
            "JAR manifest must begin with an exact `Manifest-Version: number` header".to_string(),
        ));
    }
    for section in &sections[1..] {
        let Some((name, value)) = section.attributes.first() else {
            return Err(SignatureFailure::InvalidMetadata(
                "JAR manifest contains an empty individual section".to_string(),
            ));
        };
        if name.as_slice() != b"Name" || value.is_empty() {
            return Err(SignatureFailure::InvalidMetadata(
                "JAR manifest individual section must begin with an exact non-empty Name header"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn valid_version(value: &[u8]) -> bool {
    let mut need_digit = true;
    for byte in value {
        if byte.is_ascii_digit() {
            need_digit = false;
        } else if *byte == b'.' && !need_digit {
            need_digit = true;
        } else {
            return false;
        }
    }
    !need_digit
}

fn verify_digest_attributes(
    attributes: &ManifestSection,
    scope: SignatureDigestScope,
    authenticated_bytes: &[u8],
) -> Result<DigestCheck, SignatureFailure> {
    let mut check = DigestCheck::default();
    for (name, value) in attributes {
        let expected = if digest_header_matches(name, b"SHA-256", scope) {
            Some(Sha256::digest(authenticated_bytes).to_vec())
        } else if digest_header_matches(name, b"SHA-384", scope) {
            Some(Sha384::digest(authenticated_bytes).to_vec())
        } else if digest_header_matches(name, b"SHA-512", scope) {
            Some(Sha512::digest(authenticated_bytes).to_vec())
        } else {
            if ascii_ends_with(name, scope.suffix()) {
                check.unsupported = true;
            }
            None
        };
        let Some(expected) = expected else {
            continue;
        };
        check.supported = check.supported.saturating_add(1);
        let actual = STANDARD.decode(value).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "{} is not valid base64: {error}",
                String::from_utf8_lossy(name)
            ))
        })?;
        if actual.len() != expected.len()
            || !bool::from(actual.as_slice().ct_eq(expected.as_slice()))
        {
            check.mismatched = true;
        }
    }
    Ok(check)
}

fn digest_header_matches(name: &[u8], algorithm: &[u8], scope: SignatureDigestScope) -> bool {
    name.len() == algorithm.len().saturating_add(scope.suffix().len())
        && name
            .get(..algorithm.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(algorithm))
        && name
            .get(algorithm.len()..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(scope.suffix()))
}

fn verify_apk_signature_references(
    signature_file: &[u8],
    detected: AndroidApkSchemePresence,
) -> Result<(), SignatureFailure> {
    for scheme in required_apk_signature_schemes(signature_file)? {
        if !detected.contains(scheme) {
            return Err(SignatureFailure::Mismatch(format!(
                "authenticated JAR .SF metadata requires APK Signature Scheme v{scheme}, \
                 but that signing block was not detected; the signature may have been stripped"
            )));
        }
    }
    Ok(())
}

fn required_apk_signature_schemes(
    signature_file: &[u8],
) -> Result<BTreeSet<u32>, SignatureFailure> {
    let sections = manifest_sections(signature_file).map_err(|detail| {
        SignatureFailure::InvalidMetadata(format!("JAR .SF metadata is malformed: {detail}"))
    })?;
    let main = sections.first().ok_or_else(|| {
        SignatureFailure::InvalidMetadata("JAR .SF file has no main section".to_string())
    })?;

    let mut header_value = None;
    for (key, value) in main {
        if !key.eq_ignore_ascii_case(APK_SIGNED_HEADER) {
            continue;
        }
        if header_value.replace(value.as_slice()).is_some() {
            return Err(SignatureFailure::InvalidMetadata(
                "JAR .SF repeats the X-Android-APK-Signed header".to_string(),
            ));
        }
    }
    let Some(header_value) = header_value else {
        return Ok(BTreeSet::new());
    };

    let mut seen = BTreeSet::new();
    let mut required = BTreeSet::new();
    for raw_scheme in header_value.split(|byte| *byte == b',') {
        let scheme_text = raw_scheme.trim_ascii();
        if scheme_text.is_empty() {
            return Err(SignatureFailure::InvalidMetadata(
                "X-Android-APK-Signed contains an empty scheme id".to_string(),
            ));
        }
        if !scheme_text.iter().all(u8::is_ascii_digit) {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "X-Android-APK-Signed scheme id `{}` is not an ASCII decimal integer",
                String::from_utf8_lossy(scheme_text)
            )));
        }
        let scheme = std::str::from_utf8(scheme_text)
            .map_err(|_| {
                SignatureFailure::InvalidMetadata(
                    "X-Android-APK-Signed scheme id is not ASCII".to_string(),
                )
            })?
            .parse::<u32>()
            .map_err(|_| {
                SignatureFailure::InvalidMetadata(format!(
                    "X-Android-APK-Signed scheme id `{}` is outside the supported integer range",
                    String::from_utf8_lossy(scheme_text)
                ))
            })?;
        if scheme > MAX_ANDROID_SIGNATURE_SCHEME_ID {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "X-Android-APK-Signed scheme id `{scheme}` is outside the supported integer range"
            )));
        }
        if !seen.insert(scheme) {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "X-Android-APK-Signed repeats scheme id {scheme}"
            )));
        }
        if matches!(scheme, APK_SIGNATURE_SCHEME_V2 | APK_SIGNATURE_SCHEME_V3) {
            required.insert(scheme);
        }
    }
    Ok(required)
}

fn verify_cms(
    signature_block: &[u8],
    signature_file: &[u8],
    limits: Limits,
) -> Result<Vec<[u8; 32]>, SignatureFailure> {
    preflight_der(signature_block, limits)?;
    match catch_unwind(AssertUnwindSafe(|| {
        verify_cms_inner(signature_block, signature_file)
    })) {
        Ok(result) => result,
        Err(_) => Err(SignatureFailure::InvalidMetadata(
            "CMS parser rejected malformed input without propagating its panic".to_string(),
        )),
    }
}

pub(crate) fn preflight_der(data: &[u8], limits: Limits) -> Result<(), SignatureFailure> {
    if data.is_empty() {
        return Err(SignatureFailure::InvalidMetadata(
            "CMS signature block is empty".to_string(),
        ));
    }
    let configured_depth = limits.nesting().unwrap_or(MAX_CMS_NESTING);
    let maximum_depth = configured_depth.min(MAX_CMS_NESTING);
    let mut constructed_ends = Vec::with_capacity(maximum_depth);
    let mut cursor = 0_usize;
    let mut nodes = 0_usize;
    while cursor < data.len() {
        while constructed_ends.last().copied() == Some(cursor) {
            constructed_ends.pop();
        }
        if constructed_ends
            .last()
            .is_some_and(|container_end| cursor > *container_end)
        {
            return Err(SignatureFailure::InvalidMetadata(
                "CMS DER child extends beyond its parent".to_string(),
            ));
        }
        nodes = nodes.saturating_add(1);
        if nodes > MAX_CMS_DER_NODES {
            return Err(SignatureFailure::ResourceLimit(format!(
                "CMS DER node count exceeds the fixed limit {MAX_CMS_DER_NODES}"
            )));
        }

        let tag = parse_der_tag(data, &mut cursor)?;
        let content_length = parse_der_length(data, &mut cursor)?;
        let content_end = cursor.checked_add(content_length).ok_or_else(|| {
            SignatureFailure::ResourceLimit("CMS DER content offset overflow".to_string())
        })?;
        let parent_end = constructed_ends.last().copied().unwrap_or(data.len());
        if content_end > parent_end || content_end > data.len() {
            return Err(SignatureFailure::InvalidMetadata(
                "CMS DER content extends past its enclosing value".to_string(),
            ));
        }
        if tag & 0x20 != 0 && content_length != 0 {
            if constructed_ends.len() >= maximum_depth {
                return Err(SignatureFailure::ResourceLimit(format!(
                    "CMS DER nesting exceeds configured limit {maximum_depth}"
                )));
            }
            constructed_ends.push(content_end);
        } else {
            cursor = content_end;
        }
    }
    while constructed_ends.last().copied() == Some(cursor) {
        constructed_ends.pop();
    }
    if !constructed_ends.is_empty() {
        return Err(SignatureFailure::InvalidMetadata(
            "CMS DER constructed value ended prematurely".to_string(),
        ));
    }
    Ok(())
}

fn parse_der_tag(data: &[u8], cursor: &mut usize) -> Result<u8, SignatureFailure> {
    let tag = *data
        .get(*cursor)
        .ok_or_else(|| SignatureFailure::InvalidMetadata("CMS DER tag is truncated".to_string()))?;
    *cursor = cursor.saturating_add(1);
    if tag & 0x1f != 0x1f {
        return Ok(tag);
    }
    let mut tag_octets = 0_usize;
    loop {
        let octet = *data.get(*cursor).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "CMS DER high-tag-number form is truncated".to_string(),
            )
        })?;
        *cursor = cursor.saturating_add(1);
        tag_octets = tag_octets.saturating_add(1);
        if tag_octets > core::mem::size_of::<usize>() {
            return Err(SignatureFailure::ResourceLimit(
                "CMS DER tag number is excessively long".to_string(),
            ));
        }
        if octet & 0x80 == 0 {
            return Ok(tag);
        }
    }
}

fn parse_der_length(data: &[u8], cursor: &mut usize) -> Result<usize, SignatureFailure> {
    let first = *data.get(*cursor).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("CMS DER length is truncated".to_string())
    })?;
    *cursor = cursor.saturating_add(1);
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let length_octets = usize::from(first & 0x7f);
    if length_octets == 0 {
        return Err(SignatureFailure::Unsupported(
            "indefinite-length BER CMS is not accepted by the bounded verifier".to_string(),
        ));
    }
    if length_octets > core::mem::size_of::<usize>() {
        return Err(SignatureFailure::ResourceLimit(
            "CMS DER length does not fit in memory address space".to_string(),
        ));
    }
    let end = cursor.checked_add(length_octets).ok_or_else(|| {
        SignatureFailure::ResourceLimit("CMS DER length offset overflow".to_string())
    })?;
    let encoded = data.get(*cursor..end).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("CMS DER long-form length is truncated".to_string())
    })?;
    if encoded.first() == Some(&0) {
        return Err(SignatureFailure::InvalidMetadata(
            "CMS DER length has a non-canonical leading zero".to_string(),
        ));
    }
    *cursor = end;
    encoded.iter().try_fold(0_usize, |length, octet| {
        length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*octet)))
            .ok_or_else(|| {
                SignatureFailure::ResourceLimit("CMS DER content length overflow".to_string())
            })
    })
}

fn verify_cms_inner(
    signature_block: &[u8],
    signature_file: &[u8],
) -> Result<Vec<[u8; 32]>, SignatureFailure> {
    let signed_data =
        SignedData::parse_ber(signature_block).map_err(|error| cms_failure(&error))?;
    let certificate_count = signed_data
        .certificates()
        .take(MAX_CMS_CERTIFICATES.saturating_add(1))
        .count();
    if certificate_count > MAX_CMS_CERTIFICATES {
        return Err(SignatureFailure::ResourceLimit(format!(
            "CMS certificate count {certificate_count} exceeds the fixed limit \
             {MAX_CMS_CERTIFICATES}"
        )));
    }
    let signer_count = signed_data
        .signers()
        .take(MAX_CMS_SIGNERS.saturating_add(1))
        .count();
    if signer_count == 0 {
        return Err(SignatureFailure::InvalidMetadata(
            "CMS SignedData contains no signer".to_string(),
        ));
    }
    if signer_count > MAX_CMS_SIGNERS {
        return Err(SignatureFailure::ResourceLimit(format!(
            "CMS signer count {signer_count} exceeds the fixed limit {MAX_CMS_SIGNERS}"
        )));
    }
    if signed_data
        .signed_content()
        .is_some_and(|content| content != signature_file)
    {
        return Err(SignatureFailure::Mismatch(
            "CMS encapsulated content does not match the paired JAR .SF bytes".to_string(),
        ));
    }

    let mut fingerprints = Vec::with_capacity(signer_count);
    for signer in signed_data.signers() {
        verify_signer_algorithms(signer.digest_algorithm(), signer.signature_algorithm())?;
        if signer.signed_attributes().is_some() || signed_data.signed_content().is_some() {
            signer
                .verify_signature_with_signed_data(&signed_data)
                .map_err(|error| cms_failure(&error))?;
        } else {
            signer
                .verify_signature_with_signed_data_and_content(&signed_data, signature_file)
                .map_err(|error| cms_failure(&error))?;
        }
        if signer.signed_attributes().is_some() {
            signer
                .verify_message_digest_with_content(signature_file)
                .map_err(|error| cms_failure(&error))?;
        }

        let (issuer, serial) = signer.certificate_issuer_and_serial().ok_or_else(|| {
            SignatureFailure::Unsupported(
                "CMS signer uses an unsupported certificate identifier".to_string(),
            )
        })?;
        let matching_certificates = signed_data
            .certificates()
            .filter(|certificate| {
                certificate_is_subset_of(
                    serial,
                    issuer,
                    certificate.serial_number_asn1(),
                    certificate.issuer_name(),
                )
            })
            .map(|certificate| certificate.constructed_data().to_vec())
            .collect::<BTreeSet<_>>();
        if matching_certificates.is_empty() {
            return Err(SignatureFailure::InvalidMetadata(
                "CMS signer certificate is absent from the signature block".to_string(),
            ));
        }
        if matching_certificates.len() != 1 {
            return Err(SignatureFailure::InvalidMetadata(
                "CMS signer identifier ambiguously matches multiple distinct certificates"
                    .to_string(),
            ));
        }
        let certificate = matching_certificates.into_iter().next().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "CMS signer certificate resolution unexpectedly produced no certificate"
                    .to_string(),
            )
        })?;
        fingerprints.push(Sha256::digest(&certificate).into());
    }
    Ok(fingerprints)
}

fn verify_signer_algorithms(
    digest: DigestAlgorithm,
    signature: SignatureAlgorithm,
) -> Result<(), SignatureFailure> {
    if digest == DigestAlgorithm::Sha1 {
        return Err(SignatureFailure::Unsupported(
            "SHA-1 CMS content digests are outside the verifier policy".to_string(),
        ));
    }
    match signature {
        SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::EcdsaSha384
        | SignatureAlgorithm::Ed25519 => Ok(()),
        SignatureAlgorithm::RsaSha1 | SignatureAlgorithm::NoSignature(_) => {
            Err(SignatureFailure::Unsupported(format!(
                "CMS signature algorithm {signature:?} is outside the verifier policy"
            )))
        },
    }
}

fn cms_failure(error: &CmsError) -> SignatureFailure {
    match error {
        CmsError::UnknownKeyAlgorithm(_)
        | CmsError::UnknownDigestAlgorithm(_)
        | CmsError::UnknownSignatureAlgorithm(_)
        | CmsError::SubjectKeyIdentifierUnsupported
        | CmsError::X509Certificate(_) => {
            SignatureFailure::Unsupported(format!("unsupported CMS algorithm or key: {error}"))
        },
        CmsError::SignatureVerificationError | CmsError::DigestNotEqual => {
            SignatureFailure::Mismatch(format!("CMS signature verification failed: {error}"))
        },
        _ => SignatureFailure::InvalidMetadata(format!("invalid CMS signature metadata: {error}")),
    }
}

fn signature_member(name: &[u8]) -> Option<(Vec<u8>, SignatureMemberKind)> {
    let rest = direct_meta_inf_name(name)?;
    let (suffix, kind) = [
        (b".SF".as_slice(), SignatureMemberKind::SignatureFile),
        (b".RSA".as_slice(), SignatureMemberKind::SignatureBlock),
        (b".DSA".as_slice(), SignatureMemberKind::SignatureBlock),
        (b".EC".as_slice(), SignatureMemberKind::SignatureBlock),
    ]
    .into_iter()
    .find(|(suffix, _)| ascii_ends_with(rest, suffix))?;
    let stem_length = rest.len().checked_sub(suffix.len())?;
    let stem = rest.get(..stem_length)?;
    Some((stem.iter().map(u8::to_ascii_uppercase).collect(), kind))
}

fn valid_signer_base(base: &[u8]) -> bool {
    (1..=8).contains(&base.len())
        && base
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn direct_meta_inf_name(name: &[u8]) -> Option<&[u8]> {
    name.strip_prefix(b"META-INF/")
        .filter(|rest| !rest.is_empty() && !rest.contains(&b'/'))
}

fn ascii_ends_with(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len()
        && value
            .get(value.len() - suffix.len()..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn ascii_starts_with(value: &[u8], prefix: &[u8]) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod apk_anti_strip_tests {
    use super::{APK_SIGNATURE_SCHEME_V2, SignatureFailure, required_apk_signature_schemes};

    fn signature_file(header: &str) -> Vec<u8> {
        format!("Signature-Version: 1.0\r\n{header}\r\n\r\n").into_bytes()
    }

    fn assert_invalid_header(header: &str) {
        assert!(matches!(
            required_apk_signature_schemes(&signature_file(header)),
            Err(SignatureFailure::InvalidMetadata(_))
        ));
    }

    #[test]
    fn apk_signed_header_requires_known_schemes_and_ignores_unknown_ones() {
        let required =
            required_apk_signature_schemes(&signature_file("x-android-apk-signed: 15, 2, 34"));
        assert!(matches!(
            required,
            Ok(schemes)
                if schemes.len() == 1 && schemes.contains(&APK_SIGNATURE_SCHEME_V2)
        ));
    }

    #[test]
    fn apk_signed_header_rejects_empty_non_decimal_out_of_range_and_duplicate_ids() {
        for value in [
            "X-Android-APK-Signed: ",
            "X-Android-APK-Signed: 2,,3",
            "X-Android-APK-Signed: v2",
            "X-Android-APK-Signed: 2147483648",
            "X-Android-APK-Signed: 2,02",
        ] {
            assert_invalid_header(value);
        }
    }

    #[test]
    fn apk_signed_header_is_case_insensitive_and_must_be_unique() {
        let signature_file = b"Signature-Version: 1.0\r\n\
            X-Android-APK-Signed: 2\r\n\
            x-android-apk-signed: 3\r\n\r\n";
        assert!(matches!(
            required_apk_signature_schemes(signature_file),
            Err(SignatureFailure::InvalidMetadata(_))
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        AuthenticatedSignatureGroup, SignatureFailure, SignatureProgress, apply_signature_coverage,
        group_signature_members, preflight_der, valid_signer_base, verify_signature_file,
        verify_signer_algorithms,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use libarchive_oxide_core::Limits;
    use sha2::{Digest, Sha256};
    use x509_certificate::{DigestAlgorithm, SignatureAlgorithm};

    use crate::integrity::EntryDigest;

    const MANIFEST_MAIN: &[u8] =
        b"Manifest-Version: 1.0\r\nCreated-By: libarchive-oxide tests\r\n\r\n";
    const MANIFEST_ALPHA: &[u8] = b"Name: alpha.txt\r\nSHA-256-Digest: payload-placeholder\r\n\r\n";
    const MANIFEST_BETA: &[u8] = b"Name: beta.txt\r\nSHA-256-Digest: another-placeholder\r\n\r\n";

    fn sha256_base64(bytes: &[u8]) -> String {
        STANDARD.encode(Sha256::digest(bytes))
    }

    fn test_manifest() -> Vec<u8> {
        [MANIFEST_MAIN, MANIFEST_ALPHA, MANIFEST_BETA].concat()
    }

    fn entry(name: &[u8]) -> EntryDigest {
        EntryDigest {
            name: name.to_vec(),
            size: 0,
            sha256: Vec::new(),
            sha384: Vec::new(),
            sha512: Vec::new(),
            metadata_body: None,
        }
    }

    #[test]
    fn der_preflight_enforces_configured_nesting() {
        let nested_sequence = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        let error = preflight_der(&nested_sequence, Limits::safe().with_nesting(Some(1)));
        assert!(matches!(error, Err(SignatureFailure::ResourceLimit(_))));
        assert!(preflight_der(&nested_sequence, Limits::safe().with_nesting(Some(2))).is_ok());
    }

    #[test]
    fn der_preflight_rejects_unbounded_or_truncated_encodings() {
        let indefinite = preflight_der(&[0x30, 0x80, 0x00, 0x00], Limits::safe());
        assert!(matches!(indefinite, Err(SignatureFailure::Unsupported(_))));

        let truncated = preflight_der(&[0x30, 0x04, 0x02, 0x01], Limits::safe());
        assert!(matches!(
            truncated,
            Err(SignatureFailure::InvalidMetadata(_))
        ));
    }

    #[test]
    fn cms_algorithm_policy_rejects_sha1() {
        assert!(matches!(
            verify_signer_algorithms(DigestAlgorithm::Sha1, SignatureAlgorithm::RsaSha1),
            Err(SignatureFailure::Unsupported(_))
        ));
        assert!(
            verify_signer_algorithms(DigestAlgorithm::Sha256, SignatureAlgorithm::RsaSha256)
                .is_ok()
        );
    }

    #[test]
    fn signature_file_falls_back_to_folded_individual_section_digests() {
        let manifest = test_manifest();
        let alpha = sha256_base64(MANIFEST_ALPHA);
        let beta = sha256_base64(MANIFEST_BETA);
        let (alpha_head, alpha_tail) = alpha.split_at(20);
        let signature_file = format!(
            "Signature-Version: 1.0\r\n\
             SHA-256-Digest-Manifest: {}\r\n\r\n\
             Name: alpha.txt\r\n\
             SHA-256-Digest: {alpha_head}\r\n {alpha_tail}\r\n\r\n\
             Name: beta.txt\r\n\
             SHA-256-Digest: {beta}\r\n\r\n",
            sha256_base64(b"deliberately wrong whole-manifest digest")
        );

        let result = verify_signature_file(signature_file.as_bytes(), &manifest);
        assert!(matches!(
            result,
            Ok(verified)
                if !verified.whole_manifest
                    && verified.covered_entries.contains(b"alpha.txt".as_slice())
                    && verified.covered_entries.contains(b"beta.txt".as_slice())
        ));
    }

    #[test]
    fn signature_file_validates_main_attributes_over_exact_crlf_bytes() {
        let manifest = test_manifest();
        let correct = format!(
            "Signature-Version: 1.0\r\n\
             SHA-256-Digest-Manifest: {}\r\n\
             SHA-256-Digest-Manifest-Main-Attributes: {}\r\n\r\n",
            sha256_base64(&manifest),
            sha256_base64(MANIFEST_MAIN)
        );
        assert!(matches!(
            verify_signature_file(correct.as_bytes(), &manifest),
            Ok(verified) if verified.whole_manifest
        ));

        let wrong_main = format!(
            "Signature-Version: 1.0\r\n\
             SHA-256-Digest-Manifest: {}\r\n\
             SHA-256-Digest-Manifest-Main-Attributes: {}\r\n\r\n",
            sha256_base64(&manifest),
            sha256_base64(b"same logical headers, different canonical bytes")
        );
        assert!(matches!(
            verify_signature_file(wrong_main.as_bytes(), &manifest),
            Err(SignatureFailure::Mismatch(_))
        ));
    }

    #[test]
    fn signature_file_accepts_spec_line_endings_but_rejects_case_duplicate_headers() {
        let manifest = b"Manifest-Version: 1.0\n\nName: alpha.txt\n\
            SHA-256-Digest: payload-placeholder\n\n";
        let signature_file = format!(
            "Signature-Version: 1.0\rSHA-256-Digest-Manifest: {}\r\r",
            sha256_base64(manifest)
        );
        assert!(verify_signature_file(signature_file.as_bytes(), manifest).is_ok());

        let duplicate = format!(
            "Signature-Version: 1.0\r\n\
             SHA-256-Digest-Manifest: {}\r\n\
             sha-256-digest-manifest: {}\r\n\r\n",
            sha256_base64(manifest),
            sha256_base64(manifest)
        );
        assert!(matches!(
            verify_signature_file(duplicate.as_bytes(), manifest),
            Err(SignatureFailure::InvalidMetadata(_))
        ));
    }

    #[test]
    fn apk_v1_requires_every_authenticated_signer_to_cover_every_entry() {
        let entries = [entry(b"alpha.txt"), entry(b"beta.txt")];
        let mut jar_progress = SignatureProgress {
            verified_blocks: 2,
            authenticated_groups: vec![
                AuthenticatedSignatureGroup {
                    signer_base: b"ALPHA".to_vec(),
                    whole_manifest: false,
                    covered_entries: BTreeSet::from([b"alpha.txt".to_vec()]),
                },
                AuthenticatedSignatureGroup {
                    signer_base: b"BETA".to_vec(),
                    whole_manifest: false,
                    covered_entries: BTreeSet::from([b"beta.txt".to_vec()]),
                },
            ],
            ..SignatureProgress::default()
        };
        apply_signature_coverage(&entries, "jar", false, &mut jar_progress);
        assert!(!jar_progress.failures.invalid);

        let mut apk_progress = jar_progress;
        apply_signature_coverage(&entries, "android-apk", true, &mut apk_progress);
        assert!(apk_progress.failures.invalid);
        assert_eq!(apk_progress.findings.len(), 2);
    }

    #[test]
    fn signer_member_names_are_canonicalized_without_hiding_ambiguities() {
        assert!(valid_signer_base(b"A_1-Z"));
        assert!(!valid_signer_base(b""));
        assert!(!valid_signer_base(b"123456789"));
        assert!(!valid_signer_base(b"A.B"));
        assert!(!valid_signer_base(&[0xff]));

        let entries = [
            entry(b"META-INF/signer.SF"),
            entry(b"META-INF/SIGNER.sf"),
            entry(b"META-INF/Signer.RSA"),
        ];
        let (groups, members, blocks) = group_signature_members(&entries);
        assert_eq!(members, 3);
        assert_eq!(blocks, 1);
        assert!(matches!(
            groups.get(b"SIGNER".as_slice()),
            Some(group) if group.signature_files.len() == 2 && group.signature_blocks.len() == 1
        ));
    }
}
