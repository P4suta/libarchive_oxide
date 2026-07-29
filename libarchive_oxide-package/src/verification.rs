// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Separation between structure inspection, integrity, signature validity, and trust.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

use libarchive_oxide_core::Limits;

use crate::alpine_signature::{AlpineRsaPublicKey, verify_alpine};
use crate::android_signature::{AndroidRotationEvidence, verify_android_apk_v2_v3};
use crate::android_v4_signature::{
    AndroidApkV4Revision, AndroidV4Verification, verify_android_apk_v4,
};
use crate::integrity::{verify_android_apk_v1, verify_zip};
use crate::msix_blockmap::verify_msix_block_map;
use crate::{
    AlpineApkValidation, AlpineApkValidator, AppPackageProfile, AppPackageValidation,
    AppPackageValidator, DebValidation, DebValidator, PackageFinding, RpmValidation, RpmValidator,
    SupportStatus, ZipPackageProfile, ZipPackageValidation, ZipPackageValidator,
};

/// State of one independent verification dimension.
///
/// `NotEvaluated` is deliberately distinct from success. A detected signature
/// container is not a cryptographically valid signature until a format-specific
/// verifier has checked its signed bytes and algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerificationDimension {
    /// The dimension was fully checked and passed.
    Verified,
    /// The dimension was fully checked and failed.
    Invalid,
    /// The package carries no value for this dimension.
    NotPresent,
    /// The current verifier did not evaluate this dimension.
    NotEvaluated,
    /// The package requests a scheme this build cannot verify.
    Unsupported,
}

/// Result of the optional, explicitly supplied Android APK v4/v4.1 sidecar.
///
/// This report is nested under [`VerificationReport`] only for the
/// `android-apk` profile. Absence is represented by `NotEvaluated`, not by
/// success or failure, because `.idsig` is an optional detached input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidApkV4Report {
    revision: Option<AndroidApkV4Revision>,
    integrity: VerificationDimension,
    signature_validity: VerificationDimension,
    trust: VerificationDimension,
    signer_fingerprints: Vec<[u8; 32]>,
    findings: Vec<PackageFinding>,
}

/// Verified APK Signature Scheme v3 proof-of-rotation and targeted signer layout.
///
/// This is cryptographic evidence carried by authenticated v3/v3.1 signed-data.
/// It does not make an issuer-trust decision; [`VerificationReport::trust`]
/// remains the sole trust-policy verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidApkRotationReport {
    v31_present: bool,
    rotation_min_sdk: Option<u32>,
    targets_dev_release: bool,
    signers: Vec<AndroidApkTargetedSignerReport>,
    lineage: Vec<AndroidApkLineageLevelReport>,
}

impl AndroidApkRotationReport {
    fn from_evidence(evidence: AndroidRotationEvidence) -> Self {
        Self {
            v31_present: evidence.v31_present,
            rotation_min_sdk: evidence.rotation_min_sdk,
            targets_dev_release: evidence.targets_dev_release,
            signers: evidence
                .signers
                .into_iter()
                .map(|signer| AndroidApkTargetedSignerReport {
                    scheme: signer.scheme,
                    minimum_sdk: signer.minimum_sdk,
                    maximum_sdk: signer.maximum_sdk,
                    fingerprint: signer.fingerprint,
                    lineage_levels: signer.lineage_levels,
                    targets_dev_release: signer.targets_dev_release,
                })
                .collect(),
            lineage: evidence
                .lineage
                .into_iter()
                .map(|level| AndroidApkLineageLevelReport {
                    fingerprint: level.fingerprint,
                    flags: level.flags,
                    signed_signature_algorithm_id: level.signed_signature_algorithm_id,
                    next_signature_algorithm_id: level.next_signature_algorithm_id,
                })
                .collect(),
        }
    }

    /// Whether the APK contains a verified v3.1 targeted-rotation block.
    #[must_use]
    pub const fn v31_present(&self) -> bool {
        self.v31_present
    }

    /// Authenticated minimum SDK at which the v3.1 signer is selected.
    #[must_use]
    pub const fn rotation_min_sdk(&self) -> Option<u32> {
        self.rotation_min_sdk
    }

    /// Whether the selected v3.1 boundary targets an Android development release.
    #[must_use]
    pub const fn targets_dev_release(&self) -> bool {
        self.targets_dev_release
    }

    /// Authenticated v3/v3.1 signer SDK ranges in ascending order.
    #[must_use]
    pub fn signers(&self) -> &[AndroidApkTargetedSignerReport] {
        &self.signers
    }

    /// Longest verified certificate lineage, oldest certificate first.
    #[must_use]
    pub fn lineage(&self) -> &[AndroidApkLineageLevelReport] {
        &self.lineage
    }
}

/// One authenticated SDK-targeted APK v3 or v3.1 signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidApkTargetedSignerReport {
    scheme: &'static str,
    minimum_sdk: u32,
    maximum_sdk: u32,
    fingerprint: [u8; 32],
    lineage_levels: usize,
    targets_dev_release: bool,
}

impl AndroidApkTargetedSignerReport {
    /// APK signing scheme label (`v3` or `v3.1`).
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        self.scheme
    }

    /// Inclusive authenticated minimum Android SDK.
    #[must_use]
    pub const fn minimum_sdk(&self) -> u32 {
        self.minimum_sdk
    }

    /// Inclusive authenticated maximum Android SDK.
    #[must_use]
    pub const fn maximum_sdk(&self) -> u32 {
        self.maximum_sdk
    }

    /// SHA-256 fingerprint of the exact DER signer certificate.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Number of certificates in this signer's verified effective lineage.
    #[must_use]
    pub const fn lineage_levels(&self) -> usize {
        self.lineage_levels
    }

    /// Whether this signer targets a development-release boundary.
    #[must_use]
    pub const fn targets_dev_release(&self) -> bool {
        self.targets_dev_release
    }
}

/// One certificate level in a verified APK v3 proof-of-rotation lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidApkLineageLevelReport {
    fingerprint: [u8; 32],
    flags: u32,
    signed_signature_algorithm_id: u32,
    next_signature_algorithm_id: u32,
}

impl AndroidApkLineageLevelReport {
    /// SHA-256 fingerprint of the exact DER certificate.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Authenticated proof-of-rotation capability flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Algorithm ID asserted inside this level's signed-data.
    #[must_use]
    pub const fn signed_signature_algorithm_id(&self) -> u32 {
        self.signed_signature_algorithm_id
    }

    /// Algorithm ID this certificate selected for its descendant, or zero at the terminal level.
    #[must_use]
    pub const fn next_signature_algorithm_id(&self) -> u32 {
        self.next_signature_algorithm_id
    }
}

impl AndroidApkV4Report {
    fn not_provided() -> Self {
        Self {
            revision: None,
            integrity: VerificationDimension::NotEvaluated,
            signature_validity: VerificationDimension::NotEvaluated,
            trust: VerificationDimension::NotEvaluated,
            signer_fingerprints: Vec::new(),
            findings: vec![PackageFinding::new(
                "android-apk",
                None,
                crate::PackageFindingCode::SignatureSidecarNotProvided,
                "optional APK v4 .idsig sidecar was not supplied",
            )],
        }
    }

    fn from_verification(verified: AndroidV4Verification, trust: VerificationDimension) -> Self {
        Self {
            revision: verified.revision,
            integrity: verified.integrity,
            signature_validity: verified.signature_validity,
            trust,
            signer_fingerprints: verified.signer_fingerprints,
            findings: verified.findings,
        }
    }

    /// Detected v4.0/v4.1 signing-info layout, once the sidecar parsed.
    #[must_use]
    pub const fn revision(&self) -> Option<AndroidApkV4Revision> {
        self.revision
    }

    /// APK-wide Merkle root and optional serialized-tree verdict.
    #[must_use]
    pub const fn integrity(&self) -> VerificationDimension {
        self.integrity
    }

    /// Every sidecar signature plus v2/v3 identity/digest binding verdict.
    #[must_use]
    pub const fn signature_validity(&self) -> VerificationDimension {
        self.signature_validity
    }

    /// Caller-supplied offline trust-policy verdict for all v4 signers.
    #[must_use]
    pub const fn trust(&self) -> VerificationDimension {
        self.trust
    }

    /// SHA-256 fingerprints of exact DER signer certificates.
    #[must_use]
    pub fn signer_fingerprints(&self) -> &[[u8; 32]] {
        &self.signer_fingerprints
    }

    /// Sidecar-specific typed findings.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }
}

impl VerificationDimension {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Invalid => "invalid",
            Self::NotPresent => "not-present",
            Self::NotEvaluated => "not-evaluated",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Explicit offline issuer-trust policy.
///
/// Signers are identified by caller-supplied SHA-256 fingerprints of their
/// canonical signer material: DER certificates for CMS or PKCS#1 DER public
/// keys for Alpine APK v2. The policy never fetches certificates, revocation
/// data, transparency records, or keys. When a package has multiple verified
/// signers, every signer must have an explicit pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustPolicy {
    trusted_signers: BTreeSet<Vec<u8>>,
    allow_unsigned: bool,
}

impl TrustPolicy {
    /// Creates a deny-by-default, offline policy.
    #[must_use]
    pub const fn offline() -> Self {
        Self {
            trusted_signers: BTreeSet::new(),
            allow_unsigned: false,
        }
    }

    /// Adds one exact SHA-256 pin of trusted canonical signer material.
    #[must_use]
    pub fn with_trusted_issuer(mut self, fingerprint: impl Into<Vec<u8>>) -> Self {
        self.trusted_signers.insert(fingerprint.into());
        self
    }

    /// Adds one fixed-width SHA-256 pin of trusted canonical signer material.
    #[must_use]
    pub fn with_trusted_signer_sha256(mut self, fingerprint: [u8; 32]) -> Self {
        self.trusted_signers.insert(fingerprint.to_vec());
        self
    }

    /// Controls whether an explicitly unsigned package may satisfy trust policy.
    #[must_use]
    pub const fn with_allow_unsigned(mut self, allow: bool) -> Self {
        self.allow_unsigned = allow;
        self
    }

    /// Whether a canonical signer's SHA-256 fingerprint is an explicit trust pin.
    #[must_use]
    pub fn trusts(&self, fingerprint: &[u8]) -> bool {
        self.trusted_signers.contains(fingerprint)
    }

    /// Whether this policy accepts packages proven to be unsigned.
    #[must_use]
    pub const fn allows_unsigned(&self) -> bool {
        self.allow_unsigned
    }
}

/// Result whose four verdicts cannot be conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    structure: SupportStatus,
    integrity: VerificationDimension,
    signature_validity: VerificationDimension,
    trust: VerificationDimension,
    signer_fingerprints: Vec<[u8; 32]>,
    findings: Vec<PackageFinding>,
    android_apk_rotation: Option<AndroidApkRotationReport>,
    android_apk_v4: Option<AndroidApkV4Report>,
}

impl VerificationReport {
    fn structural(
        structure: SupportStatus,
        integrity: VerificationDimension,
        signature_validity: VerificationDimension,
        trust: VerificationDimension,
        findings: &[PackageFinding],
    ) -> Self {
        Self {
            structure,
            integrity,
            signature_validity,
            trust,
            signer_fingerprints: Vec::new(),
            findings: findings.to_vec(),
            android_apk_rotation: None,
            android_apk_v4: None,
        }
    }

    fn with_signer_fingerprints(mut self, signer_fingerprints: Vec<[u8; 32]>) -> Self {
        self.signer_fingerprints = signer_fingerprints;
        self
    }

    fn with_android_apk_v4(mut self, report: AndroidApkV4Report) -> Self {
        self.findings.retain(|finding| {
            finding.code() != crate::PackageFindingCode::SignatureSidecarNotProvided
        });
        self.findings.extend(report.findings.iter().cloned());
        self.android_apk_v4 = Some(report);
        self
    }

    fn with_android_apk_rotation(mut self, report: Option<AndroidApkRotationReport>) -> Self {
        self.android_apk_rotation = report;
        self
    }

    /// Outer-container readability and ecosystem-profile conformance.
    #[must_use]
    pub const fn structure(&self) -> SupportStatus {
        self.structure
    }

    /// Payload digest/checksum verdict.
    #[must_use]
    pub const fn integrity(&self) -> VerificationDimension {
        self.integrity
    }

    /// Cryptographic signature-validity verdict.
    #[must_use]
    pub const fn signature_validity(&self) -> VerificationDimension {
        self.signature_validity
    }

    /// Issuer trust-policy verdict, independent of signature validity.
    #[must_use]
    pub const fn trust(&self) -> VerificationDimension {
        self.trust
    }

    /// SHA-256 fingerprints of canonical signer material whose signature was
    /// cryptographically verified.
    ///
    /// These bytes identify signers; they do not imply that a signer is trusted.
    /// [`TrustPolicy`] compares them only against caller-supplied offline roots.
    #[must_use]
    pub fn signer_fingerprints(&self) -> &[[u8; 32]] {
        &self.signer_fingerprints
    }

    /// Typed structural, integrity, signature, and resource findings.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Verified Android APK v3 rotation evidence, when a lineage or v3.1 block is present.
    ///
    /// This remains separate from [`Self::trust`]: a valid ancestor-to-descendant
    /// rotation proof does not implicitly trust any certificate.
    #[must_use]
    pub const fn android_apk_rotation(&self) -> Option<&AndroidApkRotationReport> {
        self.android_apk_rotation.as_ref()
    }

    /// Optional Android APK v4/v4.1 sidecar result.
    ///
    /// Android reports always return `Some`; other package profiles return
    /// `None`. A caller that did not supply a sidecar observes independent
    /// `NotEvaluated` dimensions here.
    #[must_use]
    pub const fn android_apk_v4(&self) -> Option<&AndroidApkV4Report> {
        self.android_apk_v4.as_ref()
    }

    /// Whether any finding carries `code`.
    #[must_use]
    pub fn has_code(&self, code: crate::PackageFindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code() == code)
    }
}

/// Structure-only package inspector.
#[derive(Debug, Default, Clone, Copy)]
pub struct PackageInspector;

impl PackageInspector {
    /// Inspects an Alpine APK v2 package without evaluating signature bytes.
    pub fn alpine_apk<R: Read>(reader: R) -> AlpineApkValidation {
        AlpineApkValidator::new().validate(reader)
    }

    /// Inspects a Debian package without evaluating signatures or issuer trust.
    pub fn deb<R: Read>(reader: R) -> DebValidation {
        DebValidator::new().validate(reader)
    }

    /// Inspects an RPM package without evaluating signatures or issuer trust.
    pub fn rpm<R: Read>(reader: R) -> RpmValidation {
        RpmValidator::new().validate(reader)
    }

    /// Inspects a ZIP-container profile without evaluating signatures or issuer trust.
    pub fn zip<R: Read + Seek>(profile: ZipPackageProfile, reader: R) -> ZipPackageValidation {
        ZipPackageValidator::new(profile).validate(reader)
    }

    /// Inspects an OS/application ZIP profile and reports signature containers
    /// only as detected metadata.
    pub fn app<R: Read + Seek>(profile: AppPackageProfile, reader: R) -> AppPackageValidation {
        AppPackageValidator::new(profile).validate(reader)
    }
}

/// Offline package verifier with an explicit issuer-trust policy.
///
/// JAR and Android APK v1 adapters verify bounded CMS signatures. Android APK
/// v2/v3 verifies the signing block and streamed whole-file content digests.
/// APK v4/v4.1 additionally verifies an explicitly supplied detached sidecar;
/// no API locates one implicitly.
/// Alpine APK v2 verifies exact compressed-control-member RSA signatures with
/// explicitly supplied public keys. No verifier performs network access.
#[derive(Debug, Clone)]
pub struct PackageVerifier {
    trust_policy: TrustPolicy,
    limits: Limits,
    alpine_rsa_keys: BTreeMap<Vec<u8>, AlpineRsaPublicKey>,
}

impl PackageVerifier {
    /// Creates a verifier with the supplied offline trust policy.
    #[must_use]
    pub const fn new(trust_policy: TrustPolicy) -> Self {
        Self {
            trust_policy,
            limits: Limits::safe(),
            alpine_rsa_keys: BTreeMap::new(),
        }
    }

    /// Returns the policy used for issuer decisions.
    #[must_use]
    pub const fn trust_policy(&self) -> &TrustPolicy {
        &self.trust_policy
    }

    /// Replaces all structure, decode, metadata, and integrity budgets.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Resource limits shared by inspection and integrity passes.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Adds or replaces one offline Alpine APK v2 RSA verification key.
    ///
    /// Supplying a key enables signature-validity checks but does not trust the
    /// signer. Pin [`AlpineRsaPublicKey::fingerprint_sha256`] separately in the
    /// [`TrustPolicy`] when that issuer should satisfy trust.
    #[must_use]
    pub fn with_alpine_rsa_public_key(mut self, key: AlpineRsaPublicKey) -> Self {
        self.alpine_rsa_keys.insert(key.key_id().to_vec(), key);
        self
    }

    fn trust_verdict(
        &self,
        signature_validity: VerificationDimension,
        signer_fingerprints: &[[u8; 32]],
    ) -> VerificationDimension {
        match signature_validity {
            VerificationDimension::Verified => {
                if !signer_fingerprints.is_empty()
                    && signer_fingerprints
                        .iter()
                        .all(|fingerprint| self.trust_policy.trusts(fingerprint))
                {
                    VerificationDimension::Verified
                } else {
                    VerificationDimension::Invalid
                }
            },
            VerificationDimension::NotPresent if self.trust_policy.allows_unsigned() => {
                VerificationDimension::Verified
            },
            VerificationDimension::Invalid
            | VerificationDimension::NotPresent
            | VerificationDimension::NotEvaluated
            | VerificationDimension::Unsupported => VerificationDimension::NotEvaluated,
        }
    }

    /// Inspects an Alpine APK v2 package and keeps signature presence distinct
    /// from signature validity and issuer trust.
    pub fn alpine_apk<R: Read>(&self, reader: R) -> VerificationReport {
        let validation = AlpineApkValidator::new()
            .with_limits(self.limits)
            .validate(reader);
        let verified = verify_alpine(&validation, &self.alpine_rsa_keys);
        let mut findings = validation.findings().to_vec();
        findings.extend(verified.findings);
        let trust = self.trust_verdict(verified.signature_validity, &verified.signer_fingerprints);
        VerificationReport::structural(
            validation.status(),
            verified.integrity,
            verified.signature_validity,
            trust,
            &findings,
        )
        .with_signer_fingerprints(verified.signer_fingerprints)
    }

    /// Inspects a Debian package and returns separated verification dimensions.
    pub fn deb<R: Read>(&self, reader: R) -> VerificationReport {
        let validation = DebValidator::new()
            .with_limits(self.limits)
            .validate(reader);
        let signature_validity = VerificationDimension::NotEvaluated;
        VerificationReport::structural(
            validation.status(),
            VerificationDimension::NotEvaluated,
            signature_validity,
            self.trust_verdict(signature_validity, &[]),
            validation.findings(),
        )
    }

    /// Inspects an RPM package and returns separated verification dimensions.
    pub fn rpm<R: Read>(&self, reader: R) -> VerificationReport {
        let validation = RpmValidator::new()
            .with_limits(self.limits)
            .validate(reader);
        let signature_validity = VerificationDimension::NotEvaluated;
        VerificationReport::structural(
            validation.status(),
            validation.integrity(),
            signature_validity,
            self.trust_verdict(signature_validity, &[]),
            validation.findings(),
        )
    }

    /// Inspects a ZIP-container package and returns separated verification dimensions.
    pub fn zip<R: Read + Seek>(
        &self,
        profile: ZipPackageProfile,
        mut reader: R,
    ) -> VerificationReport {
        let validation = ZipPackageValidator::new(profile)
            .with_limits(self.limits)
            .validate(&mut reader);
        if !validation.container_readable() || reader.seek(SeekFrom::Start(0)).is_err() {
            let signature_validity = VerificationDimension::NotEvaluated;
            return VerificationReport::structural(
                validation.status(),
                VerificationDimension::NotEvaluated,
                signature_validity,
                self.trust_verdict(signature_validity, &[]),
                validation.findings(),
            );
        }
        let verified = verify_zip(profile, reader, self.limits);
        let mut findings = validation.findings().to_vec();
        findings.extend(verified.findings);
        let trust = self.trust_verdict(verified.signature_validity, &verified.signer_fingerprints);
        VerificationReport::structural(
            validation.status(),
            verified.integrity,
            verified.signature_validity,
            trust,
            &findings,
        )
        .with_signer_fingerprints(verified.signer_fingerprints)
    }

    /// Verifies an Android APK together with a caller-supplied v4/v4.1
    /// `.idsig` byte source.
    ///
    /// The sidecar is never located implicitly: callers may pass a file,
    /// in-memory bytes (for example through [`std::io::Cursor`]), or any other
    /// [`Read`] source. Verification is offline and binds every sidecar signer
    /// to the APK's cryptographically verified v2/v3 and optional v3.1 blocks.
    pub fn android_apk_with_v4_sidecar<R: Read + Seek, S: Read>(
        &self,
        mut apk: R,
        idsig: S,
    ) -> VerificationReport {
        let mut report = self.app(AppPackageProfile::AndroidApk, &mut apk);
        let verified = verify_android_apk_v4(&mut apk, idsig, self.limits);
        let v4_trust =
            self.trust_verdict(verified.signature_validity, &verified.signer_fingerprints);
        let v4_report = AndroidApkV4Report::from_verification(verified, v4_trust);

        report.integrity = merge_verification_dimensions(report.integrity, v4_report.integrity);
        report.signature_validity =
            merge_verification_dimensions(report.signature_validity, v4_report.signature_validity);
        report.trust = merge_verification_dimensions(report.trust, v4_report.trust);
        report
            .signer_fingerprints
            .extend(v4_report.signer_fingerprints.iter().copied());
        report.signer_fingerprints.sort_unstable();
        report.signer_fingerprints.dedup();
        report.with_android_apk_v4(v4_report)
    }

    /// Inspects an application package. Every detected Android APK v1, v2, and
    /// v3 scheme is evaluated independently, then combined without allowing one
    /// valid scheme to hide another scheme's failure. APK v1 is verified as a
    /// JAR manifest + `.SF` + CMS chain; v2/v3 verify their whole-file content
    /// digests. MSIX package-file sizes and SHA-256 blocks are verified from
    /// `AppxBlockMap.xml`;
    /// `AppxSignature.p7x` remains detected but cryptographically unevaluated.
    /// This method never searches for an APK v4 sidecar; use
    /// [`Self::android_apk_with_v4_sidecar`] to supply one explicitly.
    pub fn app<R: Read + Seek>(
        &self,
        profile: AppPackageProfile,
        mut reader: R,
    ) -> VerificationReport {
        let validation = AppPackageValidator::new(profile)
            .with_limits(self.limits)
            .validate(&mut reader);

        if profile == AppPackageProfile::Msix
            && validation.container_readable()
            && reader.seek(SeekFrom::Start(0)).is_ok()
        {
            return self.verify_msix_app(&validation, reader);
        }

        if profile == AppPackageProfile::AndroidApk
            && validation.container_readable()
            && validation.signatures().apk_signing_block()
            && reader.seek(SeekFrom::Start(0)).is_ok()
        {
            return self
                .verify_android_signing_block_app(&validation, reader)
                .with_android_apk_v4(AndroidApkV4Report::not_provided());
        }

        if profile == AppPackageProfile::AndroidApk
            && validation.container_readable()
            && validation.signatures().apk_v1_metadata()
            && reader.seek(SeekFrom::Start(0)).is_ok()
        {
            return self
                .verify_android_v1_app(&validation, reader)
                .with_android_apk_v4(AndroidApkV4Report::not_provided());
        }

        let signature_validity = if validation.signatures().any() {
            VerificationDimension::NotEvaluated
        } else if matches!(
            profile,
            AppPackageProfile::AndroidApk | AppPackageProfile::Msix
        ) {
            VerificationDimension::NotPresent
        } else {
            VerificationDimension::NotEvaluated
        };
        let report = VerificationReport::structural(
            validation.status(),
            VerificationDimension::NotEvaluated,
            signature_validity,
            self.trust_verdict(signature_validity, &[]),
            validation.findings(),
        );
        if profile == AppPackageProfile::AndroidApk {
            report.with_android_apk_v4(AndroidApkV4Report::not_provided())
        } else {
            report
        }
    }

    fn verify_msix_app<R: Read + Seek>(
        &self,
        validation: &AppPackageValidation,
        reader: R,
    ) -> VerificationReport {
        let verified = verify_msix_block_map(reader, self.limits);
        let signature_validity = if validation.signatures().embedded_signature() {
            VerificationDimension::NotEvaluated
        } else {
            VerificationDimension::NotPresent
        };
        let mut findings = validation.findings().to_vec();
        findings.extend(verified.findings);
        VerificationReport::structural(
            validation.status(),
            verified.integrity,
            signature_validity,
            self.trust_verdict(signature_validity, &[]),
            &findings,
        )
    }

    fn verify_android_signing_block_app<R: Read + Seek>(
        &self,
        validation: &AppPackageValidation,
        mut reader: R,
    ) -> VerificationReport {
        let signatures = validation.signatures();
        let mut verified = verify_android_apk_v2_v3(&mut reader, self.limits);
        if signatures.apk_v1_metadata() {
            if reader.seek(SeekFrom::Start(0)).is_ok() {
                let mut v1 = verify_android_apk_v1(
                    &mut reader,
                    self.limits,
                    signatures.apk_v2(),
                    signatures.apk_v3(),
                );
                if v1.signature_validity == VerificationDimension::NotPresent {
                    v1.signature_validity = VerificationDimension::NotEvaluated;
                }
                verified.integrity =
                    merge_verification_dimensions(verified.integrity, v1.integrity);
                verified.signature_validity = merge_verification_dimensions(
                    verified.signature_validity,
                    v1.signature_validity,
                );
                verified.signer_fingerprints.extend(v1.signer_fingerprints);
                verified.signer_fingerprints.sort_unstable();
                verified.signer_fingerprints.dedup();
                verified.findings.extend(v1.findings);
            } else {
                verified.integrity = merge_verification_dimensions(
                    verified.integrity,
                    VerificationDimension::NotEvaluated,
                );
                verified.signature_validity = merge_verification_dimensions(
                    verified.signature_validity,
                    VerificationDimension::NotEvaluated,
                );
                verified.findings.push(PackageFinding::new(
                    "android-apk",
                    None,
                    crate::PackageFindingCode::IntegrityReadFailure,
                    "could not seek back to evaluate detected APK v1 signature metadata",
                ));
            }
        }
        let rotation = verified
            .rotation
            .take()
            .map(AndroidApkRotationReport::from_evidence);
        let mut findings = validation.findings().to_vec();
        findings.extend(verified.findings);
        let trust = self.trust_verdict(verified.signature_validity, &verified.signer_fingerprints);
        VerificationReport::structural(
            validation.status(),
            verified.integrity,
            verified.signature_validity,
            trust,
            &findings,
        )
        .with_signer_fingerprints(verified.signer_fingerprints)
        .with_android_apk_rotation(rotation)
    }

    fn verify_android_v1_app<R: Read + Seek>(
        &self,
        validation: &AppPackageValidation,
        reader: R,
    ) -> VerificationReport {
        let signatures = validation.signatures();
        let mut verified = verify_android_apk_v1(
            reader,
            self.limits,
            signatures.apk_v2(),
            signatures.apk_v3(),
        );
        if verified.signature_validity == VerificationDimension::NotPresent && signatures.any() {
            verified.signature_validity = VerificationDimension::NotEvaluated;
        }
        let mut findings = validation.findings().to_vec();
        findings.extend(verified.findings);
        let trust = self.trust_verdict(verified.signature_validity, &verified.signer_fingerprints);
        VerificationReport::structural(
            validation.status(),
            verified.integrity,
            verified.signature_validity,
            trust,
            &findings,
        )
        .with_signer_fingerprints(verified.signer_fingerprints)
    }
}

fn merge_verification_dimensions(
    first: VerificationDimension,
    second: VerificationDimension,
) -> VerificationDimension {
    use VerificationDimension::{Invalid, NotEvaluated, NotPresent, Unsupported, Verified};

    if first == Invalid || second == Invalid {
        Invalid
    } else if first == Unsupported || second == Unsupported {
        Unsupported
    } else if first == NotEvaluated || second == NotEvaluated {
        NotEvaluated
    } else if first == Verified || second == Verified {
        Verified
    } else {
        NotPresent
    }
}

impl Default for PackageVerifier {
    fn default() -> Self {
        Self::new(TrustPolicy::offline())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: [u8; 32] = [0x11; 32];
    const SECOND: [u8; 32] = [0x22; 32];

    #[test]
    fn every_verified_signer_requires_an_explicit_trust_pin() {
        let one_pin =
            PackageVerifier::new(TrustPolicy::offline().with_trusted_signer_sha256(FIRST));
        assert_eq!(
            one_pin.trust_verdict(VerificationDimension::Verified, &[FIRST, SECOND]),
            VerificationDimension::Invalid
        );

        let all_pins = PackageVerifier::new(
            TrustPolicy::offline()
                .with_trusted_signer_sha256(FIRST)
                .with_trusted_signer_sha256(SECOND),
        );
        assert_eq!(
            all_pins.trust_verdict(VerificationDimension::Verified, &[FIRST, SECOND]),
            VerificationDimension::Verified
        );
    }

    #[test]
    fn verified_without_a_captured_signer_never_satisfies_trust() {
        let verifier = PackageVerifier::new(TrustPolicy::offline());
        assert_eq!(
            verifier.trust_verdict(VerificationDimension::Verified, &[]),
            VerificationDimension::Invalid
        );
    }

    #[test]
    fn combined_scheme_verdict_never_hides_a_failure_or_unevaluated_scheme() {
        assert_eq!(
            merge_verification_dimensions(
                VerificationDimension::Verified,
                VerificationDimension::Invalid,
            ),
            VerificationDimension::Invalid
        );
        assert_eq!(
            merge_verification_dimensions(
                VerificationDimension::Verified,
                VerificationDimension::Unsupported,
            ),
            VerificationDimension::Unsupported
        );
        assert_eq!(
            merge_verification_dimensions(
                VerificationDimension::Verified,
                VerificationDimension::NotEvaluated,
            ),
            VerificationDimension::NotEvaluated
        );
        assert_eq!(
            merge_verification_dimensions(
                VerificationDimension::Verified,
                VerificationDimension::NotPresent,
            ),
            VerificationDimension::Verified
        );
    }
}
