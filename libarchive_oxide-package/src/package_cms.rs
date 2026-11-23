// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bcder::decode::{Constructed, DecodeError, Source};
use bcder::{Captured, Mode, OctetString, Oid, Tag};
use cms::cert::CertificateChoices;
use cms::content_info::CmsVersion;
use cms::signed_data::{DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerIdentifier};
use der::{DecodeOwned, Encode};
use ring::{digest, signature};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier};
use x509_cert::Certificate;

use crate::certificate::{CertificateKey, EcdsaCurve, KeyAlgorithm};

pub(crate) const ID_DATA: &str = "1.2.840.113549.1.7.1";
pub(crate) const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub(crate) const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub(crate) const COUNTER_SIGNATURE: &str = "1.2.840.113549.1.9.6";

#[derive(Debug)]
pub(crate) struct PackageSignedData {
    pub(crate) content_info: EncapsulatedContentInfo,
    pub(crate) certificates: Option<Vec<PackageCertificate>>,
    pub(crate) signer_infos: Vec<PackageSignerInfo>,
    pub(crate) has_revocations: bool,
}

#[derive(Debug)]
pub(crate) struct PackageCertificate {
    pub(crate) choice: CertificateChoices,
    pub(crate) encoded: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct PackageSignerInfo {
    pub(crate) sid: SignerIdentifier,
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    pub(crate) signature_algorithm: AlgorithmIdentifierOwned,
    pub(crate) signature: OctetString,
    pub(crate) signed_attributes: Option<Vec<PackageAttribute>>,
    pub(crate) unsigned_attributes: Option<Vec<PackageAttribute>>,
    pub(crate) signed_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct PackageAttribute {
    pub(crate) typ: Oid,
    pub(crate) values: Vec<Captured>,
}

fn typed<T: DecodeOwned, S: Source>(cons: &mut Constructed<S>) -> Result<T, DecodeError<S::Error>> {
    T::from_der(cons.capture_one()?.as_slice()).map_err(|error| cons.content_err(error.to_string()))
}

fn values<S: Source>(cons: &mut Constructed<S>) -> Result<Vec<Captured>, DecodeError<S::Error>> {
    let mut values = Vec::new();
    loop {
        let captured = cons.capture(|item| item.skip_one().map(|_| ()))?;
        if captured.as_slice().is_empty() {
            return Ok(values);
        }
        values.push(captured);
    }
}

fn attributes<S: Source>(
    cons: &mut Constructed<S>,
) -> Result<Vec<PackageAttribute>, DecodeError<S::Error>> {
    let mut attributes = Vec::new();
    while let Some(attribute) = cons.take_opt_sequence(|item| {
        Ok(PackageAttribute {
            typ: Oid::take_from(item)?,
            values: item.take_set(values)?,
        })
    })? {
        attributes.push(attribute);
    }
    Ok(attributes)
}

impl PackageSignerInfo {
    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let version: CmsVersion = typed(cons)?;
        let sid: SignerIdentifier = typed(cons)?;
        match (&sid, version) {
            (SignerIdentifier::SubjectKeyIdentifier(_), CmsVersion::V3)
            | (SignerIdentifier::IssuerAndSerialNumber(_), CmsVersion::V1) => {},
            _ => return Err(cons.content_err("CMS signer identifier/version mismatch")),
        }
        let digest_algorithm = typed(cons)?;
        let mut signed_bytes = None;
        let signed_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |field| {
            let encoded = field.capture_all()?;
            // RFC 5652 section 5.4 signs the original attribute octets under a SET tag.
            let set = der::Any::new(der::Tag::Set, encoded.as_slice())
                .and_then(|value| value.to_der())
                .map_err(|error| field.content_err(error.to_string()))?;
            signed_bytes = Some(set);
            Constructed::decode(encoded.as_slice(), Mode::Der, attributes)
                .map_err(DecodeError::convert)
        })?;
        let signature_algorithm = typed(cons)?;
        let signature = OctetString::take_from(cons)?;
        let unsigned_attributes = cons.take_opt_constructed_if(Tag::CTX_1, attributes)?;
        Ok(Self {
            sid,
            digest_algorithm,
            signature_algorithm,
            signature,
            signed_attributes,
            unsigned_attributes,
            signed_bytes,
        })
    }
}

impl PackageSignedData {
    pub(crate) fn decode_der(data: &[u8]) -> Result<Self, DecodeError<std::convert::Infallible>> {
        Constructed::decode(data, Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                if Oid::take_from(cons)?.to_string() != "1.2.840.113549.1.7.2" {
                    return Err(cons.content_err("expected the CMS signed-data content type"));
                }
                cons.take_constructed_if(Tag::CTX_0, |wrapper| {
                    wrapper.take_sequence(|cons| {
                        let _: CmsVersion = typed(cons)?;
                        let _: DigestAlgorithmIdentifiers = typed(cons)?;
                        let content_info = typed(cons)?;
                        let certificates = cons.take_opt_constructed_if(Tag::CTX_0, |field| {
                            values(field)?
                                .iter()
                                .map(|encoded| {
                                    use der::Decode as _;
                                    let choice = CertificateChoices::from_der(encoded.as_slice())
                                        .map_err(|error| {
                                        field.content_err(error.to_string())
                                    })?;
                                    Ok(PackageCertificate {
                                        choice,
                                        encoded: encoded.as_slice().to_vec(),
                                    })
                                })
                                .collect()
                        })?;
                        let has_revocations = cons
                            .take_opt_constructed_if(Tag::CTX_1, |field| {
                                field.skip_all()?;
                                Ok(true)
                            })?
                            .unwrap_or(false);
                        let signer_infos = cons.take_set(|entries| {
                            let mut signers = Vec::new();
                            while let Some(signer) =
                                entries.take_opt_sequence(PackageSignerInfo::from_sequence)?
                            {
                                signers.push(signer);
                            }
                            Ok(signers)
                        })?;
                        Ok(Self {
                            content_info,
                            certificates,
                            signer_infos,
                            has_revocations,
                        })
                    })
                })
            })
        })
    }
}

pub(crate) fn matches_certificate(sid: &SignerIdentifier, certificate: &Certificate) -> bool {
    let tbs = &certificate.tbs_certificate;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => {
            id.serial_number == tbs.serial_number
                && id.issuer.0.iter().all(|rdn| tbs.issuer.0.contains(rdn))
        },
        SignerIdentifier::SubjectKeyIdentifier(id) => tbs
            .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, extension)| extension == *id),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub(crate) fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            SHA1 => Some(Self::Sha1),
            SHA256 => Some(Self::Sha256),
            SHA384 => Some(Self::Sha384),
            SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn digester(self) -> digest::Context {
        digest::Context::new(match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
            Self::Sha512 => &digest::SHA512,
        })
    }
}

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Clone, Copy, Debug)]
pub(crate) enum PackageSignatureAlgorithm {
    Rsa(DigestAlgorithm),
    Ecdsa(DigestAlgorithm),
    Ed25519,
}

impl PackageSignatureAlgorithm {
    pub(crate) fn from_oid(oid: ObjectIdentifier, digest: DigestAlgorithm) -> Option<Self> {
        use DigestAlgorithm::{Sha256, Sha384, Sha512};
        match oid {
            RSA => Some(Self::Rsa(digest)),
            RSA_SHA256 => Some(Self::Rsa(Sha256)),
            RSA_SHA384 => Some(Self::Rsa(Sha384)),
            RSA_SHA512 => Some(Self::Rsa(Sha512)),
            EC => Some(Self::Ecdsa(digest)),
            ECDSA_SHA256 => Some(Self::Ecdsa(Sha256)),
            ECDSA_SHA384 => Some(Self::Ecdsa(Sha384)),
            ED25519 => Some(Self::Ed25519),
            _ => None,
        }
    }

    pub(crate) fn verifier(
        self,
        certificate: &Certificate,
    ) -> Option<&'static dyn signature::VerificationAlgorithm> {
        use DigestAlgorithm::{Sha256, Sha384, Sha512};
        match (self, certificate.key_algorithm()?) {
            (Self::Rsa(Sha256), KeyAlgorithm::Rsa) => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
            (Self::Rsa(Sha384), KeyAlgorithm::Rsa) => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
            (Self::Rsa(Sha512), KeyAlgorithm::Rsa) => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
            (Self::Ecdsa(Sha256), KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)) => {
                Some(&signature::ECDSA_P256_SHA256_ASN1)
            },
            (Self::Ecdsa(Sha384), KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)) => {
                Some(&signature::ECDSA_P256_SHA384_ASN1)
            },
            (Self::Ecdsa(Sha256), KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)) => {
                Some(&signature::ECDSA_P384_SHA256_ASN1)
            },
            (Self::Ecdsa(Sha384), KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)) => {
                Some(&signature::ECDSA_P384_SHA384_ASN1)
            },
            (Self::Ed25519, KeyAlgorithm::Ed25519) => Some(&signature::ED25519),
            _ => None,
        }
    }
}
