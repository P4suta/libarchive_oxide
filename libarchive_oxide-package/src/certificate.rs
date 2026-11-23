// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use der::asn1::UintRef;
use der::{Decode, Encode, Sequence};
use ring::signature::{UnparsedPublicKey, VerificationAlgorithm};
use spki::ObjectIdentifier;
use x509_cert::Certificate;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyAlgorithm {
    Rsa,
    Ecdsa(EcdsaCurve),
    Ed25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EcdsaCurve {
    Secp256r1,
    Secp384r1,
}

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

pub(crate) trait CertificateKey {
    fn key_algorithm(&self) -> Option<KeyAlgorithm>;
    fn public_key_der(&self) -> der::Result<Vec<u8>>;
    fn rsa_modulus_length(&self) -> der::Result<usize>;
    fn verify_signed_data_with_algorithm(
        &self,
        data: &[u8],
        signature: &[u8],
        algorithm: &'static dyn VerificationAlgorithm,
    ) -> Result<(), ring::error::Unspecified>;
}

impl CertificateKey for Certificate {
    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        let algorithm = &self.tbs_certificate.subject_public_key_info.algorithm;
        match algorithm.oid {
            RSA => Some(KeyAlgorithm::Rsa),
            ED25519 => Some(KeyAlgorithm::Ed25519),
            EC => match algorithm
                .parameters
                .as_ref()?
                .decode_as::<ObjectIdentifier>()
                .ok()?
            {
                P256 => Some(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)),
                P384 => Some(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)),
                _ => None,
            },
            _ => None,
        }
    }

    fn public_key_der(&self) -> der::Result<Vec<u8>> {
        self.tbs_certificate.subject_public_key_info.to_der()
    }

    fn rsa_modulus_length(&self) -> der::Result<usize> {
        let public_key = &self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;
        let bytes = public_key
            .as_bytes()
            .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
        Ok(RsaPublicKey::from_der(bytes)?.modulus.as_bytes().len())
    }

    fn verify_signed_data_with_algorithm(
        &self,
        data: &[u8],
        signature: &[u8],
        algorithm: &'static dyn VerificationAlgorithm,
    ) -> Result<(), ring::error::Unspecified> {
        let key = self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(ring::error::Unspecified)?;
        UnparsedPublicKey::new(algorithm, key).verify(data, signature)
    }
}
