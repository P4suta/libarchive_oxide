// SPDX-FileCopyrightText: 2005-2026 Marko Kreen
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: ISC

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Bounded cryptographic primitives for read-only RAR interoperability.

use aes::cipher::{BlockModeDecrypt, KeyIvInit, array::Array};
use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const AES_BLOCK_BYTES: usize = 16;
const SALT_BYTES: usize = 8;
const MAX_PASSWORD_CODE_UNITS: usize = 127;
const MAX_PASSWORD_BYTES: usize = MAX_PASSWORD_CODE_UNITS * 2;
const COUNTER_BYTES: usize = 3;
const MAX_SEED_BUFFER_BYTES: usize = MAX_PASSWORD_BYTES + SALT_BYTES + COUNTER_BYTES;
const KDF_ROUNDS: u32 = 0x4_0000;
const RAR5_KEY_BYTES: usize = 32;
const RAR5_SALT_BYTES: usize = 16;
const RAR5_PASSWORD_CHECK_BYTES: usize = 8;
const RAR5_PASSWORD_CHECKSUM_BYTES: usize = 4;
const RAR5_HASH_KEY_OFFSET: u64 = 16;
const RAR5_PASSWORD_CHECK_OFFSET: u64 = 32;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Failure while validating or decrypting RAR ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The application supplied password bytes that are not valid UTF-8.
    InvalidUtf8,
    /// AES-CBC ciphertext was not an exact sequence of 16-byte blocks.
    InvalidBlockLength,
    /// The RAR5 KDF exponent cannot be represented by the PBKDF2 primitive.
    InvalidKdfExponent,
    /// The RAR5 PBKDF2 work factor exceeds the caller's finite budget.
    KdfIterationsLimit {
        /// Base PBKDF2 iteration count requested by the archive.
        requested: u64,
        /// Maximum base PBKDF2 iteration count authorized by the caller.
        maximum: u64,
    },
    /// The self-checksum on a RAR5 password-check field is invalid.
    InvalidPasswordCheck,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("RAR password is not valid UTF-8"),
            Self::InvalidBlockLength => {
                formatter.write_str("RAR AES-CBC ciphertext is not block aligned")
            },
            Self::InvalidKdfExponent => {
                formatter.write_str("RAR5 KDF exponent is not representable")
            },
            Self::KdfIterationsLimit { requested, maximum } => write!(
                formatter,
                "RAR5 KDF requests {requested} iterations, exceeding the {maximum}-iteration budget"
            ),
            Self::InvalidPasswordCheck => {
                formatter.write_str("RAR5 password check has an invalid checksum")
            },
        }
    }
}

/// A derived RAR3 AES-128 key and initialization vector.
///
/// Both values and the expanded AES key schedule used by [`decrypt_in_place`](Self::decrypt_in_place) are zeroized on drop.
/// Debug formatting never exposes either value.
pub struct Rar3Key {
    key: Zeroizing<[u8; AES_BLOCK_BYTES]>,
    iv: Zeroizing<[u8; AES_BLOCK_BYTES]>,
}

/// Derived RAR5 AES-256 and checksum-tweak keys.
///
/// Both keys and the expanded AES key schedule used during decryption are zeroized on drop.
/// Debug formatting never exposes either value.
pub struct Rar5Key {
    encryption_key: Zeroizing<[u8; RAR5_KEY_BYTES]>,
    hash_key: Zeroizing<[u8; RAR5_KEY_BYTES]>,
}

impl fmt::Debug for Rar5Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Rar5Key([REDACTED])")
    }
}

impl Rar5Key {
    /// Decrypts complete RAR5 AES-256-CBC blocks in place with the record IV.
    pub fn decrypt_in_place(
        &self,
        iv: [u8; AES_BLOCK_BYTES],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if !ciphertext.len().is_multiple_of(AES_BLOCK_BYTES) {
            return Err(Error::InvalidBlockLength);
        }
        let mut decryptor = Aes256CbcDec::new(&Array::from(*self.encryption_key), &Array::from(iv));
        for chunk in ciphertext.as_chunks_mut::<AES_BLOCK_BYTES>().0 {
            let block: &mut Array<u8, _> = chunk.into();
            decryptor.decrypt_block(block);
        }
        Ok(())
    }

    #[cfg(test)]
    fn from_test_parts(
        encryption_key: [u8; RAR5_KEY_BYTES],
        hash_key: [u8; RAR5_KEY_BYTES],
    ) -> Self {
        Self {
            encryption_key: Zeroizing::new(encryption_key),
            hash_key: Zeroizing::new(hash_key),
        }
    }

    #[cfg(test)]
    fn test_encryption_key(&self) -> [u8; RAR5_KEY_BYTES] {
        *self.encryption_key
    }

    #[cfg(test)]
    fn test_hash_key(&self) -> [u8; RAR5_KEY_BYTES] {
        *self.hash_key
    }
}

/// Derives the RAR5 AES-256 key and checksum-tweak key for one candidate.
///
/// RAR5 uses PBKDF2-HMAC-SHA256 with `2^kdf_exponent` iterations for the AES key and another derivation with 16 additional iterations for the hash key.
/// `maximum_iterations` bounds the archive-controlled base work factor before either derivation begins.
pub fn derive_rar5_key(
    password: &[u8],
    salt: [u8; RAR5_SALT_BYTES],
    kdf_exponent: u8,
    maximum_iterations: u64,
) -> Result<Rar5Key, Error> {
    let base = rar5_base_iterations(kdf_exponent, maximum_iterations)?;
    let hash_iterations = base
        .checked_add(RAR5_HASH_KEY_OFFSET)
        .and_then(|iterations| u32::try_from(iterations).ok())
        .ok_or(Error::InvalidKdfExponent)?;
    let base = u32::try_from(base).map_err(|_| Error::InvalidKdfExponent)?;

    let mut encryption_key = Zeroizing::new([0_u8; RAR5_KEY_BYTES]);
    pbkdf2_hmac::<Sha256>(password, &salt, base, encryption_key.as_mut());
    let mut hash_key = Zeroizing::new([0_u8; RAR5_KEY_BYTES]);
    pbkdf2_hmac::<Sha256>(password, &salt, hash_iterations, hash_key.as_mut());
    Ok(Rar5Key {
        encryption_key,
        hash_key,
    })
}

/// Validates and compares a RAR5 password-check field in constant time.
///
/// The final four bytes first authenticate the stored eight-byte verifier.
/// A corrupt verifier is distinct from a well-formed verifier that rejects the supplied password candidate.
pub fn rar5_password_check(
    password: &[u8],
    salt: [u8; RAR5_SALT_BYTES],
    kdf_exponent: u8,
    stored: [u8; RAR5_PASSWORD_CHECK_BYTES + RAR5_PASSWORD_CHECKSUM_BYTES],
    maximum_iterations: u64,
) -> Result<bool, Error> {
    let checksum = Sha256::digest(&stored[..RAR5_PASSWORD_CHECK_BYTES]);
    if !bool::from(
        stored[RAR5_PASSWORD_CHECK_BYTES..].ct_eq(&checksum[..RAR5_PASSWORD_CHECKSUM_BYTES]),
    ) {
        return Err(Error::InvalidPasswordCheck);
    }

    let base = rar5_base_iterations(kdf_exponent, maximum_iterations)?;
    let iterations = base
        .checked_add(RAR5_PASSWORD_CHECK_OFFSET)
        .and_then(|iterations| u32::try_from(iterations).ok())
        .ok_or(Error::InvalidKdfExponent)?;
    let mut derived = Zeroizing::new([0_u8; RAR5_KEY_BYTES]);
    pbkdf2_hmac::<Sha256>(password, &salt, iterations, derived.as_mut());
    let mut folded = Zeroizing::new([0_u8; RAR5_PASSWORD_CHECK_BYTES]);
    for (index, byte) in derived.iter().copied().enumerate() {
        folded[index % RAR5_PASSWORD_CHECK_BYTES] ^= byte;
    }
    Ok(bool::from(
        folded.as_ref().ct_eq(&stored[..RAR5_PASSWORD_CHECK_BYTES]),
    ))
}

/// Converts a raw CRC32 into the RAR5 HMAC-tweaked representation.
#[must_use]
pub fn tweak_rar5_crc32(key: &Rar5Key, crc: u32) -> u32 {
    let digest = rar5_hmac(key, &crc.to_le_bytes());
    let mut folded = [0_u8; 4];
    for (index, byte) in digest.iter().copied().enumerate() {
        folded[index % folded.len()] ^= byte;
    }
    u32::from_le_bytes(folded)
}

/// Converts a raw `BLAKE2sp` digest into the RAR5 HMAC-tweaked representation.
#[must_use]
pub fn tweak_rar5_blake2sp(key: &Rar5Key, digest: [u8; 32]) -> [u8; 32] {
    rar5_hmac(key, &digest)
}

fn rar5_base_iterations(kdf_exponent: u8, maximum_iterations: u64) -> Result<u64, Error> {
    let base = 1_u64
        .checked_shl(u32::from(kdf_exponent))
        .ok_or(Error::InvalidKdfExponent)?;
    if base > maximum_iterations {
        return Err(Error::KdfIterationsLimit {
            requested: base,
            maximum: maximum_iterations,
        });
    }
    Ok(base)
}

fn rar5_hmac(key: &Rar5Key, bytes: &[u8]) -> [u8; 32] {
    let mut padded_key = Zeroizing::new([0_u8; 64]);
    padded_key[..RAR5_KEY_BYTES].copy_from_slice(key.hash_key.as_ref());
    let mut mac = <HmacSha256 as KeyInit>::new(&Array::from(*padded_key));
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

impl fmt::Debug for Rar3Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Rar3Key([REDACTED])")
    }
}

impl Rar3Key {
    /// Decrypts complete AES-128-CBC blocks in place.
    ///
    /// The RAR container is responsible for validating the decrypted header CRC or the decompressed entry CRC.
    /// RAR3 has no independent password verifier, so successful AES processing alone does not authenticate a password candidate.
    pub fn decrypt_in_place(&self, ciphertext: &mut [u8]) -> Result<(), Error> {
        if !ciphertext.len().is_multiple_of(AES_BLOCK_BYTES) {
            return Err(Error::InvalidBlockLength);
        }
        let mut decryptor = Aes128CbcDec::new(&Array::from(*self.key), &Array::from(*self.iv));
        for chunk in ciphertext.as_chunks_mut::<AES_BLOCK_BYTES>().0 {
            let block: &mut Array<u8, _> = chunk.into();
            decryptor.decrypt_block(block);
        }
        Ok(())
    }

    #[cfg(test)]
    fn from_test_parts(key: [u8; AES_BLOCK_BYTES], iv: [u8; AES_BLOCK_BYTES]) -> Self {
        Self {
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
        }
    }

    #[cfg(test)]
    fn test_key(&self) -> [u8; AES_BLOCK_BYTES] {
        *self.key
    }

    #[cfg(test)]
    fn test_iv(&self) -> [u8; AES_BLOCK_BYTES] {
        *self.iv
    }
}

/// Derives the RAR3 AES-128 key and IV for one password candidate and salt.
///
/// Password bytes are decoded as UTF-8, converted to UTF-16LE, and truncated to the RAR limit of 127 UTF-16 code units.
/// The fixed 2^18-round work factor and all intermediate storage are bounded independently of archive input.
pub fn derive_rar3_key(
    password_utf8: &[u8],
    salt: Option<[u8; SALT_BYTES]>,
) -> Result<Rar3Key, Error> {
    let password = core::str::from_utf8(password_utf8).map_err(|_| Error::InvalidUtf8)?;
    let mut seed = Zeroizing::new([0_u8; MAX_SEED_BUFFER_BYTES]);
    let mut seed_len = 0;
    for unit in password.encode_utf16().take(MAX_PASSWORD_CODE_UNITS) {
        let bytes = unit.to_le_bytes();
        seed[seed_len..seed_len + 2].copy_from_slice(&bytes);
        seed_len += 2;
    }
    if let Some(salt) = salt {
        seed[seed_len..seed_len + SALT_BYTES].copy_from_slice(&salt);
        seed_len += SALT_BYTES;
    }

    let mut hasher = Sha1::new();
    let mut iv = Zeroizing::new([0_u8; AES_BLOCK_BYTES]);
    let mut counter = 0_u32;
    let mut hashed_bytes = 0_usize;
    for outer in 0..AES_BLOCK_BYTES {
        seed[seed_len + 2] = u8::try_from(counter >> 16).unwrap_or(u8::MAX);
        for inner in 0..0x4000 {
            let block_position = hashed_bytes & 63;
            hashed_bytes = hashed_bytes.saturating_add(seed_len + COUNTER_BYTES);
            let low = counter.to_le_bytes();
            seed[seed_len] = low[0];
            seed[seed_len + 1] = low[1];
            counter = counter.saturating_add(1);

            hasher.update(&seed[..seed_len + COUNTER_BYTES]);
            if seed_len > 64 {
                let mut position = 64 - block_position;
                while position + 64 <= seed_len {
                    corrupt_sha1_input_block(&mut seed[position..position + 64]);
                    position += 64;
                }
            }
            if inner == 0 {
                iv[outer] = hasher.clone().finalize()[19];
            }
        }
    }
    debug_assert_eq!(counter, KDF_ROUNDS);

    let digest = Zeroizing::new(hasher.finalize());
    let mut key = Zeroizing::new([0_u8; AES_BLOCK_BYTES]);
    for (destination, source) in key
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(digest[..16].as_chunks::<4>().0.iter())
    {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }
    Ok(Rar3Key { key, iv })
}

fn corrupt_sha1_input_block(block: &mut [u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut words = [0_u32; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for _ in 0..4 {
        for index in 0..16 {
            let mixed = words[(index + 13) & 15]
                ^ words[(index + 8) & 15]
                ^ words[(index + 2) & 15]
                ^ words[index];
            words[index] = mixed.rotate_left(1);
        }
    }
    for (bytes, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Error, derive_rar3_key, derive_rar5_key, rar5_password_check, tweak_rar5_blake2sp,
        tweak_rar5_crc32,
    };

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut bytes = [0_u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn rar3_kdf_matches_one_block_seed_vector() {
        let password = [b'p'; 28];
        let key = derive_rar3_key(&password, Some(decode_hex("1122334455667788"))).unwrap();
        assert_eq!(
            key.test_key(),
            decode_hex("ffff33ffaf31987c899ccc2f965a8927")
        );
        assert_eq!(
            key.test_iv(),
            decode_hex("bdff6873721b247afa4f978448a5aeef")
        );
    }

    #[test]
    fn rar3_kdf_supports_legacy_unsalted_entries() {
        let key = derive_rar3_key(b"password", None).unwrap();
        assert_eq!(
            key.test_key(),
            decode_hex("9bde0a0b8000e732fe25f1ba7e77012c")
        );
        assert_eq!(
            key.test_iv(),
            decode_hex("353b447f82c586792fc594e64c4e67f9")
        );
    }

    #[test]
    fn rar3_kdf_preserves_long_password_sha1_bug() {
        let password = [b'p'; 29];
        let key = derive_rar3_key(&password, Some(decode_hex("1122334455667788"))).unwrap();
        assert_eq!(
            key.test_key(),
            decode_hex("306cafde28f1ea78c9427c3ec642c0db")
        );
        assert_eq!(
            key.test_iv(),
            decode_hex("173ecdf574c0bfe9e7c23bdfd96fa435")
        );
    }

    #[test]
    fn rar3_kdf_truncates_at_127_utf16_code_units() {
        let password = [b'p'; 127];
        let key = derive_rar3_key(&password, Some(decode_hex("1122334455667788"))).unwrap();
        assert_eq!(
            key.test_key(),
            decode_hex("b1bc223609af7d4f3b70e5a254ac2501")
        );
        assert_eq!(
            key.test_iv(),
            decode_hex("302c97945530d7ffa7c551eb2dd21a90")
        );

        let mut longer = [b'p'; 128];
        longer[127] = b'q';
        let truncated = derive_rar3_key(&longer, Some(decode_hex("1122334455667788"))).unwrap();
        assert_eq!(truncated.test_key(), key.test_key());
        assert_eq!(truncated.test_iv(), key.test_iv());
    }

    #[test]
    fn rar3_aes128_cbc_matches_independent_vector() {
        let key = super::Rar3Key::from_test_parts([0x02; 16], [0x80; 16]);
        let mut ciphertext =
            decode_hex("4b0d438b4a1b972bd4ab81cd64674dcce4b0158090fbe616f455354284d53502");
        key.decrypt_in_place(&mut ciphertext).unwrap();
        assert_eq!(ciphertext, *b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn rejects_invalid_utf8_and_partial_blocks() {
        assert!(matches!(
            derive_rar3_key(&[0xff], Some([0; 8])),
            Err(Error::InvalidUtf8)
        ));
        let key = super::Rar3Key::from_test_parts([0; 16], [0; 16]);
        assert_eq!(
            key.decrypt_in_place(&mut [0; 15]),
            Err(Error::InvalidBlockLength)
        );
    }

    #[test]
    fn rar5_kdf_matches_independent_rfc2898_vectors() {
        let key = derive_rar5_key(
            b"password",
            decode_hex("7e982cdd1ae21c36c7a391da8d088a68"),
            15,
            1 << 20,
        )
        .unwrap();
        assert_eq!(
            key.test_encryption_key(),
            decode_hex("be931a62d2708cb9781b4fcb7ceeca45316a9b12318d52cca4e372bfaee212a7")
        );
        assert_eq!(
            key.test_hash_key(),
            decode_hex("29adb79ce960adb7ceb0741e61ad78dcb2a77ab1027fb6e414294a8fc4146f7a")
        );
    }

    #[test]
    fn rar5_password_check_validates_integrity_and_candidate() {
        let salt = decode_hex("7e982cdd1ae21c36c7a391da8d088a68");
        let check = decode_hex("8151cff63649c16e186a220f");
        assert!(rar5_password_check(b"password", salt, 15, check, 1 << 20).unwrap());
        assert!(!rar5_password_check(b"wrong", salt, 15, check, 1 << 20).unwrap());

        let mut corrupt = check;
        corrupt[11] ^= 1;
        assert_eq!(
            rar5_password_check(b"password", salt, 15, corrupt, 1 << 20),
            Err(Error::InvalidPasswordCheck)
        );
    }

    #[test]
    fn rar5_kdf_rejects_work_above_the_caller_budget_before_derivation() {
        assert!(matches!(
            derive_rar5_key(b"password", [0; 16], 31, 1 << 20),
            Err(Error::KdfIterationsLimit { requested, maximum })
                if requested == 1_u64 << 31 && maximum == 1_u64 << 20
        ));
        assert!(matches!(
            derive_rar5_key(b"password", [0; 16], 64, u64::MAX),
            Err(Error::InvalidKdfExponent)
        ));
    }

    #[test]
    fn rar5_aes256_cbc_matches_nist_vector() {
        let key = super::Rar5Key::from_test_parts(
            decode_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            [0; 32],
        );
        let mut ciphertext: [u8; 32] =
            decode_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d");
        key.decrypt_in_place(
            decode_hex("000102030405060708090a0b0c0d0e0f"),
            &mut ciphertext,
        )
        .unwrap();
        assert_eq!(
            ciphertext,
            decode_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        );
    }

    #[test]
    fn rar5_tweaked_checksums_match_independent_hmac_vectors() {
        let key = super::Rar5Key::from_test_parts(
            [0; 32],
            decode_hex("29adb79ce960adb7ceb0741e61ad78dcb2a77ab1027fb6e414294a8fc4146f7a"),
        );
        assert_eq!(tweak_rar5_crc32(&key, 0x1234_5678), 0x0c6b_c8ff);
        assert_eq!(
            tweak_rar5_blake2sp(
                &key,
                core::array::from_fn(|index| u8::try_from(index).unwrap_or(u8::MAX)),
            ),
            decode_hex("71f41ee282fa29dfba1792ddc4ae2a925f589a294aa0f9d6b0bdc31514e18a4d")
        );
    }
}
