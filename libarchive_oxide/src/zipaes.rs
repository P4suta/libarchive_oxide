// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared `WinZip` AES AE-2 decryption primitives.

use aes::cipher::{Array, BlockCipherEncrypt, BlockSizeUser, consts::U16};
use libarchive_oxide_core::{ArchiveError, ErrorKind};
use zeroize::Zeroize;

#[derive(Clone)]
struct ZipAesCtr<C> {
    cipher: C,
    counter: u128,
    keystream: [u8; 16],
    position: usize,
}

impl<C> ZipAesCtr<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn new(cipher: C) -> Self {
        Self {
            cipher,
            counter: 1,
            keystream: [0; 16],
            position: 16,
        }
    }

    fn apply_keystream(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            if self.position == self.keystream.len() {
                let mut block = Array::from(self.counter.to_le_bytes());
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(&block);
                self.counter = self.counter.wrapping_add(1);
                self.position = 0;
            }
            *byte ^= self.keystream[self.position];
            self.position += 1;
        }
    }
}

impl<C> Drop for ZipAesCtr<C> {
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.counter.zeroize();
        self.position = 0;
    }
}

#[derive(Clone)]
enum ZipAesCipher {
    Bits128(ZipAesCtr<aes::Aes128>),
    Bits192(ZipAesCtr<aes::Aes192>),
    Bits256(ZipAesCtr<aes::Aes256>),
}

impl ZipAesCipher {
    fn apply_keystream(&mut self, bytes: &mut [u8]) {
        match self {
            Self::Bits128(cipher) => cipher.apply_keystream(bytes),
            Self::Bits192(cipher) => cipher.apply_keystream(bytes),
            Self::Bits256(cipher) => cipher.apply_keystream(bytes),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ZipAesDecoder {
    cipher: ZipAesCipher,
    mac: hmac::Hmac<sha1::Sha1>,
}

impl core::fmt::Debug for ZipAesDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZipAesDecoder([REDACTED])")
    }
}

impl ZipAesDecoder {
    pub(crate) fn new(
        password: &[u8],
        salt: &[u8],
        verifier: [u8; 2],
        strength: u8,
    ) -> Result<Self, ArchiveError> {
        use hmac::digest::KeyInit;
        use subtle::ConstantTimeEq;

        let key_len = match strength {
            1 => 16,
            2 => 24,
            3 => 32,
            _ => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "invalid WinZip AES strength code",
                ));
            },
        };
        let mut key_material = [0_u8; 66];
        let material_len = key_len * 2 + 2;
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, 1_000, &mut key_material[..material_len]);
        if key_material[key_len * 2..material_len]
            .ct_eq(&verifier)
            .unwrap_u8()
            != 1
        {
            key_material.zeroize();
            return Err(Self::error(
                ErrorKind::Integrity,
                "WinZip AES password verifier mismatch",
            ));
        }
        let cipher = match strength {
            1 => aes::Aes128::new_from_slice(&key_material[..key_len])
                .map(ZipAesCtr::new)
                .map(ZipAesCipher::Bits128),
            2 => aes::Aes192::new_from_slice(&key_material[..key_len])
                .map(ZipAesCtr::new)
                .map(ZipAesCipher::Bits192),
            3 => aes::Aes256::new_from_slice(&key_material[..key_len])
                .map(ZipAesCtr::new)
                .map(ZipAesCipher::Bits256),
            _ => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "invalid WinZip AES strength code",
                ));
            },
        }
        .map_err(|_| {
            Self::error(
                ErrorKind::Malformed,
                "WinZip AES cipher initialization failed",
            )
        })?;
        let mac = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(
            &key_material[key_len..key_len * 2],
        )
        .map_err(|_| Self::error(ErrorKind::Malformed, "WinZip AES MAC initialization failed"))?;
        key_material.zeroize();
        Ok(Self { cipher, mac })
    }

    pub(crate) fn decrypt(&mut self, bytes: &mut [u8]) {
        use hmac::Mac;

        self.mac.update(bytes);
        self.cipher.apply_keystream(bytes);
    }

    pub(crate) fn verify(&self, expected: [u8; 10]) -> Result<(), ArchiveError> {
        use hmac::Mac;
        use subtle::ConstantTimeEq;

        let actual = self.mac.clone().finalize().into_bytes();
        if actual[..10].ct_eq(&expected).unwrap_u8() != 1 {
            return Err(Self::error(
                ErrorKind::Integrity,
                "WinZip AES authentication failed",
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_after(
        &self,
        ciphertext: &[u8],
        expected: [u8; 10],
    ) -> Result<(), ArchiveError> {
        use hmac::Mac;
        use subtle::ConstantTimeEq;

        let mut mac = self.mac.clone();
        mac.update(ciphertext);
        let actual = mac.finalize().into_bytes();
        if actual[..10].ct_eq(&expected).unwrap_u8() != 1 {
            return Err(Self::error(
                ErrorKind::Integrity,
                "WinZip AES authentication failed",
            ));
        }
        Ok(())
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("zip")
            .with_context(context)
    }
}
