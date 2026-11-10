// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Traditional PKWARE `ZipCrypto` key stream.

use zeroize::Zeroize;

/// Stateful traditional ZIP encryptor/decryptor.
///
/// `ZipCrypto` updates its three keys with plaintext bytes in both directions,
/// so encryption and decryption deliberately use separate methods.
#[derive(Clone)]
pub(crate) struct ZipCrypto {
    keys: [u32; 3],
}

impl core::fmt::Debug for ZipCrypto {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZipCrypto([REDACTED])")
    }
}

impl Drop for ZipCrypto {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

impl ZipCrypto {
    pub(crate) fn new(password: &[u8]) -> Self {
        let mut crypto = Self {
            keys: [0x1234_5678, 0x2345_6789, 0x3456_7890],
        };
        for &byte in password {
            crypto.update(byte);
        }
        crypto
    }

    pub(crate) fn encrypt(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            let plaintext = *byte;
            *byte ^= self.stream_byte();
            self.update(plaintext);
        }
    }

    pub(crate) fn decrypt(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte ^= self.stream_byte();
            self.update(*byte);
        }
    }

    fn stream_byte(&self) -> u8 {
        let key = self.keys[2].to_le_bytes();
        let value = u16::from_le_bytes([key[0], key[1]]) | 2;
        (value.wrapping_mul(value ^ 1) >> 8) as u8
    }

    fn update(&mut self, plaintext: u8) {
        self.keys[0] = crc32_byte(self.keys[0], plaintext);
        self.keys[1] = self.keys[1]
            .wrapping_add(self.keys[0] & 0xff)
            .wrapping_mul(0x0808_8405)
            .wrapping_add(1);
        self.keys[2] = crc32_byte(self.keys[2], (self.keys[1] >> 24) as u8);
    }
}

fn crc32_byte(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::ZipCrypto;

    #[test]
    fn fragmented_encryption_roundtrips() {
        let password = b"binary\0password\xff";
        let plaintext = b"header and payload bytes";
        let mut ciphertext = plaintext.to_vec();
        let mut encoder = ZipCrypto::new(password);
        encoder.encrypt(&mut ciphertext[..7]);
        encoder.encrypt(&mut ciphertext[7..]);
        assert_ne!(ciphertext, plaintext);

        let mut decoder = ZipCrypto::new(password);
        for chunk in ciphertext.chunks_mut(3) {
            decoder.decrypt(chunk);
        }
        assert_eq!(ciphertext, plaintext);
    }
}
