// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 7z AES-256/SHA-256 decryption coder (method id `06 F1 07 01`) as a sans-I/O [`Codec`].
//!
//! This is the 7-Zip encryption coder, distinct from the ZIP `WinZip` `AE-2` path
//! (`seek_stream::ZipAesDecoder`, AES-256-CTR + PBKDF2-HMAC-SHA1). The two differ
//! in three ways that matter for interoperability:
//!
//! * **Cipher mode.** 7z uses AES-256 in **CBC** with a stored IV; ZIP AE-2 uses
//!   AES-256 in CTR.
//! * **Key derivation.** 7z runs a single SHA-256 context fed
//!   `salt || password || counter` `2^numCyclesPower` times (7-Zip's own KDF); ZIP
//!   uses PBKDF2-HMAC-SHA1 with 1000 iterations.
//! * **Password encoding.** 7z hashes the password as **UTF-16LE** code units;
//!   ZIP AE-2 hashes the raw password bytes. The same user string therefore yields
//!   different keys in the two formats.
//!
//! The decoder decrypts whole 16-byte blocks and buffers a partial input block
//! and a partial output block internally, so it composes with any input chunking
//! from the coder below it. The 7z encoder zero-pads the ciphertext up to a block
//! boundary; the coder's declared output size (`out_size`) caps how many decrypted
//! bytes are emitted, so that trailing padding is truncated rather than reported as
//! an error. The per-substream CRC-32 (verified by the folder reader) is what
//! ultimately distinguishes a correct password from a wrong one.

use alloc::vec::Vec;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, array::Array};
use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind};
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

/// AES block size in bytes.
const BLOCK: usize = 16;

/// Largest accepted key-derivation work factor. The KDF runs `2^numCyclesPower`
/// SHA-256 rounds, so an attacker-supplied large power is a CPU-exhaustion `DoS` (and
/// `1 << power` also overflows for `power >= 64`). 7-Zip's own encoder never exceeds
/// this bound; a larger value only ever comes from a hostile archive. Keeping it below
/// 32 also makes the `1u64 << ncp` shift trivially safe. Mirrors `sevenz-rust2`.
const MAX_CYCLES_POWER: u8 = 24;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Parsed AES256SHA256 coder properties. Salt and IV are archive-public (they are
/// stored in the clear in the header), so this carries no secret material and is safe
/// to `Debug`. The derived key never lives here.
#[derive(Debug, Clone, Copy)]
pub struct AesParams {
    ncp: u8,
    salt: [u8; BLOCK],
    salt_len: usize,
    iv: [u8; BLOCK],
}

impl AesParams {
    /// Parses the coder property bytes for method `06 F1 07 01`.
    ///
    /// Returns `None` (→ the folder lists but is not decodable) for an external-key
    /// marker (`numCyclesPower == 0x3F`), a work factor above `MAX_CYCLES_POWER`, or
    /// any malformed / out-of-range salt/IV framing. The property layout is:
    /// `b0` = `numCyclesPower | (saltHi << 7) | (ivHi << 6)`, `b1` =
    /// `(saltLow << 4) | ivLow`, then `saltSize` salt bytes and `ivSize` IV bytes.
    #[must_use]
    pub fn parse(props: &[u8]) -> Option<Self> {
        let b0 = *props.first()?;
        let ncp = b0 & 0x3F;
        // 0x3F is 7-Zip's "key supplied externally" marker; unsupported here.
        if ncp == 0x3F || ncp > MAX_CYCLES_POWER {
            return None;
        }
        // A one-byte property (some archives store the kEnd byte as a lone property) is
        // treated as a zero second byte, matching mainstream decoders.
        let b1 = props.get(1).copied().unwrap_or(0);
        let header_len: usize = if props.len() == 1 { 1 } else { 2 };
        let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 0x0F));
        let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
        if salt_size > BLOCK || iv_size > BLOCK {
            return None;
        }
        let end = header_len.checked_add(salt_size)?.checked_add(iv_size)?;
        if end > props.len() {
            return None;
        }
        // Only `salt[..salt_size]` is consumed by the KDF. Seed the unused tail
        // from the archive header so the fixed-size storage is not mistaken for
        // a hard-coded cryptographic salt.
        let mut salt = [b0; BLOCK];
        salt[..salt_size].copy_from_slice(&props[header_len..header_len + salt_size]);
        let mut iv = [0u8; BLOCK];
        iv[..iv_size].copy_from_slice(&props[header_len + salt_size..end]);
        Some(Self {
            ncp,
            salt,
            salt_len: salt_size,
            iv,
        })
    }
}

/// Encodes a password (interpreted as a UTF-8 string) as UTF-16LE code units, the
/// form 7-Zip hashes. Lossy for invalid UTF-8 (one U+FFFD per maximal invalid
/// subsequence), matching `String::from_utf8_lossy`.
///
/// Uses [`slice::utf8_chunks`] rather than `from_utf8_lossy` so the password is never
/// copied into an intermediate owned `String`: `chunk.valid()` borrows directly from
/// the caller's buffer, so no un-zeroized heap copy of password-derived bytes is left
/// behind on the invalid-UTF-8 path. The returned buffer is the caller's to zeroize.
fn password_utf16le(password: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let capacity = password_buffer_capacity(password.len())?;
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| password_allocation_error("7z AES password encoding exceeds memory"))?;
    for chunk in password.utf8_chunks() {
        for unit in chunk.valid().encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        if !chunk.invalid().is_empty() {
            out.extend_from_slice(&(char::REPLACEMENT_CHARACTER as u16).to_le_bytes());
        }
    }
    Ok(out)
}

fn password_buffer_capacity(input_len: usize) -> Result<usize, ArchiveError> {
    input_len
        .checked_mul(2)
        .ok_or_else(|| password_allocation_error("7z AES password encoding size overflow"))
}

fn password_allocation_error(context: &'static str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Limit)
        .with_format("7z")
        .with_context(context)
}

/// The 7-Zip AES key schedule: a single SHA-256 context fed `salt || password ||
/// counter` `2^ncp` times, where `counter` is a little-endian 64-bit round index.
/// `ncp == 0` degenerates to one round over `salt || password || 0u64`.
fn derive_key(ncp: u8, salt: &[u8], password_utf16le: &[u8]) -> [u8; 32] {
    let mut sha = sha2::Sha256::default();
    let mut counter = [0u8; 8];
    for _ in 0..(1u64 << ncp) {
        sha.update(salt);
        sha.update(password_utf16le);
        sha.update(counter);
        for byte in &mut counter {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
    sha.finalize().into()
}

/// Streaming AES-256-CBC decryption coder for a 7z folder. Holds one partial input
/// block and one partial output block (32 bytes of buffering total), so it never
/// retains more than a block regardless of the chunking below it.
pub struct AesDecoder {
    dec: Aes256CbcDec,
    in_block: [u8; BLOCK],
    in_len: usize,
    out_block: [u8; BLOCK],
    out_pos: usize,
    out_len: usize,
    /// Declared plaintext bytes that have not yet been decrypted.
    remaining: u64,
    finished: bool,
}

impl AesDecoder {
    /// Builds a decoder from parsed properties and a raw (UTF-8) password. `out_size`
    /// is the coder's declared uncompressed output size, used to validate and
    /// truncate the final zero-padded block.
    ///
    /// Password-derived buffers are zeroized before this function returns. The
    /// expanded AES key schedule is also zeroized when the decoder is dropped.
    pub fn new(params: AesParams, out_size: u64, password: &[u8]) -> Result<Self, ArchiveError> {
        let password_utf16le = Zeroizing::new(password_utf16le(password)?);
        let derived_key = Zeroizing::new(derive_key(
            params.ncp,
            &params.salt[..params.salt_len],
            password_utf16le.as_slice(),
        ));
        let key: &Array<u8, _> = derived_key
            .as_slice()
            .try_into()
            .map_err(|_| Self::malformed("derived AES-256 key has an invalid length"))?;
        let iv: &Array<u8, _> = params
            .iv
            .as_slice()
            .try_into()
            .map_err(|_| Self::malformed("AES-CBC IV has an invalid length"))?;
        let dec = Aes256CbcDec::new(key, iv);
        Ok(Self {
            dec,
            in_block: [0; BLOCK],
            in_len: 0,
            out_block: [0; BLOCK],
            out_pos: 0,
            out_len: 0,
            remaining: out_size,
            finished: false,
        })
    }

    fn malformed(context: &'static str) -> ArchiveError {
        ArchiveError::new(ErrorKind::Malformed)
            .with_format("7z")
            .with_context(context)
    }

    fn integrity(context: &'static str) -> ArchiveError {
        ArchiveError::new(ErrorKind::Integrity)
            .with_format("7z")
            .with_context(context)
    }

    /// Decrypts one complete ciphertext block and stages only declared plaintext.
    fn decrypt_block(&mut self) -> Result<(), ArchiveError> {
        let block: &mut Array<u8, _> = self
            .in_block
            .as_mut_slice()
            .try_into()
            .map_err(|_| Self::malformed("AES block framing is invalid"))?;
        self.dec.decrypt_block(block);

        let plain_len_u64 = self.remaining.min(BLOCK as u64);
        let plain_len = usize::try_from(plain_len_u64)
            .map_err(|_| Self::malformed("AES output size exceeds this platform"))?;
        if block[plain_len..].iter().any(|byte| *byte != 0) {
            return Err(Self::integrity(
                "wrong password or corrupt AES zero padding",
            ));
        }

        self.out_block.zeroize();
        self.out_block[..plain_len].copy_from_slice(&block[..plain_len]);
        self.in_block.zeroize();
        self.in_len = 0;
        self.out_pos = 0;
        self.out_len = plain_len;
        self.remaining -= plain_len_u64;
        Ok(())
    }

    fn finish_at_end(
        &mut self,
        consumed: usize,
        produced: usize,
    ) -> Result<CodecStep, ArchiveError> {
        if self.in_len != 0 {
            return Err(Self::malformed("AES ciphertext ends in a partial block"));
        }
        if self.remaining != 0 {
            return Err(Self::malformed(
                "AES ciphertext is shorter than its declared output size",
            ));
        }
        self.finished = true;
        Ok(CodecStep {
            consumed,
            produced,
            status: CodecStatus::Done,
        })
    }
}

impl core::fmt::Debug for AesDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AesDecoder")
            .field("buffered_ciphertext", &self.in_len)
            .field("pending_plaintext", &(self.out_len - self.out_pos))
            .field("remaining", &self.remaining)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Drop for AesDecoder {
    fn drop(&mut self) {
        self.in_block.zeroize();
        self.out_block.zeroize();
    }
}

impl Codec for AesDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        if self.finished {
            return Ok(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            });
        }

        let mut consumed = 0usize;
        let mut produced = 0usize;
        loop {
            // 1. Drain already-decrypted output first.
            if self.out_pos < self.out_len {
                let avail = self.out_len - self.out_pos;
                let room = output.len() - produced;
                let take = avail.min(room);
                if take == 0 {
                    break; // output is full
                }
                output[produced..produced + take]
                    .copy_from_slice(&self.out_block[self.out_pos..self.out_pos + take]);
                self.out_pos += take;
                produced += take;
                continue;
            }

            // The declared plaintext is complete. Wait for true end-of-input so
            // surplus ciphertext cannot be silently ignored.
            if self.remaining == 0 {
                if consumed < input.len() {
                    return Err(Self::malformed(
                        "AES ciphertext exceeds its declared output size",
                    ));
                }
                if matches!(end, EndOfInput::End) {
                    return self.finish_at_end(consumed, produced);
                }
                break;
            }

            // 2. Fill the pending input block, decrypting it once complete.
            while self.in_len < BLOCK && consumed < input.len() {
                self.in_block[self.in_len] = input[consumed];
                self.in_len += 1;
                consumed += 1;
            }
            if self.in_len == BLOCK {
                self.decrypt_block()?;
                continue;
            }
            break; // partial input block; need more bytes
        }

        let output_pending = self.out_pos < self.out_len;
        if matches!(end, EndOfInput::End) && !output_pending && consumed == input.len() {
            return self.finish_at_end(consumed, produced);
        }
        if produced != 0 || consumed != 0 {
            return Ok(CodecStep {
                consumed,
                produced,
                status: if output_pending {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                },
            });
        }
        Ok(CodecStep {
            consumed: 0,
            produced: 0,
            status: if output_pending {
                CodecStatus::NeedOutput
            } else {
                CodecStatus::NeedInput
            },
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::trivially_copy_pass_by_ref
)]
mod tests {
    use alloc::{string::String, vec, vec::Vec};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::test_support::{drive_codec, try_drive_codec};

    fn runtime_crypto_bytes() -> [u8; BLOCK] {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes()
    }

    fn runtime_password() -> Vec<u8> {
        runtime_crypto_bytes().to_vec()
    }

    /// Builds coder properties matching what `sevenz-rust2` / 7-Zip write:
    /// `b0 = ncp | 0xC0`, `b1 = 0xFF` (16-byte salt and IV), then salt, then IV.
    fn props(ncp: u8, salt: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
        let mut p = vec![(ncp & 0x3F) | 0xC0, 0xFF];
        p.extend_from_slice(salt);
        p.extend_from_slice(iv);
        p
    }

    /// Independent AES-256-CBC encryption of a padded plaintext, for a round trip.
    fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        use aes::cipher::BlockModeEncrypt;
        type Enc = cbc::Encryptor<aes::Aes256>;
        let mut enc = Enc::new(&Array::from(*key), &Array::from(*iv));
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        for chunk in padded.chunks_mut(16) {
            let block: &mut Array<u8, _> = chunk.try_into().unwrap();
            enc.encrypt_block(block);
        }
        padded
    }

    #[test]
    fn parses_standard_properties() {
        let salt = runtime_crypto_bytes();
        let iv = runtime_crypto_bytes();
        let params = AesParams::parse(&props(8, &salt, &iv)).unwrap();
        assert_eq!(params.ncp, 8);
        assert_eq!(params.salt_len, 16);
        assert_eq!(&params.salt, &salt);
        assert_eq!(&params.iv, &iv);
    }

    #[test]
    fn parses_one_byte_properties_without_salt_or_iv() {
        let params = AesParams::parse(&[8]).unwrap();
        assert_eq!(params.ncp, 8);
        assert_eq!(params.salt_len, 0);
        assert!(params.salt[..params.salt_len].is_empty());
        assert_eq!(params.iv, [0; BLOCK]);
    }

    #[test]
    fn password_utf16le_matches_lossy_reference() {
        // The `utf8_chunks`-based encoder (which avoids an un-zeroized password copy)
        // must be byte-identical to `String::from_utf8_lossy(..).encode_utf16()`,
        // including one U+FFFD per maximal invalid subsequence.
        let cases: [&[u8]; 5] = [
            b"correct horse",
            &[0x66, 0x6f, 0xff, 0x6f], // valid, one invalid byte, valid
            &[0xff, 0xfe, 0xfd],       // all invalid
            &[0xf0, 0x28, 0x8c, 0x28], // invalid lead + stray continuations
            &[],
        ];
        for pw in cases {
            let reference: Vec<u8> = String::from_utf8_lossy(pw)
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            assert_eq!(password_utf16le(pw).unwrap(), reference, "pw = {pw:02x?}");
        }
    }

    #[test]
    fn password_encoding_capacity_overflow_is_a_limit_error() {
        let error = password_buffer_capacity(usize::MAX).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Limit);
    }

    #[test]
    fn rejects_external_oversized_kdf_and_truncated_properties() {
        // External-key marker.
        assert!(AesParams::parse(&[0x3F | 0xC0, 0xFF]).is_none());
        // Work factor above the DoS cap.
        assert!(AesParams::parse(&props(30, &[0; 16], &[0; 16])).is_none());
        // Declared salt+IV longer than the property buffer.
        assert!(AesParams::parse(&[0xC0, 0xFF, 1, 2, 3]).is_none());
        // Empty properties.
        assert!(AesParams::parse(&[]).is_none());
    }

    #[test]
    fn decrypts_round_trip_at_every_chunking() {
        let salt = runtime_crypto_bytes();
        let iv = runtime_crypto_bytes();
        let ncp = 4;
        let password = runtime_password();
        let encoded_password = Zeroizing::new(password_utf16le(&password).unwrap());
        let key = Zeroizing::new(derive_key(ncp, &salt, encoded_password.as_slice()));
        let plaintext: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        let ciphertext = encrypt(&key, &iv, &plaintext);

        let params = AesParams::parse(&props(ncp, &salt, &iv)).unwrap();
        for (input_chunk, output_chunk) in [
            (1usize, 1usize),
            (3, 7),
            (16, 16),
            (17, 3),
            (512, 31),
            (4096, 4096),
        ] {
            let decoder = AesDecoder::new(params, plaintext.len() as u64, &password).unwrap();
            let out = drive_codec(decoder, &ciphertext, input_chunk, output_chunk);
            assert_eq!(
                out, plaintext,
                "mismatch at input={input_chunk}, output={output_chunk}"
            );
        }
    }

    #[test]
    fn wrong_password_never_silently_returns_the_expected_plaintext() {
        // A block-aligned message has no zero padding to authenticate here; the
        // 7z folder CRC is responsible for classifying the wrong password.
        let salt = runtime_crypto_bytes();
        let iv = runtime_crypto_bytes();
        let password = runtime_password();
        let mut wrong_password = password.clone();
        wrong_password.push(password.len() as u8);
        let plaintext = (0_u8..64).collect::<Vec<_>>();
        let encoded_password = Zeroizing::new(password_utf16le(&password).unwrap());
        let key = Zeroizing::new(derive_key(2, &salt, encoded_password.as_slice()));
        let ciphertext = encrypt(&key, &iv, &plaintext);
        let params = AesParams::parse(&props(2, &salt, &iv)).unwrap();
        let decoder = AesDecoder::new(params, plaintext.len() as u64, &wrong_password).unwrap();

        let wrong_plaintext = drive_codec(decoder, &ciphertext, 5, 7);
        assert_eq!(wrong_plaintext.len(), plaintext.len());
        assert_ne!(wrong_plaintext, plaintext);
    }

    #[test]
    fn corrupt_zero_padding_is_an_integrity_error() {
        let salt = runtime_crypto_bytes();
        let iv = runtime_crypto_bytes();
        let password = runtime_password();
        let plaintext = (0_u8..17).collect::<Vec<_>>();
        let encoded_password = Zeroizing::new(password_utf16le(&password).unwrap());
        let key = Zeroizing::new(derive_key(2, &salt, encoded_password.as_slice()));
        let mut ciphertext = encrypt(&key, &iv, &plaintext);
        // CBC XORs the preceding ciphertext block into the next plaintext block.
        // This deterministically flips the last byte of final zero padding.
        ciphertext[BLOCK - 1] ^= 1;
        let params = AesParams::parse(&props(2, &salt, &iv)).unwrap();
        let decoder = AesDecoder::new(params, plaintext.len() as u64, &password).unwrap();

        let error = try_drive_codec(decoder, &ciphertext, 3, 5).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Integrity);
    }

    #[test]
    fn truncated_or_size_mismatched_ciphertext_is_malformed() {
        let salt = runtime_crypto_bytes();
        let iv = runtime_crypto_bytes();
        let password = runtime_password();
        let plaintext = (0_u8..32).collect::<Vec<_>>();
        let encoded_password = Zeroizing::new(password_utf16le(&password).unwrap());
        let key = Zeroizing::new(derive_key(2, &salt, encoded_password.as_slice()));
        let ciphertext = encrypt(&key, &iv, &plaintext);
        let params = AesParams::parse(&props(2, &salt, &iv)).unwrap();

        let truncated = AesDecoder::new(params, plaintext.len() as u64, &password).unwrap();
        let error =
            try_drive_codec(truncated, &ciphertext[..ciphertext.len() - 1], 7, 11).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);

        let declared_too_large =
            AesDecoder::new(params, plaintext.len() as u64 + BLOCK as u64, &password).unwrap();
        let error = try_drive_codec(declared_too_large, &ciphertext, 16, 9).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);

        let declared_too_small = AesDecoder::new(params, BLOCK as u64, &password).unwrap();
        let error = try_drive_codec(declared_too_small, &ciphertext, 5, 13).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn expanded_key_schedule_is_zeroized_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Aes256CbcDec>();
        assert_zeroize_on_drop::<sha2::Sha256>();
    }
}
