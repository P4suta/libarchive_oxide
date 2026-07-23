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

use aes::cipher::{BlockModeDecrypt, KeyIvInit, array::Array};
use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind};
use sha2::Digest;
use zeroize::Zeroize;

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
pub(crate) struct AesParams {
    ncp: u8,
    salt: [u8; BLOCK],
    salt_len: usize,
    iv: [u8; BLOCK],
}

impl AesParams {
    /// Parses the coder property bytes for method `06 F1 07 01`.
    ///
    /// Returns `None` (→ the folder lists but is not decodable) for an external-key
    /// marker (`numCyclesPower == 0x3F`), a work factor above [`MAX_CYCLES_POWER`], or
    /// any malformed / out-of-range salt/IV framing. The property layout is:
    /// `b0` = `numCyclesPower | (saltHi << 7) | (ivHi << 6)`, `b1` =
    /// `(saltLow << 4) | ivLow`, then `saltSize` salt bytes and `ivSize` IV bytes.
    pub(crate) fn parse(props: &[u8]) -> Option<Self> {
        let b0 = *props.first()?;
        let ncp = b0 & 0x3F;
        // 0x3F is 7-Zip's "key supplied externally" marker; unsupported here.
        if ncp == 0x3F || ncp > MAX_CYCLES_POWER {
            return None;
        }
        // A one-byte property (some archives store the kEnd byte as a lone property) is
        // treated as a zero second byte, matching mainstream decoders.
        let b1 = props.get(1).copied().unwrap_or(0);
        let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 0x0F));
        let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
        if salt_size > BLOCK || iv_size > BLOCK {
            return None;
        }
        let end = 2usize.checked_add(salt_size)?.checked_add(iv_size)?;
        if end > props.len() {
            return None;
        }
        let mut salt = [0u8; BLOCK];
        salt[..salt_size].copy_from_slice(&props[2..2 + salt_size]);
        let mut iv = [0u8; BLOCK];
        iv[..iv_size].copy_from_slice(&props[2 + salt_size..end]);
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
fn password_utf16le(password: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len().saturating_mul(2));
    for chunk in password.utf8_chunks() {
        for unit in chunk.valid().encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        if !chunk.invalid().is_empty() {
            out.extend_from_slice(&(char::REPLACEMENT_CHARACTER as u16).to_le_bytes());
        }
    }
    out
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
pub(crate) struct AesDecoder {
    dec: Aes256CbcDec,
    in_block: [u8; BLOCK],
    in_len: usize,
    out_block: [u8; BLOCK],
    out_pos: usize,
    out_len: usize,
    /// Remaining decrypted bytes to emit (the coder's declared output size). Trailing
    /// ciphertext padding beyond this is dropped rather than surfaced.
    remaining: u64,
}

impl AesDecoder {
    /// Builds a decoder from parsed properties and a raw (UTF-8) password. `out_size`
    /// is the coder's declared uncompressed output size, used to truncate padding.
    pub(crate) fn new(params: AesParams, out_size: u64, password: &[u8]) -> Self {
        let mut pw = password_utf16le(password);
        let mut key = derive_key(params.ncp, &params.salt[..params.salt_len], &pw);
        pw.zeroize();
        let dec = Aes256CbcDec::new(&Array::from(key), &Array::from(params.iv));
        key.zeroize();
        Self {
            dec,
            in_block: [0; BLOCK],
            in_len: 0,
            out_block: [0; BLOCK],
            out_pos: 0,
            out_len: 0,
            remaining: out_size,
        }
    }
}

impl Codec for AesDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        let mut consumed = 0usize;
        let mut produced = 0usize;
        loop {
            if self.remaining == 0 {
                // Output budget reached: drop any buffered plaintext and padding.
                return Ok(CodecStep {
                    consumed,
                    produced,
                    status: CodecStatus::Done,
                });
            }
            // 1. Drain already-decrypted output first.
            if self.out_pos < self.out_len {
                let avail = self.out_len - self.out_pos;
                let room = output.len() - produced;
                let budget = usize::try_from(self.remaining).unwrap_or(usize::MAX);
                let take = avail.min(room).min(budget);
                if take == 0 {
                    break; // output is full
                }
                output[produced..produced + take]
                    .copy_from_slice(&self.out_block[self.out_pos..self.out_pos + take]);
                self.out_pos += take;
                produced += take;
                self.remaining -= take as u64;
                continue;
            }
            // 2. Fill the pending input block, decrypting it once complete.
            while self.in_len < BLOCK && consumed < input.len() {
                self.in_block[self.in_len] = input[consumed];
                self.in_len += 1;
                consumed += 1;
            }
            if self.in_len == BLOCK {
                let block: &mut Array<u8, _> =
                    self.in_block.as_mut_slice().try_into().map_err(|_| {
                        ArchiveError::new(ErrorKind::Malformed)
                            .with_context("7z AES: block framing")
                    })?;
                self.dec.decrypt_block(block);
                self.out_block = self.in_block;
                self.out_pos = 0;
                self.out_len = BLOCK;
                self.in_len = 0;
                continue;
            }
            break; // partial input block; need more bytes
        }
        if produced != 0 || consumed != 0 {
            return Ok(CodecStep {
                consumed,
                produced,
                status: CodecStatus::NeedInput,
            });
        }
        // No progress: a partial trailing block at end-of-input is padding and dropped.
        let status = match end {
            EndOfInput::End => CodecStatus::Done,
            EndOfInput::More => CodecStatus::NeedInput,
        };
        Ok(CodecStep {
            consumed: 0,
            produced: 0,
            status,
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
    use std::io::Read;

    use super::*;
    use crate::codec_read::CodecReader;

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
        let salt = [7u8; 16];
        let iv = [9u8; 16];
        let params = AesParams::parse(&props(8, &salt, &iv)).unwrap();
        assert_eq!(params.ncp, 8);
        assert_eq!(params.salt_len, 16);
        assert_eq!(&params.salt, &salt);
        assert_eq!(&params.iv, &iv);
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
            assert_eq!(password_utf16le(pw), reference, "pw = {pw:02x?}");
        }
    }

    #[test]
    fn rejects_external_and_overlong_and_truncated() {
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
        let salt = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let ncp = 4;
        let password = b"correct horse";
        let key = derive_key(ncp, &salt, &password_utf16le(password));
        let plaintext: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        let ciphertext = encrypt(&key, &iv, &plaintext);

        let params = AesParams::parse(&props(ncp, &salt, &iv)).unwrap();
        for chunk in [1usize, 3, 16, 17, 512, 4096] {
            let reader = ChunkReader {
                data: ciphertext.clone(),
                pos: 0,
                chunk,
            };
            let decoder = AesDecoder::new(params, plaintext.len() as u64, password);
            let mut cr = CodecReader::new(reader, decoder, "7z-aes");
            let mut out = Vec::new();
            cr.read_to_end(&mut out).unwrap();
            assert_eq!(out, plaintext, "mismatch at chunk {chunk}");
        }
    }

    struct ChunkReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.data.len() - self.pos).min(self.chunk).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
}
