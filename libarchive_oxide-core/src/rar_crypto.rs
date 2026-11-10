// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Injectable RAR cryptography boundary.
//!
//! Container state machines own framing, buffering, limits, and integrity validation.
//! A provider owns password candidates and cryptographic primitives.
//! Associated types are unnecessary here because decryption is an in-place operation; the boundary remains generic and statically dispatched.

use core::panic::RefUnwindSafe;

use crate::{ArchiveError, ErrorKind};

/// Supplies ordered RAR3 password candidates without coupling the format parser to password storage or an AES implementation.
pub trait Rar3CryptoProvider: Send + Sync + RefUnwindSafe {
    /// Whether this provider can decrypt any RAR3 ciphertext.
    fn available(&self) -> bool {
        true
    }

    /// Number of ordered password candidates available to the decoder.
    ///
    /// The RAR3 decoder independently rejects counts above 16 before invoking a candidate, including when callers bypass the high-level open API.
    fn candidate_count(&self) -> usize;

    /// Decrypts one complete AES-128-CBC ciphertext in place.
    ///
    /// `salt` is absent for legacy unsalted entries.
    /// Successful decryption does not authenticate the candidate; the container validates header or plaintext CRC32 before exposing any bytes.
    fn decrypt(
        &self,
        candidate: usize,
        salt: Option<[u8; 8]>,
        ciphertext: &mut [u8],
    ) -> Result<(), ArchiveError>;
}

/// Empty provider used by format-only builds and callers without passwords.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoRar3CryptoProvider;

impl Rar3CryptoProvider for NoRar3CryptoProvider {
    fn available(&self) -> bool {
        false
    }

    fn candidate_count(&self) -> usize {
        0
    }

    fn decrypt(
        &self,
        _candidate: usize,
        _salt: Option<[u8; 8]>,
        _ciphertext: &mut [u8],
    ) -> Result<(), ArchiveError> {
        Err(ArchiveError::new(ErrorKind::Protocol)
            .with_format("rar-legacy")
            .with_context("empty RAR3 crypto provider was invoked"))
    }
}

/// Validated key-derivation and integrity parameters from one RAR5 encryption record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rar5CryptoParameters {
    kdf_exponent: u8,
    salt: [u8; 16],
    password_check: Option<[u8; 12]>,
    tweaked_checksums: bool,
}

impl Rar5CryptoParameters {
    /// Creates validated RAR5 cryptographic parameters.
    #[must_use]
    pub const fn new(
        kdf_exponent: u8,
        salt: [u8; 16],
        password_check: Option<[u8; 12]>,
        tweaked_checksums: bool,
    ) -> Self {
        Self {
            kdf_exponent,
            salt,
            password_check,
            tweaked_checksums,
        }
    }

    /// Base-2 logarithm of the PBKDF2 iteration count.
    #[must_use]
    pub const fn kdf_exponent(self) -> u8 {
        self.kdf_exponent
    }

    /// Per-record 16-byte KDF salt.
    #[must_use]
    pub const fn salt(self) -> [u8; 16] {
        self.salt
    }

    /// Optional password verifier and its four-byte self-checksum.
    #[must_use]
    pub const fn password_check(self) -> Option<[u8; 12]> {
        self.password_check
    }

    /// Whether stored payload checksums are HMAC-tweaked.
    #[must_use]
    pub const fn tweaked_checksums(self) -> bool {
        self.tweaked_checksums
    }
}

/// Supplies ordered RAR5 password candidates and statically typed key handles.
///
/// The container owns ciphertext buffering, codec replay, resource limits,
/// and the decision to expose authenticated plaintext.
/// A provider owns secret storage, KDF caching, AES, and checksum tweaking.
pub trait Rar5CryptoProvider: Send + Sync + RefUnwindSafe {
    /// Provider-owned key handle retained while one encrypted member is read.
    type Key;

    /// Whether this provider can decrypt any RAR5 ciphertext.
    fn available(&self) -> bool {
        true
    }

    /// Number of ordered password candidates available to the decoder.
    fn candidate_count(&self) -> usize;

    /// Validates one candidate and returns its provider-owned key handle.
    ///
    /// `Ok(None)` means a well-formed password check rejected this candidate.
    /// `maximum_iterations` is the caller's finite KDF work budget.
    fn derive_key(
        &self,
        candidate: usize,
        parameters: Rar5CryptoParameters,
        maximum_iterations: u64,
    ) -> Result<Option<Self::Key>, ArchiveError>;

    /// Decrypts complete AES-256-CBC blocks in place.
    fn decrypt(
        &self,
        key: &Self::Key,
        iv: [u8; 16],
        ciphertext: &mut [u8],
    ) -> Result<(), ArchiveError>;

    /// Converts a raw CRC32 to its RAR5 HMAC-tweaked representation.
    fn tweak_crc32(&self, key: &Self::Key, crc: u32) -> Result<u32, ArchiveError>;

    /// Converts a raw `BLAKE2sp` digest to its RAR5 HMAC representation.
    fn tweak_blake2sp(&self, key: &Self::Key, digest: [u8; 32]) -> Result<[u8; 32], ArchiveError>;
}

/// Uninhabited key handle used by [`NoRar5CryptoProvider`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRar5CryptoKey {}

/// Empty RAR5 provider used by format-only builds and callers without keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoRar5CryptoProvider;

impl Rar5CryptoProvider for NoRar5CryptoProvider {
    type Key = NoRar5CryptoKey;

    fn available(&self) -> bool {
        false
    }

    fn candidate_count(&self) -> usize {
        0
    }

    fn derive_key(
        &self,
        _candidate: usize,
        _parameters: Rar5CryptoParameters,
        _maximum_iterations: u64,
    ) -> Result<Option<Self::Key>, ArchiveError> {
        Err(rar5_empty_provider_error())
    }

    fn decrypt(
        &self,
        key: &Self::Key,
        _iv: [u8; 16],
        _ciphertext: &mut [u8],
    ) -> Result<(), ArchiveError> {
        match *key {}
    }

    fn tweak_crc32(&self, key: &Self::Key, _crc: u32) -> Result<u32, ArchiveError> {
        match *key {}
    }

    fn tweak_blake2sp(&self, key: &Self::Key, _digest: [u8; 32]) -> Result<[u8; 32], ArchiveError> {
        match *key {}
    }
}

fn rar5_empty_provider_error() -> ArchiveError {
    ArchiveError::new(ErrorKind::Protocol)
        .with_format("rar5")
        .with_context("empty RAR5 crypto provider was invoked")
}
