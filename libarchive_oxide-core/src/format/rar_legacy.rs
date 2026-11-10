// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded incremental RAR 3.x/4.x container reader.
//!
//! This clean-room container implementation follows the documented wire fields in libarchive's BSD-2-Clause RAR reader.
//! It reads Store (`0x30`) directly and delegates methods `0x31`–`0x35` through an optional generic payload codec provider.
//! Encrypted file data and main-header encryption use an optional generic crypto provider with ordered password candidates.
//! Ciphertext, candidate plaintext, and authenticated output are bounded before allocation; no data is exposed until exact output and CRC32 validation succeeds.
//! Sequential LZ or `PPMd` solid members reuse one concrete codec state.
//! The five standard RAR3 VM filters use a bounded closed-enum implementation; arbitrary VM bytecode and encrypted solid or split-volume payloads remain explicit typed failures.
//! A hidden physical-volume mode supplies split Store or raw compressed parts, verified ENDARC signals, and per-volume resource use to the bounded high-level `VolumeSet` provider.

use alloc::{boxed::Box, vec, vec::Vec};
use core::fmt;

use crate::metadata::{
    ArchiveMetadata, ArchivePath, Checksum, ChecksumAlgorithm, EntryMetadata, EntryTimes,
    Extension, PathEncoding,
};
use crate::protocol::{ArchiveDecoder, Chunk, DecodeEvent, DecodeStep, EndOfInput};
use crate::{
    ArchiveError, Codec, CodecStatus, EntryKind, ErrorKind, Limits, NoPayloadCodecProvider,
    NoRar3CryptoProvider, PayloadCodecAlgorithm, PayloadCodecProvider, PayloadCodecRequest,
    Rar3CryptoProvider, Timestamp,
};

const SIGNATURE: &[u8; 7] = b"Rar!\x1a\x07\x00";
const MAX_SFX_BYTES: u64 = 1024 * 1024;
const BASE_HEADER: usize = 7;
const FILE_HEADER: usize = 32;
const AES_BLOCK_BYTES: usize = 16;
const MAX_PASSWORD_CANDIDATES: usize = 16;

const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const COMM_HEAD: u8 = 0x75;
const AV_HEAD: u8 = 0x76;
const SUB_HEAD: u8 = 0x77;
const PROTECT_HEAD: u8 = 0x78;
const SIGN_HEAD: u8 = 0x79;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

const MHD_VOLUME: u16 = 0x0001;
const MHD_SOLID: u16 = 0x0008;
const MHD_PASSWORD: u16 = 0x0080;
const MHD_FIRSTVOLUME: u16 = 0x0100;
const MHD_ENCRYPTVER: u16 = 0x0200;

const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const FHD_SOLID: u16 = 0x0010;
const FHD_DIRECTORY: u16 = 0x00e0;
const FHD_LARGE: u16 = 0x0100;
const FHD_UNICODE: u16 = 0x0200;
const FHD_SALT: u16 = 0x0400;
const FHD_EXTTIME: u16 = 0x1000;
const HD_SKIP_IF_UNKNOWN: u16 = 0x4000;
const HD_ADD_SIZE_PRESENT: u16 = 0x8000;

const METHOD_STORE: u8 = 0x30;

fn rar_legacy_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("rar-legacy")
        .with_context(context)
}

#[derive(Debug, Clone, Copy)]
struct AuxiliaryState {
    remaining: u64,
    expected_crc: u16,
    crc: Crc32,
    verify_payload_crc: bool,
    end_after: bool,
}

#[derive(Debug, Clone, Copy)]
struct EncryptedState {
    remaining: u64,
    unpacked_size: u64,
    expected_crc: u32,
    verify_checksum: bool,
    method: u8,
    unpack_version: u8,
    salt: Option<[u8; 8]>,
    solid: bool,
    split: bool,
}

#[derive(Debug, Clone, Copy)]
struct EncryptedHeaderCandidate {
    password: usize,
    plaintext_size: usize,
    ciphertext_size: usize,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Signature {
        window: [u8; SIGNATURE.len()],
        length: usize,
        scanned: u64,
    },
    Header,
    EncryptedHeaders,
    Data {
        remaining: u64,
        expected_crc: u32,
        verify_checksum: bool,
        physical_raw: bool,
        crc: Crc32,
    },
    EncryptedData(EncryptedState),
    BufferedData,
    LinkData {
        remaining: u64,
        expected_crc: u32,
        crc: Crc32,
    },
    LinkEnd,
    AuxData(AuxiliaryState),
    Tail,
    Done,
}

enum HeaderAction<D> {
    ArchiveMetadata(ArchiveMetadata),
    EncryptedHeaders(ArchiveMetadata),
    Entry {
        metadata: Box<EntryMetadata>,
        packed_size: u64,
        unpacked_size: u64,
        expected_crc: u32,
        verify_checksum: bool,
        encrypted: bool,
        encryption_salt: Option<[u8; 8]>,
        method: u8,
        unpack_version: u8,
        solid: bool,
        split: bool,
        physical_raw: bool,
        payload_codec: Option<D>,
    },
    Symlink {
        metadata: Box<EntryMetadata>,
        packed_size: u64,
        expected_crc: u32,
    },
    Auxiliary {
        metadata: Option<ArchiveMetadata>,
        state: AuxiliaryState,
    },
}

/// Incremental RAR 3.x/4.x reader with injectable compressed-payload codecs.
pub struct RarLegacyDecoder<P = NoPayloadCodecProvider, C = NoRar3CryptoProvider>
where
    P: PayloadCodecProvider,
    C: Rar3CryptoProvider,
{
    limits: Limits,
    state: State,
    header: Vec<u8>,
    target: Option<usize>,
    entries: u64,
    decoded: u64,
    saw_main: bool,
    current_path: Vec<u8>,
    pending_link: Option<Box<EntryMetadata>>,
    link_target: Vec<u8>,
    pending_archive_metadata: Option<ArchiveMetadata>,
    allow_volumes: bool,
    main_flags: u16,
    payload_codecs: P,
    payload_codec: Option<P::Decoder>,
    retained_payload_codec: Option<P::Decoder>,
    crypto: C,
    encrypted_data: Vec<u8>,
    buffered_data: Vec<u8>,
    buffered_offset: usize,
    encrypted_header_salt: [u8; 8],
    encrypted_header_salt_len: usize,
    encrypted_header_data: Vec<u8>,
    encrypted_header_candidates: Vec<EncryptedHeaderCandidate>,
}

impl<P, C> fmt::Debug for RarLegacyDecoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar3CryptoProvider,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RarLegacyDecoder")
            .field("limits", &self.limits)
            .field("state", &self.state)
            .field("entries", &self.entries)
            .field("decoded", &self.decoded)
            .field("saw_main", &self.saw_main)
            .field("allow_volumes", &self.allow_volumes)
            .field("has_payload_provider", &self.payload_codecs.available())
            .field("has_payload_codec", &self.payload_codec.is_some())
            .field("has_crypto_provider", &self.crypto.available())
            .field("password_candidates", &self.crypto.candidate_count())
            .field(
                "has_retained_payload_codec",
                &self.retained_payload_codec.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl RarLegacyDecoder<NoPayloadCodecProvider, NoRar3CryptoProvider> {
    /// Creates a decoder with explicit finite budgets.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: State::Signature {
                window: [0; SIGNATURE.len()],
                length: 0,
                scanned: 0,
            },
            header: Vec::new(),
            target: None,
            entries: 0,
            decoded: 0,
            saw_main: false,
            current_path: Vec::new(),
            pending_link: None,
            link_target: Vec::new(),
            pending_archive_metadata: None,
            allow_volumes: false,
            main_flags: 0,
            payload_codecs: NoPayloadCodecProvider,
            payload_codec: None,
            retained_payload_codec: None,
            crypto: NoRar3CryptoProvider,
            encrypted_data: Vec::new(),
            buffered_data: Vec::new(),
            buffered_offset: 0,
            encrypted_header_salt: [0; 8],
            encrypted_header_salt_len: 0,
            encrypted_header_data: Vec::new(),
            encrypted_header_candidates: Vec::new(),
        }
    }

    /// Creates a physical-volume decoder for the bounded high-level provider.
    #[doc(hidden)]
    #[must_use]
    pub const fn with_volume_provider(limits: Limits) -> Self {
        let mut decoder = Self::new(limits);
        decoder.allow_volumes = true;
        decoder
    }
}

impl<P> RarLegacyDecoder<P, NoRar3CryptoProvider>
where
    P: PayloadCodecProvider,
{
    /// Creates a decoder with an injectable inner-payload codec provider.
    #[must_use]
    pub fn with_payload_codecs(limits: Limits, provider: P) -> Self {
        Self::with_providers(limits, provider, NoRar3CryptoProvider, false)
    }

    /// Creates a physical-volume decoder with inner-payload codecs.
    #[doc(hidden)]
    #[must_use]
    pub fn with_volume_provider_and_payload_codecs(limits: Limits, provider: P) -> Self {
        Self::with_providers(limits, provider, NoRar3CryptoProvider, true)
    }
}

impl<C> RarLegacyDecoder<NoPayloadCodecProvider, C>
where
    C: Rar3CryptoProvider,
{
    /// Creates a decoder with an injectable RAR3 cryptography provider.
    #[must_use]
    pub fn with_crypto(limits: Limits, crypto: C) -> Self {
        Self::with_providers(limits, NoPayloadCodecProvider, crypto, false)
    }

    /// Creates a physical-volume decoder with RAR3 cryptography.
    #[doc(hidden)]
    #[must_use]
    pub fn with_volume_provider_and_crypto(limits: Limits, crypto: C) -> Self {
        Self::with_providers(limits, NoPayloadCodecProvider, crypto, true)
    }
}

impl<P, C> RarLegacyDecoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar3CryptoProvider,
{
    /// Creates a decoder with injectable payload and RAR3 crypto providers.
    #[must_use]
    pub fn with_payload_and_crypto(limits: Limits, payload: P, crypto: C) -> Self {
        Self::with_providers(limits, payload, crypto, false)
    }

    /// Creates a physical-volume decoder with payload and crypto providers.
    #[doc(hidden)]
    #[must_use]
    pub fn with_volume_providers(limits: Limits, payload: P, crypto: C) -> Self {
        Self::with_providers(limits, payload, crypto, true)
    }

    fn with_providers(limits: Limits, provider: P, crypto: C, allow_volumes: bool) -> Self {
        Self {
            limits,
            state: State::Signature {
                window: [0; SIGNATURE.len()],
                length: 0,
                scanned: 0,
            },
            header: Vec::new(),
            target: None,
            entries: 0,
            decoded: 0,
            saw_main: false,
            current_path: Vec::new(),
            pending_link: None,
            link_target: Vec::new(),
            pending_archive_metadata: None,
            allow_volumes,
            main_flags: 0,
            payload_codecs: provider,
            payload_codec: None,
            retained_payload_codec: None,
            crypto,
            encrypted_data: Vec::new(),
            buffered_data: Vec::new(),
            buffered_offset: 0,
            encrypted_header_salt: [0; 8],
            encrypted_header_salt_len: 0,
            encrypted_header_data: Vec::new(),
            encrypted_header_candidates: Vec::new(),
        }
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        rar_legacy_error(kind, context)
    }

    fn entry_error(&self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        Self::error(kind, context).with_entry(self.entries, self.current_path.clone())
    }

    fn password_candidate_count(&self) -> Result<usize, ArchiveError> {
        let count = self.crypto.candidate_count();
        if count > MAX_PASSWORD_CANDIDATES {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR password candidates exceed the decoder limit",
            ));
        }
        Ok(count)
    }

    fn scan_signature(
        &mut self,
        input: &[u8],
        end: EndOfInput,
        mut window: [u8; SIGNATURE.len()],
        mut length: usize,
        mut scanned: u64,
    ) -> Result<DecodeStep<'_>, ArchiveError> {
        let mut consumed = 0;
        while consumed < input.len() {
            let byte = input[consumed];
            consumed += 1;
            scanned = scanned
                .checked_add(1)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR SFX scan offset overflow"))?;
            if length < window.len() {
                window[length] = byte;
                length += 1;
            } else {
                window.copy_within(1.., 0);
                window[window.len() - 1] = byte;
            }
            if length == window.len() && window == *SIGNATURE {
                let prefix = scanned - SIGNATURE.len() as u64;
                if prefix > MAX_SFX_BYTES {
                    return Err(Self::error(
                        ErrorKind::Limit,
                        "RAR SFX prefix exceeds the 1 MiB scan limit",
                    ));
                }
                self.state = State::Header;
                return Ok(step(consumed, DecodeEvent::NeedInput));
            }
            if scanned > MAX_SFX_BYTES + SIGNATURE.len() as u64 {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "RAR signature was not found within the 1 MiB SFX scan limit",
                ));
            }
        }
        self.state = State::Signature {
            window,
            length,
            scanned,
        };
        if matches!(end, EndOfInput::End) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR signature is missing or truncated",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    fn read_header(
        &mut self,
        input: &[u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'_>, ArchiveError> {
        let mut consumed = 0;
        while consumed < input.len() && self.target.is_none_or(|target| self.header.len() < target)
        {
            self.push_header(input[consumed])?;
            consumed += 1;
        }
        if self
            .target
            .is_some_and(|target| self.header.len() == target)
        {
            let header = core::mem::take(&mut self.header);
            self.target = None;
            let action = self.parse_header(&header)?;
            return Ok(step(consumed, self.apply(action)));
        }
        if matches!(end, EndOfInput::End) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "truncated RAR archive header",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    fn read_encrypted_header<'a>(
        &mut self,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if !self.crypto.available() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR headers require a decryption provider",
            ));
        }
        let candidate_count = self.password_candidate_count()?;
        if candidate_count == 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR headers require a password candidate",
            ));
        }

        let mut consumed = 0;
        if self.encrypted_header_salt_len < self.encrypted_header_salt.len() {
            let count = (self.encrypted_header_salt.len() - self.encrypted_header_salt_len)
                .min(input.len());
            let end_offset = self.encrypted_header_salt_len + count;
            self.encrypted_header_salt[self.encrypted_header_salt_len..end_offset]
                .copy_from_slice(&input[..count]);
            self.encrypted_header_salt_len = end_offset;
            consumed += count;
            if self.encrypted_header_salt_len < self.encrypted_header_salt.len() {
                return Self::encrypted_header_wait(consumed, end);
            }
        }

        if self.encrypted_header_data.len() < AES_BLOCK_BYTES {
            let needed = AES_BLOCK_BYTES - self.encrypted_header_data.len();
            let count = needed.min(input.len() - consumed);
            self.push_encrypted_header_bytes(&input[consumed..consumed + count])?;
            consumed += count;
            if self.encrypted_header_data.len() < AES_BLOCK_BYTES {
                return Self::encrypted_header_wait(consumed, end);
            }
        }
        if self.encrypted_header_candidates.is_empty() {
            self.build_encrypted_header_candidates(candidate_count)?;
        }

        loop {
            let mut index = 0;
            while index < self.encrypted_header_candidates.len() {
                let candidate = self.encrypted_header_candidates[index];
                if candidate.ciphertext_size > self.encrypted_header_data.len() {
                    index += 1;
                    continue;
                }
                let mut plaintext = Vec::new();
                plaintext
                    .try_reserve_exact(candidate.ciphertext_size)
                    .map_err(|_| {
                        Self::error(
                            ErrorKind::Limit,
                            "encrypted RAR header candidate allocation failed",
                        )
                    })?;
                plaintext
                    .extend_from_slice(&self.encrypted_header_data[..candidate.ciphertext_size]);
                match self.crypto.decrypt(
                    candidate.password,
                    Some(self.encrypted_header_salt),
                    &mut plaintext,
                ) {
                    Ok(()) => {},
                    Err(error) if error.kind() == ErrorKind::Protocol => return Err(error),
                    Err(_) => {
                        self.encrypted_header_candidates.remove(index);
                        continue;
                    },
                }
                plaintext.truncate(candidate.plaintext_size);
                let expected = le_u16(&plaintext, 0)?;
                if validate_header_crc(&plaintext, expected).is_err() {
                    self.encrypted_header_candidates.remove(index);
                    continue;
                }

                self.reset_encrypted_header();
                let action = self.parse_header(&plaintext)?;
                return Ok(step(consumed, self.apply(action)));
            }

            let Some(target) = self
                .encrypted_header_candidates
                .iter()
                .map(|candidate| candidate.ciphertext_size)
                .filter(|target| *target > self.encrypted_header_data.len())
                .min()
            else {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "wrong password or corrupt encrypted RAR header",
                ));
            };
            let available = input.len() - consumed;
            let count = (target - self.encrypted_header_data.len()).min(available);
            self.push_encrypted_header_bytes(&input[consumed..consumed + count])?;
            consumed += count;
            if self.encrypted_header_data.len() < target {
                return Self::encrypted_header_wait(consumed, end);
            }
        }
    }

    fn encrypted_header_wait(
        consumed: usize,
        end: EndOfInput,
    ) -> Result<DecodeStep<'static>, ArchiveError> {
        if matches!(end, EndOfInput::End) {
            return Err(Self::error(
                ErrorKind::Integrity,
                "encrypted RAR header is truncated or the password is wrong",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    fn push_encrypted_header_bytes(&mut self, bytes: &[u8]) -> Result<(), ArchiveError> {
        self.encrypted_header_data
            .try_reserve(bytes.len())
            .map_err(|_| Self::error(ErrorKind::Limit, "encrypted RAR header allocation failed"))?;
        self.encrypted_header_data.extend_from_slice(bytes);
        Ok(())
    }

    fn build_encrypted_header_candidates(
        &mut self,
        candidate_count: usize,
    ) -> Result<(), ArchiveError> {
        self.encrypted_header_candidates
            .try_reserve_exact(candidate_count)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "encrypted RAR header candidate table allocation failed",
                )
            })?;
        for password in 0..candidate_count {
            let mut first_block: [u8; AES_BLOCK_BYTES] = self.encrypted_header_data
                [..AES_BLOCK_BYTES]
                .try_into()
                .map_err(|_| {
                    Self::error(
                        ErrorKind::Protocol,
                        "encrypted RAR first block is unavailable",
                    )
                })?;
            match self
                .crypto
                .decrypt(password, Some(self.encrypted_header_salt), &mut first_block)
            {
                Ok(()) => {},
                Err(error) if error.kind() == ErrorKind::Protocol => return Err(error),
                Err(_) => continue,
            }
            let plaintext_size = usize::from(u16::from_le_bytes([first_block[5], first_block[6]]));
            let Some(ciphertext_size) = plaintext_size
                .checked_add(AES_BLOCK_BYTES - 1)
                .map(|size| size / AES_BLOCK_BYTES * AES_BLOCK_BYTES)
            else {
                continue;
            };
            if plaintext_size < BASE_HEADER
                || self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|maximum| plaintext_size > maximum)
                || self.limits.in_flight_bytes().is_some_and(|maximum| {
                    ciphertext_size
                        .checked_mul(2)
                        .is_none_or(|workspace| workspace > maximum)
                })
            {
                continue;
            }
            self.encrypted_header_candidates
                .push(EncryptedHeaderCandidate {
                    password,
                    plaintext_size,
                    ciphertext_size,
                });
        }
        if self.encrypted_header_candidates.is_empty() {
            return Err(Self::error(
                ErrorKind::Integrity,
                "wrong password or invalid encrypted RAR header size",
            ));
        }
        Ok(())
    }

    fn reset_encrypted_header(&mut self) {
        self.encrypted_header_salt = [0; 8];
        self.encrypted_header_salt_len = 0;
        self.encrypted_header_data = Vec::new();
        self.encrypted_header_candidates = Vec::new();
    }

    const fn next_header_state(&self) -> State {
        if self.main_flags & MHD_PASSWORD != 0 {
            State::EncryptedHeaders
        } else {
            State::Header
        }
    }

    fn push_header(&mut self, byte: u8) -> Result<(), ArchiveError> {
        let next = self
            .header
            .len()
            .checked_add(1)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR header length overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| next > maximum)
            || self
                .limits
                .in_flight_bytes()
                .is_some_and(|maximum| next > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR header exceeds the metadata or in-flight budget",
            ));
        }
        self.header
            .try_reserve(1)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR header allocation failed"))?;
        self.header.push(byte);
        if self.header.len() == BASE_HEADER {
            let target = usize::from(le_u16(&self.header, 5)?);
            if target < BASE_HEADER {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR header is shorter than its base",
                ));
            }
            if self
                .limits
                .metadata_bytes()
                .is_some_and(|maximum| target > maximum)
                || self
                    .limits
                    .in_flight_bytes()
                    .is_some_and(|maximum| target > maximum)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "RAR header exceeds the metadata or in-flight budget",
                ));
            }
            self.target = Some(target);
        }
        Ok(())
    }

    fn parse_header(&mut self, header: &[u8]) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        let expected = le_u16(header, 0)?;
        let kind = *header
            .get(2)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "RAR header type is missing"))?;
        let flags = le_u16(header, 3)?;
        match kind {
            MAIN_HEAD => {
                validate_header_crc(header, expected)?;
                self.parse_main(header, flags)
            },
            FILE_HEAD => {
                validate_header_crc(header, expected)?;
                self.parse_file(header, flags)
            },
            COMM_HEAD | AV_HEAD | SUB_HEAD | PROTECT_HEAD | SIGN_HEAD => {
                self.parse_auxiliary(header, kind, flags, expected, true, false)
            },
            NEWSUB_HEAD => self.parse_auxiliary(header, kind, flags, expected, false, false),
            ENDARC_HEAD => self.parse_auxiliary(header, kind, flags, expected, true, true),
            _ if flags & HD_SKIP_IF_UNKNOWN != 0 => {
                self.parse_auxiliary(header, kind, flags, expected, true, false)
            },
            _ => {
                validate_header_crc(header, expected)?;
                Err(Self::error(
                    ErrorKind::Unsupported,
                    "RAR archive header type is not implemented",
                ))
            },
        }
    }

    fn parse_auxiliary(
        &self,
        header: &[u8],
        kind: u8,
        flags: u16,
        expected_crc: u16,
        verify_payload_crc: bool,
        end_after: bool,
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if !self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR auxiliary header appears before the main header",
            ));
        }
        let next_volume = end_after && flags & 1 != 0;
        if next_volume && !self.allow_volumes {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR end header declares a following volume",
            ));
        }
        if kind == NEWSUB_HEAD && (flags & HD_ADD_SIZE_PRESENT == 0 || header.len() < FILE_HEADER) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR NEWSUB block is missing its long file-header fields",
            ));
        }
        let payload_size = if flags & HD_ADD_SIZE_PRESENT != 0 {
            if header.len() < 11 {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR long auxiliary header is missing its data size",
                ));
            }
            u64::from(le_u32(header, 7)?)
        } else {
            0
        };
        if !verify_payload_crc {
            validate_header_crc(header, expected_crc)?;
        }
        let metadata = if end_after && self.allow_volumes {
            let mut physical = vec![u8::from(next_volume)];
            physical.extend_from_slice(&self.entries.to_le_bytes());
            physical.extend_from_slice(&self.decoded.to_le_bytes());
            Some(ArchiveMetadata::new().with_extension(Extension::new(
                "rar-legacy",
                b"physical-volume-end".to_vec(),
                physical,
            )))
        } else if end_after {
            None
        } else {
            let mut detail = Vec::new();
            detail.try_reserve_exact(14).map_err(|_| {
                Self::error(ErrorKind::Limit, "RAR auxiliary metadata allocation failed")
            })?;
            detail.push(kind);
            detail.extend_from_slice(&flags.to_le_bytes());
            detail.extend_from_slice(
                &u16::try_from(header.len())
                    .map_err(|_| {
                        Self::error(ErrorKind::Limit, "RAR auxiliary header size overflow")
                    })?
                    .to_le_bytes(),
            );
            detail.extend_from_slice(&payload_size.to_le_bytes());
            detail.push(u8::from(verify_payload_crc));
            Some(ArchiveMetadata::new().with_extension(Extension::new(
                "rar-legacy",
                b"aux-block".to_vec(),
                detail,
            )))
        };
        let mut crc = Crc32::new();
        crc.update(&header[2..]);
        Ok(HeaderAction::Auxiliary {
            metadata,
            state: AuxiliaryState {
                remaining: payload_size,
                expected_crc,
                crc,
                verify_payload_crc,
                end_after,
            },
        })
    }

    fn parse_main(
        &mut self,
        header: &[u8],
        flags: u16,
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR archive contains more than one main header",
            ));
        }
        if header.len() < 13 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR main header is truncated",
            ));
        }
        if flags & MHD_ENCRYPTVER != 0 && header.len() < 14 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR main header encryption version is truncated",
            ));
        }
        let encrypted_headers = flags & MHD_PASSWORD != 0;
        if !encrypted_headers && flags & (MHD_VOLUME | MHD_FIRSTVOLUME) != 0 && !self.allow_volumes
        {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR multi-volume archives require a volume provider",
            ));
        }
        self.main_flags = flags;
        self.saw_main = true;
        let mut metadata = ArchiveMetadata::new().with_extension(Extension::new(
            "rar-legacy",
            b"main-flags".to_vec(),
            flags.to_le_bytes().to_vec(),
        ));
        if flags & MHD_ENCRYPTVER != 0 {
            metadata = metadata.with_extension(Extension::new(
                "rar-legacy",
                b"encrypt-version".to_vec(),
                vec![header[13]],
            ));
        }
        if encrypted_headers {
            metadata = metadata.with_extension(Extension::new(
                "rar-legacy",
                b"header-encryption".to_vec(),
                vec![1],
            ));
            Ok(HeaderAction::EncryptedHeaders(metadata))
        } else {
            Ok(HeaderAction::ArchiveMetadata(metadata))
        }
    }

    #[allow(clippy::too_many_lines)] // Fixed wire-order validation is easiest to audit linearly.
    fn parse_file(
        &mut self,
        header: &[u8],
        flags: u16,
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if !self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR file header appears before the main header",
            ));
        }
        if header.len() < FILE_HEADER {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR file header is truncated",
            ));
        }
        if flags & HD_ADD_SIZE_PRESENT == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR file header is missing its LONG_BLOCK marker",
            ));
        }
        let split_before = flags & FHD_SPLIT_BEFORE != 0;
        let split_after = flags & FHD_SPLIT_AFTER != 0;
        let split = split_before || split_after;
        let solid = flags & FHD_SOLID != 0;
        if split && !self.allow_volumes {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR split file data requires a volume provider",
            ));
        }
        if split && self.main_flags & MHD_VOLUME == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR split file appears outside a volume archive",
            ));
        }
        if solid && self.main_flags & MHD_SOLID == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR solid member appears outside a solid archive",
            ));
        }
        let encrypted = flags & FHD_PASSWORD != 0;
        let method = header[25];
        if !(0x30..=0x35).contains(&method) {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR entry uses an unknown compression method",
            ));
        }
        let mut packed_size = u64::from(le_u32(header, 7)?);
        let mut unpacked_size = u64::from(le_u32(header, 11)?);
        let host = header[15];
        if host > 5 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR entry uses an unknown host operating system",
            ));
        }
        let expected_crc = le_u32(header, 16)?;
        let dos_time = le_u32(header, 20)?;
        let unpack_version = header[24];
        let name_length = usize::from(le_u16(header, 26)?);
        let attributes = le_u32(header, 28)?;
        let mut cursor = FILE_HEADER;
        if flags & FHD_LARGE != 0 {
            let high_packed = u64::from(le_u32(header, cursor)?);
            let high_unpacked = u64::from(le_u32(header, cursor + 4)?);
            cursor = cursor
                .checked_add(8)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR header cursor overflow"))?;
            packed_size |= high_packed << 32;
            unpacked_size |= high_unpacked << 32;
        }
        let name_end = cursor
            .checked_add(name_length)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR path offset overflow"))?;
        let raw_name = header
            .get(cursor..name_end)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "RAR path exceeds its header"))?;
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| raw_name.len() > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR path exceeds the configured path budget",
            ));
        }
        let (mut name, encoding) = decode_name(raw_name, flags)?;
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| name.len() > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "decoded RAR path exceeds the configured path budget",
            ));
        }
        for byte in &mut name {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
        self.current_path.clone_from(&name);

        let mut extension_start = name_end;
        let encryption_salt = if flags & FHD_SALT != 0 {
            extension_start = extension_start
                .checked_add(8)
                .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR salt offset overflow"))?;
            if extension_start > header.len() {
                return Err(self.entry_error(ErrorKind::Malformed, "RAR salt is truncated"));
            }
            Some(
                header[name_end..extension_start]
                    .try_into()
                    .map_err(|_| self.entry_error(ErrorKind::Malformed, "RAR salt is malformed"))?,
            )
        } else {
            None
        };
        let mut times = EntryTimes::default();
        if dos_time != 0 {
            times.modified = Some(dos_timestamp(dos_time)?);
        }
        if flags & FHD_EXTTIME != 0 {
            let extended = header.get(extension_start..).ok_or_else(|| {
                self.entry_error(ErrorKind::Malformed, "RAR extended-time data is truncated")
            })?;
            times = extended_times(extended, times.modified)?;
        }
        let trailing = header.get(name_end..).ok_or_else(|| {
            self.entry_error(
                ErrorKind::Malformed,
                "RAR optional header data is truncated",
            )
        })?;

        if method == METHOD_STORE && !encrypted && !split && packed_size != unpacked_size {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "RAR Store packed and unpacked sizes differ",
            ));
        }
        if method == METHOD_STORE && !encrypted && split && packed_size > unpacked_size {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "RAR split Store part exceeds its declared logical size",
            ));
        }
        let budget_size = if split_before {
            packed_size
        } else {
            unpacked_size
        };
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| budget_size > maximum)
            || self.limits.decoded_total().is_some_and(|maximum| {
                self.decoded
                    .checked_add(budget_size)
                    .is_none_or(|total| total > maximum)
            })
        {
            return Err(self.entry_error(
                ErrorKind::Limit,
                "RAR entry exceeds the configured decoded-byte budget",
            ));
        }
        let next_entry = if split_before {
            self.entries
        } else {
            self.entries
                .checked_add(1)
                .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR entry count overflow"))?
        };
        if self
            .limits
            .entries()
            .is_some_and(|maximum| next_entry > maximum)
        {
            return Err(self.entry_error(
                ErrorKind::Limit,
                "RAR entry count exceeds the configured limit",
            ));
        }

        let (kind, mode) = entry_kind_and_mode(host, flags, attributes)?;
        let stored_symlink = kind == EntryKind::Symlink;
        if method != METHOD_STORE && !(29..=36).contains(&unpack_version) {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "compressed RAR entry requires an unsupported unpack generation",
            ));
        }
        if method != METHOD_STORE && stored_symlink {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "compressed RAR symbolic-link targets are not implemented",
            ));
        }
        if encrypted && stored_symlink {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "encrypted RAR symbolic-link targets require a decryption provider",
            ));
        }
        if split && kind != EntryKind::File {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "RAR non-file entry cannot be split between volumes",
            ));
        }
        if stored_symlink {
            let target_size = usize::try_from(unpacked_size).map_err(|_| {
                self.entry_error(
                    ErrorKind::Limit,
                    "RAR symbolic-link target exceeds the address space",
                )
            })?;
            if self
                .limits
                .path_bytes()
                .is_some_and(|maximum| target_size > maximum)
                || self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|maximum| target_size > maximum)
                || self
                    .limits
                    .in_flight_bytes()
                    .is_some_and(|maximum| target_size > maximum)
            {
                return Err(self.entry_error(
                    ErrorKind::Limit,
                    "RAR symbolic-link target exceeds a configured metadata budget",
                ));
            }
        }
        if kind != EntryKind::File && !stored_symlink && unpacked_size != 0 {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "non-file RAR entry unexpectedly carries data",
            ));
        }
        let path = ArchivePath::try_from_encoded(name, encoding).map_err(|_| {
            self.entry_error(ErrorKind::Malformed, "RAR entry path encoding is malformed")
        })?;
        let metadata_kind = if stored_symlink {
            EntryKind::File
        } else {
            kind
        };
        let metadata_size = if stored_symlink { 0 } else { unpacked_size };
        let mut builder = EntryMetadata::builder(metadata_kind, path)
            .size(Some(metadata_size))
            .mode(Some(mode))
            .encrypted(encrypted);
        if host <= 2 {
            builder = builder.file_flags(u64::from(attributes & !0x10));
        }
        if times != EntryTimes::default() {
            builder = builder.times(times);
        }
        builder = builder
            .extension(Extension::new(
                "rar-legacy",
                b"file-flags".to_vec(),
                flags.to_le_bytes().to_vec(),
            ))
            .extension(Extension::new(
                "rar-legacy",
                b"host-os".to_vec(),
                vec![host],
            ))
            .extension(Extension::new(
                "rar-legacy",
                b"file-attributes".to_vec(),
                attributes.to_le_bytes().to_vec(),
            ));
        if !trailing.is_empty() {
            builder = builder.extension(Extension::new(
                "rar-legacy",
                b"file-optional".to_vec(),
                trailing.to_vec(),
            ));
        }
        builder = builder.extension(Extension::new(
            "rar-legacy",
            b"unpack-version".to_vec(),
            vec![unpack_version],
        ));
        builder = builder.extension(Extension::new(
            "rar-legacy",
            b"compression-method".to_vec(),
            vec![method],
        ));
        if solid {
            builder = builder.extension(Extension::new("rar-legacy", b"solid".to_vec(), vec![1]));
        }
        if !split_after {
            builder = builder.checksum(Some(Checksum::new(
                ChecksumAlgorithm::Crc32,
                expected_crc.to_be_bytes().to_vec(),
            )?));
        }
        self.entries = next_entry;
        let metadata = Box::new(builder.build());
        let physical_raw = self.allow_volumes && split && method != METHOD_STORE && !encrypted;
        let payload_codec = if method == METHOD_STORE || encrypted || stored_symlink || physical_raw
        {
            if encrypted {
                self.retained_payload_codec = None;
            }
            None
        } else {
            let request = PayloadCodecRequest::new(
                PayloadCodecAlgorithm::Rar3,
                u64::from(method),
                u64::from(unpack_version),
                packed_size,
                unpacked_size,
                4 * 1024 * 1024,
            );
            if !self.payload_codecs.available() {
                return Err(self.entry_error(
                    ErrorKind::Unsupported,
                    "compressed RAR entry requires a payload codec provider",
                ));
            }
            let decoder = if solid {
                let previous = self.retained_payload_codec.take().ok_or_else(|| {
                    self.entry_error(
                        ErrorKind::Malformed,
                        "RAR solid compressed entry has no reusable decoder state",
                    )
                })?;
                self.payload_codecs
                    .continue_decoder(previous, request, self.limits)?
                    .ok_or_else(|| {
                        self.entry_error(
                            ErrorKind::Unsupported,
                            "RAR payload codec provider cannot continue this solid method",
                        )
                    })?
            } else {
                self.retained_payload_codec = None;
                self.payload_codecs
                    .decoder(request, self.limits)?
                    .ok_or_else(|| {
                        self.entry_error(
                            ErrorKind::Unsupported,
                            "RAR payload codec provider does not support this compression method",
                        )
                    })?
            };
            Some(decoder)
        };
        Ok(if stored_symlink {
            HeaderAction::Symlink {
                metadata,
                packed_size,
                expected_crc,
            }
        } else {
            HeaderAction::Entry {
                metadata,
                packed_size,
                unpacked_size,
                expected_crc,
                verify_checksum: (!split_before || split_after)
                    && !(split_after && expected_crc == u32::MAX),
                encrypted,
                encryption_salt,
                method,
                unpack_version,
                solid,
                split,
                physical_raw,
                payload_codec,
            }
        })
    }

    fn apply(&mut self, action: HeaderAction<P::Decoder>) -> DecodeEvent<'static> {
        match action {
            HeaderAction::ArchiveMetadata(metadata) => {
                self.state = State::Header;
                DecodeEvent::ArchiveMetadata(metadata)
            },
            HeaderAction::EncryptedHeaders(metadata) => {
                self.state = State::EncryptedHeaders;
                DecodeEvent::ArchiveMetadata(metadata)
            },
            HeaderAction::Entry {
                metadata,
                packed_size,
                unpacked_size,
                expected_crc,
                verify_checksum,
                encrypted,
                encryption_salt,
                method,
                unpack_version,
                solid,
                split,
                physical_raw,
                payload_codec,
            } => {
                self.encrypted_data = Vec::new();
                self.buffered_data = Vec::new();
                self.buffered_offset = 0;
                self.state = if encrypted {
                    State::EncryptedData(EncryptedState {
                        remaining: packed_size,
                        unpacked_size,
                        expected_crc,
                        verify_checksum,
                        method,
                        unpack_version,
                        salt: encryption_salt,
                        solid,
                        split,
                    })
                } else {
                    State::Data {
                        remaining: packed_size,
                        expected_crc,
                        verify_checksum,
                        physical_raw,
                        crc: Crc32::new(),
                    }
                };
                self.payload_codec = payload_codec;
                DecodeEvent::Entry(*metadata)
            },
            HeaderAction::Symlink {
                metadata,
                packed_size,
                expected_crc,
            } => {
                self.pending_link = Some(metadata);
                self.link_target.clear();
                self.state = State::LinkData {
                    remaining: packed_size,
                    expected_crc,
                    crc: Crc32::new(),
                };
                DecodeEvent::NeedInput
            },
            HeaderAction::Auxiliary { metadata, state } => {
                self.pending_archive_metadata = metadata;
                self.state = State::AuxData(state);
                DecodeEvent::NeedInput
            },
        }
    }

    #[allow(clippy::too_many_arguments)] // Arguments are the copied Data state fields.
    fn read_compressed_data<'a>(
        &mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        remaining: u64,
        expected_crc: u32,
        verify_checksum: bool,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let mut codec = self.payload_codec.take().ok_or_else(|| {
            self.entry_error(ErrorKind::Protocol, "RAR payload codec state is missing")
        })?;
        let count = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let codec_end = if count as u64 == remaining {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let codec_step = codec
            .process(&input[..count], scratch, codec_end)
            .map_err(|error| error.with_entry(self.entries, self.current_path.clone()))?
            .validate(count, scratch.len())?;
        let consumed = u64::try_from(codec_step.consumed)
            .map_err(|_| self.entry_error(ErrorKind::Limit, "RAR codec progress exceeds u64"))?;
        if consumed > remaining {
            return Err(self.entry_error(
                ErrorKind::Protocol,
                "RAR payload codec consumed beyond the packed data area",
            ));
        }
        let bytes = &scratch[..codec_step.produced];
        crc.update(bytes);
        self.decoded = self
            .decoded
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR decoded total overflow"))?;
        let remaining = remaining - consumed;
        match codec_step.status {
            CodecStatus::Done if remaining != 0 => {
                return Err(self.entry_error(
                    ErrorKind::Malformed,
                    "RAR payload codec ended before the packed data area",
                ));
            },
            CodecStatus::Done => {
                if self.main_flags & MHD_SOLID != 0 {
                    self.retained_payload_codec = Some(codec);
                }
            },
            CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                self.payload_codec = Some(codec);
            },
            _ => {
                return Err(self.entry_error(
                    ErrorKind::Protocol,
                    "RAR payload codec returned an unknown status",
                ));
            },
        }
        self.state = State::Data {
            remaining,
            expected_crc,
            verify_checksum,
            physical_raw: false,
            crc,
        };
        let event = if !bytes.is_empty() {
            DecodeEvent::Data(Chunk::new(bytes))
        } else if matches!(codec_step.status, CodecStatus::NeedOutput) {
            DecodeEvent::NeedOutput
        } else {
            DecodeEvent::NeedInput
        };
        Ok(DecodeStep {
            consumed: codec_step.consumed,
            produced: codec_step.produced,
            event,
        })
    }

    #[allow(clippy::too_many_arguments)] // Arguments are the copied Data state fields.
    fn read_data<'a>(
        &mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
        remaining: u64,
        expected_crc: u32,
        verify_checksum: bool,
        physical_raw: bool,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if remaining == 0 && self.payload_codec.is_none() {
            if verify_checksum && crc.finish() != expected_crc {
                return Err(self.entry_error(ErrorKind::Integrity, "RAR file CRC32 mismatch"));
            }
            self.state = self.next_header_state();
            return Ok(step(0, DecodeEvent::EndEntry));
        }
        if self.payload_codec.is_some() {
            return self.read_compressed_data(
                input,
                scratch,
                remaining,
                expected_crc,
                verify_checksum,
                crc,
            );
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(self.entry_error(ErrorKind::Malformed, "truncated RAR file data"));
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let bytes = &input[..count];
        crc.update(bytes);
        if !physical_raw {
            self.decoded = self
                .decoded
                .checked_add(count as u64)
                .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR decoded total overflow"))?;
        }
        self.state = State::Data {
            remaining: remaining - count as u64,
            expected_crc,
            verify_checksum,
            physical_raw,
            crc,
        };
        Ok(step(count, DecodeEvent::Data(Chunk::new(bytes))))
    }

    fn read_encrypted_data<'a>(
        &mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
        mut encrypted: EncryptedState,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if !self.crypto.available() {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "encrypted RAR file data requires a decryption provider",
            ));
        }
        let candidate_count = self.password_candidate_count()?;
        if candidate_count == 0 {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "encrypted RAR file data requires a password candidate",
            ));
        }
        if encrypted.solid || encrypted.split {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "solid or split encrypted RAR data requires replayable decoder state",
            ));
        }
        let total_ciphertext = self
            .encrypted_data
            .len()
            .checked_add(usize::try_from(encrypted.remaining).map_err(|_| {
                self.entry_error(
                    ErrorKind::Limit,
                    "encrypted RAR ciphertext exceeds the address space",
                )
            })?)
            .ok_or_else(|| {
                self.entry_error(ErrorKind::Limit, "encrypted RAR ciphertext length overflow")
            })?;
        let _ = self.encrypted_payload_limits(total_ciphertext, encrypted.unpacked_size)?;
        if encrypted.remaining != 0 {
            if input.is_empty() {
                if matches!(end, EndOfInput::End) {
                    return Err(self.entry_error(
                        ErrorKind::Malformed,
                        "encrypted RAR file data is truncated",
                    ));
                }
                return Ok(step(0, DecodeEvent::NeedInput));
            }
            let count = usize::try_from(encrypted.remaining)
                .unwrap_or(usize::MAX)
                .min(input.len());
            self.encrypted_data.try_reserve(count).map_err(|_| {
                self.entry_error(
                    ErrorKind::Limit,
                    "encrypted RAR ciphertext allocation failed",
                )
            })?;
            self.encrypted_data.extend_from_slice(&input[..count]);
            encrypted.remaining -= count as u64;
            self.state = State::EncryptedData(encrypted);
            return Ok(step(count, DecodeEvent::NeedInput));
        }

        if self.encrypted_data.is_empty()
            || !self.encrypted_data.len().is_multiple_of(AES_BLOCK_BYTES)
        {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "encrypted RAR file data is not AES block aligned",
            ));
        }
        if encrypted.method != METHOD_STORE && scratch.is_empty() {
            self.state = State::EncryptedData(encrypted);
            return Ok(step(0, DecodeEvent::NeedOutput));
        }

        let plaintext = self.try_encrypted_candidates(encrypted, scratch, candidate_count)?;
        self.encrypted_data = Vec::new();
        let Some(plaintext) = plaintext else {
            return Err(self.entry_error(
                ErrorKind::Integrity,
                "wrong password or corrupt encrypted RAR data",
            ));
        };
        self.buffered_data = plaintext;
        self.buffered_offset = 0;
        self.state = State::BufferedData;
        Ok(step(0, DecodeEvent::NeedInput))
    }

    fn try_encrypted_candidates(
        &self,
        encrypted: EncryptedState,
        scratch: &mut [u8],
        candidate_count: usize,
    ) -> Result<Option<Vec<u8>>, ArchiveError> {
        let unpacked = usize::try_from(encrypted.unpacked_size).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "encrypted RAR output exceeds the address space",
            )
        })?;
        for candidate in 0..candidate_count {
            let mut plaintext = Vec::new();
            plaintext
                .try_reserve_exact(self.encrypted_data.len())
                .map_err(|_| {
                    self.entry_error(
                        ErrorKind::Limit,
                        "encrypted RAR candidate allocation failed",
                    )
                })?;
            plaintext.extend_from_slice(&self.encrypted_data);
            if let Err(error) = self
                .crypto
                .decrypt(candidate, encrypted.salt, &mut plaintext)
            {
                if error.kind() == ErrorKind::Protocol {
                    return Err(error.with_entry(self.entries, self.current_path.clone()));
                }
                continue;
            }

            let decoded = if encrypted.method == METHOD_STORE {
                if unpacked > plaintext.len() {
                    continue;
                }
                plaintext.truncate(unpacked);
                plaintext
            } else {
                let Some(decoded) =
                    self.decode_encrypted_candidate(&plaintext, encrypted, scratch)?
                else {
                    continue;
                };
                decoded
            };
            if (!encrypted.verify_checksum || crc32(&decoded) == encrypted.expected_crc)
                && decoded.len() == unpacked
            {
                return Ok(Some(decoded));
            }
        }
        Ok(None)
    }

    fn decode_encrypted_candidate(
        &self,
        plaintext: &[u8],
        encrypted: EncryptedState,
        scratch: &mut [u8],
    ) -> Result<Option<Vec<u8>>, ArchiveError> {
        if !self.payload_codecs.available() {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "compressed encrypted RAR entry requires a payload codec provider",
            ));
        }
        let limits = self.encrypted_payload_limits(plaintext.len(), encrypted.unpacked_size)?;
        let request = PayloadCodecRequest::new(
            PayloadCodecAlgorithm::Rar3,
            u64::from(encrypted.method),
            u64::from(encrypted.unpack_version),
            plaintext.len() as u64,
            encrypted.unpacked_size,
            4 * 1024 * 1024,
        );
        let mut codec = self
            .payload_codecs
            .decoder(request, limits)?
            .ok_or_else(|| {
                self.entry_error(
                    ErrorKind::Unsupported,
                    "RAR payload codec provider does not support the encrypted compression method",
                )
            })?;
        let expected = usize::try_from(encrypted.unpacked_size).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "encrypted RAR output exceeds the address space",
            )
        })?;
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(expected).map_err(|_| {
            self.entry_error(ErrorKind::Limit, "encrypted RAR output allocation failed")
        })?;
        let mut offset = 0;
        loop {
            let codec_step = match codec.process(&plaintext[offset..], scratch, EndOfInput::End) {
                Ok(step) => step.validate(plaintext.len() - offset, scratch.len())?,
                Err(error) if error.kind() == ErrorKind::Protocol => return Err(error),
                Err(_) => return Ok(None),
            };
            let next_len = decoded
                .len()
                .checked_add(codec_step.produced)
                .ok_or_else(|| {
                    self.entry_error(ErrorKind::Limit, "encrypted RAR output length overflow")
                })?;
            if next_len > expected {
                return Ok(None);
            }
            decoded.extend_from_slice(&scratch[..codec_step.produced]);
            offset = offset.checked_add(codec_step.consumed).ok_or_else(|| {
                self.entry_error(ErrorKind::Limit, "encrypted RAR codec offset overflow")
            })?;
            match codec_step.status {
                CodecStatus::Done => return Ok(Some(decoded)),
                CodecStatus::NeedInput if offset == plaintext.len() => return Ok(None),
                CodecStatus::NeedInput | CodecStatus::NeedOutput => {},
                _ => {
                    return Err(self.entry_error(
                        ErrorKind::Protocol,
                        "RAR payload codec returned an unknown status",
                    ));
                },
            }
        }
    }

    fn encrypted_payload_limits(
        &self,
        packed: usize,
        unpacked: u64,
    ) -> Result<Limits, ArchiveError> {
        let unpacked = usize::try_from(unpacked).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "encrypted RAR output exceeds the address space",
            )
        })?;
        let external = packed
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(unpacked))
            .ok_or_else(|| {
                self.entry_error(ErrorKind::Limit, "encrypted RAR buffer accounting overflow")
            })?;
        let in_flight = self
            .limits
            .in_flight_bytes()
            .map(|maximum| {
                maximum.checked_sub(external).ok_or_else(|| {
                    self.entry_error(
                        ErrorKind::Limit,
                        "encrypted RAR buffers exceed the in-flight budget",
                    )
                })
            })
            .transpose()?;
        Ok(self.limits.with_in_flight_bytes(in_flight))
    }

    fn read_buffered_data<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if self.buffered_offset == self.buffered_data.len() {
            self.buffered_data = Vec::new();
            self.buffered_offset = 0;
            self.state = self.next_header_state();
            return Ok(step(0, DecodeEvent::EndEntry));
        }
        if output.is_empty() {
            return Ok(step(0, DecodeEvent::NeedOutput));
        }
        let count = (self.buffered_data.len() - self.buffered_offset).min(output.len());
        let end = self.buffered_offset + count;
        output[..count].copy_from_slice(&self.buffered_data[self.buffered_offset..end]);
        self.buffered_offset = end;
        self.decoded = self
            .decoded
            .checked_add(count as u64)
            .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR decoded total overflow"))?;
        Ok(DecodeStep {
            consumed: 0,
            produced: count,
            event: DecodeEvent::Data(Chunk::new(&output[..count])),
        })
    }

    fn read_link_data(
        &mut self,
        input: &[u8],
        end: EndOfInput,
        remaining: u64,
        expected_crc: u32,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'static>, ArchiveError> {
        if remaining == 0 {
            if crc.finish() != expected_crc {
                return Err(self.entry_error(
                    ErrorKind::Integrity,
                    "RAR symbolic-link target CRC32 mismatch",
                ));
            }
            if self.link_target.is_empty() || self.link_target.contains(&0) {
                return Err(self.entry_error(
                    ErrorKind::Malformed,
                    "RAR symbolic-link target is empty or contains a NUL byte",
                ));
            }
            let target = ArchivePath::try_from_encoded(
                core::mem::take(&mut self.link_target),
                PathEncoding::Bytes,
            )
            .map_err(|_| {
                self.entry_error(
                    ErrorKind::Malformed,
                    "RAR symbolic-link target encoding is malformed",
                )
            })?;
            let metadata = self.pending_link.take().ok_or_else(|| {
                self.entry_error(ErrorKind::Protocol, "RAR symbolic-link metadata is missing")
            })?;
            let metadata = (*metadata)
                .into_builder()
                .kind(EntryKind::Symlink)
                .size(Some(0))
                .link_target(Some(target))
                .try_build()
                .map_err(|error| error.with_format("rar-legacy"))?;
            self.state = State::LinkEnd;
            return Ok(step(0, DecodeEvent::Entry(metadata)));
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(
                    self.entry_error(ErrorKind::Malformed, "truncated RAR symbolic-link target")
                );
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
        self.link_target.try_reserve(count).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "RAR symbolic-link target allocation failed",
            )
        })?;
        let bytes = &input[..count];
        self.link_target.extend_from_slice(bytes);
        crc.update(bytes);
        self.decoded = self
            .decoded
            .checked_add(count as u64)
            .ok_or_else(|| self.entry_error(ErrorKind::Limit, "RAR decoded total overflow"))?;
        self.state = State::LinkData {
            remaining: remaining - count as u64,
            expected_crc,
            crc,
        };
        Ok(step(count, DecodeEvent::NeedInput))
    }

    fn read_auxiliary(
        &mut self,
        input: &[u8],
        end: EndOfInput,
        mut auxiliary: AuxiliaryState,
    ) -> Result<DecodeStep<'static>, ArchiveError> {
        if auxiliary.remaining == 0 {
            if auxiliary.verify_payload_crc
                && auxiliary.crc.finish() & u32::from(u16::MAX) != u32::from(auxiliary.expected_crc)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "RAR auxiliary block CRC32 mismatch",
                ));
            }
            if auxiliary.end_after {
                if let Some(metadata) = self.pending_archive_metadata.take() {
                    self.state = State::Tail;
                    return Ok(step(0, DecodeEvent::ArchiveMetadata(metadata)));
                }
                if matches!(end, EndOfInput::End) {
                    self.state = State::Done;
                    return Ok(step(input.len(), DecodeEvent::Done));
                }
                self.state = State::Tail;
                return Ok(step(input.len(), DecodeEvent::NeedInput));
            }
            self.state = self.next_header_state();
            return Ok(step(
                0,
                self.pending_archive_metadata
                    .take()
                    .map_or(DecodeEvent::NeedInput, DecodeEvent::ArchiveMetadata),
            ));
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR auxiliary block payload is truncated",
                ));
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(auxiliary.remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
        auxiliary.crc.update(&input[..count]);
        auxiliary.remaining -= count as u64;
        self.state = State::AuxData(auxiliary);
        Ok(step(count, DecodeEvent::NeedInput))
    }
}

impl<P, C> ArchiveDecoder for RarLegacyDecoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar3CryptoProvider,
{
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self.state {
            State::Signature {
                window,
                length,
                scanned,
            } => self.scan_signature(input, end, window, length, scanned),
            State::Header => self.read_header(input, end),
            State::EncryptedHeaders => self.read_encrypted_header(input, end),
            State::Data {
                remaining,
                expected_crc,
                verify_checksum,
                physical_raw,
                crc,
            } => self.read_data(
                input,
                output,
                end,
                remaining,
                expected_crc,
                verify_checksum,
                physical_raw,
                crc,
            ),
            State::EncryptedData(encrypted) => {
                self.read_encrypted_data(input, output, end, encrypted)
            },
            State::BufferedData => self.read_buffered_data(output),
            State::LinkData {
                remaining,
                expected_crc,
                crc,
            } => self.read_link_data(input, end, remaining, expected_crc, crc),
            State::LinkEnd => {
                self.state = self.next_header_state();
                Ok(step(0, DecodeEvent::EndEntry))
            },
            State::AuxData(auxiliary) => self.read_auxiliary(input, end, auxiliary),
            State::Tail => {
                if matches!(end, EndOfInput::End) {
                    self.state = State::Done;
                    Ok(step(input.len(), DecodeEvent::Done))
                } else {
                    Ok(step(input.len(), DecodeEvent::NeedInput))
                }
            },
            State::Done => {
                if input.is_empty() {
                    Ok(step(0, DecodeEvent::Done))
                } else {
                    Err(Self::error(
                        ErrorKind::Protocol,
                        "RAR decoder received input after completion",
                    ))
                }
            },
        }
    }
}

fn validate_header_crc(header: &[u8], expected: u16) -> Result<(), ArchiveError> {
    if crc32(&header[2..]) & u32::from(u16::MAX) != u32::from(expected) {
        return Err(rar_legacy_error(
            ErrorKind::Integrity,
            "RAR header CRC32 mismatch",
        ));
    }
    Ok(())
}

fn decode_name(bytes: &[u8], flags: u16) -> Result<(Vec<u8>, PathEncoding), ArchiveError> {
    if flags & FHD_UNICODE == 0 {
        if bytes.contains(&0) {
            return Err(rar_legacy_error(
                ErrorKind::Malformed,
                "RAR path contains a NUL byte",
            ));
        }
        return Ok((bytes.to_vec(), PathEncoding::Bytes));
    }
    let Some(separator) = bytes.iter().position(|byte| *byte == 0) else {
        core::str::from_utf8(bytes).map_err(|_| {
            rar_legacy_error(ErrorKind::Malformed, "RAR Unicode path is not valid UTF-8")
        })?;
        return Ok((bytes.to_vec(), PathEncoding::Utf8));
    };
    if separator == 0 || separator + 1 >= bytes.len() {
        return Err(rar_legacy_error(
            ErrorKind::Malformed,
            "RAR compressed Unicode path is truncated",
        ));
    }
    let ansi = &bytes[..separator];
    let encoded = &bytes[separator + 1..];
    let units = decode_unicode_units(ansi, encoded)?;
    let mut name = alloc::string::String::new();
    for decoded in char::decode_utf16(units) {
        name.push(decoded.map_err(|_| {
            rar_legacy_error(
                ErrorKind::Malformed,
                "RAR Unicode path contains an unpaired surrogate",
            )
        })?);
    }
    Ok((name.into_bytes(), PathEncoding::Utf8))
}

fn decode_unicode_units(ansi: &[u8], encoded: &[u8]) -> Result<Vec<u16>, ArchiveError> {
    let high = u16::from(encoded[0]) << 8;
    let mut cursor = 1;
    let mut flags = 0_u8;
    let mut flag_bits = 0_u8;
    let mut units = Vec::new();
    while cursor < encoded.len() {
        if flag_bits == 0 {
            flags = encoded[cursor];
            cursor += 1;
            flag_bits = 8;
        }
        flag_bits -= 2;
        match (flags >> flag_bits) & 3 {
            0 => {
                let low = take_byte(encoded, &mut cursor)?;
                units.push(u16::from(low));
            },
            1 => {
                let low = take_byte(encoded, &mut cursor)?;
                units.push(high | u16::from(low));
            },
            2 => {
                let low = take_byte(encoded, &mut cursor)?;
                let high_byte = take_byte(encoded, &mut cursor)?;
                units.push(u16::from_le_bytes([low, high_byte]));
            },
            3 => {
                let length = take_byte(encoded, &mut cursor)?;
                let correction = if length & 0x80 != 0 {
                    take_byte(encoded, &mut cursor)?
                } else {
                    0
                };
                let count = usize::from(length & 0x7f) + 2;
                for _ in 0..count {
                    let source = ansi.get(units.len()).ok_or_else(|| {
                        rar_legacy_error(
                            ErrorKind::Malformed,
                            "RAR Unicode path references missing fallback bytes",
                        )
                    })?;
                    units.push(high | u16::from(source.wrapping_add(correction)));
                }
            },
            _ => {
                return Err(rar_legacy_error(
                    ErrorKind::Protocol,
                    "RAR Unicode flag decoder entered an invalid state",
                ));
            },
        }
    }
    if units.is_empty() {
        return Err(rar_legacy_error(
            ErrorKind::Malformed,
            "RAR Unicode path decodes to an empty name",
        ));
    }
    Ok(units)
}

fn take_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, ArchiveError> {
    let byte = bytes
        .get(*cursor)
        .copied()
        .ok_or_else(|| rar_legacy_error(ErrorKind::Malformed, "RAR Unicode path is truncated"))?;
    *cursor = cursor
        .checked_add(1)
        .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR path cursor overflow"))?;
    Ok(byte)
}

fn entry_kind_and_mode(
    host: u8,
    flags: u16,
    attributes: u32,
) -> Result<(EntryKind, u32), ArchiveError> {
    if host == 3 || host == 4 || host == 5 {
        let kind = match attributes & 0o170_000 {
            0 | 0o100_000 => EntryKind::File,
            0o040_000 => EntryKind::Dir,
            0o120_000 => EntryKind::Symlink,
            0o020_000 => EntryKind::Char,
            0o060_000 => EntryKind::Block,
            0o010_000 => EntryKind::Fifo,
            0o140_000 => EntryKind::Socket,
            _ => {
                return Err(rar_legacy_error(
                    ErrorKind::Unsupported,
                    "RAR Unix entry type is unknown",
                ));
            },
        };
        return Ok((kind, attributes));
    }
    let directory = flags & FHD_DIRECTORY == FHD_DIRECTORY || attributes & 0x10 != 0;
    Ok(if directory {
        (EntryKind::Dir, 0o040_755)
    } else {
        (EntryKind::File, 0o100_644)
    })
}

fn dos_timestamp(raw: u32) -> Result<Timestamp, ArchiveError> {
    let second = i64::from(raw & 0x1f) * 2;
    let minute = i64::from((raw >> 5) & 0x3f);
    let hour = i64::from((raw >> 11) & 0x1f);
    let day = i64::from((raw >> 16) & 0x1f);
    let month = i64::from((raw >> 21) & 0x0f);
    let year = i64::from((raw >> 25) & 0x7f) + 1980;
    if second > 59
        || minute > 59
        || hour > 23
        || day == 0
        || month == 0
        || month > 12
        || day > days_in_month(year, month)
    {
        return Err(rar_legacy_error(
            ErrorKind::Malformed,
            "RAR DOS timestamp fields are out of range",
        ));
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR timestamp overflow"))?;
    Ok(Timestamp::from_seconds(seconds))
}

fn extended_times(bytes: &[u8], base_mtime: Option<Timestamp>) -> Result<EntryTimes, ArchiveError> {
    if bytes.len() < 2 {
        return Err(rar_legacy_error(
            ErrorKind::Malformed,
            "RAR extended-time flags are truncated",
        ));
    }
    let flags = le_u16(bytes, 0)?;
    let mut cursor = 2_usize;
    let mut times = EntryTimes {
        modified: base_mtime,
        ..EntryTimes::default()
    };
    for slot in 0..4 {
        let shift = 12 - slot * 4;
        let mode = (flags >> shift) & 0x0f;
        if mode & 8 == 0 {
            if mode != 0 {
                return Err(rar_legacy_error(
                    ErrorKind::Malformed,
                    "RAR extended-time mode has fields without the valid bit",
                ));
            }
            continue;
        }
        let base = if slot == 0 {
            base_mtime.ok_or_else(|| {
                rar_legacy_error(
                    ErrorKind::Malformed,
                    "RAR extended mtime is missing its DOS base time",
                )
            })?
        } else {
            let raw = le_u32(bytes, cursor)?;
            cursor = cursor
                .checked_add(4)
                .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR time cursor overflow"))?;
            dos_timestamp(raw)?
        };
        let count = usize::from(mode & 3);
        let end = cursor.checked_add(count).ok_or_else(|| {
            rar_legacy_error(ErrorKind::Limit, "RAR time fraction offset overflow")
        })?;
        let fraction = bytes.get(cursor..end).ok_or_else(|| {
            rar_legacy_error(
                ErrorKind::Malformed,
                "RAR extended-time fraction is truncated",
            )
        })?;
        cursor = end;
        let mut ticks = 0_u32;
        for byte in fraction {
            ticks = (u32::from(*byte) << 16) | (ticks >> 8);
        }
        if ticks >= 10_000_000 {
            return Err(rar_legacy_error(
                ErrorKind::Malformed,
                "RAR extended-time fraction is at least one second",
            ));
        }
        let seconds = base
            .seconds()
            .checked_add(i64::from(mode & 4 != 0))
            .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR extended time overflow"))?;
        let timestamp = Timestamp::new(seconds, ticks * 100)
            .map_err(|error| error.with_format("rar-legacy"))?;
        match slot {
            0 => times.modified = Some(timestamp),
            1 => times.changed = Some(timestamp),
            2 => times.accessed = Some(timestamp),
            3 => {}, // Archive time has no matching portable EntryTimes field.
            _ => {
                return Err(rar_legacy_error(
                    ErrorKind::Protocol,
                    "RAR extended-time decoder entered an invalid state",
                ));
            },
        }
    }
    Ok(times)
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, ArchiveError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR u16 offset overflow"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| rar_legacy_error(ErrorKind::Malformed, "RAR u16 is truncated"))?
        .try_into()
        .map_err(|_| rar_legacy_error(ErrorKind::Malformed, "RAR u16 is malformed"))?;
    Ok(u16::from_le_bytes(raw))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| rar_legacy_error(ErrorKind::Limit, "RAR u32 offset overflow"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| rar_legacy_error(ErrorKind::Malformed, "RAR u32 is truncated"))?
        .try_into()
        .map_err(|_| rar_legacy_error(ErrorKind::Malformed, "RAR u32 is malformed"))?;
    Ok(u32::from_le_bytes(raw))
}

#[derive(Debug, Clone, Copy)]
struct Crc32(u32);

impl Crc32 {
    const fn new() -> Self {
        Self(0xffff_ffff)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let index = ((self.0 ^ u32::from(*byte)) & 0xff) as usize;
            self.0 = CRC32_TABLE[index] ^ (self.0 >> 8);
        }
    }

    const fn finish(self) -> u32 {
        !self.0
    }
}

const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    let mut polynomial_input = 0_u32;
    while index < table.len() {
        let mut value = polynomial_input;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
        polynomial_input += 1;
    }
    table
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

const fn step(consumed: usize, event: DecodeEvent<'_>) -> DecodeStep<'_> {
    DecodeStep {
        consumed,
        produced: 0,
        event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct CountCrypto(usize);

    impl Rar3CryptoProvider for CountCrypto {
        fn candidate_count(&self) -> usize {
            self.0
        }

        fn decrypt(
            &self,
            _candidate: usize,
            _salt: Option<[u8; 8]>,
            _ciphertext: &mut [u8],
        ) -> Result<(), ArchiveError> {
            Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("candidate bounds were not validated before decryption"))
        }
    }

    #[test]
    fn crypto_candidate_count_is_bounded_independently_of_the_provider() {
        let accepted = RarLegacyDecoder::with_crypto(Limits::safe(), CountCrypto(16));
        assert_eq!(accepted.password_candidate_count().unwrap(), 16);

        let rejected = RarLegacyDecoder::with_crypto(Limits::safe(), CountCrypto(17));
        assert_eq!(
            rejected.password_candidate_count().unwrap_err().kind(),
            ErrorKind::Limit
        );
    }
}
