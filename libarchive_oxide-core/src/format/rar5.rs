// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RAR5 container reader with injected payload and crypto providers.
//!
//! The container structures are implemented from RARLAB's public RAR 5.0 technote.
//! File times, Unix ownership, versions, links, and unknown extra records are preserved or typed.
//! `CRC32` and `BLAKE2sp` payload hashes are verified, compression generations 0/1 are validated, and Store or injected generation-0 UTF-8 archive comments are decoded.
//! Quick-open caches and recovery records are checksum-verified and skipped with their sizes reported.
//! Store-method NTFS ACL descriptors are retained under the metadata budget; alternate-stream bodies are verified and skipped while their file association, size, and raw parameters are preserved.
//! Independent compressed services use a concrete provider decoder without disturbing a retained solid-file decoder or exposing their plaintext as entry data.
//! Recovery repair is intentionally not performed.
//! Compression dictionary claims,
//! including generation-1 fractional sizes, are bounded before codec dispatch.
//! Forward-compatible unknown headers carrying the documented skip flag have their CRC-checked header and exact data extent discarded without allocation.
//! A generic associated-key crypto provider handles ordered RAR5 password candidates, encrypted headers, services, and single-volume non-solid file data.
//! Ciphertext, candidate plaintext, PBKDF2 work, and compressed padding replay are bounded; exact output plus raw or HMAC-tweaked CRC32/BLAKE2sp is authenticated before any plaintext is exposed.
//! An independent generic payload-codec provider handles generation-0 methods 1–5 without coupling this container to a concrete codec crate.
//! Completed concrete decoders are moved back through that same boundary to continue unencrypted solid members without type erasure.
//! Generation 1, unsupported filters, and encrypted solid or split members remain explicit typed failures.
//! A hidden physical-volume mode supplies Store data or raw compressed parts and validated end-header signals to the bounded high-level `VolumeSet` provider,
//! which owns compressed-state continuation across physical readers.

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::blake2sp::Blake2sp;
use crate::metadata::{
    ArchiveMetadata, ArchivePath, Checksum, ChecksumAlgorithm, EntryMetadata, EntryTimes,
    Extension, Owner, PathEncoding,
};
use crate::protocol::{ArchiveDecoder, Chunk, DecodeEvent, DecodeStep, EndOfInput};
use crate::{
    ArchiveError, Codec, CodecStatus, EntryKind, ErrorKind, Limits, NoPayloadCodecProvider,
    NoRar5CryptoProvider, PayloadCodecAlgorithm, PayloadCodecProvider, PayloadCodecRequest,
    Rar5CryptoParameters, Rar5CryptoProvider, Timestamp,
};

const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const MAX_SFX_BYTES: u64 = 1024 * 1024;
const MAX_HEADER_BYTES: u64 = 2 * 1024 * 1024;
const AES_BLOCK_BYTES: usize = 16;
const MAX_PASSWORD_CANDIDATES: usize = 16;

fn rar5_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("rar5")
        .with_context(context)
}

const HEADER_EXTRA: u64 = 0x0001;
const HEADER_DATA: u64 = 0x0002;
const HEADER_SKIP_IF_UNKNOWN: u64 = 0x0004;
const HEADER_PREVIOUS_VOLUME: u64 = 0x0008;
const HEADER_NEXT_VOLUME: u64 = 0x0010;
const HEADER_DEPENDS_ON_PREVIOUS: u64 = 0x0020;
const HEADER_PRESERVE_CHILD: u64 = 0x0040;
const HEADER_KNOWN_FLAGS: u64 = 0x007f;

const FILE_DIRECTORY: u64 = 0x0001;
const FILE_MTIME: u64 = 0x0002;
const FILE_CRC32: u64 = 0x0004;
const FILE_UNKNOWN_SIZE: u64 = 0x0008;
const FILE_KNOWN_FLAGS: u64 = 0x000f;

const ARCHIVE_VOLUME: u64 = 0x0001;
const ARCHIVE_SOLID: u64 = 0x0004;
const ARCHIVE_RECOVERY: u64 = 0x0008;

#[derive(Debug, Clone, Copy)]
enum Rar5State {
    Signature {
        window: [u8; SIGNATURE.len()],
        length: usize,
        scanned: u64,
    },
    Header,
    EncryptedHeaders,
    EncryptedData(EncryptedState),
    EncryptedService(EncryptedServiceState),
    BufferedData,
    Data {
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        verify_checksum: bool,
        physical_raw: bool,
        crc: Crc32,
    },
    ServiceData {
        kind: ServiceKind,
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        crc: Crc32,
    },
    SkipData {
        remaining: u64,
    },
    Tail,
    Done,
}

#[allow(clippy::large_enum_variant)] // Each action is consumed immediately into one DecodeEvent.
enum HeaderAction<D> {
    ArchiveMetadata(ArchiveMetadata),
    EncryptedHeaders {
        metadata: ArchiveMetadata,
        parameters: Rar5CryptoParameters,
    },
    Entry {
        metadata: EntryMetadata,
        packed_size: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        verify_checksum: bool,
        encryption: Option<Rar5FileEncryption>,
        unpacked_size: u64,
        compression: Rar5CompressionInfo,
        split: bool,
        physical_raw: bool,
        payload_codec: Option<D>,
    },
    Service {
        kind: ServiceKind,
        packed_size: u64,
        unpacked_size: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        encryption: Option<Rar5FileEncryption>,
        compression: Rar5CompressionInfo,
        payload_codec: Option<D>,
    },
    Skip {
        packed_size: u64,
    },
    End {
        next_volume: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceKind {
    ArchiveComment,
    QuickOpen,
    RecoveryRecord,
    Acl,
    AlternateStream,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ServiceProgress {
    #[default]
    None,
    ArchiveComment,
    QuickOpen,
    RecoveryRecord,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SplitFlags {
    before: bool,
    after: bool,
}

#[derive(Debug, Clone, Copy)]
struct Rar5FileEncryption {
    parameters: Rar5CryptoParameters,
    iv: [u8; AES_BLOCK_BYTES],
}

#[derive(Debug, Clone, Copy)]
struct EncryptedState {
    remaining: u64,
    unpacked_size: u64,
    expected_crc: Option<u32>,
    expected_blake2sp: Option<[u8; 32]>,
    verify_checksum: bool,
    compression: Rar5CompressionInfo,
    encryption: Rar5FileEncryption,
    split: bool,
}

#[derive(Debug, Clone, Copy)]
struct EncryptedServiceState {
    kind: ServiceKind,
    payload: EncryptedState,
}

struct EncryptedHeaderCandidate<K> {
    key: K,
    plaintext_size: usize,
    ciphertext_size: usize,
}

impl SplitFlags {
    const fn from_common_flags(flags: u64) -> Self {
        Self {
            before: flags & HEADER_PREVIOUS_VOLUME != 0,
            after: flags & HEADER_NEXT_VOLUME != 0,
        }
    }

    const fn any(self) -> bool {
        self.before || self.after
    }

    const fn encoded(self) -> [u8; 2] {
        [self.before as u8, self.after as u8]
    }
}

/// Streaming checksum state used by the bounded RAR5 volume adapter.
///
/// This is an internal cross-crate seam rather than a general hashing API.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Rar5SplitVerifier {
    crc: Crc32,
    blake2sp: Blake2sp,
}

impl Rar5SplitVerifier {
    /// Starts checksum accumulation for one logical split Store entry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            crc: Crc32::new(),
            blake2sp: Blake2sp::new(),
        }
    }

    /// Folds one decoded Store chunk into both possible RAR5 checksums.
    pub fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        self.blake2sp.update(bytes);
    }

    /// Verifies the final part's logical checksum.
    #[must_use]
    pub fn verifies(&self, checksum: &Checksum) -> bool {
        match checksum.algorithm() {
            ChecksumAlgorithm::Crc32 => self.crc.finish().to_be_bytes() == checksum.as_bytes(),
            ChecksumAlgorithm::Blake2sp => self.blake2sp.clone().finalize() == checksum.as_bytes(),
            _ => false,
        }
    }

    /// Verifies the optional CRC stored alongside a RAR5 `BLAKE2sp` record.
    #[must_use]
    pub fn verifies_crc32(&self, expected: u32) -> bool {
        self.crc.finish() == expected
    }

    /// Returns the accumulated `BLAKE2sp` digest for conformance tests.
    #[must_use]
    pub fn blake2sp(&self) -> [u8; 32] {
        self.blake2sp.clone().finalize()
    }
}

impl Default for Rar5SplitVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct FileExtras {
    blake2sp: Option<[u8; 32]>,
    times: Option<EntryTimes>,
    owner: Option<Owner>,
    redirection: Option<Redirection>,
    version: Option<u64>,
    encryption: Option<Rar5FileEncryption>,
    retained_bytes: usize,
}

#[derive(Debug, Default)]
struct ServiceExtras {
    blake2sp: Option<[u8; 32]>,
    encryption: Option<Rar5FileEncryption>,
}

/// Validated RAR5 compression-information word carried by a file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rar5CompressionInfo {
    version: u64,
    method: u64,
    solid: bool,
    dictionary: u64,
}

impl Rar5CompressionInfo {
    /// Parses and validates one wire-format compression-information word.
    pub fn from_raw(value: u64) -> Result<Self, ArchiveError> {
        parse_compression_info(value)
    }

    /// Compression algorithm generation.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Compression method/level identifier (`0` is Store, `1..=5` are LZ).
    #[must_use]
    pub const fn method(self) -> u64 {
        self.method
    }

    /// Whether this file continues the previous solid dictionary.
    #[must_use]
    pub const fn solid(self) -> bool {
        self.solid
    }

    /// Exact dictionary size declared by the header.
    #[must_use]
    pub const fn dictionary(self) -> u64 {
        self.dictionary
    }
}

#[derive(Debug)]
struct Redirection {
    kind: EntryKind,
    target: ArchivePath,
}

#[derive(Debug, Default)]
struct MainExtras {
    original_name: Option<ArchivePath>,
    created: Option<Timestamp>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
}

/// Incremental RAR5 reader with statically dispatched payload and crypto seams.
pub struct Rar5Decoder<P = NoPayloadCodecProvider, C = NoRar5CryptoProvider>
where
    P: PayloadCodecProvider,
    C: Rar5CryptoProvider,
{
    limits: Limits,
    state: Rar5State,
    header: Vec<u8>,
    header_target: Option<usize>,
    entries: u64,
    decoded: u64,
    saw_main: bool,
    current_path: Vec<u8>,
    previous_path: Vec<u8>,
    blake2sp: Option<Blake2sp>,
    archive_metadata: ArchiveMetadata,
    service_data: Vec<u8>,
    service_progress: ServiceProgress,
    service_size: u64,
    archive_flags: u64,
    allow_volumes: bool,
    payload_codecs: P,
    payload_codec: Option<P::Decoder>,
    retained_payload_codec: Option<P::Decoder>,
    crypto: C,
    encrypted_data: Vec<u8>,
    buffered_data: Vec<u8>,
    buffered_offset: usize,
    encrypted_header_parameters: Option<Rar5CryptoParameters>,
    encrypted_header_iv: [u8; AES_BLOCK_BYTES],
    encrypted_header_iv_len: usize,
    encrypted_header_data: Vec<u8>,
    encrypted_header_candidates: Vec<EncryptedHeaderCandidate<C::Key>>,
}

impl<P, C> fmt::Debug for Rar5Decoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar5CryptoProvider,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rar5Decoder")
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
                "encrypted_headers",
                &self.encrypted_header_parameters.is_some(),
            )
            .field(
                "has_retained_payload_codec",
                &self.retained_payload_codec.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl Rar5Decoder<NoPayloadCodecProvider, NoRar5CryptoProvider> {
    /// Creates a RAR5 decoder with explicit finite budgets.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Rar5State::Signature {
                window: [0; SIGNATURE.len()],
                length: 0,
                scanned: 0,
            },
            header: Vec::new(),
            header_target: None,
            entries: 0,
            decoded: 0,
            saw_main: false,
            current_path: Vec::new(),
            previous_path: Vec::new(),
            blake2sp: None,
            archive_metadata: ArchiveMetadata::new(),
            service_data: Vec::new(),
            service_progress: ServiceProgress::None,
            service_size: 0,
            archive_flags: 0,
            allow_volumes: false,
            payload_codecs: NoPayloadCodecProvider,
            payload_codec: None,
            retained_payload_codec: None,
            crypto: NoRar5CryptoProvider,
            encrypted_data: Vec::new(),
            buffered_data: Vec::new(),
            buffered_offset: 0,
            encrypted_header_parameters: None,
            encrypted_header_iv: [0; AES_BLOCK_BYTES],
            encrypted_header_iv_len: 0,
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

impl<P> Rar5Decoder<P, NoRar5CryptoProvider>
where
    P: PayloadCodecProvider,
{
    /// Creates a decoder with an injectable inner-payload codec provider.
    #[must_use]
    pub fn with_payload_codecs(limits: Limits, provider: P) -> Self {
        Self::with_providers(limits, provider, NoRar5CryptoProvider, false)
    }

    /// Creates a physical-volume decoder with inner-payload codecs.
    #[doc(hidden)]
    #[must_use]
    pub fn with_volume_provider_and_payload_codecs(limits: Limits, provider: P) -> Self {
        Self::with_providers(limits, provider, NoRar5CryptoProvider, true)
    }
}

impl<C> Rar5Decoder<NoPayloadCodecProvider, C>
where
    C: Rar5CryptoProvider,
{
    /// Creates a decoder with an injectable RAR5 cryptography provider.
    #[must_use]
    pub fn with_crypto(limits: Limits, crypto: C) -> Self {
        Self::with_providers(limits, NoPayloadCodecProvider, crypto, false)
    }

    /// Creates a physical-volume decoder with RAR5 cryptography.
    #[doc(hidden)]
    #[must_use]
    pub fn with_volume_provider_and_crypto(limits: Limits, crypto: C) -> Self {
        Self::with_providers(limits, NoPayloadCodecProvider, crypto, true)
    }
}

impl<P, C> Rar5Decoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar5CryptoProvider,
{
    /// Creates a decoder with injectable payload and RAR5 crypto providers.
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
            state: Rar5State::Signature {
                window: [0; SIGNATURE.len()],
                length: 0,
                scanned: 0,
            },
            header: Vec::new(),
            header_target: None,
            entries: 0,
            decoded: 0,
            saw_main: false,
            current_path: Vec::new(),
            previous_path: Vec::new(),
            blake2sp: None,
            archive_metadata: ArchiveMetadata::new(),
            service_data: Vec::new(),
            service_progress: ServiceProgress::None,
            service_size: 0,
            archive_flags: 0,
            allow_volumes,
            payload_codecs: provider,
            payload_codec: None,
            retained_payload_codec: None,
            crypto,
            encrypted_data: Vec::new(),
            buffered_data: Vec::new(),
            buffered_offset: 0,
            encrypted_header_parameters: None,
            encrypted_header_iv: [0; AES_BLOCK_BYTES],
            encrypted_header_iv_len: 0,
            encrypted_header_data: Vec::new(),
            encrypted_header_candidates: Vec::new(),
        }
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        rar5_error(kind, context)
    }

    fn entry_error(&self, kind: ErrorKind, context: &'static str) -> ArchiveError {
        Self::error(kind, context).with_entry(self.entries, self.current_path.clone())
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
                .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 SFX scan offset overflow"))?;
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
                        "RAR5 SFX prefix exceeds the 1 MiB scan limit",
                    ));
                }
                self.state = Rar5State::Header;
                return Ok(step(consumed, DecodeEvent::NeedInput));
            }
            if scanned > MAX_SFX_BYTES + SIGNATURE.len() as u64 {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "RAR5 signature was not found within the 1 MiB SFX scan limit",
                ));
            }
        }
        self.state = Rar5State::Signature {
            window,
            length,
            scanned,
        };
        if matches!(end, EndOfInput::End) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 signature is missing or truncated",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    fn append_header_byte(&mut self, byte: u8) -> Result<(), ArchiveError> {
        let next = self
            .header
            .len()
            .checked_add(1)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 header length overflow"))?;
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
                "RAR5 header exceeds the metadata or in-flight budget",
            ));
        }
        self.header
            .try_reserve(1)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 header allocation failed"))?;
        self.header.push(byte);
        self.update_header_target()
    }

    fn update_header_target(&mut self) -> Result<(), ArchiveError> {
        if self.header_target.is_some() || self.header.len() <= 4 {
            return Ok(());
        }
        let Some((size, width)) = partial_header_size(&self.header[4..])? else {
            return Ok(());
        };
        if size > MAX_HEADER_BYTES {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 header exceeds the format 2 MiB limit",
            ));
        }
        if size < 2 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 header is too short for its type and flags",
            ));
        }
        let size = usize::try_from(size)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 header size exceeds usize"))?;
        let target = 4_usize
            .checked_add(width)
            .and_then(|prefix| prefix.checked_add(size))
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 header size overflow"))?;
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
                "RAR5 header exceeds the metadata or in-flight budget",
            ));
        }
        self.header_target = Some(target);
        Ok(())
    }

    fn read_header(
        &mut self,
        input: &[u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'_>, ArchiveError> {
        let mut consumed = 0;
        while consumed < input.len()
            && self
                .header_target
                .is_none_or(|target| self.header.len() < target)
        {
            self.append_header_byte(input[consumed])?;
            consumed += 1;
        }
        if self
            .header_target
            .is_some_and(|target| self.header.len() == target)
        {
            let header = core::mem::take(&mut self.header);
            self.header_target = None;
            let action = self.parse_header(&header)?;
            return Ok(step(consumed, self.apply_header_action(action)));
        }
        if matches!(end, EndOfInput::End) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "truncated RAR5 archive header",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    #[allow(clippy::too_many_lines)] // Candidate framing is one indivisible incremental state.
    fn read_encrypted_header(
        &mut self,
        input: &[u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'_>, ArchiveError> {
        if !self.crypto.available() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR5 headers require a decryption provider",
            ));
        }
        let candidate_count = self.password_candidate_count()?;
        if candidate_count == 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR5 headers require a password candidate",
            ));
        }
        let parameters = self.encrypted_header_parameters.ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "RAR5 encrypted-header parameters are missing",
            )
        })?;

        let mut consumed = 0;
        if self.encrypted_header_iv_len < AES_BLOCK_BYTES {
            let count = (AES_BLOCK_BYTES - self.encrypted_header_iv_len).min(input.len());
            let iv_end = self.encrypted_header_iv_len + count;
            self.encrypted_header_iv[self.encrypted_header_iv_len..iv_end]
                .copy_from_slice(&input[..count]);
            self.encrypted_header_iv_len = iv_end;
            consumed += count;
            if self.encrypted_header_iv_len < AES_BLOCK_BYTES {
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
            self.build_encrypted_header_candidates(parameters, candidate_count)?;
        }

        loop {
            let mut index = 0;
            while index < self.encrypted_header_candidates.len() {
                let plaintext_size = self.encrypted_header_candidates[index].plaintext_size;
                let ciphertext_size = self.encrypted_header_candidates[index].ciphertext_size;
                if ciphertext_size > self.encrypted_header_data.len() {
                    index += 1;
                    continue;
                }
                let mut plaintext = Vec::new();
                plaintext.try_reserve_exact(ciphertext_size).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "encrypted RAR5 header candidate allocation failed",
                    )
                })?;
                plaintext.extend_from_slice(&self.encrypted_header_data[..ciphertext_size]);
                let decrypt = self.crypto.decrypt(
                    &self.encrypted_header_candidates[index].key,
                    self.encrypted_header_iv,
                    &mut plaintext,
                );
                match decrypt {
                    Ok(()) => {},
                    Err(error)
                        if matches!(error.kind(), ErrorKind::Protocol | ErrorKind::Limit) =>
                    {
                        return Err(error);
                    },
                    Err(_) => {
                        self.encrypted_header_candidates.remove(index);
                        continue;
                    },
                }
                plaintext.truncate(plaintext_size);
                let expected = le_u32(&plaintext, 0)?;
                if crc32(&plaintext[4..]) != expected {
                    self.encrypted_header_candidates.remove(index);
                    continue;
                }

                let action = self.parse_header(&plaintext)?;
                self.reset_encrypted_header_buffers();
                return Ok(step(consumed, self.apply_header_action(action)));
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
                    "wrong password or corrupt encrypted RAR5 header",
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
                "encrypted RAR5 header is truncated or the password is wrong",
            ));
        }
        Ok(step(consumed, DecodeEvent::NeedInput))
    }

    fn push_encrypted_header_bytes(&mut self, bytes: &[u8]) -> Result<(), ArchiveError> {
        let next = self
            .encrypted_header_data
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| Self::error(ErrorKind::Limit, "encrypted RAR5 header overflow"))?;
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
                "encrypted RAR5 header exceeds a configured buffer budget",
            ));
        }
        self.encrypted_header_data
            .try_reserve(bytes.len())
            .map_err(|_| {
                Self::error(ErrorKind::Limit, "encrypted RAR5 header allocation failed")
            })?;
        self.encrypted_header_data.extend_from_slice(bytes);
        Ok(())
    }

    fn build_encrypted_header_candidates(
        &mut self,
        parameters: Rar5CryptoParameters,
        candidate_count: usize,
    ) -> Result<(), ArchiveError> {
        self.encrypted_header_candidates
            .try_reserve_exact(candidate_count)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "encrypted RAR5 header candidate table allocation failed",
                )
            })?;
        let maximum_iterations = self.limits.kdf_iterations().unwrap_or(u64::MAX);
        for candidate in 0..candidate_count {
            let Some(key) = self
                .crypto
                .derive_key(candidate, parameters, maximum_iterations)?
            else {
                continue;
            };
            let mut first_block: [u8; AES_BLOCK_BYTES] = self.encrypted_header_data
                [..AES_BLOCK_BYTES]
                .try_into()
                .map_err(|_| {
                    Self::error(
                        ErrorKind::Protocol,
                        "encrypted RAR5 first block is unavailable",
                    )
                })?;
            match self
                .crypto
                .decrypt(&key, self.encrypted_header_iv, &mut first_block)
            {
                Ok(()) => {},
                Err(error) if matches!(error.kind(), ErrorKind::Protocol | ErrorKind::Limit) => {
                    return Err(error);
                },
                Err(_) => continue,
            }
            let Some((size, width)) = (match partial_header_size(&first_block[4..]) {
                Ok(value) => value,
                Err(_) => continue,
            }) else {
                continue;
            };
            if !(2..=MAX_HEADER_BYTES).contains(&size) {
                continue;
            }
            let plaintext_size = 4_usize
                .checked_add(width)
                .and_then(|prefix| prefix.checked_add(usize::try_from(size).ok()?));
            let Some(plaintext_size) = plaintext_size else {
                continue;
            };
            let Some(ciphertext_size) = plaintext_size
                .checked_add(AES_BLOCK_BYTES - 1)
                .map(|size| size / AES_BLOCK_BYTES * AES_BLOCK_BYTES)
            else {
                continue;
            };
            if self
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
                    key,
                    plaintext_size,
                    ciphertext_size,
                });
        }
        if self.encrypted_header_candidates.is_empty() {
            return Err(Self::error(
                ErrorKind::Integrity,
                "wrong password or invalid encrypted RAR5 header size",
            ));
        }
        Ok(())
    }

    fn reset_encrypted_header_buffers(&mut self) {
        self.encrypted_header_iv = [0; AES_BLOCK_BYTES];
        self.encrypted_header_iv_len = 0;
        self.encrypted_header_data = Vec::new();
        self.encrypted_header_candidates = Vec::new();
    }

    const fn next_header_state(&self) -> Rar5State {
        if self.encrypted_header_parameters.is_some() {
            Rar5State::EncryptedHeaders
        } else {
            Rar5State::Header
        }
    }

    fn parse_header(&mut self, header: &[u8]) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        let expected_crc = le_u32(header, 0)?;
        if crc32(&header[4..]) != expected_crc {
            return Err(Self::error(
                ErrorKind::Integrity,
                "RAR5 archive header CRC32 mismatch",
            ));
        }
        let (_, size_width) = read_vint_at(header, 4, 3)?;
        let body_start = 4_usize
            .checked_add(size_width)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 header offset overflow"))?;
        let mut cursor = Cursor::new(header, body_start);
        let header_type = cursor.vint()?;
        let flags = cursor.vint()?;
        if flags & !HEADER_KNOWN_FLAGS != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 header uses unknown common flags",
            ));
        }
        let extra_size = if flags & HEADER_EXTRA != 0 {
            cursor.vint()?
        } else {
            0
        };
        let data_size = if flags & HEADER_DATA != 0 {
            cursor.vint()?
        } else {
            0
        };
        let extra_size = usize::try_from(extra_size)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 extra area exceeds usize"))?;
        let fields_end = header
            .len()
            .checked_sub(extra_size)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "RAR5 extra area exceeds header"))?;
        if fields_end < cursor.position {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 extra area overlaps common header fields",
            ));
        }
        cursor.end = fields_end;
        let extra = &header[fields_end..];
        validate_extra_records(extra)?;

        match header_type {
            1 => self.parse_main_header(&mut cursor, flags, data_size, extra),
            2 => self.parse_file_header(&mut cursor, flags, data_size, extra),
            3 => self.parse_service_header(&mut cursor, flags, data_size, extra),
            4 => self.parse_encryption_header(&mut cursor, flags, data_size, extra),
            5 => self.parse_end_header(&mut cursor, flags, data_size, extra),
            _ if flags & HEADER_SKIP_IF_UNKNOWN != 0 => Ok(HeaderAction::Skip {
                packed_size: data_size,
            }),
            _ => Err(Self::error(
                ErrorKind::Unsupported,
                "unknown RAR5 archive header type",
            )),
        }
    }

    fn parse_encryption_header(
        &mut self,
        cursor: &mut Cursor<'_>,
        common_flags: u64,
        data_size: u64,
        extra: &[u8],
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 header-encryption header appears after the main header",
            ));
        }
        if common_flags & !HEADER_SKIP_IF_UNKNOWN != 0 || data_size != 0 || !extra.is_empty() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 header-encryption header carries common flags, data, or extras",
            ));
        }

        let fields = cursor.bytes[cursor.position..cursor.end].to_vec();
        let version = cursor.vint()?;
        if version != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 header encryption uses an unsupported version",
            ));
        }
        let flags = cursor.vint()?;
        if flags & !0x0001 != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 header encryption uses unknown flags",
            ));
        }
        let kdf_exponent = cursor.bytes(1)?[0];
        let salt = cursor
            .bytes(16)?
            .try_into()
            .map_err(|_| Self::error(ErrorKind::Protocol, "RAR5 salt width changed"))?;
        let password_check = if flags & 0x0001 != 0 {
            Some(
                cursor
                    .bytes(12)?
                    .try_into()
                    .map_err(|_| Self::error(ErrorKind::Protocol, "RAR5 check width changed"))?,
            )
        } else {
            None
        };
        cursor.finish()?;

        self.archive_metadata = self.archive_metadata.clone().with_extension(Extension::new(
            "rar5",
            b"header-encryption".to_vec(),
            fields,
        ));
        Ok(HeaderAction::EncryptedHeaders {
            metadata: self.archive_metadata.clone(),
            parameters: Rar5CryptoParameters::new(kdf_exponent, salt, password_check, false),
        })
    }

    fn parse_main_header(
        &mut self,
        cursor: &mut Cursor<'_>,
        common_flags: u64,
        data_size: u64,
        extra: &[u8],
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 archive contains more than one main header",
            ));
        }
        if common_flags & HEADER_DATA != 0 || data_size != 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 main header unexpectedly carries data",
            ));
        }
        if common_flags & !(HEADER_EXTRA | HEADER_SKIP_IF_UNKNOWN) != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 main header uses unsupported common flags",
            ));
        }
        let archive_flags = cursor.vint()?;
        if archive_flags & !0x1f != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 main header uses unknown archive flags",
            ));
        }
        let volume_number = if archive_flags & 0x02 != 0 {
            Some(cursor.vint()?)
        } else {
            None
        };
        cursor.finish()?;
        if archive_flags & 0x01 != 0 && !self.allow_volumes {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR5 multi-volume archives require a volume provider",
            ));
        }

        let extras = parse_main_extra_records(extra, self.limits)?;
        self.archive_flags = archive_flags;
        self.saw_main = true;
        let mut metadata = ArchiveMetadata::new().with_extension(Extension::new(
            "rar5",
            b"archive-flags".to_vec(),
            archive_flags.to_le_bytes().to_vec(),
        ));
        if let Some(number) = volume_number {
            metadata = metadata.with_extension(Extension::new(
                "rar5",
                b"volume-number".to_vec(),
                number.to_le_bytes().to_vec(),
            ));
        }
        if !extra.is_empty() {
            metadata = metadata.with_extension(Extension::new(
                "rar5",
                b"main-extra".to_vec(),
                extra.to_vec(),
            ));
        }
        if let Some(original_name) = extras.original_name {
            metadata = metadata.with_volume_name(original_name);
        }
        if let Some(created) = extras.created {
            metadata = metadata.with_extension(Extension::new(
                "rar5",
                b"created".to_vec(),
                timestamp_bytes(created),
            ));
        }
        for (key, offset) in [
            (b"quick-open-offset".as_slice(), extras.quick_open_offset),
            (b"recovery-offset".as_slice(), extras.recovery_offset),
        ] {
            if let Some(offset) = offset {
                metadata = metadata.with_extension(Extension::new(
                    "rar5",
                    key.to_vec(),
                    offset.to_le_bytes().to_vec(),
                ));
            }
        }
        self.archive_metadata = metadata.clone();
        Ok(HeaderAction::ArchiveMetadata(metadata))
    }

    #[allow(clippy::too_many_lines)] // Wire-order checks mirror the documented service header.
    fn parse_service_header(
        &mut self,
        cursor: &mut Cursor<'_>,
        common_flags: u64,
        data_size: u64,
        extra: &[u8],
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if !self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 service header appears before the main header",
            ));
        }
        if common_flags & (HEADER_PREVIOUS_VOLUME | HEADER_NEXT_VOLUME) != 0 {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR5 split service data requires a volume provider",
            ));
        }
        if common_flags
            & !(HEADER_EXTRA
                | HEADER_DATA
                | HEADER_SKIP_IF_UNKNOWN
                | HEADER_DEPENDS_ON_PREVIOUS
                | HEADER_PRESERVE_CHILD)
            != 0
        {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 service header uses unsupported common flags",
            ));
        }
        if common_flags & HEADER_DATA == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 archive comment service has no data area",
            ));
        }

        let file_flags = cursor.vint()?;
        if file_flags & !FILE_KNOWN_FLAGS != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 service header uses unknown file flags",
            ));
        }
        if file_flags & FILE_DIRECTORY != 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 service header is marked as a directory",
            ));
        }
        if file_flags & FILE_UNKNOWN_SIZE != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 service data with an unknown size is not supported",
            ));
        }
        let unpacked_size = cursor.vint()?;
        let attributes = cursor.vint()?;
        if file_flags & FILE_MTIME != 0 {
            let _ = cursor.u32()?;
        }
        let expected_crc = if file_flags & FILE_CRC32 != 0 {
            Some(cursor.u32()?)
        } else {
            None
        };
        let compression = cursor.vint()?;
        let compression_info = parse_compression_info(compression)?;
        let host_os = cursor.vint()?;
        if host_os > 1 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 service header uses an unknown host operating system",
            ));
        }
        let name_length = usize::try_from(cursor.vint()?)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 service name exceeds usize"))?;
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| name_length > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 service name exceeds the configured path budget",
            ));
        }
        let name = cursor.bytes(name_length)?;
        cursor.finish()?;

        let kind = match name {
            b"CMT" => ServiceKind::ArchiveComment,
            b"QO" => ServiceKind::QuickOpen,
            b"RR" => ServiceKind::RecoveryRecord,
            b"ACL" => ServiceKind::Acl,
            b"STM" => ServiceKind::AlternateStream,
            _ => {
                return Err(Self::error(
                    ErrorKind::Unsupported,
                    "RAR5 service type is not implemented yet",
                ));
            },
        };
        let child = common_flags & HEADER_DEPENDS_ON_PREVIOUS != 0;
        let preserve_child = common_flags & HEADER_PRESERVE_CHILD != 0;
        match kind {
            ServiceKind::Acl | ServiceKind::AlternateStream if !child || self.entries == 0 => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 file service does not depend on a preceding file",
                ));
            },
            ServiceKind::Acl | ServiceKind::AlternateStream
                if matches!(
                    self.service_progress,
                    ServiceProgress::QuickOpen | ServiceProgress::RecoveryRecord
                ) =>
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 file service appears after trailing archive services",
                ));
            },
            ServiceKind::ArchiveComment | ServiceKind::QuickOpen | ServiceKind::RecoveryRecord
                if child || preserve_child =>
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 archive service is incorrectly marked as a child block",
                ));
            },
            ServiceKind::Acl
            | ServiceKind::AlternateStream
            | ServiceKind::ArchiveComment
            | ServiceKind::QuickOpen
            | ServiceKind::RecoveryRecord => {},
        }
        match kind {
            ServiceKind::ArchiveComment
                if self.entries != 0
                    || matches!(
                        self.service_progress,
                        ServiceProgress::QuickOpen | ServiceProgress::RecoveryRecord
                    ) =>
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 archive comment appears after file or trailing service data",
                ));
            },
            ServiceKind::ArchiveComment
                if self.service_progress == ServiceProgress::ArchiveComment =>
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 archive contains duplicate comment services",
                ));
            },
            ServiceKind::QuickOpen if self.service_progress == ServiceProgress::QuickOpen => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 archive contains duplicate quick-open services",
                ));
            },
            ServiceKind::QuickOpen if self.service_progress == ServiceProgress::RecoveryRecord => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 quick-open service appears after the recovery record",
                ));
            },
            ServiceKind::RecoveryRecord if self.archive_flags & ARCHIVE_RECOVERY == 0 => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 recovery record is not declared by the main header",
                ));
            },
            ServiceKind::RecoveryRecord
                if self.service_progress == ServiceProgress::RecoveryRecord =>
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 archive contains duplicate recovery records",
                ));
            },
            ServiceKind::ArchiveComment
            | ServiceKind::QuickOpen
            | ServiceKind::RecoveryRecord
            | ServiceKind::Acl
            | ServiceKind::AlternateStream => {},
        }
        if attributes != 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 service header uses non-zero reserved attributes",
            ));
        }
        if compression_info.method != 0
            && self.limits.codec_memory().is_some_and(|maximum| {
                compression_info.dictionary > u64::try_from(maximum).unwrap_or(u64::MAX)
            })
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 service dictionary exceeds the configured codec-memory budget",
            ));
        }
        if compression_info.solid {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "solid compressed RAR5 service data is not implemented",
            ));
        }
        let extras = parse_service_extra_records(extra)?;
        let encrypted = extras.encryption.is_some();
        if compression_info.method == 0 && !encrypted && unpacked_size != data_size {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 service packed and unpacked sizes differ",
            ));
        }

        let retained_payload = match kind {
            ServiceKind::ArchiveComment | ServiceKind::Acl => usize::try_from(unpacked_size)
                .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 service size exceeds usize"))?,
            ServiceKind::QuickOpen | ServiceKind::RecoveryRecord | ServiceKind::AlternateStream => {
                0
            },
        };
        let retained = retained_payload
            .checked_add(extra.len())
            .and_then(|bytes| {
                if matches!(kind, ServiceKind::Acl | ServiceKind::AlternateStream) {
                    bytes.checked_add(self.previous_path.len())
                } else {
                    Some(bytes)
                }
            })
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 service metadata size overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| retained > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 service metadata exceeds the metadata budget",
            ));
        }
        if self.limits.decoded_total().is_some_and(|maximum| {
            self.decoded
                .checked_add(unpacked_size)
                .is_none_or(|sum| sum > maximum)
        }) {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 service data exceeds the decoded-byte budget",
            ));
        }

        self.service_data.clear();
        if matches!(kind, ServiceKind::ArchiveComment | ServiceKind::Acl) {
            self.service_data
                .try_reserve_exact(retained_payload)
                .map_err(|_| {
                    Self::error(ErrorKind::Limit, "RAR5 service metadata allocation failed")
                })?;
        }
        if !extra.is_empty() {
            let key = match kind {
                ServiceKind::ArchiveComment => b"comment-extra".as_slice(),
                ServiceKind::QuickOpen => b"quick-open-extra".as_slice(),
                ServiceKind::RecoveryRecord => b"recovery-record-extra".as_slice(),
                ServiceKind::Acl => b"acl-extra".as_slice(),
                ServiceKind::AlternateStream => b"stream-extra".as_slice(),
            };
            self.archive_metadata = self.archive_metadata.clone().with_extension(Extension::new(
                "rar5",
                key.to_vec(),
                extra.to_vec(),
            ));
        }
        match kind {
            ServiceKind::ArchiveComment => self.service_progress = ServiceProgress::ArchiveComment,
            ServiceKind::QuickOpen => self.service_progress = ServiceProgress::QuickOpen,
            ServiceKind::RecoveryRecord => {
                self.service_progress = ServiceProgress::RecoveryRecord;
            },
            ServiceKind::Acl | ServiceKind::AlternateStream => {},
        }
        let payload_codec = if compression_info.method == 0 || encrypted {
            None
        } else {
            if !self.payload_codecs.available() {
                return Err(Self::error(
                    ErrorKind::Unsupported,
                    "compressed RAR5 service requires a payload codec provider",
                ));
            }
            let request = PayloadCodecRequest::new(
                PayloadCodecAlgorithm::Rar5,
                compression_info.method,
                compression_info.version,
                data_size,
                unpacked_size,
                compression_info.dictionary,
            );
            Some(
                self.payload_codecs
                    .decoder(request, self.limits)?
                    .ok_or_else(|| {
                        Self::error(
                            ErrorKind::Unsupported,
                            "RAR5 payload codec provider does not support this service method",
                        )
                    })?,
            )
        };
        self.service_size = unpacked_size;
        Ok(HeaderAction::Service {
            kind,
            packed_size: data_size,
            unpacked_size,
            expected_crc,
            expected_blake2sp: extras.blake2sp,
            encryption: extras.encryption,
            compression: compression_info,
            payload_codec,
        })
    }

    #[allow(clippy::too_many_lines)] // Wire-order checks keep declarations ahead of data.
    fn parse_file_header(
        &mut self,
        cursor: &mut Cursor<'_>,
        common_flags: u64,
        data_size: u64,
        extra: &[u8],
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if !self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 file header appears before the main header",
            ));
        }
        if matches!(
            self.service_progress,
            ServiceProgress::QuickOpen | ServiceProgress::RecoveryRecord
        ) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 file header appears after a trailing service",
            ));
        }
        let split = SplitFlags::from_common_flags(common_flags);
        if split.any() && !self.allow_volumes {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR5 split file data requires a volume provider",
            ));
        }
        if common_flags
            & !(HEADER_EXTRA
                | HEADER_DATA
                | HEADER_SKIP_IF_UNKNOWN
                | HEADER_PREVIOUS_VOLUME
                | HEADER_NEXT_VOLUME)
            != 0
        {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 file header uses unsupported common flags",
            ));
        }
        if split.any() && self.archive_flags & ARCHIVE_VOLUME == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 split file appears outside a volume archive",
            ));
        }
        if split.any() && common_flags & HEADER_DATA == 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 split file header has no data area",
            ));
        }
        let file_flags = cursor.vint()?;
        if file_flags & !FILE_KNOWN_FLAGS != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 file header uses unknown file flags",
            ));
        }
        let declared_unpacked = cursor.vint()?;
        let attributes = cursor.vint()?;
        let modified = if file_flags & FILE_MTIME != 0 {
            Some(cursor.u32()?)
        } else {
            None
        };
        let expected_crc = if file_flags & FILE_CRC32 != 0 {
            Some(cursor.u32()?)
        } else {
            None
        };
        let compression = cursor.vint()?;
        let compression_info = parse_compression_info(compression)?;
        if compression_info.method != 0
            && self.limits.codec_memory().is_some_and(|maximum| {
                compression_info.dictionary > u64::try_from(maximum).unwrap_or(u64::MAX)
            })
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 dictionary exceeds the configured codec-memory budget",
            ));
        }
        if compression_info.solid
            && (self.archive_flags & ARCHIVE_SOLID == 0
                || (self.entries == 0 && !self.allow_volumes))
        {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 solid entry has no declared preceding dictionary",
            ));
        }
        let host_os = cursor.vint()?;
        if host_os > 1 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 entry uses an unknown host operating system",
            ));
        }
        let name_length = usize::try_from(cursor.vint()?)
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 path length exceeds usize"))?;
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| name_length > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 path exceeds the configured path budget",
            ));
        }
        let name = cursor.bytes(name_length)?.to_vec();
        cursor.finish()?;
        let extras = parse_file_extra_records(extra, self.limits)?;
        let encryption = extras.encryption;
        let encrypted = encryption.is_some();

        let directory = file_flags & FILE_DIRECTORY != 0;
        if directory && data_size != 0 {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 directory unexpectedly carries file data",
            ));
        }
        let unknown_size = file_flags & FILE_UNKNOWN_SIZE != 0;
        let logical_size = (!unknown_size).then_some(declared_unpacked);
        let unpacked = logical_size.unwrap_or(data_size);
        let metadata_size = if split.any() {
            logical_size
        } else {
            Some(unpacked)
        };
        let budget_size = if split.before { data_size } else { unpacked };
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| budget_size > maximum)
            || self.limits.decoded_total().is_some_and(|maximum| {
                self.decoded
                    .checked_add(budget_size)
                    .is_none_or(|sum| sum > maximum)
            })
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 entry exceeds the configured decoded-byte budget",
            ));
        }
        if compression_info.method == 0 && !directory && !split.any() && data_size != unpacked {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 Store entry packed and unpacked sizes differ",
            ));
        }
        if compression_info.method == 0
            && split.any()
            && logical_size.is_some_and(|size| data_size > size)
        {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 split Store part exceeds its declared logical size",
            ));
        }
        if split.any() && directory {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 directory cannot be split between volumes",
            ));
        }
        if compression_info.method != 0 && (directory || extras.redirection.is_some()) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 metadata-only entry declares a compressed payload",
            ));
        }
        if compression_info.method != 0 && unknown_size {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 compressed entry has no declared unpacked size",
            ));
        }
        if extras.redirection.is_some() && (directory || unpacked != 0 || data_size != 0) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 redirected entry must not be a directory or carry data",
            ));
        }
        if split.any() && extras.redirection.is_some() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 redirected entry cannot be split between volumes",
            ));
        }
        let next_entry = if split.before {
            self.entries
        } else {
            self.entries
                .checked_add(1)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 entry count overflow"))?
        };
        if self
            .limits
            .entries()
            .is_some_and(|maximum| next_entry > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 archive exceeds the configured entry-count budget",
            ));
        }

        let path = ArchivePath::try_from_encoded(name.clone(), PathEncoding::Utf8)
            .map_err(|_| Self::error(ErrorKind::Malformed, "RAR5 path is not valid UTF-8"))?;
        let kind = extras.redirection.as_ref().map_or_else(
            || {
                if directory {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                }
            },
            |redirection| redirection.kind,
        );
        let mut builder = EntryMetadata::builder(kind, path)
            .size(metadata_size)
            .encrypted(encrypted)
            .extension(Extension::new(
                "rar5",
                b"compression-info".to_vec(),
                compression.to_le_bytes().to_vec(),
            ));
        if split.any() {
            builder = builder.extension(Extension::new(
                "rar5",
                b"split".to_vec(),
                split.encoded().to_vec(),
            ));
        }
        if compression_info.solid {
            builder =
                builder.extension(Extension::new("rar5", b"solid".to_vec(), b"\x01".to_vec()));
        }
        if !extra.is_empty() {
            builder = builder.extension(Extension::new(
                "rar5",
                b"file-extra".to_vec(),
                extra.to_vec(),
            ));
        }
        if let Some(version) = extras.version {
            builder = builder.extension(Extension::new(
                "rar5",
                b"file-version".to_vec(),
                version.to_le_bytes().to_vec(),
            ));
        }
        if host_os == 1 {
            builder = builder.mode(Some(u32::try_from(attributes).map_err(|_| {
                Self::error(ErrorKind::Malformed, "RAR5 Unix mode exceeds 32 bits")
            })?));
        } else {
            builder = builder
                .file_flags(attributes & !0x10)
                .extension(Extension::new(
                    "rar5",
                    b"windows-attributes".to_vec(),
                    attributes.to_le_bytes().to_vec(),
                ));
        }
        let mut times = EntryTimes {
            modified: modified.map(|seconds| Timestamp::from_seconds(i64::from(seconds))),
            ..EntryTimes::default()
        };
        if let Some(extra_times) = extras.times {
            if extra_times.modified.is_some() {
                times.modified = extra_times.modified;
            }
            times.created = extra_times.created;
            times.accessed = extra_times.accessed;
        }
        if times != EntryTimes::default() {
            builder = builder.times(times);
        }
        if let Some(owner) = extras.owner {
            builder = builder.owner(owner);
        }
        if let Some(redirection) = extras.redirection {
            builder = builder.link_target(Some(redirection.target));
        }
        if !split.after
            && extras.blake2sp.is_some()
            && let Some(crc) = expected_crc
        {
            builder = builder.extension(Extension::new(
                "rar5",
                b"data-crc32".to_vec(),
                crc.to_be_bytes().to_vec(),
            ));
        }
        if !split.after {
            if let Some(digest) = extras.blake2sp {
                builder = builder.checksum(Some(Checksum::new(
                    ChecksumAlgorithm::Blake2sp,
                    digest.to_vec(),
                )?));
            } else if let Some(crc) = expected_crc {
                builder = builder.checksum(Some(Checksum::new(
                    ChecksumAlgorithm::Crc32,
                    crc.to_be_bytes().to_vec(),
                )?));
            }
        }
        let metadata = builder.try_build()?;
        let physical_raw = self.allow_volumes && compression_info.method != 0 && !encrypted;
        let payload_codec = if compression_info.method == 0 || encrypted || physical_raw {
            if encrypted {
                self.retained_payload_codec = None;
            }
            None
        } else {
            let request = PayloadCodecRequest::new(
                PayloadCodecAlgorithm::Rar5,
                compression_info.method,
                compression_info.version,
                data_size,
                unpacked,
                compression_info.dictionary,
            );
            if !self.payload_codecs.available() {
                return Err(Self::error(
                    ErrorKind::Unsupported,
                    "RAR5 compressed entry requires a payload codec provider",
                ));
            }
            let decoder = if compression_info.solid {
                let previous = self.retained_payload_codec.take().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Malformed,
                        "RAR5 solid compressed entry has no reusable decoder state",
                    )
                })?;
                self.payload_codecs
                    .continue_decoder(previous, request, self.limits)?
                    .ok_or_else(|| {
                        Self::error(
                            ErrorKind::Unsupported,
                            "RAR5 payload codec provider cannot continue this solid method",
                        )
                    })?
            } else {
                self.retained_payload_codec = None;
                self.payload_codecs
                    .decoder(request, self.limits)?
                    .ok_or_else(|| {
                        Self::error(
                            ErrorKind::Unsupported,
                            "RAR5 payload codec provider does not support this compression method",
                        )
                    })?
            };
            Some(decoder)
        };
        self.entries = next_entry;
        self.current_path = name;
        self.previous_path.clear();
        Ok(HeaderAction::Entry {
            metadata,
            packed_size: data_size,
            expected_crc,
            expected_blake2sp: extras.blake2sp,
            verify_checksum: if physical_raw {
                split.after && !split.before
            } else {
                !split.before || split.after
            },
            encryption,
            unpacked_size: unpacked,
            compression: compression_info,
            split: split.any(),
            physical_raw,
            payload_codec,
        })
    }

    fn parse_end_header(
        &mut self,
        cursor: &mut Cursor<'_>,
        common_flags: u64,
        data_size: u64,
        extra: &[u8],
    ) -> Result<HeaderAction<P::Decoder>, ArchiveError> {
        if !self.saw_main {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 end header appears before the main header",
            ));
        }
        if common_flags & (HEADER_EXTRA | HEADER_DATA) != 0 || data_size != 0 || !extra.is_empty() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 end header unexpectedly carries extra fields or data",
            ));
        }
        if common_flags & !HEADER_SKIP_IF_UNKNOWN != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 end header uses unsupported common flags",
            ));
        }
        let end_flags = cursor.vint()?;
        if end_flags & !0x01 != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "RAR5 end header uses unknown flags",
            ));
        }
        cursor.finish()?;
        let next_volume = end_flags & 0x01 != 0;
        if next_volume && !self.allow_volumes {
            return Err(Self::error(
                ErrorKind::Capability,
                "RAR5 next volume is required",
            ));
        }
        let saw_recovery = self.service_progress == ServiceProgress::RecoveryRecord;
        if (self.archive_flags & ARCHIVE_RECOVERY != 0) != saw_recovery {
            return Err(Self::error(
                ErrorKind::Malformed,
                "RAR5 recovery-record flag does not match archive contents",
            ));
        }
        Ok(HeaderAction::End { next_volume })
    }

    #[allow(clippy::too_many_arguments)] // Arguments are the copied Data state fields.
    fn read_compressed_file_data<'a>(
        &'a mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        verify_checksum: bool,
        physical_raw: bool,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let mut codec = self.payload_codec.take().ok_or_else(|| {
            self.entry_error(ErrorKind::Protocol, "RAR5 payload codec state is missing")
        })?;
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 data window exceeds usize"))?;
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
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 codec progress exceeds u64"))?;
        if consumed > remaining {
            return Err(self.entry_error(
                ErrorKind::Protocol,
                "RAR5 payload codec consumed beyond the packed data area",
            ));
        }
        let bytes = &scratch[..codec_step.produced];
        crc.update(bytes);
        if let Some(blake2sp) = &mut self.blake2sp {
            blake2sp.update(bytes);
        }
        self.decoded = self
            .decoded
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        let remaining = remaining - consumed;
        match codec_step.status {
            CodecStatus::Done if remaining != 0 => {
                return Err(self.entry_error(
                    ErrorKind::Malformed,
                    "RAR5 payload codec ended before the packed data area",
                ));
            },
            CodecStatus::Done => {
                if self.archive_flags & ARCHIVE_SOLID != 0 {
                    self.retained_payload_codec = Some(codec);
                }
            },
            CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                self.payload_codec = Some(codec);
            },
            _ => {
                return Err(self.entry_error(
                    ErrorKind::Protocol,
                    "RAR5 payload codec returned an unknown status",
                ));
            },
        }
        self.state = Rar5State::Data {
            remaining,
            expected_crc,
            expected_blake2sp,
            verify_checksum,
            physical_raw,
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
    fn read_file_data<'a>(
        &'a mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        verify_checksum: bool,
        physical_raw: bool,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if remaining == 0 && self.payload_codec.is_none() {
            if verify_checksum && expected_crc.is_some_and(|expected| crc.finish() != expected) {
                return Err(self.entry_error(
                    ErrorKind::Integrity,
                    "RAR5 entry CRC-32 does not match its payload",
                ));
            }
            if verify_checksum && let Some(expected) = expected_blake2sp {
                let actual = self
                    .blake2sp
                    .take()
                    .ok_or_else(|| {
                        self.entry_error(
                            ErrorKind::Protocol,
                            "RAR5 BLAKE2sp verifier state is missing",
                        )
                    })?
                    .finalize();
                if actual != expected {
                    return Err(self.entry_error(
                        ErrorKind::Integrity,
                        "RAR5 entry BLAKE2sp does not match its payload",
                    ));
                }
            } else {
                self.blake2sp = None;
            }
            self.state = self.next_header_state();
            self.previous_path = core::mem::take(&mut self.current_path);
            return Ok(step(0, DecodeEvent::EndEntry));
        }
        if self.payload_codec.is_some() {
            return self.read_compressed_file_data(
                input,
                scratch,
                remaining,
                expected_crc,
                expected_blake2sp,
                verify_checksum,
                physical_raw,
                crc,
            );
        }
        if input.is_empty() {
            self.state = Rar5State::Data {
                remaining,
                expected_crc,
                expected_blake2sp,
                verify_checksum,
                physical_raw,
                crc,
            };
            if matches!(end, EndOfInput::End) {
                return Err(self.entry_error(ErrorKind::Malformed, "RAR5 entry data is truncated"));
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 data window exceeds usize"))?;
        let bytes = &input[..count];
        crc.update(bytes);
        if !physical_raw && let Some(blake2sp) = &mut self.blake2sp {
            blake2sp.update(bytes);
        }
        if !physical_raw {
            self.decoded = self
                .decoded
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        }
        self.state = Rar5State::Data {
            remaining: remaining - count as u64,
            expected_crc,
            expected_blake2sp,
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
                "encrypted RAR5 file data requires a decryption provider",
            ));
        }
        let candidate_count = self.password_candidate_count()?;
        if candidate_count == 0 {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "encrypted RAR5 file data requires a password candidate",
            ));
        }
        if encrypted.compression.solid || encrypted.split {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "solid or split encrypted RAR5 data requires replayable decoder state",
            ));
        }
        let total_ciphertext = self
            .encrypted_data
            .len()
            .checked_add(usize::try_from(encrypted.remaining).map_err(|_| {
                self.entry_error(
                    ErrorKind::Limit,
                    "encrypted RAR5 ciphertext exceeds the address space",
                )
            })?)
            .ok_or_else(|| {
                self.entry_error(
                    ErrorKind::Limit,
                    "encrypted RAR5 ciphertext length overflow",
                )
            })?;
        let _ = self.encrypted_payload_limits(total_ciphertext, encrypted.unpacked_size)?;
        if encrypted.remaining != 0 {
            if input.is_empty() {
                if matches!(end, EndOfInput::End) {
                    return Err(self.entry_error(
                        ErrorKind::Malformed,
                        "encrypted RAR5 file data is truncated",
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
                    "encrypted RAR5 ciphertext allocation failed",
                )
            })?;
            self.encrypted_data.extend_from_slice(&input[..count]);
            encrypted.remaining -= count as u64;
            self.state = Rar5State::EncryptedData(encrypted);
            return Ok(step(count, DecodeEvent::NeedInput));
        }

        if self.encrypted_data.is_empty()
            || !self.encrypted_data.len().is_multiple_of(AES_BLOCK_BYTES)
        {
            return Err(self.entry_error(
                ErrorKind::Malformed,
                "encrypted RAR5 file data is not AES block aligned",
            ));
        }
        if encrypted.compression.method != 0 && scratch.is_empty() {
            self.state = Rar5State::EncryptedData(encrypted);
            return Ok(step(0, DecodeEvent::NeedOutput));
        }

        let plaintext = self.try_encrypted_candidates(encrypted, scratch, candidate_count)?;
        self.encrypted_data = Vec::new();
        let Some(plaintext) = plaintext else {
            return Err(self.entry_error(
                ErrorKind::Integrity,
                "wrong password or corrupt encrypted RAR5 data",
            ));
        };
        self.buffered_data = plaintext;
        self.buffered_offset = 0;
        self.state = Rar5State::BufferedData;
        Ok(step(0, DecodeEvent::NeedInput))
    }

    fn read_encrypted_service<'a>(
        &mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
        mut service: EncryptedServiceState,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if !self.crypto.available() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR5 service data requires a decryption provider",
            ));
        }
        let candidate_count = self.password_candidate_count()?;
        if candidate_count == 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted RAR5 service data requires a password candidate",
            ));
        }
        let total_ciphertext = self
            .encrypted_data
            .len()
            .checked_add(usize::try_from(service.payload.remaining).map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "encrypted RAR5 service exceeds the address space",
                )
            })?)
            .ok_or_else(|| {
                Self::error(ErrorKind::Limit, "encrypted RAR5 service length overflow")
            })?;
        let _ = self.encrypted_payload_limits(total_ciphertext, service.payload.unpacked_size)?;
        if service.payload.remaining != 0 {
            if input.is_empty() {
                if matches!(end, EndOfInput::End) {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "encrypted RAR5 service data is truncated",
                    ));
                }
                return Ok(step(0, DecodeEvent::NeedInput));
            }
            let count = usize::try_from(service.payload.remaining)
                .unwrap_or(usize::MAX)
                .min(input.len());
            self.encrypted_data.try_reserve(count).map_err(|_| {
                Self::error(ErrorKind::Limit, "encrypted RAR5 service allocation failed")
            })?;
            self.encrypted_data.extend_from_slice(&input[..count]);
            service.payload.remaining -= count as u64;
            self.state = Rar5State::EncryptedService(service);
            return Ok(step(count, DecodeEvent::NeedInput));
        }
        if self.encrypted_data.is_empty()
            || !self.encrypted_data.len().is_multiple_of(AES_BLOCK_BYTES)
        {
            return Err(Self::error(
                ErrorKind::Malformed,
                "encrypted RAR5 service data is not AES block aligned",
            ));
        }
        if service.payload.compression.method != 0 && scratch.is_empty() {
            self.state = Rar5State::EncryptedService(service);
            return Ok(step(0, DecodeEvent::NeedOutput));
        }

        let plaintext = self.try_encrypted_candidates(service.payload, scratch, candidate_count)?;
        self.encrypted_data = Vec::new();
        let Some(mut plaintext) = plaintext else {
            return Err(Self::error(
                ErrorKind::Integrity,
                "wrong password or corrupt encrypted RAR5 service data",
            ));
        };
        self.decoded = self
            .decoded
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        if service.kind == ServiceKind::ArchiveComment
            && let Some(terminator) = plaintext.iter().position(|byte| *byte == 0)
        {
            plaintext.truncate(terminator);
        }
        if matches!(service.kind, ServiceKind::ArchiveComment | ServiceKind::Acl) {
            self.service_data = plaintext;
        }
        self.retain_service_metadata(service.kind)?;
        self.state = self.next_header_state();
        Ok(step(
            0,
            DecodeEvent::ArchiveMetadata(self.archive_metadata.clone()),
        ))
    }

    fn password_candidate_count(&self) -> Result<usize, ArchiveError> {
        let count = self.crypto.candidate_count();
        if count > MAX_PASSWORD_CANDIDATES {
            return Err(Self::error(
                ErrorKind::Limit,
                "RAR5 password candidate count exceeds the format-core limit",
            ));
        }
        Ok(count)
    }

    fn try_encrypted_candidates(
        &self,
        encrypted: EncryptedState,
        scratch: &mut [u8],
        candidate_count: usize,
    ) -> Result<Option<Vec<u8>>, ArchiveError> {
        if encrypted.expected_crc.is_none() && encrypted.expected_blake2sp.is_none() {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "encrypted RAR5 payload has no checksum and cannot be authenticated",
            ));
        }
        let unpacked = usize::try_from(encrypted.unpacked_size).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "encrypted RAR5 output exceeds the address space",
            )
        })?;
        let maximum_iterations = self.limits.kdf_iterations().unwrap_or(u64::MAX);
        for candidate in 0..candidate_count {
            let Some(key) = self.crypto.derive_key(
                candidate,
                encrypted.encryption.parameters,
                maximum_iterations,
            )?
            else {
                continue;
            };
            let mut plaintext = Vec::new();
            plaintext
                .try_reserve_exact(self.encrypted_data.len())
                .map_err(|_| {
                    self.entry_error(
                        ErrorKind::Limit,
                        "encrypted RAR5 candidate allocation failed",
                    )
                })?;
            plaintext.extend_from_slice(&self.encrypted_data);
            if let Err(error) = self
                .crypto
                .decrypt(&key, encrypted.encryption.iv, &mut plaintext)
            {
                if matches!(error.kind(), ErrorKind::Protocol | ErrorKind::Limit) {
                    return Err(error.with_entry(self.entries, self.current_path.clone()));
                }
                continue;
            }

            let decoded = if encrypted.compression.method == 0 {
                if unpacked > plaintext.len() || plaintext.len() - unpacked >= AES_BLOCK_BYTES {
                    continue;
                }
                plaintext.truncate(unpacked);
                plaintext
            } else {
                let Some(decoded) =
                    self.decode_encrypted_candidate(&plaintext, encrypted, scratch, &key)?
                else {
                    continue;
                };
                return Ok(Some(decoded));
            };
            if decoded.len() != unpacked {
                continue;
            }
            let checksums_match = !encrypted.verify_checksum
                || self.encrypted_checksums_match(&key, encrypted, &decoded)?;
            if checksums_match {
                return Ok(Some(decoded));
            }
        }
        Ok(None)
    }

    fn encrypted_checksums_match(
        &self,
        key: &C::Key,
        encrypted: EncryptedState,
        decoded: &[u8],
    ) -> Result<bool, ArchiveError> {
        let tweaked = encrypted.encryption.parameters.tweaked_checksums();
        if let Some(expected) = encrypted.expected_crc {
            let raw = crc32(decoded);
            let actual = if tweaked {
                self.crypto.tweak_crc32(key, raw)?
            } else {
                raw
            };
            if actual != expected {
                return Ok(false);
            }
        }
        if let Some(expected) = encrypted.expected_blake2sp {
            let mut hasher = Blake2sp::new();
            hasher.update(decoded);
            let raw = hasher.finalize();
            let actual = if tweaked {
                self.crypto.tweak_blake2sp(key, raw)?
            } else {
                raw
            };
            if actual != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn decode_encrypted_candidate(
        &self,
        plaintext: &[u8],
        encrypted: EncryptedState,
        scratch: &mut [u8],
        key: &C::Key,
    ) -> Result<Option<Vec<u8>>, ArchiveError> {
        for padding in 0..AES_BLOCK_BYTES.min(plaintext.len()) {
            let prefix = &plaintext[..plaintext.len() - padding];
            let decoded = match self.decode_encrypted_prefix(prefix, encrypted, scratch) {
                Ok(Some(decoded)) => decoded,
                Err(error) if error.kind() == ErrorKind::Limit => return Err(error),
                Ok(None) | Err(_) => continue,
            };
            if decoded.len() == usize::try_from(encrypted.unpacked_size).unwrap_or(usize::MAX)
                && (!encrypted.verify_checksum
                    || self.encrypted_checksums_match(key, encrypted, &decoded)?)
            {
                return Ok(Some(decoded));
            }
        }
        Ok(None)
    }

    fn decode_encrypted_prefix(
        &self,
        plaintext: &[u8],
        encrypted: EncryptedState,
        scratch: &mut [u8],
    ) -> Result<Option<Vec<u8>>, ArchiveError> {
        if !self.payload_codecs.available() {
            return Err(self.entry_error(
                ErrorKind::Unsupported,
                "compressed encrypted RAR5 entry requires a payload codec provider",
            ));
        }
        let limits = self.encrypted_payload_limits(plaintext.len(), encrypted.unpacked_size)?;
        let request = PayloadCodecRequest::new(
            PayloadCodecAlgorithm::Rar5,
            encrypted.compression.method,
            encrypted.compression.version,
            plaintext.len() as u64,
            encrypted.unpacked_size,
            encrypted.compression.dictionary,
        );
        let mut codec = self
            .payload_codecs
            .decoder(request, limits)?
            .ok_or_else(|| {
                self.entry_error(
                    ErrorKind::Unsupported,
                    "RAR5 payload codec provider does not support encrypted compression",
                )
            })?;
        let expected = usize::try_from(encrypted.unpacked_size).map_err(|_| {
            self.entry_error(
                ErrorKind::Limit,
                "encrypted RAR5 output exceeds the address space",
            )
        })?;
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(expected).map_err(|_| {
            self.entry_error(ErrorKind::Limit, "encrypted RAR5 output allocation failed")
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
                    self.entry_error(ErrorKind::Limit, "encrypted RAR5 output length overflow")
                })?;
            if next_len > expected {
                return Ok(None);
            }
            decoded.extend_from_slice(&scratch[..codec_step.produced]);
            offset = offset.checked_add(codec_step.consumed).ok_or_else(|| {
                self.entry_error(ErrorKind::Limit, "encrypted RAR5 codec offset overflow")
            })?;
            match codec_step.status {
                CodecStatus::Done => return Ok(Some(decoded)),
                CodecStatus::NeedInput if offset == plaintext.len() => return Ok(None),
                CodecStatus::NeedInput | CodecStatus::NeedOutput => {},
                _ => {
                    return Err(self.entry_error(
                        ErrorKind::Protocol,
                        "RAR5 payload codec returned an unknown status",
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
                "encrypted RAR5 output exceeds the address space",
            )
        })?;
        let external = packed
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(unpacked))
            .ok_or_else(|| {
                self.entry_error(
                    ErrorKind::Limit,
                    "encrypted RAR5 buffer accounting overflow",
                )
            })?;
        let in_flight = self
            .limits
            .in_flight_bytes()
            .map(|maximum| {
                maximum.checked_sub(external).ok_or_else(|| {
                    self.entry_error(
                        ErrorKind::Limit,
                        "encrypted RAR5 buffers exceed the in-flight budget",
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
            self.previous_path = core::mem::take(&mut self.current_path);
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
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        Ok(DecodeStep {
            consumed: 0,
            produced: count,
            event: DecodeEvent::Data(Chunk::new(&output[..count])),
        })
    }

    fn retain_service_metadata(&mut self, kind: ServiceKind) -> Result<(), ArchiveError> {
        match kind {
            ServiceKind::ArchiveComment => {
                let comment = core::mem::take(&mut self.service_data);
                if core::str::from_utf8(&comment).is_err() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "RAR5 archive comment is not valid UTF-8",
                    ));
                }
                self.archive_metadata = self.archive_metadata.clone().with_comment(comment);
            },
            ServiceKind::QuickOpen => {
                self.archive_metadata =
                    self.archive_metadata.clone().with_extension(Extension::new(
                        "rar5",
                        b"quick-open-size".to_vec(),
                        self.service_size.to_le_bytes().to_vec(),
                    ));
            },
            ServiceKind::RecoveryRecord => {
                self.archive_metadata =
                    self.archive_metadata.clone().with_extension(Extension::new(
                        "rar5",
                        b"recovery-record-size".to_vec(),
                        self.service_size.to_le_bytes().to_vec(),
                    ));
            },
            ServiceKind::Acl => {
                let data = core::mem::take(&mut self.service_data);
                self.archive_metadata = self
                    .archive_metadata
                    .clone()
                    .with_extension(Extension::new(
                        "rar5",
                        b"acl-target".to_vec(),
                        self.previous_path.clone(),
                    ))
                    .with_extension(Extension::new("rar5", b"acl-data".to_vec(), data));
            },
            ServiceKind::AlternateStream => {
                self.archive_metadata = self
                    .archive_metadata
                    .clone()
                    .with_extension(Extension::new(
                        "rar5",
                        b"stream-target".to_vec(),
                        self.previous_path.clone(),
                    ))
                    .with_extension(Extension::new(
                        "rar5",
                        b"stream-size".to_vec(),
                        self.service_size.to_le_bytes().to_vec(),
                    ));
            },
        }
        Ok(())
    }

    fn read_skipped_data(
        &mut self,
        input: &[u8],
        end: EndOfInput,
        remaining: u64,
    ) -> Result<DecodeStep<'_>, ArchiveError> {
        if remaining == 0 {
            self.state = self.next_header_state();
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        if input.is_empty() {
            self.state = Rar5State::SkipData { remaining };
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "skipped RAR5 header data is truncated",
                ));
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 skipped data exceeds usize"))?;
        let remaining = remaining - count as u64;
        self.state = if remaining == 0 {
            self.next_header_state()
        } else {
            Rar5State::SkipData { remaining }
        };
        Ok(step(count, DecodeEvent::NeedInput))
    }

    #[allow(clippy::too_many_arguments)] // Arguments are the copied ServiceData state fields.
    fn read_compressed_service_data<'a>(
        &'a mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        kind: ServiceKind,
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let mut codec = self.payload_codec.take().ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "RAR5 service payload codec state is missing",
            )
        })?;
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 service data window exceeds usize"))?;
        let codec_end = if count as u64 == remaining {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let codec_step = codec
            .process(&input[..count], scratch, codec_end)?
            .validate(count, scratch.len())?;
        let consumed = u64::try_from(codec_step.consumed).map_err(|_| {
            Self::error(ErrorKind::Limit, "RAR5 service codec progress exceeds u64")
        })?;
        if consumed > remaining {
            return Err(Self::error(
                ErrorKind::Protocol,
                "RAR5 service codec consumed beyond the packed data area",
            ));
        }
        let bytes = &scratch[..codec_step.produced];
        crc.update(bytes);
        if let Some(blake2sp) = &mut self.blake2sp {
            blake2sp.update(bytes);
        }
        if matches!(kind, ServiceKind::ArchiveComment | ServiceKind::Acl) {
            self.service_data.extend_from_slice(bytes);
        }
        self.decoded = self
            .decoded
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        let remaining = remaining - consumed;
        match codec_step.status {
            CodecStatus::Done if remaining != 0 => {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 service codec ended before the packed data area",
                ));
            },
            CodecStatus::Done => {},
            CodecStatus::NeedInput | CodecStatus::NeedOutput => {
                if matches!(codec_step.status, CodecStatus::NeedOutput)
                    && codec_step.consumed == 0
                    && codec_step.produced == 0
                {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "RAR5 service codec requested output without making progress",
                    ));
                }
                self.payload_codec = Some(codec);
            },
            _ => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "RAR5 service codec returned an unknown status",
                ));
            },
        }
        self.state = Rar5State::ServiceData {
            kind,
            remaining,
            expected_crc,
            expected_blake2sp,
            crc,
        };
        Ok(DecodeStep {
            consumed: codec_step.consumed,
            produced: 0,
            event: if matches!(codec_step.status, CodecStatus::NeedInput)
                && codec_step.produced == 0
            {
                DecodeEvent::NeedInput
            } else {
                DecodeEvent::Progress
            },
        })
    }

    #[allow(clippy::too_many_arguments)] // Arguments are the copied ServiceData state fields.
    fn read_service_data<'a>(
        &'a mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
        kind: ServiceKind,
        remaining: u64,
        expected_crc: Option<u32>,
        expected_blake2sp: Option<[u8; 32]>,
        mut crc: Crc32,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if remaining == 0 && self.payload_codec.is_none() {
            if expected_crc.is_some_and(|expected| crc.finish() != expected) {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "RAR5 service CRC-32 does not match its payload",
                ));
            }
            if let Some(expected) = expected_blake2sp {
                let actual = self
                    .blake2sp
                    .take()
                    .ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "RAR5 service BLAKE2sp verifier state is missing",
                        )
                    })?
                    .finalize();
                if actual != expected {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "RAR5 service BLAKE2sp does not match its payload",
                    ));
                }
            } else {
                self.blake2sp = None;
            }
            self.retain_service_metadata(kind)?;
            self.state = self.next_header_state();
            return Ok(step(
                0,
                DecodeEvent::ArchiveMetadata(self.archive_metadata.clone()),
            ));
        }
        if self.payload_codec.is_some() {
            if scratch.is_empty() {
                self.state = Rar5State::ServiceData {
                    kind,
                    remaining,
                    expected_crc,
                    expected_blake2sp,
                    crc,
                };
                return Ok(step(0, DecodeEvent::NeedOutput));
            }
            if input.is_empty() && remaining != 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 service data is truncated",
                ));
            }
            return self.read_compressed_service_data(
                input,
                scratch,
                kind,
                remaining,
                expected_crc,
                expected_blake2sp,
                crc,
            );
        }
        if input.is_empty() {
            self.state = Rar5State::ServiceData {
                kind,
                remaining,
                expected_crc,
                expected_blake2sp,
                crc,
            };
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "RAR5 service data is truncated",
                ));
            }
            return Ok(step(0, DecodeEvent::NeedInput));
        }
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "RAR5 service data window exceeds usize"))?;
        let bytes = &input[..count];
        crc.update(bytes);
        if let Some(blake2sp) = &mut self.blake2sp {
            blake2sp.update(bytes);
        }
        if matches!(kind, ServiceKind::ArchiveComment | ServiceKind::Acl) {
            self.service_data.extend_from_slice(bytes);
        }
        self.decoded = self
            .decoded
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "RAR5 decoded size overflow"))?;
        self.state = Rar5State::ServiceData {
            kind,
            remaining: remaining - count as u64,
            expected_crc,
            expected_blake2sp,
            crc,
        };
        Ok(step(count, DecodeEvent::NeedInput))
    }

    #[allow(clippy::too_many_lines)] // Exhaustive closed actions keep state initialization local.
    fn apply_header_action(&mut self, action: HeaderAction<P::Decoder>) -> DecodeEvent<'static> {
        match action {
            HeaderAction::ArchiveMetadata(metadata) => {
                self.state = self.next_header_state();
                DecodeEvent::ArchiveMetadata(metadata)
            },
            HeaderAction::EncryptedHeaders {
                metadata,
                parameters,
            } => {
                self.encrypted_header_parameters = Some(parameters);
                self.reset_encrypted_header_buffers();
                self.state = Rar5State::EncryptedHeaders;
                DecodeEvent::ArchiveMetadata(metadata)
            },
            HeaderAction::Entry {
                metadata,
                packed_size,
                expected_crc,
                expected_blake2sp,
                verify_checksum,
                encryption,
                unpacked_size,
                compression,
                split,
                physical_raw,
                payload_codec,
            } => {
                self.blake2sp = (encryption.is_none()
                    && !physical_raw
                    && verify_checksum
                    && expected_blake2sp.is_some())
                .then(Blake2sp::new);
                self.state = if let Some(encryption) = encryption {
                    self.encrypted_data = Vec::new();
                    self.buffered_data = Vec::new();
                    self.buffered_offset = 0;
                    Rar5State::EncryptedData(EncryptedState {
                        remaining: packed_size,
                        unpacked_size,
                        expected_crc,
                        expected_blake2sp,
                        verify_checksum,
                        compression,
                        encryption,
                        split,
                    })
                } else {
                    Rar5State::Data {
                        remaining: packed_size,
                        expected_crc,
                        expected_blake2sp,
                        verify_checksum,
                        physical_raw,
                        crc: Crc32::new(),
                    }
                };
                self.payload_codec = payload_codec;
                DecodeEvent::Entry(metadata)
            },
            HeaderAction::Service {
                kind,
                packed_size,
                unpacked_size,
                expected_crc,
                expected_blake2sp,
                encryption,
                compression,
                payload_codec,
            } => {
                self.blake2sp = encryption
                    .is_none()
                    .then(|| expected_blake2sp.map(|_| Blake2sp::new()))
                    .flatten();
                self.payload_codec = payload_codec;
                self.state = if let Some(encryption) = encryption {
                    self.encrypted_data = Vec::new();
                    Rar5State::EncryptedService(EncryptedServiceState {
                        kind,
                        payload: EncryptedState {
                            remaining: packed_size,
                            unpacked_size,
                            expected_crc,
                            expected_blake2sp,
                            verify_checksum: true,
                            compression,
                            encryption,
                            split: false,
                        },
                    })
                } else {
                    Rar5State::ServiceData {
                        kind,
                        remaining: packed_size,
                        expected_crc,
                        expected_blake2sp,
                        crc: Crc32::new(),
                    }
                };
                DecodeEvent::NeedInput
            },
            HeaderAction::Skip { packed_size } => {
                self.state = if packed_size == 0 {
                    self.next_header_state()
                } else {
                    Rar5State::SkipData {
                        remaining: packed_size,
                    }
                };
                DecodeEvent::NeedInput
            },
            HeaderAction::End { next_volume } if self.allow_volumes => {
                self.state = Rar5State::Tail;
                let mut physical = vec![u8::from(next_volume)];
                physical.extend_from_slice(&self.entries.to_le_bytes());
                physical.extend_from_slice(&self.decoded.to_le_bytes());
                self.archive_metadata = self.archive_metadata.clone().with_extension(
                    Extension::new("rar5", b"physical-volume-end".to_vec(), physical),
                );
                DecodeEvent::ArchiveMetadata(self.archive_metadata.clone())
            },
            HeaderAction::End { .. } => {
                self.state = Rar5State::Tail;
                DecodeEvent::NeedInput
            },
        }
    }
}

impl<P, C> ArchiveDecoder for Rar5Decoder<P, C>
where
    P: PayloadCodecProvider,
    C: Rar5CryptoProvider,
{
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        scratch: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        match self.state {
            Rar5State::Signature {
                window,
                length,
                scanned,
            } => self.scan_signature(input, end, window, length, scanned),
            Rar5State::Header => self.read_header(input, end),
            Rar5State::EncryptedHeaders => self.read_encrypted_header(input, end),
            Rar5State::EncryptedData(encrypted) => {
                self.read_encrypted_data(input, scratch, end, encrypted)
            },
            Rar5State::EncryptedService(service) => {
                self.read_encrypted_service(input, scratch, end, service)
            },
            Rar5State::BufferedData => self.read_buffered_data(scratch),
            Rar5State::Data {
                remaining,
                expected_crc,
                expected_blake2sp,
                verify_checksum,
                physical_raw,
                crc,
            } => self.read_file_data(
                input,
                scratch,
                end,
                remaining,
                expected_crc,
                expected_blake2sp,
                verify_checksum,
                physical_raw,
                crc,
            ),
            Rar5State::ServiceData {
                kind,
                remaining,
                expected_crc,
                expected_blake2sp,
                crc,
            } => self.read_service_data(
                input,
                scratch,
                end,
                kind,
                remaining,
                expected_crc,
                expected_blake2sp,
                crc,
            ),
            Rar5State::SkipData { remaining } => self.read_skipped_data(input, end, remaining),
            Rar5State::Tail => {
                if matches!(end, EndOfInput::End) {
                    self.state = Rar5State::Done;
                    Ok(step(input.len(), DecodeEvent::Done))
                } else {
                    Ok(step(input.len(), DecodeEvent::NeedInput))
                }
            },
            Rar5State::Done => {
                if input.is_empty() {
                    Ok(step(0, DecodeEvent::Done))
                } else {
                    Err(Self::error(
                        ErrorKind::Protocol,
                        "RAR5 decoder received input after completion",
                    ))
                }
            },
        }
    }
}

fn partial_header_size(bytes: &[u8]) -> Result<Option<(u64, usize)>, ArchiveError> {
    for width in 1..=bytes.len().min(3) {
        if bytes[width - 1] & 0x80 == 0 {
            return read_vint_at(bytes, 0, 3).map(|(value, actual)| Some((value, actual)));
        }
    }
    if bytes.len() >= 3 {
        Err(rar5_error(
            ErrorKind::Limit,
            "RAR5 header-size vint exceeds three bytes",
        ))
    } else {
        Ok(None)
    }
}

fn read_vint_at(
    bytes: &[u8],
    offset: usize,
    maximum_width: usize,
) -> Result<(u64, usize), ArchiveError> {
    let mut value = 0_u64;
    for width in 0..maximum_width.min(10) {
        let index = offset
            .checked_add(width)
            .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 vint offset overflow"))?;
        let byte = *bytes
            .get(index)
            .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 vint is truncated"))?;
        if width == 9 && byte & 0xfe != 0 {
            return Err(rar5_error(ErrorKind::Limit, "RAR5 vint exceeds 64 bits"));
        }
        value |= u64::from(byte & 0x7f) << (width * 7);
        if byte & 0x80 == 0 {
            return Ok((value, width + 1));
        }
    }
    Err(rar5_error(
        ErrorKind::Malformed,
        "RAR5 vint is too wide or unterminated",
    ))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], position: usize) -> Self {
        Self {
            bytes,
            position,
            end: bytes.len(),
        }
    }

    fn vint(&mut self) -> Result<u64, ArchiveError> {
        let (value, width) = read_vint_at(&self.bytes[..self.end], self.position, 10)?;
        self.position += width;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, ArchiveError> {
        let value = le_u32(&self.bytes[..self.end], self.position)?;
        self.position += 4;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, ArchiveError> {
        let value = le_u64(&self.bytes[..self.end], self.position)?;
        self.position += 8;
        Ok(value)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ArchiveError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 field length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 header field is truncated"))?;
        if end > self.end {
            return Err(rar5_error(
                ErrorKind::Malformed,
                "RAR5 header field overlaps the extra area",
            ));
        }
        self.position = end;
        Ok(value)
    }

    fn finish(&self) -> Result<(), ArchiveError> {
        if self.position == self.end {
            Ok(())
        } else {
            Err(rar5_error(
                ErrorKind::Malformed,
                "RAR5 header contains unconsumed fields",
            ))
        }
    }
}

struct ExtraRecord<'a> {
    record_type: u64,
    data: &'a [u8],
    consumed: usize,
}

fn extra_record(bytes: &[u8]) -> Result<ExtraRecord<'_>, ArchiveError> {
    let (record_size, size_width) = read_vint_at(bytes, 0, 10)?;
    let record_size = usize::try_from(record_size)
        .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 extra record exceeds usize"))?;
    if record_size == 0 {
        return Err(rar5_error(
            ErrorKind::Malformed,
            "RAR5 extra record is empty",
        ));
    }
    let record_end = size_width
        .checked_add(record_size)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 extra record size overflow"))?;
    let record = bytes
        .get(size_width..record_end)
        .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 extra record is truncated"))?;
    let (record_type, type_width) = read_vint_at(record, 0, 10)?;
    Ok(ExtraRecord {
        record_type,
        data: &record[type_width..],
        consumed: record_end,
    })
}

fn charge_retained(
    extras: &mut FileExtras,
    amount: usize,
    limits: Limits,
) -> Result<(), ArchiveError> {
    extras.retained_bytes = extras
        .retained_bytes
        .checked_add(amount)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 retained metadata size overflow"))?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| extras.retained_bytes > maximum)
    {
        return Err(rar5_error(
            ErrorKind::Limit,
            "RAR5 extra records exceed the configured metadata budget",
        ));
    }
    Ok(())
}

fn parse_main_extra_records(bytes: &[u8], limits: Limits) -> Result<MainExtras, ArchiveError> {
    let mut extras = MainExtras::default();
    let mut saw_locator = false;
    let mut saw_metadata = false;
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let record = extra_record(remaining)?;
        match record.record_type {
            1 => {
                if saw_locator {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 main header contains duplicate locator records",
                    ));
                }
                saw_locator = true;
                parse_locator_record(record.data, &mut extras)?;
            },
            2 => {
                if saw_metadata {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 main header contains duplicate metadata records",
                    ));
                }
                saw_metadata = true;
                parse_archive_metadata_record(record.data, limits, &mut extras)?;
            },
            _ => {},
        }
        remaining = &remaining[record.consumed..];
    }
    Ok(extras)
}

fn parse_locator_record(bytes: &[u8], extras: &mut MainExtras) -> Result<(), ArchiveError> {
    let mut cursor = Cursor::new(bytes, 0);
    let flags = cursor.vint()?;
    if flags & !0x0003 != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 locator record uses unknown flags",
        ));
    }
    if flags & 0x0001 != 0 {
        extras.quick_open_offset = nonzero(cursor.vint()?);
    }
    if flags & 0x0002 != 0 {
        extras.recovery_offset = nonzero(cursor.vint()?);
    }
    cursor.finish()
}

fn parse_archive_metadata_record(
    bytes: &[u8],
    limits: Limits,
    extras: &mut MainExtras,
) -> Result<(), ArchiveError> {
    const NAME: u64 = 0x0001;
    const TIME: u64 = 0x0002;
    const UNIX: u64 = 0x0004;
    const NANOSECONDS: u64 = 0x0008;

    let mut cursor = Cursor::new(bytes, 0);
    let flags = cursor.vint()?;
    if flags & !(NAME | TIME | UNIX | NANOSECONDS) != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 archive metadata record uses unknown flags",
        ));
    }
    if flags & NANOSECONDS != 0 && flags & (TIME | UNIX) != TIME | UNIX {
        return Err(rar5_error(
            ErrorKind::Malformed,
            "RAR5 archive nanosecond time requires Unix creation time",
        ));
    }
    if flags & NAME != 0 {
        let length = usize::try_from(cursor.vint()?)
            .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 original name length exceeds usize"))?;
        let raw = cursor.bytes(length)?;
        let significant = raw.split(|byte| *byte == 0).next().unwrap_or_default();
        if !significant.is_empty() {
            if limits
                .path_bytes()
                .is_some_and(|maximum| significant.len() > maximum)
            {
                return Err(rar5_error(
                    ErrorKind::Limit,
                    "RAR5 original name exceeds the configured path budget",
                ));
            }
            extras.original_name = Some(
                ArchivePath::try_from_encoded(significant.to_vec(), PathEncoding::Utf8).map_err(
                    |_| {
                        rar5_error(
                            ErrorKind::Malformed,
                            "RAR5 original archive name is not valid UTF-8",
                        )
                    },
                )?,
            );
        }
    }
    if flags & TIME != 0 {
        extras.created = Some(if flags & UNIX != 0 {
            if flags & NANOSECONDS != 0 {
                unix_nanoseconds_timestamp(cursor.u64()?)?
            } else {
                Timestamp::from_seconds(i64::from(cursor.u32()?))
            }
        } else {
            filetime_timestamp(cursor.u64()?)?
        });
    }
    cursor.finish()
}

const fn nonzero(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

fn unix_nanoseconds_timestamp(value: u64) -> Result<Timestamp, ArchiveError> {
    let seconds = i64::try_from(value / 1_000_000_000).map_err(|_| {
        rar5_error(
            ErrorKind::Malformed,
            "RAR5 Unix nanosecond timestamp exceeds i64 seconds",
        )
    })?;
    let nanoseconds = u32::try_from(value % 1_000_000_000).map_err(|_| {
        rar5_error(
            ErrorKind::Malformed,
            "RAR5 Unix nanosecond timestamp fraction is invalid",
        )
    })?;
    Timestamp::new(seconds, nanoseconds).map_err(|_| {
        rar5_error(
            ErrorKind::Malformed,
            "RAR5 Unix nanosecond timestamp is malformed",
        )
    })
}

fn timestamp_bytes(timestamp: Timestamp) -> Vec<u8> {
    let mut bytes = timestamp.seconds().to_le_bytes().to_vec();
    bytes.extend_from_slice(&timestamp.nanoseconds().to_le_bytes());
    bytes
}

fn parse_file_extra_records(bytes: &[u8], limits: Limits) -> Result<FileExtras, ArchiveError> {
    let mut extras = FileExtras::default();
    if !bytes.is_empty() {
        charge_retained(
            &mut extras,
            bytes
                .len()
                .checked_add(b"rar5file-extra".len())
                .and_then(|size| size.checked_add(core::mem::size_of::<Extension>()))
                .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 retained extra size overflow"))?,
            limits,
        )?;
    }
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let record = extra_record(remaining)?;
        match record.record_type {
            1 => {
                let encryption = parse_file_encryption_record(record.data)?;
                if extras.encryption.is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate encryption records",
                    ));
                }
                extras.encryption = Some(encryption);
            },
            2 => {
                let digest = parse_hash_record(record.data)?;
                if extras.blake2sp.replace(digest).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate hash records",
                    ));
                }
            },
            3 => {
                if extras
                    .times
                    .replace(parse_time_record(record.data)?)
                    .is_some()
                {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate time records",
                    ));
                }
            },
            4 => {
                let version = parse_version_record(record.data)?;
                if extras.version.replace(version).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate version records",
                    ));
                }
            },
            5 => {
                let redirection = parse_redirection_record(record.data, limits)?;
                charge_retained(&mut extras, redirection.target.as_bytes().len(), limits)?;
                if extras.redirection.replace(redirection).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate redirection records",
                    ));
                }
            },
            6 => {
                let owner = parse_owner_record(record.data)?;
                let retained = owner
                    .user
                    .as_ref()
                    .map_or(0, Vec::len)
                    .checked_add(owner.group.as_ref().map_or(0, Vec::len))
                    .ok_or_else(|| {
                        rar5_error(ErrorKind::Limit, "RAR5 owner metadata size overflow")
                    })?;
                charge_retained(&mut extras, retained, limits)?;
                if extras.owner.replace(owner).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 file contains duplicate owner records",
                    ));
                }
            },
            7 => {
                return Err(rar5_error(
                    ErrorKind::Malformed,
                    "RAR5 file header contains a service-only data record",
                ));
            },
            _ => {},
        }
        remaining = &remaining[record.consumed..];
    }
    Ok(extras)
}

fn parse_file_encryption_record(bytes: &[u8]) -> Result<Rar5FileEncryption, ArchiveError> {
    const PASSWORD_CHECK: u64 = 0x0001;
    const TWEAKED_CHECKSUMS: u64 = 0x0002;

    let mut cursor = Cursor::new(bytes, 0);
    let version = cursor.vint()?;
    if version != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 file uses an unknown encryption algorithm version",
        ));
    }
    let flags = cursor.vint()?;
    if flags & !(PASSWORD_CHECK | TWEAKED_CHECKSUMS) != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 file encryption record uses unknown flags",
        ));
    }
    let kdf_exponent = cursor.bytes(1)?[0];
    let salt = cursor
        .bytes(16)?
        .try_into()
        .map_err(|_| rar5_error(ErrorKind::Protocol, "RAR5 salt width changed"))?;
    let iv = cursor
        .bytes(16)?
        .try_into()
        .map_err(|_| rar5_error(ErrorKind::Protocol, "RAR5 IV width changed"))?;
    let password_check = if flags & PASSWORD_CHECK != 0 {
        Some(
            cursor
                .bytes(12)?
                .try_into()
                .map_err(|_| rar5_error(ErrorKind::Protocol, "RAR5 check width changed"))?,
        )
    } else {
        None
    };
    cursor.finish()?;
    Ok(Rar5FileEncryption {
        parameters: Rar5CryptoParameters::new(
            kdf_exponent,
            salt,
            password_check,
            flags & TWEAKED_CHECKSUMS != 0,
        ),
        iv,
    })
}

fn parse_service_extra_records(bytes: &[u8]) -> Result<ServiceExtras, ArchiveError> {
    let mut extras = ServiceExtras::default();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let record = extra_record(remaining)?;
        match record.record_type {
            1 => {
                let encryption = parse_file_encryption_record(record.data)?;
                if extras.encryption.replace(encryption).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 service contains duplicate encryption records",
                    ));
                }
            },
            2 => {
                let digest = parse_hash_record(record.data)?;
                if extras.blake2sp.replace(digest).is_some() {
                    return Err(rar5_error(
                        ErrorKind::Malformed,
                        "RAR5 service contains duplicate hash records",
                    ));
                }
            },
            _ => {},
        }
        remaining = &remaining[record.consumed..];
    }
    Ok(extras)
}

fn parse_compression_info(value: u64) -> Result<Rar5CompressionInfo, ArchiveError> {
    const KNOWN_BITS: u64 = 0x001f_ffff;
    const DICTIONARY_MASK: u64 = 0x0000_7c00;
    const FRACTION_MASK: u64 = 0x000f_8000;
    const VERSION_ONE_USES_OLD_ALGORITHM: u64 = 0x0010_0000;

    if value & !KNOWN_BITS != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 compression information uses unknown bits",
        ));
    }
    let dictionary_version = value & 0x3f;
    if dictionary_version > 1 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 entry requires an unknown compression algorithm version",
        ));
    }
    let exponent = u32::try_from((value & DICTIONARY_MASK) >> 10).map_err(|_| {
        rar5_error(
            ErrorKind::Malformed,
            "RAR5 dictionary exponent is malformed",
        )
    })?;
    let fraction = (value & FRACTION_MASK) >> 15;
    if dictionary_version == 0
        && (exponent > 15 || fraction != 0 || value & VERSION_ONE_USES_OLD_ALGORITHM != 0)
    {
        return Err(rar5_error(
            ErrorKind::Malformed,
            "RAR5 generation 0 entry uses generation 1 dictionary fields",
        ));
    }
    if exponent > 23 || (exponent == 23 && fraction != 0) {
        return Err(rar5_error(
            ErrorKind::Malformed,
            "RAR5 dictionary exponent exceeds the format maximum",
        ));
    }
    let base = (128_u64 * 1024)
        .checked_shl(exponent)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 dictionary size overflow"))?;
    let fractional = (base / 32)
        .checked_mul(fraction)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 dictionary size overflow"))?;
    let dictionary = base
        .checked_add(fractional)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 dictionary size overflow"))?;
    let version = if value & VERSION_ONE_USES_OLD_ALGORITHM != 0 {
        0
    } else {
        dictionary_version
    };
    Ok(Rar5CompressionInfo {
        version,
        method: (value & 0x0380) >> 7,
        solid: value & 0x0040 != 0,
        dictionary,
    })
}

fn parse_hash_record(bytes: &[u8]) -> Result<[u8; 32], ArchiveError> {
    let mut cursor = Cursor::new(bytes, 0);
    if cursor.vint()? != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 file uses an unknown hash algorithm",
        ));
    }
    let digest = cursor
        .bytes(32)?
        .try_into()
        .map_err(|_| rar5_error(ErrorKind::Malformed, "RAR5 BLAKE2sp digest is malformed"))?;
    cursor.finish()?;
    Ok(digest)
}

fn parse_time_record(bytes: &[u8]) -> Result<EntryTimes, ArchiveError> {
    const UNIX: u64 = 0x0001;
    const MODIFIED: u64 = 0x0002;
    const CREATED: u64 = 0x0004;
    const ACCESSED: u64 = 0x0008;
    const NANOSECONDS: u64 = 0x0010;

    let mut cursor = Cursor::new(bytes, 0);
    let flags = cursor.vint()?;
    if flags & !(UNIX | MODIFIED | CREATED | ACCESSED | NANOSECONDS) != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 time record uses unknown flags",
        ));
    }
    if flags & NANOSECONDS != 0 && flags & UNIX == 0 {
        return Err(rar5_error(
            ErrorKind::Malformed,
            "RAR5 nanosecond times require Unix time format",
        ));
    }
    let mut raw_times = [None; 3];
    for (index, present) in [MODIFIED, CREATED, ACCESSED].into_iter().enumerate() {
        if flags & present != 0 {
            raw_times[index] = Some(if flags & UNIX != 0 {
                Timestamp::from_seconds(i64::from(cursor.u32()?))
            } else {
                filetime_timestamp(cursor.u64()?)?
            });
        }
    }
    if flags & UNIX != 0 && flags & NANOSECONDS != 0 {
        for (index, present) in [MODIFIED, CREATED, ACCESSED].into_iter().enumerate() {
            if flags & present != 0 {
                let seconds = raw_times[index]
                    .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 time field is missing"))?
                    .seconds();
                raw_times[index] = Some(Timestamp::new(seconds, cursor.u32()?).map_err(|_| {
                    rar5_error(ErrorKind::Malformed, "RAR5 nanoseconds are out of range")
                })?);
            }
        }
    }
    cursor.finish()?;
    Ok(EntryTimes {
        modified: raw_times[0],
        created: raw_times[1],
        accessed: raw_times[2],
        changed: None,
    })
}

fn parse_version_record(bytes: &[u8]) -> Result<u64, ArchiveError> {
    let mut cursor = Cursor::new(bytes, 0);
    if cursor.vint()? != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 file version record uses unknown flags",
        ));
    }
    let version = cursor.vint()?;
    cursor.finish()?;
    Ok(version)
}

fn parse_redirection_record(bytes: &[u8], limits: Limits) -> Result<Redirection, ArchiveError> {
    let mut cursor = Cursor::new(bytes, 0);
    let redirection_type = cursor.vint()?;
    let flags = cursor.vint()?;
    if flags & !0x0001 != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 redirection record uses unknown flags",
        ));
    }
    let length = usize::try_from(cursor.vint()?)
        .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 link target length exceeds usize"))?;
    if limits.path_bytes().is_some_and(|maximum| length > maximum) {
        return Err(rar5_error(
            ErrorKind::Limit,
            "RAR5 link target exceeds the configured path budget",
        ));
    }
    let target = ArchivePath::try_from_encoded(cursor.bytes(length)?.to_vec(), PathEncoding::Utf8)
        .map_err(|_| rar5_error(ErrorKind::Malformed, "RAR5 link target is not valid UTF-8"))?;
    cursor.finish()?;
    let kind = match redirection_type {
        1..=3 => EntryKind::Symlink,
        4 => EntryKind::Hardlink,
        5 => {
            return Err(rar5_error(
                ErrorKind::Unsupported,
                "RAR5 file-copy redirection is not represented by core metadata",
            ));
        },
        _ => {
            return Err(rar5_error(
                ErrorKind::Unsupported,
                "RAR5 redirection type is unknown",
            ));
        },
    };
    Ok(Redirection { kind, target })
}

fn parse_owner_record(bytes: &[u8]) -> Result<Owner, ArchiveError> {
    let mut cursor = Cursor::new(bytes, 0);
    let flags = cursor.vint()?;
    if flags & !0x000f != 0 {
        return Err(rar5_error(
            ErrorKind::Unsupported,
            "RAR5 owner record uses unknown flags",
        ));
    }
    let user = if flags & 0x0001 != 0 {
        let length = usize::try_from(cursor.vint()?)
            .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 user name length exceeds usize"))?;
        Some(cursor.bytes(length)?.to_vec())
    } else {
        None
    };
    let group = if flags & 0x0002 != 0 {
        let length = usize::try_from(cursor.vint()?)
            .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 group name length exceeds usize"))?;
        Some(cursor.bytes(length)?.to_vec())
    } else {
        None
    };
    let uid = if flags & 0x0004 != 0 {
        Some(cursor.vint()?)
    } else {
        None
    };
    let gid = if flags & 0x0008 != 0 {
        Some(cursor.vint()?)
    } else {
        None
    };
    cursor.finish()?;
    Ok(Owner {
        uid,
        gid,
        user,
        group,
    })
}

fn filetime_timestamp(ticks: u64) -> Result<Timestamp, ArchiveError> {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const UNIX_EPOCH_SECONDS: i128 = 11_644_473_600;

    let seconds = i128::from(ticks / TICKS_PER_SECOND) - UNIX_EPOCH_SECONDS;
    let seconds = i64::try_from(seconds).map_err(|_| {
        rar5_error(
            ErrorKind::Malformed,
            "RAR5 FILETIME is outside timestamp range",
        )
    })?;
    let nanoseconds = u32::try_from(ticks % TICKS_PER_SECOND)
        .ok()
        .and_then(|fraction| fraction.checked_mul(100))
        .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 FILETIME fraction is invalid"))?;
    Timestamp::new(seconds, nanoseconds)
        .map_err(|_| rar5_error(ErrorKind::Malformed, "RAR5 FILETIME is malformed"))
}

fn validate_extra_records(mut bytes: &[u8]) -> Result<(), ArchiveError> {
    while !bytes.is_empty() {
        let (record_size, size_width) = read_vint_at(bytes, 0, 10)?;
        let record_size = usize::try_from(record_size)
            .map_err(|_| rar5_error(ErrorKind::Limit, "RAR5 extra record exceeds usize"))?;
        if record_size == 0 {
            return Err(rar5_error(
                ErrorKind::Malformed,
                "RAR5 extra record is empty",
            ));
        }
        let record_end = size_width
            .checked_add(record_size)
            .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 extra record size overflow"))?;
        let record = bytes
            .get(size_width..record_end)
            .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 extra record is truncated"))?;
        let _ = read_vint_at(record, 0, 10)?;
        bytes = &bytes[record_end..];
    }
    Ok(())
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 u32 offset overflow"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 u32 is truncated"))?
        .try_into()
        .map_err(|_| rar5_error(ErrorKind::Malformed, "RAR5 u32 is malformed"))?;
    Ok(u32::from_le_bytes(raw))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, ArchiveError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| rar5_error(ErrorKind::Limit, "RAR5 u64 offset overflow"))?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| rar5_error(ErrorKind::Malformed, "RAR5 u64 is truncated"))?
        .try_into()
        .map_err(|_| rar5_error(ErrorKind::Malformed, "RAR5 u64 is malformed"))?;
    Ok(u64::from_le_bytes(raw))
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
            value = if value & 1 == 0 {
                value >> 1
            } else {
                (value >> 1) ^ 0xedb8_8320
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

    impl Rar5CryptoProvider for CountCrypto {
        type Key = ();

        fn candidate_count(&self) -> usize {
            self.0
        }

        fn derive_key(
            &self,
            _candidate: usize,
            _parameters: Rar5CryptoParameters,
            _maximum_iterations: u64,
        ) -> Result<Option<Self::Key>, ArchiveError> {
            Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("candidate bounds were not validated before RAR5 KDF"))
        }

        fn decrypt(
            &self,
            _key: &Self::Key,
            _iv: [u8; 16],
            _ciphertext: &mut [u8],
        ) -> Result<(), ArchiveError> {
            Err(ArchiveError::new(ErrorKind::Protocol)
                .with_context("candidate bounds were not validated before RAR5 decryption"))
        }

        fn tweak_crc32(&self, _key: &Self::Key, crc: u32) -> Result<u32, ArchiveError> {
            Ok(crc)
        }

        fn tweak_blake2sp(
            &self,
            _key: &Self::Key,
            digest: [u8; 32],
        ) -> Result<[u8; 32], ArchiveError> {
            Ok(digest)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct IdentityCrypto;

    impl Rar5CryptoProvider for IdentityCrypto {
        type Key = ();

        fn candidate_count(&self) -> usize {
            1
        }

        fn derive_key(
            &self,
            _candidate: usize,
            _parameters: Rar5CryptoParameters,
            _maximum_iterations: u64,
        ) -> Result<Option<Self::Key>, ArchiveError> {
            Ok(Some(()))
        }

        fn decrypt(
            &self,
            _key: &Self::Key,
            _iv: [u8; 16],
            _ciphertext: &mut [u8],
        ) -> Result<(), ArchiveError> {
            Ok(())
        }

        fn tweak_crc32(&self, _key: &Self::Key, crc: u32) -> Result<u32, ArchiveError> {
            Ok(crc)
        }

        fn tweak_blake2sp(
            &self,
            _key: &Self::Key,
            digest: [u8; 32],
        ) -> Result<[u8; 32], ArchiveError> {
            Ok(digest)
        }
    }

    #[test]
    fn crypto_candidate_count_is_bounded_independently_of_the_provider() {
        let accepted = Rar5Decoder::with_crypto(Limits::safe(), CountCrypto(16));
        assert_eq!(accepted.password_candidate_count().unwrap(), 16);

        let rejected = Rar5Decoder::with_crypto(Limits::safe(), CountCrypto(17));
        assert_eq!(
            rejected.password_candidate_count().unwrap_err().kind(),
            ErrorKind::Limit
        );
    }

    #[test]
    fn rar7_compatibility_flag_selects_generation_zero_with_exact_dictionary() {
        let compression = Rar5CompressionInfo::from_raw(1 | (1 << 7) | (1 << 15) | 0x0010_0000)
            .expect("RAR7 compatibility algorithm header");

        assert_eq!(compression.version(), 0);
        assert_eq!(compression.method(), 1);
        assert_eq!(compression.dictionary(), 132 * 1024);
    }

    #[test]
    fn encrypted_payload_without_a_checksum_is_never_released() {
        let mut decoder = Rar5Decoder::with_crypto(Limits::safe(), IdentityCrypto);
        decoder.encrypted_data = vec![0x41; AES_BLOCK_BYTES];
        let encrypted = EncryptedState {
            remaining: 0,
            unpacked_size: 1,
            expected_crc: None,
            expected_blake2sp: None,
            verify_checksum: true,
            compression: Rar5CompressionInfo::from_raw(0).unwrap(),
            encryption: Rar5FileEncryption {
                parameters: Rar5CryptoParameters::new(0, [0; 16], None, false),
                iv: [0; 16],
            },
            split: false,
        };
        let error = decoder
            .try_encrypted_candidates(encrypted, &mut [0; 1], 1)
            .expect_err("unauthenticated encrypted RAR5 payload must fail closed");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }
}
